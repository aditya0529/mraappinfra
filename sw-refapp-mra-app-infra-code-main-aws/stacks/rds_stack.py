"""
Aurora Documentation:
*********************
https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/CHAP_AuroraOverview.html

Aurora Serverless:
*****************
Read more about the limitations of Aurora Serverless
https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless.html#aurora-serverless.limitations

Learn more about using Amazon Aurora Serverless by reading the documentation
https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless.html

For information about Aurora global databases, see Working with Amazon Aurora Global Databases in the Amazon Aurora User Guide .
https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-global-database.html

This stack will be triggered based on the global database option in "resource.config" to create the primary regional Cluster.
Code related to Password Rotation is commented out to support the global database, which can be enabled for non-global database.
"""

from aws_cdk import (
    Duration,
    Stack,
    Tags,
    aws_rds as rds,
    aws_ec2 as ec2,
    aws_logs as logs,
    aws_kms as kms,
    aws_secretsmanager as secretsmanager,
    SecretValue as SecretValue
)

from constructs import Construct
import json

class RdsStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, resource_config, pgaudit=None, cluster=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here
        config = resource_config

        # vpc lookup from account
        vpc = ec2.Vpc.from_lookup(
            self,
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-vpc-{config['app_name']}-{config['deployment_region_1']}-{config['resource_suffix']}",
            vpc_id=f"{config['vpc_id_1']}")

        # Select workload subnets from VPC
        workload_subnet_selection = ec2.SubnetSelection(
            one_per_az=True,
            subnet_filters=[
                ec2.SubnetFilter.by_ids([
                    f"{config['subnet_id_1_1']}",
                    f"{config['subnet_id_1_2']}"
                ])
            ])

        # Database security group for mySql, postgres
        rds_sg = ec2.SecurityGroup(
            self,
            "rds-sg",
            security_group_name=
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-rds0-{config['resource_suffix']}",
            description=
            "Allow the communication DB",
            allow_all_outbound=True,
            vpc=vpc)
        if config.get('database_engine') == "aurora_mysql":
            # Security group port for aurora-mysql
            rds_sg.add_ingress_rule(
                ec2.Peer.ipv4(vpc.vpc_cidr_block),
                ec2.Port.tcp(3306))
        elif config.get('database_engine') == "aurora_postgres":
            # Security group for aurora-postgres
            rds_sg.add_ingress_rule(
                ec2.Peer.ipv4(vpc.vpc_cidr_block),
                ec2.Port.tcp(5432))

        #Cluster and Instance Name.
        database_cl_name = f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-cl-{config['resource_suffix']}"
        database_instance_name = f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-instance-{config['resource_suffix']}"
        database_secret_name = f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-secret-{config['resource_suffix']}"

        rds_key = kms.Key.from_key_arn(
            self,
            id="customer-managed-rds-key",
            key_arn=f"arn:aws:kms:{config['deployment_region_1']}:{config['workload_account']}:key/{config['rds_kms_id']}")

        # custom option group.
        # option_group_config = rds.OptionGroup(
        #     option_group_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-rds-og-{config['resource_suffix']}"
        # )

        # RDS cluster with serverless instances.
        if config.get('database_instance_type') == "serverless_v2":
            if ((config.get('database_engine') == "aurora_mysql") and (config.get('database_cluster_type') == "Regional")):
                cluster = rds.DatabaseCluster(self, database_cl_name,
                                              engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_02_0),
                                              credentials=rds.Credentials.from_generated_secret("cluster_admin"),  # Optional - will default to 'admin' username and generated password
                                              storage_encrypted=True,
                                              writer=rds.ClusterInstance.serverless_v2(database_instance_name+"1",publicly_accessible=False),
                                              serverless_v2_min_capacity=0.5,
                                              serverless_v2_max_capacity=2,
                                              #readers=[rds.ClusterInstance.serverless_v2("reader1",ca_certificate=rds.CaCertificate.of("custom-ca"))],
                                              readers=[rds.ClusterInstance.serverless_v2(database_instance_name+"2", scale_with_writer=True),
                                                       rds.ClusterInstance.serverless_v2(database_instance_name+"3")],
                                              instance_update_behaviour=rds.InstanceUpdateBehaviour.ROLLING,
                                              vpc_subnets=workload_subnet_selection,
                                              parameter_group=rds.ParameterGroup.from_parameter_group_name(self, cluster_pg_name, "default.aurora-mysql8.0"),
                                              copy_tags_to_snapshot=True,
                                              vpc=vpc,
                                              security_groups=[rds_sg],
                                              cloudwatch_logs_exports=["error", "general", "slowquery", "audit"],  # Export all available MySQL-based logs
                                              cloudwatch_logs_retention=logs.RetentionDays.THREE_MONTHS,  # Optional - default is to never expire logs
                                              #option_group=option_group_config,
                                              #parameter_group=parameter_group_cluster_config,
                                              #instance_parameter_group=parameter_group_instance_config
                                              )
                cluster.metric_serverless_database_capacity(period=Duration.minutes(10)).create_alarm(self, "capacity", threshold=1.5, evaluation_periods=3)
            elif (config.get('database_engine') == "aurora_postgres") and (config.get('database_cluster_type') == "Regional"):
                #Postgresql Cluster custom parameter group.
                cluster_pg_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-cl-cpg-{config['resource_suffix']}"
                cluster_pg=rds.ParameterGroup(self, cluster_pg_name,
                                              engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_16_1),
                                              parameters={
                                                  "pgaudit.log": "ddl",
                                                  "pgaudit.log_level": "info",
                                                  "log_connections": "1",
                                                  "log_disconnections": "1"
                                              }
                                              )

                # Postgresql Instance custom parameter group.
                instance_pg_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-rds-ipg-{config['resource_suffix']}"
                instance_pg=rds.ParameterGroup(self,instance_pg_name,
                                               engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_16_1),
                                               parameters={
                                                   "pgaudit.log": "ddl",
                                                   "pgaudit.log_level": "info",
                                                   "log_connections": "1",
                                                   "log_disconnections": "1"
                                               }
                                               )

                cluster = rds.DatabaseCluster(self,database_cl_name,
                                              cluster_identifier=database_cl_name,
                                              engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_16_1),
                                              credentials=rds.Credentials.from_generated_secret(username="postgres",secret_name=database_secret_name,replica_regions=[secretsmanager.ReplicaRegion(region="us-east-1")]),
                                              storage_encrypted=True,
                                              storage_encryption_key=rds_key,
                                              writer=rds.ClusterInstance.serverless_v2("instance-1",instance_identifier=f"{database_cl_name}-instance-1",publicly_accessible=False,enable_performance_insights=True,auto_minor_version_upgrade = True,parameter_group=instance_pg),
                                              readers=[rds.ClusterInstance.serverless_v2("instance-2",instance_identifier=f"{database_cl_name}-instance-2",publicly_accessible=False,scale_with_writer=True,enable_performance_insights=True,auto_minor_version_upgrade = True,parameter_group=instance_pg)],
                                              instance_update_behaviour=rds.InstanceUpdateBehaviour.ROLLING,
                                              #parameter_group=cluster_pg,
                                              copy_tags_to_snapshot=True,
                                              vpc_subnets=workload_subnet_selection,
                                              vpc=vpc,
                                              security_groups=[rds_sg],
                                              cloudwatch_logs_exports=["postgresql"],  # Export all available logs
                                              cloudwatch_logs_retention=logs.RetentionDays.THREE_MONTHS,  # Optional - default is to never expire logs
                                              deletion_protection=False,
                                              backup=rds.BackupProps(retention=Duration.days(30)),
                                              monitoring_interval=Duration.seconds(60)
                                              )
                #TAG to enable the backup to backup-vault.
                Tags.of(cluster).add("swift:backup", "backup-to-vault_auroradb")

                #Enable RDS Managed MasterUser Password  rotation, Only after the initial database creation.
                #Disable the password rotation option for Global Database.
                # TBD: Add Dependency.
                #cluster.node.default_child.add_override('Properties.ManageMasterUserPassword', True)

                #Application user Secret creation with Temporary Password.
                #TBD/Enhancement: Read appuser list from config file.
                # appuser1_secret = secretsmanager.Secret(self,"appuser1",
                # #secret_object_value=json.loads(database_appuser_credentials)
                # secret_object_value={
                #     "engine": SecretValue.unsafe_plain_text("postgres"),
                #     "host": SecretValue.unsafe_plain_text("sw-ccoe-sandbox-cl-main-aws.cluster-cvcjjdhyfmoh.eu-central-1.rds.amazonaws.com"),
                #     #"host": SecretValue.unsafe_plain_text(self.cluster_postgres.cluster_endpoint),
                #     "username": SecretValue.unsafe_plain_text("appuser1"),
                #     "password": SecretValue.unsafe_plain_text("TempPwd!23"),
                #     "dbname": SecretValue.unsafe_plain_text("postgres"),
                #     "port": SecretValue.unsafe_plain_text("5432")
                # }
                # )
                # Application user secret creation with random password.
                #appuser2_secret = secretsmanager.Secret(self, "appuser2",
                # generate_secret_string=secretsmanager.SecretStringGenerator(
                # secret_string_template=json.dumps({"username":"appuser2","host":"sw-ccoe-sandbox-cl-main-aws.cluster-cvcjjdhyfmoh.eu-central-1.rds.amazonaws.com",
                #                                    "engine":"postgres","dbname":"postgres","port":"5432"}),
                # generate_string_key="password",
                # exclude_characters=" %+~`#$&*()|[]{}:;<>?!'/@\"\\"
                # )
                # )
                #TBD/Enahancement Application user password rotation using multi user option.
                # secretsmanager.SecretRotation(self, "appuser_rotation",
                #                               application=secretsmanager.SecretRotationApplication.POSTGRES_ROTATION_MULTI_USER,
                #                               secret=appuser_secret1.secret_arn,
                #                               master_secret="arn:aws:secretsmanager:eu-central-1:573792771178:secret:rds!cluster-67d73b06-9287-4efd-82f0-7f6c0aeba8cf-2w89tE",
                #                               target=database_cl_name,
                #                               vpc=vpc)
                # Enable Single user Rotation after the database configuration: Create appusers with passwords from secrets manager.
                # Dependency on DB user with expected Temp/Secrets manager password.
                #appuser1_secret.add_rotation_schedule("RotationSchedule", hosted_rotation=secretsmanager.HostedRotation.postgre_sql_single_user(vpc=vpc,vpc_subnets=workload_subnet_selection,security_groups=[rds_sg]))
                #appuser2_secret.add_rotation_schedule("RotationSchedule", hosted_rotation=secretsmanager.HostedRotation.postgre_sql_single_user(vpc=vpc,vpc_subnets=workload_subnet_selection,security_groups=[rds_sg]))
                # TBD/Enhancement: Enable Multi user password Rotaion.
                #appuser_secret1.add_rotation_schedule("RotationSchedule", hosted_rotation=secretsmanager.HostedRotation.postgre_sql_multi_user())

        else:
            if config.get('database_engine') == "aurora_mysql":
                cluster = rds.DatabaseCluster(self, database_cl_name,
                                              engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_02_0),
                                              credentials=rds.Credentials.from_generated_secret("cluster_admin"),  # Optional - will default to 'admin' username and generated password
                                              storage_encrypted=True,
                                              writer=rds.ClusterInstance.provisioned(database_instance_name,publicly_accessible=False,instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM)),
                                              readers=[rds.ClusterInstance.provisioned(database_instance_name, promotion_tier=1)],
                                              instance_update_behaviour=rds.InstanceUpdateBehaviour.ROLLING,
                                              parameter_group=rds.ParameterGroup.from_parameter_group_name(self, cluster_pg_name, "default.aurora-mysql8.0"),
                                              copy_tags_to_snapshot=True,
                                              vpc_subnets=workload_subnet_selection,
                                              vpc=vpc,
                                              security_groups=[rds_sg],
                                              cloudwatch_logs_exports=["error", "general", "slowquery", "audit"],  # Export all available MySQL-based logs
                                              cloudwatch_logs_retention=logs.RetentionDays.THREE_MONTHS,  # Optional - default is to never expire logs
                                              )
            elif config.get('database_engine') == "aurora_postgres":
                cluster = rds.DatabaseCluster(self, database_cl_name,
                                              engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_16_1),
                                              credentials=rds.Credentials.from_generated_secret("cluster_admin"),  # Optional - will default to 'admin' username and generated password
                                              storage_encrypted=True,
                                              writer=rds.ClusterInstance.provisioned(database_instance_name,publicly_accessible=False,instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM)),
                                              readers=[rds.ClusterInstance.provisioned(database_instance_name, promotion_tier=1)],
                                              instance_update_behaviour=rds.InstanceUpdateBehaviour.ROLLING,
                                              parameter_group=rds.ParameterGroup.from_parameter_group_name(self, cluster_pg_name, "default.aurora-postgresql16"),
                                              copy_tags_to_snapshot=True,
                                              vpc_subnets=workload_subnet_selection,
                                              vpc=vpc,
                                              security_groups=[rds_sg],
                                              cloudwatch_logs_exports=["error", "general", "slowquery", "audit"],  # Export all available MySQL-based logs
                                              cloudwatch_logs_retention=logs.RetentionDays.THREE_MONTHS,  # Optional - default is to never expire logs
                                              )

        # Global cluster creation
        if config.get('enable_global_database') == "true":
            global_cl_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-rds-gc-{config['resource_suffix']}"
            global_cluster = rds.CfnGlobalCluster(self, global_cl_name,
                                                  # deletion_protection=False,
                                                  # engine="aurora-postgresql",
                                                  #engine_lifecycle_support="engineLifecycleSupport",
                                                  # engine_version="16.1",
                                                  global_cluster_identifier=global_cl_name,
                                                  source_db_cluster_identifier=cluster.cluster_identifier,
                                                  # storage_encrypted=True,
                                                  #tags=[CfnTag(key="key",value="value")]
                                                  )
            #global_cluster.add_dependency(cluster)
