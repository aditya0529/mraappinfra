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

This stack will be triggered based on the global database option in "resource.config" to re-create the primary Cluster.
"""

from aws_cdk import (
    Duration,
    Stack,
    Tags,
    aws_rds as rds,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_logs as logs,
    aws_kms as kms,
    aws_secretsmanager as secretsmanager,
    SecretValue as SecretValue
)
from constructs import Construct
from aws_cdk.aws_iam import ManagedPolicy
import json
class RdsStack1(Stack):
    def __init__(self, scope: Construct, construct_id: str, resource_config, cluster=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here
        config = resource_config

        # vpc lookup from account
        vpc = ec2.Vpc.from_lookup(
            self,
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-vpc-{config['app_name']}-{config['deployment_region_1']}-{config['resource_suffix']}",
            vpc_id=f"{config['vpc_id_1']}")

        # Select workload subnets from VPC
        # workload_subnet_selection = ec2.SubnetSelection(
        #     one_per_az=True,
        #     subnet_filters=[
        #         ec2.SubnetFilter.by_ids([
        #             f"{config['subnet_id_2_1']}",
        #             f"{config['subnet_id_2_2']}"
        #         ])
        #     ])
        database_subnet_group_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-db-subnet-group-{config['app_name']}-{config['deployment_region_1']}-{config['resource_suffix']}"
        database_subnet_group = rds.CfnDBSubnetGroup(
            self,
            database_subnet_group_name,
            db_subnet_group_description="Database Subnet Group",
            subnet_ids=[f"{config['subnet_id_1_1']}",f"{config['subnet_id_1_2']}"],
            # the properties below are optional
            db_subnet_group_name=database_subnet_group_name,
        )

        # Database security group for mySql, postgres
        rds_sg = ec2.SecurityGroup(
            self,
            "rds-sg",
            security_group_name=
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-rds1-{config['resource_suffix']}",
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

        #Cluster Name.
        database_cl_name = f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-rds-cl1-{config['resource_suffix']}"

        key_arn=f"arn:aws:kms:{config['deployment_region_1']}:{config['workload_account']}:key/{config['mrk_id']}"

        cluster_pg_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-cl1-cpg-{config['resource_suffix']}"
        cluster_pg=rds.CfnDBClusterParameterGroup(self, cluster_pg_name,
                                                  family="aurora-postgresql16",
                                                  description="Custom Cluster parameter group for Aurora PostgreSQL",
                                                  parameters={
                                                      "pgaudit.log": "ddl",
                                                      "pgaudit.log_level": "info",
                                                      "log_connections": "1",
                                                      "log_disconnections": "1",
                                                      "rds.force_ssl": "1"
                                                  }
                                                  )

        # Postgresql Instance custom parameter group.
        instance_pg_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-rds-ipg1-{config['resource_suffix']}"
        instance_pg=rds.CfnDBParameterGroup(self,instance_pg_name,
                                            family="aurora-postgresql16",
                                            description="Custom Instance parameter group for Aurora PostgreSQL",
                                            parameters={
                                                "pgaudit.log": "ddl",
                                                "pgaudit.log_level": "info",
                                                "log_connections": "1",
                                                "log_disconnections": "1"
                                            }
                                            )

        # custom option group.
        # option_group_config = rds.OptionGroup(
        #     option_group_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-rds-og-{config['resource_suffix']}"
        # )

        # Create IAM role for RDS Enhanced Monitoring
        rds_em_role_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-rds-em-role1-{config['resource_suffix']}"
        rds_enhanced_monitoring_role = iam.Role(
            self,
            rds_em_role_name,
            role_name=rds_em_role_name,
            assumed_by=iam.ServicePrincipal("monitoring.rds.amazonaws.com").with_conditions({
                "StringEquals":
                    {"aws:SourceAccount": f"{config['workload_account']}"}
            }),
            managed_policies=[
                ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonRDSEnhancedMonitoringRole")
            ]
        )

        # RDS cluster with serverless instances.

        if config.get('database_instance_type') == "serverless_v2":
            if ((config.get('database_engine') == "aurora_mysql") and (config.get('database_cluster_type') == "Regional")):
                cluster= rds.CfnDBCluster(self, database_cl_name, db_cluster_identifier=database_cl_name,
                                          engine="aurora-mysql",
                                          engine_version="16.1",
                                          storage_encrypted=True,
                                          kms_key_id=key_arn,
                                          publicly_accessible=False,
                                          # db_cluster_parameter_group_name=cluster_pg,
                                          # db_instance_parameter_group_name=instance_pg,
                                          vpc_security_group_ids=[rds_sg.security_group_id]
                                          # global_cluster_identifier=RdsStack.global_cluster.global_cluster_identifier
                                          )
            elif (config.get('database_engine') == "aurora_postgres") and (config.get('database_cluster_type') == "Regional"):
                cluster= rds.CfnDBCluster(self, database_cl_name,db_cluster_identifier=database_cl_name,
                                          engine="aurora-postgresql",
                                          engine_version="16.1",
                                          # master_username="postgres",
                                          # master_user_password="TempPassword",
                                          #manage_master_user_password=False,
                                          storage_encrypted=True,
                                          kms_key_id=key_arn,
                                          #publicly_accessible=False,
                                          db_cluster_parameter_group_name=cluster_pg.ref,
                                          db_instance_parameter_group_name=instance_pg.ref,
                                          vpc_security_group_ids=[rds_sg.security_group_id],
                                          db_subnet_group_name=database_subnet_group.ref,
                                          port=5432,
                                          serverless_v2_scaling_configuration=rds.CfnDBCluster.ServerlessV2ScalingConfigurationProperty(
                                              max_capacity=123,
                                              min_capacity=0.5),
                                          global_cluster_identifier=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-rds-gc-{config['resource_suffix']}",
                                          enable_global_write_forwarding=True,
                                          performance_insights_enabled=True,
                                          monitoring_interval=60,
                                          monitoring_role_arn=rds_enhanced_monitoring_role.role_arn,
                                          deletion_protection=False,
                                          enable_cloudwatch_logs_exports=["postgresql"],
                                          )
                # cluster1= rds.CfnDBCluster(self, "test-cl1",db_cluster_identifier="test-cl1",
                #                           engine="aurora-postgresql",
                #                           engine_version="16.1",
                #                           # master_username="postgres",
                #                           # master_user_password="TempPassword",
                #                           #manage_master_user_password=False,
                #                           storage_encrypted=True,
                #                           kms_key_id=key_arn,
                #                           #publicly_accessible=False,
                #                           db_cluster_parameter_group_name=cluster_pg.ref,
                #                           db_instance_parameter_group_name=instance_pg.ref,
                #                           vpc_security_group_ids=[rds_sg.security_group_id],
                #                           db_subnet_group_name=database_subnet_group.ref,
                #                           port=5432,
                #                           serverless_v2_scaling_configuration=rds.CfnDBCluster.ServerlessV2ScalingConfigurationProperty(
                #                               max_capacity=123,
                #                               min_capacity=0.5),
                #                           global_cluster_identifier="sw-ccoe-sandbox-rds-gc2-main-aws",
                #                           enable_global_write_forwarding=True,
                #                           performance_insights_enabled=True,
                #                           deletion_protection=False,
                #                           enable_cloudwatch_logs_exports=["postgresql"],
                #                           )
                for i in range(0, int(config.get('database_instance_count'))):
                    instance = rds.CfnDBInstance(self,
                                                 f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-instance-{i}-{config['resource_suffix']}",
                                                 db_cluster_identifier=cluster.db_cluster_identifier,
                                                 db_instance_class="db.serverless",
                                                 db_subnet_group_name=database_subnet_group.ref,
                                                 enable_performance_insights=True,
                                                 engine="aurora-postgresql",
                                                 performance_insights_retention_period=7,
                                                 publicly_accessible=False,
                                                 auto_minor_version_upgrade=True,
                                                 # monitoring_interval=60,
                                                 # monitoring_role_arn=enhanced_monitoring_role.role_arn
                                                 )
                    instance.add_dependency(cluster)
                    # instance1 = rds.CfnDBInstance(self,
                    #                              f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-temp-instance-{i}-{config['resource_suffix']}",
                    #                              db_cluster_identifier=cluster1.db_cluster_identifier,
                    #                              db_instance_class="db.serverless",
                    #                              db_subnet_group_name=database_subnet_group.ref,
                    #                              enable_performance_insights=True,
                    #                              engine="aurora-postgresql",
                    #                              performance_insights_retention_period=7,
                    #                              publicly_accessible=False,
                    #                              auto_minor_version_upgrade=True,
                    #                              # monitoring_interval=60,
                    #                              # monitoring_role_arn=enhanced_monitoring_role.role_arn
                    #                              )
                    # instance1.add_dependency(cluster1)

            #TAG to enable the backup to backup-vault.
            #Tags.of(cluster).add("swift:backup", "backup-to-vault_auroradb")

            # imported_secret = secretsmanager.Secret.from_secret_complete_arn(
            #     self, "ImportedSecret",
            #     secret_complete_arn="arn:aws:secretsmanager:eu-central-1:573792771178:secret:sw-ccoe-sandbox-secret-main-aws-fzQ9H0"
            # )
    def rds_enhanced_monitoring_policy(self,config):
        return iam.PolicyDocument.from_json({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableCreationAndManagementOfRDSCloudwatchLogGroups",
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:PutRetentionPolicy"
                    ],
                    "Resource": [
                        "arn:aws:logs:*:*:log-group:RDS*"
                    ]
                },
                {
                    "Sid": "EnableCreationAndManagementOfRDSCloudwatchLogStreams",
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:DescribeLogStreams",
                        "logs:GetLogEvents"
                    ],
                    "Resource": [
                        "arn:aws:logs:*:*:log-group:RDS*:log-stream:*"
                    ]
                }
            ]
        })
