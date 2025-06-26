from constructs import Construct
from aws_cdk import (Duration, Stack, aws_ssm as ssm, aws_ec2 as ec2, aws_iam
as iam, aws_ecr as ecr, aws_ecs as ecs, aws_logs as logs,
                     aws_route53 as route53, aws_certificatemanager as cert,
                     aws_elasticloadbalancingv2 as elb, aws_kms as kms, aws_sns
                     as sns, RemovalPolicy, aws_elasticloadbalancingv2_targets
                     as elbv2_targets)

from aws_cdk.aws_route53 import (
    HostedZone, ARecord, RecordTarget
)
import aws_cdk.aws_route53_targets as targets
from stacks.ssm_agent_container import create_ssm_agent_container


class NLBECSFargateEndpointService2(Stack):

    def container_env(self, container_env_file: str, region: str) -> dict:
        env_vars = {"AWS_STS_REGIONAL_ENDPOINTS": "regional",
                    "AWS_XRAY_DAEMON_ADDRESS": "127.0.0.1:2000",
                    "AWS_REGION": region,
                    "XRAY_DAEMON_NO_EC2_METADATA": "true"
                    }
        with open(container_env_file) as f:
            for line in f:
                name, value = line.strip().split('=', 1)
                env_vars[name] = value
        return env_vars

    def __init__(self, scope: Construct, construct_id: str, resource_config,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.ssm_related_vol_config = {
            'var-lib-amazon-ssm': '/var/lib/amazon/ssm',
            'var-log-amazon-ssm': '/var/log/amazon/ssm'
        }

        # Get configuration variables from resource file
        config = resource_config

        # vpc lookup from account
        vpc = ec2.Vpc.from_lookup(
            self,
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-vpc-{config['app_name']}-{config['deployment_region_2']}-{config['resource_suffix']}",
            vpc_id=f"{config['vpc_id_2']}")

        # Select workload subnets from VPC
        workload_subnet_selection = ec2.SubnetSelection(
            one_per_az=True,
            subnet_filters=[
                ec2.SubnetFilter.by_ids([
                    f"{config['subnet_id_2_1']}", f"{config['subnet_id_2_2']}"
                ])
            ])

        # Route53 public hosted zone domain name and certificate manager
        hosted_zone = route53.HostedZone.from_hosted_zone_attributes(
            self,
            "public-dns-zone",
            #zone_name=f"{config['service_name']}.{config['app_env']}.{config['cloud_hosted_domain']}",
            zone_name=f"{config['service_name']}.{config['cloud_hosted_domain']}",
            hosted_zone_id=f"{config['hosted_zone_id']}"
        )

        acm = cert.Certificate(
            self,
            f"{config['resource_prefix']}-{config['service_name']}-private-domain-certs-{config['resource_suffix']}",
            #domain_name=f"service1.{config['service_name']}.{config['app_env']}.{config['cloud_hosted_domain']}",
            domain_name=f"service2.{config['service_name']}.{config['cloud_hosted_domain']}",
            certificate_name=f"{config['certificate_name']}",
            validation=cert.CertificateValidation.from_dns(hosted_zone)
        )

        #########################
        # Start of ECS resources
        #########################

        log_group = logs.LogGroup(
            self,
            "ecs-log-groups",
            log_group_name=
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-ecs-log-groups-fra-{config['resource_suffix']}",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # logs.CfnSubscriptionFilter(
        #     self,
        #     id=f"{config['resource_prefix']}-{config['app_name']}-{config['service_name']}-subfilter-{config['resource_suffix']}",
        #     filter_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_name']}-oasis-{config['resource_suffix']}",
        #     filter_pattern="{ $.action = CREATE || $.actions = UPDATE || $.actions = DELETE || $.actions = FETCH }",
        #     log_group_name=log_group.log_group_name,
        #     destination_arn=f"arn:aws:logs:eu-central-1:{config['monitoring_tools_account']}:destination:{config['oasis_log_destination_name']}"
        # )

        # create ecs cluster
        cluster = ecs.Cluster(
            self,
            "ecs-cluster",
            cluster_name=
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-ecs-cluster-fra-{config['resource_suffix']}",
            vpc=vpc,
            container_insights=True,
            execute_command_configuration=ecs.ExecuteCommandConfiguration(
                log_configuration=ecs.ExecuteCommandLogConfiguration(
                    cloud_watch_log_group=log_group,
                    cloud_watch_encryption_enabled=True
                ),
                logging=ecs.ExecuteCommandLogging.OVERRIDE
            )
        )

        image_repository = ecr.Repository.from_repository_arn(
            self, "ecs-repository",
            f"arn:aws:ecr:{config['deployment_region_2']}:{config['deployment_sdlc_account']}:repository/{config['ecr_repo_name']}"
        )


        managed_instance_role = iam.Role(
            self,
            "ManagedInstanceRole",
            assumed_by=iam.ServicePrincipal("ssm.amazonaws.com"),
            role_name=f"{config['resource_prefix']}-{config['service_name1']}-{config['app_env']}-managed-instance-role-{config['resource_suffix']}"
        )

        managed_instance_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")
        )

        managed_instance_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ssm:DeleteActivation",
                    "ssm:DeregisterManagedInstance"
                ],
                resources=["*"]
            )
        )


        ecs_task_role = iam.Role(
            self,
            'ecs-task-role',
            assumed_by=iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
            role_name=
            f"{config['resource_prefix']}-{config['service_name1']}-{config['app_env']}-{config['service_name']}-ecs-task-execution-role-{config['resource_suffix']}"
        )

        # TODO scope down both actions and resources based on https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncloudwatch.html
        ecs_task_role.add_to_policy(
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=['cloudwatch:*'],
                                resources=["*"]))

        ecs_task_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    'ecr:BatchCheckLayerAvailability', 'ecr:BatchGetImage',
                    'ecr:GetDownloadUrlForLayer'
                ],
                resources=[
                    f"arn:aws:ecr:*:{config['deployment_sdlc_account']}:repository/{config['ecr_repo_name']}"
                ]))
        ecs_task_role.add_to_policy(
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=['ecr:GetAuthorizationToken'],
                                resources=["*"]))
        ecs_task_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                resources=["arn:aws:logs:*:*:log-group:*:*"]))

        ecs_task_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                resources=["arn:aws:secretsmanager:*:*:secret:*"]))

        ecs_task_role.add_to_policy(
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=[
                                    "ssmmessages:CreateControlChannel",
                                    "ssmmessages:CreateDataChannel",
                                    "ssmmessages:OpenControlChannel",
                                    "ssmmessages:OpenDataChannel",
                                    "ssm:CreateActivation",
                                    "ssm:AddTagsToResource"
                                ],
                                resources=["*"]))

        ecs_task_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["iam:PassRole"],
                resources=[managed_instance_role.role_arn]))

        # Allow X-Ray daemon to send trace data
        ecs_task_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AWSXRayDaemonWriteAccess")
        )

        ecs_task_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonECSTaskExecutionRolePolicy")
        )

        volume_name = f"{config['service_name']}-tmp-volume"
        # create task definition, commented out until needed, letting AWS auto configure
        task_definition = ecs.FargateTaskDefinition(
            self,
            "ecs-task-definition",
            cpu=2048,
            memory_limit_mib=4096,
            task_role=ecs_task_role,
            volumes=[ecs.Volume(name=volume_name)],
            execution_role=ecs_task_role)

        task_definition.node.default_child.add_property_override("EnableFaultInjection", True)

        # Adding xray as sidecar container

        xray_log_group = logs.LogGroup(
            self,
            "xray_log_group-log-groups",
            log_group_name=
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-xray-log-groups-fra-{config['resource_suffix']}",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )

        task_definition.add_container(
            "XRayDaemon",
            image=ecs.ContainerImage.from_ecr_repository(
                image_repository, "xray-daemon"),
            readonly_root_filesystem=True,
            logging=ecs.LogDriver.aws_logs(stream_prefix="xray", log_group=xray_log_group),
            essential=False,
            port_mappings=[
                ecs.PortMapping(container_port=2000, protocol=ecs.Protocol.UDP)
            ],
            command=["-o", "-n", config['deployment_region_2']],
            cpu=32
        )

        # create_ssm_agent_container(self, config, task_definition, config['deployment_region_2'])

        for _vol in self.ssm_related_vol_config.keys():
            task_definition.add_volume(
                name=_vol
            )

        container_definition = ecs.ContainerDefinition(
            self,
            "ecs-container-definition",
            image=ecs.ContainerImage.from_ecr_repository(
                image_repository, f"{config['image_version']}"),
            task_definition=task_definition,

            cpu=1024,  # 1vCPU
            environment={
                **self.container_env("ecs.env", config['deployment_region_2']),
                "MANAGED_INSTANCE_ROLE_NAME": managed_instance_role.role_name
            },
            readonly_root_filesystem=True,
            health_check=ecs.HealthCheck(
                command=["CMD-SHELL", f"{config['health_check_command']}"],
                interval=Duration.seconds(30),
                retries=3,
                start_period=Duration.minutes(1),
                timeout=Duration.seconds(10)),
            logging=ecs.LogDriver.aws_logs(
                stream_prefix=f"{config['service_name']}-app",
                log_group=log_group),
            memory_limit_mib=2048,
            memory_reservation_mib=2048,  # 2 GB
            port_mappings=[
                ecs.PortMapping(
                    container_port=int(f"{config['container_port']}"),
                    protocol=ecs.Protocol.TCP)
            ])

        container_definition.add_mount_points(
            ecs.MountPoint(container_path="/tmp",
                           read_only=False,
                           source_volume=volume_name))

        for _vol, _path in self.ssm_related_vol_config.items():
            container_definition.add_mount_points(
                ecs.MountPoint(container_path=_path,
                               read_only=False,
                               source_volume=_vol)
            )

        # ECS security group
        ecs_sg = ec2.SecurityGroup(
            self,
            "ecs-security-group",
            security_group_name=
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-ecs-sg-fra-{config['resource_suffix']}",
            description="Allow the communication NLB to ECS.",
            allow_all_outbound=True,
            # if this is set to `false` then no egress rule will be automatically created
            vpc=vpc)

        # Security group for ALB and ECS
        ecs_sg.add_ingress_rule(
            ec2.Peer.ipv4(vpc.vpc_cidr_block),
            ec2.Port.tcp(int(f"{config['container_port']}")))
        ecs_sg.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block),
                                ec2.Port.tcp(443))
        ecs_sg.add_ingress_rule(ec2.Peer.ipv4('192.168.100.0/24'),ec2.Port.tcp(443))

        service2 = ecs.FargateService(
            self,
            "ecs-service",
            service_name=
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-ecs-service-fra-{config['resource_suffix']}",
            cluster=cluster,
            task_definition=task_definition,
            assign_public_ip=False,
            desired_count=2,
            propagate_tags=ecs.PropagatedTagSource.TASK_DEFINITION,
            security_groups=[ecs_sg],
            vpc_subnets=workload_subnet_selection,
            circuit_breaker=ecs.DeploymentCircuitBreaker(rollback=True),
            enable_execute_command=True,
        )

        # service2 = ecs.FargateService(
        #     self,
        #     "ecs-service2",
        #     service_name=
        #     f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-ecs-service2-fra-{config['resource_suffix']}",
        #     cluster=cluster,
        #     task_definition=task_definition,
        #     assign_public_ip=False,
        #     desired_count=2,
        #     propagate_tags=ecs.PropagatedTagSource.TASK_DEFINITION,
        #     security_groups=[ecs_sg],
        #     vpc_subnets=workload_subnet_selection,
        #     circuit_breaker=ecs.DeploymentCircuitBreaker(rollback=True)
        # )

        #########################
        # End of ECS resources
        #########################

        # NLB
        nlb = elb.NetworkLoadBalancer(
            self,
            id=
            f"{config['resource_prefix']}-{config['service_name']}-network-loadbalancer2-{config['resource_suffix']}",
            vpc=vpc,
            vpc_subnets=workload_subnet_selection,
            security_groups=[ecs_sg],
            internet_facing=False)

        # DNS record to go in front of NLB
        nlb_dns_record = ARecord(self, "nlb-dns-alias-record",
                                 record_name="service2",
                                 zone=hosted_zone,
                                 target=RecordTarget.from_alias(targets.LoadBalancerTarget(nlb)),
                                 ttl=Duration.minutes(1)
                                 )
        # nlb.add_security_group(ecs_sg)

        nlb_listener = nlb.add_listener(
            f"{config['resource_prefix']}-{config['service_name']}-nlb-listener-{config['resource_suffix']}",
            certificates=[acm],
            #protocol=elb.Protocol.TCP,
            protocol=elb.Protocol.TLS,
            port=443)

        nlb_target_group = elb.NetworkTargetGroup(
            self,
            id=
            f"{config['resource_prefix']}-{config['service_name']}-nlb-tg-{config['resource_suffix']}",
            target_type=elb.TargetType.IP,
            targets=[service2],
            protocol=elb.Protocol.TLS,
            vpc=vpc,
            port=int(f"{config['container_port']}")
        )

        nlb_listener.add_target_groups(
            f"{config['resource_prefix']}-{config['service_name']}-nlb-fargate-targetgroup-{config['resource_suffix']}",
            nlb_target_group
        )

        if config['app_env'] in ['dev']:
            # Add SNS topic for endpointservice notification
            # key = kms.Key.from_key_arn(
            #     self,
            #     id="aws-managed-sns-key",
            #     key_arn=
            #     f"arn:aws:kms:{config['deployment_region_1']}:{config['workload_account']}:key/{config['sns_kms_id']}"
            # )
            # topic = sns.Topic(
            #     self,
            #     id=
            #     f"{config['resource_prefix']}-{config['service_name']}-sns-endpoint-notification-topics-{config['resource_suffix']}",
            #     display_name='Topic for Endpoint Service connect notfication',
            #     fifo=True,
            #     master_key=key,
            #     topic_name=
            #     f"{config['resource_prefix']}-{config['service_name']}-sns-endpoint-notification-topics-{config['resource_suffix']}"
            # )

            # Endpoint service
            allow_arn = f"arn:aws:iam::{config['workload_idmz_account']}:role/{config['resource_prefix']}-{config['service_name1']}-{config['app_env']}-{config['service_name']}_idmzdply-role-main-a"
            endpoint_service = ec2.VpcEndpointService(
                self,
                f"{config['resource_prefix']}-{config['service_name']}-vpc-endpoint-service-{config['resource_suffix']}",
                vpc_endpoint_service_load_balancers=[nlb],
                acceptance_required=False,
                allowed_principals=[iam.ArnPrincipal(allow_arn)],
            )
