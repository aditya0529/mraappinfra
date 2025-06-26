from constructs import Construct
from aws_cdk import (Duration, Stack, aws_ssm as ssm, aws_ec2 as ec2, aws_iam
as iam, aws_ecr as ecr, aws_ecs as ecs, aws_logs as logs,
                     aws_route53 as route53, aws_certificatemanager as cert,
                     aws_elasticloadbalancingv2 as elb, aws_kms as kms, aws_sns
                     as sns, RemovalPolicy, aws_elasticloadbalancingv2_targets
                     as elbv2_targets)


class NLBALBECSFargateEndpointService(Stack):

    def __init__(self, scope: Construct, construct_id: str, resource_config,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Get configuration variables from resource file
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
                    f"{config['subnet_id_1_1']}", f"{config['subnet_id_1_2']}"
                ])
            ])

        # Route53 public hosted zone domain name and certificate manager
        hosted_zone = route53.HostedZone.from_hosted_zone_id(
            self,
            f"{config['service_name']}.{config['app_env']}.{config['cloud_hosted_domain']}",
            f"{config['hosted_zone_id']}")

        acm = cert.Certificate(
            self,
            f"{config['resource_prefix']}-{config['service_name']}-private-domain-certs-{config['resource_suffix']}",
            domain_name=
            f"{config['service_name']}.{config['app_env']}.{config['cloud_hosted_domain']}",
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

        # create ecs cluster
        cluster = ecs.Cluster(
            self,
            "ecs-cluster",
            cluster_name=
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-ecs-cluster-fra-{config['resource_suffix']}",
            vpc=vpc,
            container_insights=True,
        )

        image_repository = ecr.Repository.from_repository_arn(
            self, "ecs-repository",
            f"arn:aws:ecr:{config['deployment_region_1']}:{config['deployment_sdlc_account']}:repository/{config['ecr_repo_name']}"
        )
        # Execution role for ECS to manage tasks (ECR, CloudWatch)
        ecs_execution_role = iam.Role(
            self,
            'ecs-execution-role',
            assumed_by=iam.ServicePrincipal('ecs-tasks.amazonaws.com').with_conditions({
                "StringEquals": {
                    "aws:SourceAccount": config['workload_account']
                }
            }),
            role_name=
            f"{config['resource_prefix']}-{config['service_name']}-ecs-task-execution-role-{config['resource_suffix']}"
        )

        ecs_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    'ecr:BatchCheckLayerAvailability',
                    'ecr:BatchGetImage',
                    'ecr:GetDownloadUrlForLayer'
                ],
                resources=[
                    f"arn:aws:ecr:*:{config['deployment_sdlc_account']}:repository/{config['ecr_repo_name']}"
                ],
            )
        )

        ecs_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=['ecr:GetAuthorizationToken'],
                resources=["*"]
            )
        )

        ecs_execution_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                resources=["arn:aws:logs:*:*:log-group:*:*"],
            )
        )

        # Task role for the application to access AWS resources
        ecs_task_role = iam.Role(
            self,
            'ecs-task-role',
            assumed_by=iam.ServicePrincipal('ecs-tasks.amazonaws.com').with_conditions({
                "StringEquals": {
                    "aws:SourceAccount": config['workload_account']
                }
            }),
            role_name=
            f"{config['resource_prefix']}-{config['service_name']}-ecs-task-role-{config['resource_suffix']}"
        )

        ecs_task_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "cloudwatch:GetMetricData",
                    "cloudwatch:ListMetrics",
                    "cloudwatch:GetDashboard",
                    "cloudwatch:DescribeAlarms"
                ],
                resources=["*"],
            )
        )
        # S3 access specific to the application
        ecs_task_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "s3:ListAllMyBuckets",
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                resources=["*"],
            )
        )
        # Task definition for ECS
        volume_name = f"{config['service_name']}-tmp-volume"
        # create task definition, commented out until needed, letting AWS auto configure
        task_definition = ecs.FargateTaskDefinition(
            self,
            "ecs-task-definition",
            cpu=1024,
            memory_limit_mib=4096,
            task_role=ecs_task_role,
            volumes=[ecs.Volume(name=volume_name)],
            execution_role=ecs_execution_role)

        container_definition = ecs.ContainerDefinition(
            self,
            "ecs-container-definition",
            image=ecs.ContainerImage.from_ecr_repository(
                image_repository, f"{config['image_version']}"),
            task_definition=task_definition,
            cpu=1024,  # 1vCPU
            environment={"AWS_STS_REGIONAL_ENDPOINTS": "regional"},
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

        # ECS security group
        ecs_sg = ec2.SecurityGroup(
            self,
            "ecs-security-group",
            security_group_name=
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-ecs-sg-fra-{config['resource_suffix']}",
            description="Allow the communication NLB to ALB and ALB to ECS.",
            allow_all_outbound=True,
            # if this is set to `false` then no egress rule will be automatically created
            vpc=vpc)

        # Security group for ALB and ECS
        ecs_sg.add_ingress_rule(
            ec2.Peer.ipv4(vpc.vpc_cidr_block),
            ec2.Port.tcp(int(f"{config['container_port']}")))

        ecs_sg.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block),
                                ec2.Port.tcp(443))

        service1 = ecs.FargateService(
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
            circuit_breaker=ecs.DeploymentCircuitBreaker(rollback=True)
        )

        #Create target group for service 1
        target_group1 = elb.ApplicationTargetGroup(
            self,
            id=
            f"{config['resource_prefix']}-{config['service_name']}-alb-tg1-{config['resource_suffix']}",
            port=int(f"{config['container_port']}"),
            targets=[service1],
            vpc=vpc)

        #Add ECS service as a target of the ALB's sole target group
        #Create ALB
        alb = elb.ApplicationLoadBalancer(
            self,
            id=
            f"{config['resource_prefix']}-{config['service_name']}-alb-{config['resource_suffix']}",
            vpc=vpc,
            vpc_subnets=workload_subnet_selection,
            security_group=ecs_sg,
            internet_facing=False,
            load_balancer_name=f"{config['resource_prefix']}-{config['service_name']}-alb-{config['resource_suffix']}"
        )
        #Add listener to ALB, to accept the connection from NLB
        listener = alb.add_listener(
            id=
            f"{config['resource_prefix']}-{config['service_name']}-alb-listener-{config['resource_suffix']}",
            port=443,
            #Disable the protocol HTTP, if the valid public domain is available.
            protocol=elb.ApplicationProtocol.HTTP,
            #Enable the following line, if the valid public domain is available.
            #certificates=[acm],
            default_target_groups=[target_group1])

        listener.add_target_groups(
            id=
            f"{config['resource_prefix']}-{config['service_name']}-alb-listenertg1-{config['resource_suffix']}",
            conditions=[elb.ListenerCondition.path_patterns(['/service1'])],
            priority=1,
            target_groups=[target_group1])

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
        #     )
        #
        # target_group2 = elb.ApplicationTargetGroup(
        #     self,
        #     id=
        #     f"{config['resource_prefix']}-{config['service_name']}-alb-tg2-{config['resource_suffix']}",
        #     port=int(f"{config['container_port']}"),
        #     targets=[service2],
        #     vpc=vpc)
        #
        # listener.add_target_groups(
        #     id=
        #     f"{config['resource_prefix']}-{config['service_name']}-alb-listenertg2-{config['resource_suffix']}",
        #     conditions=[elb.ListenerCondition.path_patterns(['/service2'])],
        #     priority=2,
        #     target_groups=[target_group2])

        #########################
        # End of ECS resources
        #########################

        # NLB
        nlb = elb.NetworkLoadBalancer(
            self,
            id=
            f"{config['resource_prefix']}-{config['service_name']}-network-loadbalancer-{config['resource_suffix']}",
            vpc=vpc,
            vpc_subnets=workload_subnet_selection,
            #security_groups=[ecs_sg],
            internet_facing=False)
        # nlb.add_security_group(ecs_sg)

        nlb_listener = nlb.add_listener(
            f"{config['resource_prefix']}-{config['service_name']}-nlb-listener-{config['resource_suffix']}",
            #certificates=[acm],
            protocol=elb.Protocol.TCP,
            port=443)

        alb_target_group = elb.NetworkTargetGroup(
            self,
            id=
            f"{config['resource_prefix']}-{config['service_name']}-nlb-alb-tg-{config['resource_suffix']}",
            target_type=elb.TargetType.ALB,
            targets=[elbv2_targets.AlbTarget(alb, 443)],
            protocol=elb.Protocol.TCP,
            vpc=vpc,
            port=443)

        nlb_listener.add_target_groups(
            f"{config['resource_prefix']}-{config['service_name']}-nlb-farget-targetgroup-{config['resource_suffix']}",
            alb_target_group)

        if config['app_env'] in ['dev']:
            # Add SNS topic for endpointservice notification
            key = kms.Key.from_key_arn(
                self,
                id="aws-managed-sns-key",
                key_arn=
                f"arn:aws:kms:{config['deployment_region_1']}:{config['workload_account']}:key/{config['sns_kms_id']}"
            )
            topic = sns.Topic(
                self,
                id=
                f"{config['resource_prefix']}-{config['service_name']}-sns-endpoint-notification-topics-{config['resource_suffix']}",
                display_name='Topic for Endpoint Service connect notfication',
                fifo=True,
                master_key=key,
                topic_name=
                f"{config['resource_prefix']}-{config['service_name']}-sns-endpoint-notification-topics-{config['resource_suffix']}"
            )

            # Endpoint service
            allow_arn = f"arn:aws:iam::{config['workload_idmz_account']}:role/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-idmzdply-role-main-a"
            endpoint_service = ec2.VpcEndpointService(
                self,
                f"{config['resource_prefix']}-{config['service_name']}-vpc-endpoint-service-{config['resource_suffix']}",
                vpc_endpoint_service_load_balancers=[nlb],
                acceptance_required=False,
                allowed_principals=[iam.ArnPrincipal(allow_arn)],
            )