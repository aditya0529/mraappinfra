from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_elasticache as elasticache,
    aws_secretsmanager as secretsmanager,
    RemovalPolicy,
    aws_iam as iam,
    custom_resources,
    aws_logs as logs,
)
from constructs import Construct
from aws_cdk.aws_logs import RetentionDays


class ElastiCacheStack(Stack):
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

        elasticache_security_group = ec2.CfnSecurityGroup(self, "ElastiCacheSecurityGroup",
                                                          group_description="The security group attached to the ElastiCache cache.",

                                                          # the properties below are optional
                                                          group_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-elasticache-{config['resource_suffix']}",
                                                          security_group_egress=[],
                                                          security_group_ingress=[ec2.CfnSecurityGroup.IngressProperty(
                                                              ip_protocol="tcp",

                                                              # the properties below are optional
                                                              cidr_ip=vpc.vpc_cidr_block,
                                                              # TODO can scope down to ECS SG rather than entire VPC CIDR
                                                              description="Allow ingress from entire VPC",
                                                              from_port=6379,
                                                              # source_security_group_id="sourceSecurityGroupId",
                                                              # source_security_group_name="sourceSecurityGroupName",
                                                              to_port=6379
                                                          )],
                                                          vpc_id=f"{config['vpc_id_1']}"
                                                          )
        # Generated password for custom cache user
        # TODO set this password in the cache user as well as the RDS database
        cache_password_secret = secretsmanager.Secret(self, "CacheUserPasswordSecret",
                                                      generate_secret_string=secretsmanager.SecretStringGenerator(
                                                          password_length=32,
                                                          require_each_included_type=True
                                                      ),
                                                      removal_policy=RemovalPolicy.DESTROY,
                                                      secret_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-cache-password-secret-{config['resource_suffix']}"
                                                      )
        # User with proper authentication enabled
        elasticache_user = elasticache.CfnUser(self, "ElastiCacheUser",
                                               engine="redis",
                                               user_id="app-user",
                                               user_name="default",

                                               # the properties below are optional
                                               access_string="on ~* +@all",  # user has full access within the cache
                                               authentication_mode={
                                                   "Type": "no-password-required"  # TODO change Type to 'password'
                                               },
                                               no_password_required=True  # TODO change to 'False'
                                               )

        # User group for cache RBAC - configured with default user
        elasticache_user_group = elasticache.CfnUserGroup(self, "ElastiCacheUserGroup",
                                                          engine="redis",
                                                          user_group_id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-user-group-{config['resource_suffix']}",
                                                          user_ids=["default"]
                                                          # default user is required at time of creation
                                                          )

        lambda_function_name = f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-modify-user-group-custom-resource-{config['resource_suffix']}"

        # Creates log group for Lambda function with proper retention period
        custom_resource_log_group = logs.LogGroup(self, "CustomResourceLogGroup",
                                                  log_group_name="/aws/lambda/" + lambda_function_name,
                                                  removal_policy=RemovalPolicy.DESTROY,
                                                  retention=RetentionDays.THREE_MONTHS
                                                  )
        # Creates execution role for Lambda function
        lambda_execution_role = iam.Role(self, "CustomResourceExecutionRole",
                                         role_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-custom-resource-role-{config['resource_suffix']}",
                                         assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),

                                         inline_policies={
                                             # IAM policy for Lambda function which only allows writing logs to CloudWatch, executing one ElastiCache API, and running the function in a VPC
                                             f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-custom-resource-inline-policy-{config['resource_suffix']}": iam.PolicyDocument(
                                                 statements=[
                                                     iam.PolicyStatement(
                                                         sid="CloudWatch",
                                                         actions=["logs:CreateLogGroup",
                                                                  "logs:CreateLogStream",
                                                                  "logs:PutLogEvents"
                                                                  ],
                                                         resources=[
                                                             custom_resource_log_group.log_group_arn,
                                                             custom_resource_log_group.log_group_arn + ":*"
                                                         ]
                                                     ),
                                                     iam.PolicyStatement(
                                                         sid="ElastiCache",
                                                         actions=["elasticache:ModifyUserGroup"],
                                                         resources=[elasticache_user_group.attr_arn,
                                                                    elasticache_user.attr_arn,
                                                                    f"arn:aws:elasticache:{config['deployment_region_1']}:{config['workload_account']}:user:default"
                                                                    # ARN of built-in default user
                                                                    ]
                                                     ),
                                                     iam.PolicyStatement(
                                                         sid="VPC",
                                                         actions=["ec2:CreateNetworkInterface",
                                                                  "ec2:DescribeNetworkInterfaces",
                                                                  "ec2:DescribeSubnets",
                                                                  "ec2:DeleteNetworkInterface",
                                                                  "ec2:AssignPrivateIpAddresses",
                                                                  "ec2:UnassignPrivateIpAddresses"
                                                                  ],
                                                         resources=["*"]
                                                     )
                                                 ]
                                             )
                                         },

                                         )

        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.custom_resources/AwsCustomResource.html
        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.custom_resources/AwsSdkCall.html
        # This custom resource overrides the insecure 'default' cache user by replacing it with a custom user
        # The AWS CDK call is asynchronous and may take several minutes to complete even after the Lambda function has finished
        # TODO use CDK escape hatch to update Lambda runtime to version nodejsv20 to satisfy cdk-nag rule
        custom_resource = custom_resources.AwsCustomResource(self, "ReplaceDefaultUserCustomResource",
                                                             function_name=lambda_function_name,
                                                             on_update=custom_resources.AwsSdkCall(
                                                                 # will also be called for a CREATE event
                                                                 service="elasticache",
                                                                 action="ModifyUserGroup",
                                                                 parameters={
                                                                     "UserGroupId": elasticache_user_group.user_group_id,
                                                                     "UserIdsToAdd": [elasticache_user.user_id],
                                                                     "UserIdsToRemove": ["default"]
                                                                 },
                                                                 physical_resource_id=custom_resources.PhysicalResourceId.of(
                                                                     "dts-custom-resource-physical-id")),
                                                             log_group=custom_resource_log_group,
                                                             removal_policy=RemovalPolicy.DESTROY,
                                                             role=lambda_execution_role,
                                                             vpc=vpc,
                                                             # If running in a VPC, we must have VPC endpoints for AWS services 'logs' and 'elasticache'
                                                             vpc_subnets=workload_subnet_selection
                                                             )

        custom_resource.node.add_dependency(elasticache_user_group)
        custom_resource.node.add_dependency(custom_resource_log_group)
        elasticache_user_group.node.add_dependency(elasticache_user)

        elasticache_serverless_cache = elasticache.CfnServerlessCache(self, "ElastiCacheServerlessCache",
                                                                      engine="redis",
                                                                      serverless_cache_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-ecache-{config['resource_suffix']}",

                                                                      # the properties below are optional
                                                                      # cache_usage_limits=elasticache.CfnServerlessCache.CacheUsageLimitsProperty(
                                                                      #     data_storage=elasticache.CfnServerlessCache.DataStorageProperty(
                                                                      #         maximum=123,
                                                                      #         unit="unit"
                                                                      #     ),
                                                                      #     ecpu_per_second=elasticache.CfnServerlessCache.ECPUPerSecondProperty(
                                                                      #         maximum=123
                                                                      #     )
                                                                      # ),
                                                                      daily_snapshot_time="00:00",  # UTC timezone
                                                                      description="ElastiCache Serverless Cache",
                                                                      # endpoint=elasticache.CfnServerlessCache.EndpointProperty(
                                                                      #     address="address",
                                                                      #     port="port"
                                                                      # ),
                                                                      # final_snapshot_name="finalSnapshotName",
                                                                      # kms_key_id="kmsKeyId",
                                                                      # major_engine_version="majorEngineVersion",
                                                                      # reader_endpoint=elasticache.CfnServerlessCache.EndpointProperty(
                                                                      #     address="address",
                                                                      #     port="port"
                                                                      # ),
                                                                      security_group_ids=[
                                                                          elasticache_security_group.ref
                                                                      ],
                                                                      # snapshot_arns_to_restore=["snapshotArnsToRestore"],
                                                                      snapshot_retention_limit=14,
                                                                      subnet_ids=[f"{config['subnet_id_1_1']}",
                                                                                  f"{config['subnet_id_1_2']}"],
                                                                      # tags=[CfnTag(
                                                                      #     key="key",
                                                                      #     value="value"
                                                                      # )],
                                                                      user_group_id=elasticache_user_group.user_group_id
                                                                      )

        elasticache_serverless_cache.node.add_dependency(elasticache_user_group)
        elasticache_serverless_cache.node.add_dependency(elasticache_security_group)
        elasticache_serverless_cache.node.add_dependency(custom_resource)
