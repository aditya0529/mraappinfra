#!/usr/bin/env python3
import configparser
import aws_cdk as cdk
from aws_cdk import (
    Aspects,
    Tags,
)

from cdk_nag import AwsSolutionsChecks, NagSuppressions

from stacks.elasticache_stack import ElastiCacheStack
from stacks.rds_stack import RdsStack
from stacks.rds_stack2 import RdsStack2
from stacks.rds_stack1 import RdsStack1
from stacks.nlb_alb_ecs_fargate import NLBALBECSFargateEndpointService
from stacks.nlb_ecs_fargate import NLBECSFargateEndpointService
from stacks.nlb_ecs_fargate2 import NLBECSFargateEndpointService2
from stacks.cmk_stack1 import CmkStack
from stacks.cmk_stack2 import CmkStack2

def get_def_stack_synth(config):
    return cdk.DefaultStackSynthesizer(
        cloud_formation_execution_role=f"arn:aws:iam::{config['workload_account']}:role/{config['deployment_role_name']}",
        deploy_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['deployment_role_name']}",
        file_asset_publishing_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['deployment_role_name']}",
        image_asset_publishing_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['deployment_role_name']}",
        lookup_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['deployment_role_name']}",
        file_assets_bucket_name=f"{config['asset_prefix']}-{config['workload_account']}-{config['deployment_region_1']}-{config['resource_suffix']}",
        bootstrap_stack_version_ssm_parameter=f"{config['bootstrap_stack_version']}"
    )

def get_def_stack2_synth(config):
    return cdk.DefaultStackSynthesizer(
        cloud_formation_execution_role=f"arn:aws:iam::{config['workload_account']}:role/{config['deployment_role_name']}",
        deploy_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['deployment_role_name']}",
        file_asset_publishing_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['deployment_role_name']}",
        image_asset_publishing_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['deployment_role_name']}",
        lookup_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['deployment_role_name']}",
        file_assets_bucket_name=f"{config['asset_prefix']}-{config['workload_account']}-{config['deployment_region_2']}-{config['resource_suffix']}",
        bootstrap_stack_version_ssm_parameter=f"{config['bootstrap_stack_version']}"
    )

if __name__ == "__main__":
    # Reading Application infra resource varibales using git branch name
    config_parser = configparser.ConfigParser()
    config_parser.read(filenames="resource.config")
    config = config_parser['develop']

    # Initializing CDK app
    app = cdk.App()

    # Add a tag to all constructs in the application
    Tags.of(app).add("sw:application", f"{config['app_name']}")
    Tags.of(app).add("sw:product", f"{config['service_name']}")
    Tags.of(app).add("sw:environment", f"{config['app_env']}")
    Tags.of(app).add("sw:cost_center", f"{config['cost_center']}")

    if config.get('Enable_RDS_stack') == "true":
        # Application infra stack for RDS
        cdk_stack_rds = RdsStack(
            app,
            f"{config['app_infra_rds_stack_name']}",
            env=cdk.Environment(account=f"{config['workload_account']}",
                                region=f"{config['deployment_region_1']}"),
            synthesizer=get_def_stack_synth(config),
            resource_config=config
        )
        # Suppress findings for RDS stack.
        NagSuppressions.add_stack_suppressions(cdk_stack_rds, [
            # {'id': 'AwsSolutions-ELB2', 'reason': 'ALB access logging is not required as we already have VPC flow logs and application logs.'},
            {'id': 'AwsSolutions-IAM5', 'reason': 'TBV =>The IAM entity contains wildcard permissions and does not have a cdk-nag rule suppression with evidence for those permission.'},
            {'id': 'AwsSolutions-SMG4', 'reason': 'In-correct check=> AwsSolutions-SMG4: The secret does not have automatic rotation scheduled.'},
            {'id': 'AwsSolutions-RDS6', 'reason': 'Not Applicable=> AwsSolutions-RDS6: The RDS Aurora MySQL/PostgresSQL cluster does not have IAM Database Authentication enabled.'},
            {'id': 'AwsSolutions-RDS10', 'reason': 'Test environment=> AwsSolutions-RDS10: The RDS instance or Aurora DB cluster does not have deletion protection enabled.'},
            # {'id': 'AwsSolutions-RDS11', 'reason': 'Suppressed temporarily for the test.js DB in SBX-account'},
            # {'id': 'AwsSolutions-RDS13', 'reason': 'Suppressed temporarily for the test.js DB in SBX-account'},
            # {'id': 'AwsSolutions-RDS14', 'reason': 'Suppressed temporarily for the test.js DB in SBX-account'},
            # {'id': 'AwsSolutions-RDS18', 'reason': 'Suppressed temporarily for the test.js DB in SBX-account'},
            {'id': 'AwsSolutions-IAM4', 'reason': 'TBV=> The IAM user, role, or group uses AWS managed policies'}
        ])

    if config.get('Enable_RDS_stack2') == "true":
        # Application infra stack for RDS
        cdk_stack_rds2 = RdsStack2(
            app,
            f"{config['app_infra_rds_stack_name2']}",
            env=cdk.Environment(account=f"{config['workload_account']}",
                                region=f"{config['deployment_region_2']}"),
            synthesizer=get_def_stack2_synth(config),
            resource_config=config
        )
        # Suppress findings for RDS stack.
        NagSuppressions.add_stack_suppressions(cdk_stack_rds2, [
            # {'id': 'AwsSolutions-ELB2', 'reason': 'ALB access logging is not required as we already have VPC flow logs and application logs.'},
            {'id': 'AwsSolutions-IAM5', 'reason': 'TBV =>The IAM entity contains wildcard permissions and does not have a cdk-nag rule suppression with evidence for those permission.'},
            {'id': 'AwsSolutions-SMG4', 'reason': 'In-correct check=> AwsSolutions-SMG4: The secret does not have automatic rotation scheduled.'},
            {'id': 'AwsSolutions-RDS6', 'reason': 'Not Applicable=> AwsSolutions-RDS6: The RDS Aurora MySQL/PostgresSQL cluster does not have IAM Database Authentication enabled.'},
            {'id': 'AwsSolutions-RDS10', 'reason': 'Test environment=> AwsSolutions-RDS10: The RDS instance or Aurora DB cluster does not have deletion protection enabled.'},
            # {'id': 'AwsSolutions-RDS11', 'reason': 'Suppressed temporarily for the test.js DB in SBX-account'},
            # {'id': 'AwsSolutions-RDS13', 'reason': 'Suppressed temporarily for the test.js DB in SBX-account'},
            # {'id': 'AwsSolutions-RDS14', 'reason': 'Suppressed temporarily for the test.js DB in SBX-account'},
            # {'id': 'AwsSolutions-RDS18', 'reason': 'Suppressed temporarily for the test.js DB in SBX-account'},
            {'id': 'AwsSolutions-IAM4', 'reason': 'TBV=> The IAM user, role, or group uses AWS managed policies'}
        ])

    if config.get('Enable_RDS_stack1') == "true":
        # Enable to migrate/re-create the primary-database with MRK.
        cdk_stack_rds1 = RdsStack1(
            app,
            f"{config['app_infra_rds_stack_name1']}",
            env=cdk.Environment(account=f"{config['workload_account']}",
                                region=f"{config['deployment_region_1']}"),
            synthesizer=get_def_stack_synth(config),
            resource_config=config
        )
        # Suppress findings for RDS stack.
        NagSuppressions.add_stack_suppressions(cdk_stack_rds1, [
            # {'id': 'AwsSolutions-ELB2', 'reason': 'ALB access logging is not required as we already have VPC flow logs and application logs.'},
            {'id': 'AwsSolutions-IAM5', 'reason': 'TBV =>The IAM entity contains wildcard permissions and does not have a cdk-nag rule suppression with evidence for those permission.'},
            {'id': 'AwsSolutions-SMG4', 'reason': 'In-correct check=> AwsSolutions-SMG4: The secret does not have automatic rotation scheduled.'},
            {'id': 'AwsSolutions-RDS6', 'reason': 'Not Applicable=> AwsSolutions-RDS6: The RDS Aurora MySQL/PostgresSQL cluster does not have IAM Database Authentication enabled.'},
            {'id': 'AwsSolutions-RDS10', 'reason': 'Test environment=> AwsSolutions-RDS10: The RDS instance or Aurora DB cluster does not have deletion protection enabled.'},
            # {'id': 'AwsSolutions-RDS11', 'reason': 'Suppressed temporarily for the test.js DB in SBX-account'},
            # {'id': 'AwsSolutions-RDS13', 'reason': 'Suppressed temporarily for the test.js DB in SBX-account'},
            # {'id': 'AwsSolutions-RDS14', 'reason': 'Suppressed temporarily for the test.js DB in SBX-account'},
            # {'id': 'AwsSolutions-RDS18', 'reason': 'Suppressed temporarily for the test.js DB in SBX-account'},
            {'id': 'AwsSolutions-IAM4', 'reason': 'TBV=> The IAM user, role, or group uses AWS managed policies'}
        ])

    if config.get('Enable_CMK_Stack1') == "true":
        # Application infra stack for CMK
        cmk_stack = CmkStack(
            app,
            f"{config['app_infra_cmk_stack_name']}",
            env=cdk.Environment(account=f"{config['workload_account']}",
                                region=f"{config['deployment_region_1']}"),
            synthesizer=get_def_stack_synth(config),
            resource_config=config
        )
        # Suppress findings for CMK stack.
        NagSuppressions.add_stack_suppressions(cmk_stack, [
            {'id': 'AwsSolutions-KMS5', 'reason': 'TBV=> Encountered Permissions issue and disabled temporarily for PoC'}
        ])

    if config.get('Enable_CMK_Stack2') == "true":
        # Application infra stack for CMK
        cmk_stack = CmkStack2(
            app,
            f"{config['app_infra_cmk_stack_name2']}",
            env=cdk.Environment(account=f"{config['workload_account']}",
                                region=f"{config['deployment_region_2']}"),
            synthesizer=get_def_stack2_synth(config),
            resource_config=config
        )

    if config.get('Enable_NLB_ALB_ECS_stack') == "true":
        #Application infra stack for NLB=>ALB=>ECS
        cdk_stack_ecs_v1 = NLBALBECSFargateEndpointService(
            app,
            f"{config['app_infra_ecs_stack_name_v1']}",
            env=cdk.Environment(account=f"{config['workload_account']}",
                                region=f"{config['deployment_region_1']}"),
            synthesizer=get_def_stack_synth(config),
            resource_config=config
        )
        #Suppress findings for ECS stack
        NagSuppressions.add_stack_suppressions(cdk_stack_ecs_v1, [
            {'id': 'AwsSolutions-ELB2', 'reason': 'ALB access logging is not required as we already have VPC flow logs and application logs.'},
            {'id': 'AwsSolutions-IAM5', 'reason': 'ecr:GetAuthorizationToken must have wildcard resource.'},
            {'id': 'AwsSolutions-ECS2', 'reason': 'Environment variable values are not secrets.'},
            {'id': 'AwsSolutions-EC23', 'reason': 'Security Group'}
        ])

    if config.get('Enable_NLB_ECS_stack') == "true":
        # Application infra stack for NLB=>ECS
        cdk_stack_ecs_v2 = NLBECSFargateEndpointService(
            app,
            f"{config['app_infra_ecs_stack_name_v2']}",
            env=cdk.Environment(account=f"{config['workload_account']}",
                                region=f"{config['deployment_region_1']}"),
            synthesizer=get_def_stack_synth(config),
            resource_config=config
        )
        NagSuppressions.add_stack_suppressions(cdk_stack_ecs_v2, [
            {'id': 'AwsSolutions-IAM5', 'reason': 'Log stream names are not known at time of deployment.'},
            {'id': 'AwsSolutions-ECS2', 'reason': 'Low risk with plans to upgrade in the future.'},
            {'id': 'AwsSolutions-ELB2', 'reason': 'Low risk with plans to upgrade in the future.'},
            {'id': 'AwsSolutions-IAM4', 'reason': 'TBV=> The IAM user, role, or group uses AWS managed policies'}
        ])

    if config.get('Enable_NLB_ECS_stack2') == "true":
        # Application infra stack for NLB=>ECS
        cdk_stack_ecs_v2_2 = NLBECSFargateEndpointService2(
            app,
            f"{config['app_infra_ecs_stack_name_v2_2']}",
            env=cdk.Environment(account=f"{config['workload_account']}",
                                region=f"{config['deployment_region_2']}"),
            synthesizer=get_def_stack2_synth(config),
            resource_config=config
        )
        NagSuppressions.add_stack_suppressions(cdk_stack_ecs_v2_2, [
            {'id': 'AwsSolutions-IAM5', 'reason': 'Log stream names are not known at time of deployment.'},
            {'id': 'AwsSolutions-ECS2', 'reason': 'Low risk with plans to upgrade in the future.'},
            {'id': 'AwsSolutions-ELB2', 'reason': 'Low risk with plans to upgrade in the future.'},
            {'id': 'AwsSolutions-IAM4', 'reason': 'TBV=> The IAM user, role, or group uses AWS managed policies'}
        ])

    if config.get('Enable_ElasticCache_Stack') == "true":
        # Application infra stack for ElastiCache cache
        cdk_stack_elasticache = ElastiCacheStack(
            app,
            f"{config['app_infra_elasticache_stack_name']}",
            env=cdk.Environment(account=f"{config['workload_account']}",
                                region=f"{config['deployment_region_1']}"),
            synthesizer=get_def_stack_synth(config),
            resource_config=config
        )
        # Suppress findings for ElastiCache stack
        NagSuppressions.add_stack_suppressions(cdk_stack_elasticache, [
            {'id': 'AwsSolutions-SMG4', 'reason': 'Rotation will be enabled at a later time.'},
            {'id': 'AwsSolutions-IAM5', 'reason': 'Log stream names are not known at time of deployment.'},
            {'id': 'AwsSolutions-L1', 'reason': 'Low risk with plans to upgrade in the future.'}
        ])

    # Check stack resource for compliance
    Aspects.of(app).add(AwsSolutionsChecks())

    # Synthesize and produce CloudFormation template
    app.synth()
