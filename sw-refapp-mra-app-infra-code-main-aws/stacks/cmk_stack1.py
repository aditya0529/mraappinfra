from aws_cdk import (
    aws_kms as kms,
    Stack,
    aws_iam as iam
)
from constructs import Construct


class CmkStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, resource_config, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        config = resource_config

        if config.get('create_cmk') == "true":
            self.create_cmk(config)
        # if config.get('cmk_replication') == "true":
        #     self.replicate_cmk(config)
    def create_cmk(self,config):
        cmk = kms.CfnKey(self,
                         f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-cmk-{config['resource_suffix']}",
                         description="Multi region key",
                         enable_key_rotation=True,
                         multi_region=True,
                         key_policy=self.kms_key_policy(config)
                         )
        # return cmk
        kms.CfnAlias(
            self, "Multi region key Alias",
            alias_name=f"alias/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-cmk-{config['resource_suffix']}",  # Custom alias
            target_key_id=cmk.attr_arn  # ✅ Attach to the Replica Key
        )
    def replicate_cmk(self,config):
        cmk_replica = kms.CfnReplicaKey(self,
                                        f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-mrk-{config['resource_suffix']}",
                                        description="Replica of MRK",
                                        primary_key_arn=f"arn:aws:kms:{config['deployment_region_1']}:{config['workload_account']}:key/{config['mrk_id']}",
                                        key_policy=self.kms_key_policy(config)
                                        )
        # Create Alias for CMK
        kms.CfnAlias(
            self, "Multi region key Replica Alias",
            alias_name=f"alias/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-cmk-{config['resource_suffix']}",  # Custom alias
            target_key_id=cmk_replica.attr_arn  # ✅ Attach to the Replica Key
        )
    def kms_key_policy(self,config):
        return iam.PolicyDocument.from_json({
            "Id": f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-cmk-policy-{config['resource_suffix']}",
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Enable IAM Permissions for everyone in the account",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{config['workload_account']}:root"
                    },
                    "Action": [
                        # "kms:*"
                        "kms:PutKeyPolicy",
                        "kms:ListGrants",
                        "kms:DescribeKey",
                        "kms:GetKeyPolicy",
                        "kms:Decrypt",
                        "kms:CreateGrant",
                        "kms:GetKeyRotationStatus",
                        "kms:ListResourceTags",
                        "kms:CreateAlias",
                        "kms:DeleteAlias",
                        "kms:GenerateDataKeyWithoutPlaintext",
                        "kms:EnableKeyRotation"
                    ],

                    "Resource": "*"
                },
                {
                    "Sid": "Enable IAM Permissions for rds",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{config['workload_account']}:root"
                    },
                    "Action": [
                        # "kms:*",
                        "kms:ListGrants",
                        "kms:DescribeKey",
                        "kms:GetKeyPolicy",
                        "kms:Decrypt",
                        "kms:CreateGrant",
                        "kms:GetKeyRotationStatus",
                        "kms:ListResourceTags",
                        "kms:GenerateDataKeyWithoutPlaintext"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringLike": {
                            "kms:ViaService": f"rds.{config['deployment_region_2']}.amazonaws.com",
                            "kms:CallerAccount": f"{config['workload_account']}"
                        }
                    }
                },
                {
                    "Sid": "Enable IAM Permissions for deployment role",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{config['workload_account']}:role/{config['deployment_role_name']}"
                    },
                    "Action": [
                        "kms:*",
                        "kms:PutKeyPolicy",
                        "kms:ListGrants",
                        "kms:DescribeKey",
                        "kms:GetKeyPolicy",
                        "kms:Decrypt",
                        "kms:CreateGrant",
                        "kms:GetKeyRotationStatus",
                        "kms:ListResourceTags",
                        "kms:CreateAlias",
                        "kms:DeleteAlias",
                        "kms:GenerateDataKeyWithoutPlaintext",
                        "kms:EnableKeyRotation"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "CMK for RDS",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": [
                        # "kms:*",
                        "kms:ListGrants",
                        "kms:DescribeKey",
                        "kms:GetKeyPolicy",
                        "kms:Decrypt",
                        "kms:CreateGrant",
                        "kms:GetKeyRotationStatus",
                        "kms:ListResourceTags",
                        "kms:CreateAlias",
                        "kms:DeleteAlias",
                        "kms:GenerateDataKeyWithoutPlaintext",
                        "kms:EnableKeyRotation"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringLike": {
                            "kms:CallerAccount": f"{config['workload_account']}"
                        }
                    }
                },
                {
                    "Sid": "Allow KMS delete actions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": [
                        "kms:Delete*",
                        "kms:PutKeyPolicy",
                        "kms:ScheduleKeyDeletion",
                        "kms:CancelKeyDeletion"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "ArnEquals": {
                            "aws:PrincipalArn": f"arn:aws:iam::{config['workload_account']}:role/AWSControlTowerExecution"
                        }
                    }
                }
            ]
        })