from aws_cdk import (
    aws_ecs as ecs,
    aws_logs as logs,
    aws_ecr as ecr,
    RemovalPolicy
)

def create_ssm_agent_container(scope, config, task_definition):
    ssm_agent_log_group = logs.LogGroup(
        scope,
        "ssm-agent-log-group",
        log_group_name=
        f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-ssm-agent-log-groups-mra-{config['resource_suffix']}",
        retention=logs.RetentionDays.ONE_MONTH,
        removal_policy=RemovalPolicy.DESTROY,
    )

    ssm_agent_repository = ecr.Repository.from_repository_arn(
        scope, "ssm-agent-repository",
        f"arn:aws:ecr:{config['deployment_region_1']}:{config['deployment_sdlc_account']}:repository/{config['ssm_agent_ecr_repo_name']}"
    )

    ssm_agent_container = task_definition.add_container(
        "SSMAgent",
        image=ecs.ContainerImage.from_ecr_repository(
            ssm_agent_repository, config.get('ssm_agent_image_tag', 'latest')
        ),
        logging=ecs.LogDriver.aws_logs(stream_prefix="ssm-agent", log_group=ssm_agent_log_group),
        essential=False,
        readonly_root_filesystem=True,
        memory_reservation_mib=32,
        cpu=32
    )

    for _vol, _path in scope.ssm_related_vol_config.items():
        ssm_agent_container.add_mount_points(
            ecs.MountPoint(container_path=_path,
                           read_only=False,
                           source_volume=_vol)
        )

    return ssm_agent_container
