#!/usr/bin/env python3

from typing import Optional, List, Dict
from aws_cdk import Duration, Stack, aws_ec2, aws_ecs, aws_route53, aws_logs, aws_iam, App, aws_ecr_assets
from constructs import Construct
import os

local_env = {"region": "us-east-2", "account": "000000000000"}
local_us_east_1_environment = {"region": "us-east-1", "account": "000000000000"}


class DatadogAgentVars(object):
    def __init__(
        self,
        environment: str,
        version: str,
        service_name: str,
    ) -> None:
        self.name = "datadog"
        self.environment = environment
        self.version = version
        self.service_name = service_name
        self.host = "http-intake.logs.datadoghq.com"

    def get_vars(self) -> dict:
        vars_dict = dict(
            ECS_FARGATE="true",
            DD_APM_ENABLED="true",
            DD_AC_EXCLUDE="name:datadog-agent name:ecs-agent",
            DD_API_KEY="API_KEY",
        )
        return vars_dict

    def get_service_vars(self) -> dict:
        vars_dict = dict(
            DD_ENV=self.environment,
            DD_VERSION=self.version,
            DD_SERVICE=self.service_name,
            DD_LOGS_INJECTION="true",
            DD_REMOTE_CONFIGURATION_ENABLED="false",
        )
        return vars_dict


class FargateServiceBuilder(object):
    def __init__(
        self,
        base_stack: Stack,
        fargate_cluster: aws_ecs.Cluster,
        service_name: str,
        vpc: aws_ec2.Vpc,
        image_directory: str = "src",
        dockerfile_name: str = "Dockerfile",
        port: Optional[int] = None,
        command: Optional[List[str]] = None,
        health_check: Optional[aws_ecs.HealthCheck] = None,
        cpu: Optional[int] = 1024,
        hosted_zone: Optional[aws_route53.HostedZone] = None,
        enable_execute_command: Optional[bool] = None,
        min_healthy_percent: Optional[int] = None,
        max_healthy_percent: int = 200,
    ) -> None:

        datadog_env = "local"

        datadog_agent_vars = DatadogAgentVars(
            environment=datadog_env,
            version="1.0.0",
            service_name=service_name,
        )

        self.base_stack = base_stack
        self.cpu = cpu or 1024
        self.environment_variables: Dict[
            str, str
        ] = datadog_agent_vars.get_service_vars()
        self.fargate_cluster = fargate_cluster
        self.memory = self.cpu * 2
        self.service_name = service_name
        self.hosted_zone = hosted_zone
        self.vpc = vpc
        self.command = command
        self.health_check = health_check
        self.security_groups: List[aws_ec2.SecurityGroup] = []
        self.secret_arns: List[str] = []
        self.port = port
        self.circuit_breaker = None
        self.enable_execute_command = enable_execute_command
        self.min_healthy_percent = min_healthy_percent
        self.max_healthy_percent = max_healthy_percent
        self.task_name = f"{self.service_name}-service"

        self.service_family_name = f"{self.task_name}-family"

        docker_image = aws_ecr_assets.DockerImageAsset(
            scope=self.base_stack,
            id=f"{self.service_name}-image",
            directory=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                f"../../{image_directory}",
            ),
            file=dockerfile_name,
        )
        container_image = aws_ecs.ContainerImage.from_docker_image_asset(
            asset=docker_image
        )

        self.security_group = aws_ec2.SecurityGroup(
            scope=self.base_stack,
            id=f"{self.service_name}-service-sg",
            security_group_name=f"{self.service_name}-service-sg",
            vpc=self.vpc,
            allow_all_outbound=False,
            description=f"{self.service_name} service security group",
        )

        self.security_group.add_egress_rule(
            peer=aws_ec2.Peer.any_ipv4(),
            connection=aws_ec2.Port.tcp(443),
            description="Allow outbound to the internet",
        )
        self.security_groups.append(self.security_group)

        if self.port:
            self.security_group.add_ingress_rule(
                peer=aws_ec2.Peer.ipv4(cidr_ip=self.vpc.vpc_cidr_block),
                connection=aws_ec2.Port.tcp(self.port),
                description=f"Allow vpc to the {self.service_name} port {self.port}",
            )
            self.port_mappings = [
                aws_ecs.PortMapping(
                    container_port=self.port,
                    protocol=aws_ecs.Protocol.TCP,
                ),
            ]
        else:
            self.port_mappings = None

        self.service_task_role = aws_iam.Role(
            scope=self.base_stack,
            id=f"{self.task_name}-task-role",
            assumed_by=aws_iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            role_name=f"{self.task_name}-task-role",
            description=f"{self.service_name} task role",
        )
        self.service_execution_role = aws_iam.Role(
            scope=self.base_stack,
            id=f"{self.task_name}-execution-role",
            assumed_by=aws_iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            role_name=f"{self.task_name}-execution-role",
            description=f"{self.service_name} task execution role",
        )

        self.service_task_definition = aws_ecs.FargateTaskDefinition(
            scope=self.base_stack,
            id=f"{self.task_name}-definition",
            cpu=self.cpu,
            memory_limit_mib=self.memory * 2,
            family=self.service_family_name,
            task_role=self.service_task_role,
            execution_role=self.service_execution_role,
        )

        # this is the main service container, no cpu limit
        self.container_definition = self.service_task_definition.add_container(
            id=f"{self.service_name}-container",
            container_name=self.service_name,
            image=container_image,
            linux_parameters=aws_ecs.LinuxParameters(
                scope=self.base_stack,
                id=f"{self.service_name}-linux-params",
                init_process_enabled=True,
            ),
            port_mappings=self.port_mappings,
            command=self.command,
            health_check=self.health_check,
            essential=True,
            docker_labels={
                "com.datadoghq.tags.env": datadog_agent_vars.environment,
                "com.datadoghq.tags.service": datadog_agent_vars.service_name,
                "com.datadoghq.ad.instances": f'[{{"host": "%%host%%", "port": {self.port}}}]',
                "com.datadoghq.ad.check_names": f'["{self.service_name}"]',
                "com.datadoghq.ad.init_configs": "[{}]",
                "org.opencontainers.image.revision": "1.0.0",
            },
            logging=aws_ecs.LogDrivers.firelens(
                options={
                    "Name": datadog_agent_vars.name,
                    "Host": datadog_agent_vars.host,
                    "TLS": "on",
                    "dd_service": datadog_agent_vars.service_name,
                    "dd_source": "ecs",
                    "provider": "ecs",
                    "dd_tags": f"env:{datadog_agent_vars.environment}",
                },
            ),
        )

        # fluentbit router
        self.service_task_definition.add_firelens_log_router(
            id="log-router",
            container_name="log_router",
            memory_reservation_mib=256,
            cpu=256,
            essential=False,
            image=aws_ecs.ContainerImage.from_registry(
                name="amazon/aws-for-fluent-bit:stable"
            ),
            firelens_config=aws_ecs.FirelensConfig(
                type=aws_ecs.FirelensLogRouterType.FLUENTBIT,
                options=aws_ecs.FirelensOptions(
                    config_file_type=aws_ecs.FirelensConfigFileType.FILE,
                    config_file_value="/fluent-bit/configs/parse-json.conf",
                    enable_ecs_log_metadata=True,
                ),
            ),
            logging=aws_ecs.LogDrivers.aws_logs(
                stream_prefix=f"{self.service_name}-firelens",
                log_retention=aws_logs.RetentionDays.ONE_WEEK,
                mode=aws_ecs.AwsLogDriverMode.NON_BLOCKING,
            ),
        )

        # add datadog agent
        self.service_task_definition.add_container(
            id="datadog-agent",
            container_name="datadog-agent",
            image=aws_ecs.ContainerImage.from_registry(name="datadog/agent:7.43.1"),
            essential=False,
            environment=datadog_agent_vars.get_vars(),
            port_mappings=[
                aws_ecs.PortMapping(
                    container_port=8126,
                    host_port=8126,
                    protocol=aws_ecs.Protocol.TCP,
                ),
            ],
            memory_reservation_mib=512,
            cpu=512,
            health_check=aws_ecs.HealthCheck(
                retries=2,
                command=["CMD-SHELL", "agent health"],
                timeout=Duration.seconds(5),
                interval=Duration.seconds(30),
                start_period=Duration.seconds(15),
            ),
            logging=aws_ecs.LogDrivers.aws_logs(
                stream_prefix=f"{self.service_name}-datadog",
                log_retention=aws_logs.RetentionDays.ONE_WEEK,
                mode=aws_ecs.AwsLogDriverMode.NON_BLOCKING,
            ),
        )


    def build(
        self,
    ):
        # add all env variables to container
        for var in self.environment_variables:
            self.container_definition.add_environment(
                name=var,
                value=self.environment_variables[var],
            )

        fargate_service = aws_ecs.FargateService(
            scope=self.base_stack,
            id=f"{self.service_name}-service",
            service_name=self.service_name,
            cluster=self.fargate_cluster,
            task_definition=self.service_task_definition,
            desired_count=1,
            assign_public_ip=True,
        )
        return fargate_service


class WebApiServiceStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        service_name: str,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        vpc = aws_ec2.Vpc(
            scope=self,
            id="vpc",
            cidr="10.0.0.0/16",
            enable_dns_hostnames=True,
            enable_dns_support=True,
            subnet_configuration=[
                aws_ec2.SubnetConfiguration(
                    name="public-subnet-config",
                    subnet_type=aws_ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                    reserved=False,
                ),
                aws_ec2.SubnetConfiguration(
                    name="private-subnet-config",
                    subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24,
                    reserved=False,
                ),
            ],
        )

        log_group = aws_logs.LogGroup(
            self,
            id="fargate-logs",
            log_group_name="fargate-logs",
            retention=aws_logs.RetentionDays.ONE_MONTH,
        )

        cluster = aws_ecs.Cluster(
            scope=self,
            id="cluster",
            cluster_name="cluster",
            vpc=vpc,
            container_insights=True,
            enable_fargate_capacity_providers=True,
            execute_command_configuration=aws_ecs.ExecuteCommandConfiguration(
                log_configuration=aws_ecs.ExecuteCommandLogConfiguration(
                    cloud_watch_log_group=log_group,
                    cloud_watch_encryption_enabled=False,
                ),
                logging=aws_ecs.ExecuteCommandLogging.OVERRIDE,
            ),
        )

        web_api_entrypoint = "./webapi_entrypoint_dev.sh"
        # ignore health check in dev
        web_api_health_check = aws_ecs.HealthCheck(
            retries=3,
            command=["CMD-SHELL", "exit 0"],
            timeout=Duration.seconds(15),
            interval=Duration.seconds(30),
            start_period=Duration.seconds(60),
        )

        web_api_service = FargateServiceBuilder(
            base_stack=self,
            service_name=service_name,
            vpc=vpc,
            fargate_cluster=cluster,
            image_directory="src",
            dockerfile_name="Dockerfile.web_api",
            command=[web_api_entrypoint],
            health_check=web_api_health_check,
            port=80,
            cpu=2048,
        )

        # finally build the service
        self.web_api_fargate_service = web_api_service.build()

app = App()

WebApiServiceStack(
    scope=app,
    construct_id="web-api",
    service_name="web-api",
    env=local_env,
)

app.synth()
