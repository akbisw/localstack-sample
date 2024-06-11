#!/usr/bin/env python3

from typing import Optional, List, Dict
from aws_cdk import Duration, Stack, Tags, aws_ec2, aws_ecs, aws_route53, aws_logs, aws_iam, App, aws_ecr_assets, aws_ecs_patterns, aws_elasticloadbalancingv2, aws_secretsmanager, aws_rds, aws_s3, aws_sqs, aws_certificatemanager, aws_cognito, aws_apigatewayv2, aws_apigatewayv2_integrations, aws_apigatewayv2_authorizers
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

        load_balanced_fargate_service = aws_ecs_patterns.ApplicationLoadBalancedFargateService(
            scope=self.base_stack,
            id=f"{self.service_name}-service",
            assign_public_ip=False,
            service_name=self.service_name,
            cluster=self.fargate_cluster,
            cpu=self.cpu,
            desired_count=1,
            memory_limit_mib=self.memory,
            public_load_balancer=False,
            task_definition=self.service_task_definition,
            protocol=aws_elasticloadbalancingv2.ApplicationProtocol.HTTP,
            open_listener=True,
            protocol_version=aws_elasticloadbalancingv2.ApplicationProtocolVersion.HTTP1,
            target_protocol=aws_elasticloadbalancingv2.ApplicationProtocol.HTTP,
            health_check_grace_period=Duration.seconds(20),
            min_healthy_percent=self.min_healthy_percent,
            max_healthy_percent=self.max_healthy_percent,
            enable_execute_command=False,
            circuit_breaker=self.circuit_breaker,
            propagate_tags=aws_ecs.PropagatedTagSource.SERVICE,
            enable_ecs_managed_tags=True,
        )
        return load_balanced_fargate_service


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


class AuthStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)


        self.user_pool = aws_cognito.UserPool(
            self,
            id="meow-userpool",
            advanced_security_mode=aws_cognito.AdvancedSecurityMode.ENFORCED,
            user_pool_name="meow-userpool",
            self_sign_up_enabled=True,
            user_invitation=aws_cognito.UserInvitationConfig(
                email_subject="Welcome to meow!",
                email_body="Hey {username}, you've been invited to join meow! "
                "Your temporary password is {####}",
                sms_message="Welcome to meow, {username}! Your temporary password for meow is {####}",
            ),
            sign_in_aliases=aws_cognito.SignInAliases(email=True, username=False),
            password_policy=aws_cognito.PasswordPolicy(
                min_length=10,
                require_lowercase=False,
                require_uppercase=False,
                require_digits=False,
                require_symbols=False,
            ),
            mfa=aws_cognito.Mfa.OPTIONAL,
            mfa_second_factor=aws_cognito.MfaSecondFactor(sms=True, otp=True),
            account_recovery=aws_cognito.AccountRecovery.EMAIL_ONLY,
            # Note: These custom attributes can't be removed once added
            custom_attributes={
                "referral_code": aws_cognito.StringAttribute(mutable=True),
                "affiliate_id": aws_cognito.StringAttribute(mutable=True),
            },
            device_tracking=aws_cognito.DeviceTracking(
                challenge_required_on_new_device=True,
                device_only_remembered_on_user_prompt=True,
            ),
        )



        resource_server_scope = aws_cognito.ResourceServerScope(
            scope_description="oauth scope for cognito access token",
            scope_name="api",
        )
        resource_server = self.user_pool.add_resource_server(
            id="resource-server",
            identifier="meow.com",
            user_pool_resource_server_name="meow.com",
            scopes=[resource_server_scope],
        )

        self.user_pool_client = self.user_pool.add_client(
            id="meow-app-client",
            user_pool_client_name="meow-app-client",
            # setting user_password to False disallows username/password authentication
            auth_flows=aws_cognito.AuthFlow(user_password=False, user_srp=True),
            # return generic error when user not found
            prevent_user_existence_errors=True,
            # OAuth 2.0 token settings
            access_token_validity=Duration.minutes(30),
            id_token_validity=Duration.minutes(30),
            refresh_token_validity=Duration.hours(12),
            o_auth=aws_cognito.OAuthSettings(
                callback_urls=[
                    url + "/signin-redirect"
                    for url in [
                        "https://app.meow.com",
                        "http://localhost:3000",
                    ]
                    if url
                ],
                logout_urls=[
                    url
                    for url in [
                        "https://app.meow.com",
                        "http://localhost:3000",
                    ]
                    if url
                ],
                scopes=[
                    aws_cognito.OAuthScope.resource_server(
                        server=resource_server, scope=resource_server_scope
                    ),
                    aws_cognito.OAuthScope.PHONE,
                    aws_cognito.OAuthScope.EMAIL,
                    aws_cognito.OAuthScope.OPENID,
                    aws_cognito.OAuthScope.PROFILE,
                    aws_cognito.OAuthScope.COGNITO_ADMIN,
                ],
            ),
            supported_identity_providers=[
                aws_cognito.UserPoolClientIdentityProvider.COGNITO,
                aws_cognito.UserPoolClientIdentityProvider.GOOGLE,
            ],
        )


class LocalHttpApiStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        user_pool: aws_cognito.IUserPool,
        user_pool_client: aws_cognito.IUserPoolClient,
        web_api_lb_listener: aws_elasticloadbalancingv2.IApplicationListener,
        web_api_service_domain: str,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.api_gateway = aws_apigatewayv2.HttpApi(
            self,
            id="local-api-gateway",
            api_name="local-api-gateway",
            description="Local HTTP API Gateway",
            cors_preflight=aws_apigatewayv2.CorsPreflightOptions(
                allow_credentials=True,
                allow_origins=[
                    "https://app.meow.com",
                    "http://localhost:3000",
                ],
                allow_methods=[
                    aws_apigatewayv2.CorsHttpMethod.GET,
                    aws_apigatewayv2.CorsHttpMethod.POST,
                    aws_apigatewayv2.CorsHttpMethod.PATCH,
                    aws_apigatewayv2.CorsHttpMethod.PUT,
                    aws_apigatewayv2.CorsHttpMethod.DELETE,
                    aws_apigatewayv2.CorsHttpMethod.OPTIONS,
                ],
                allow_headers=[
                    "authorization",
                    "content-type",
                    "x-datadog-trace-id",
                    "x-datadog-parent-id",
                    "x-datadog-origin",
                    "x-datadog-sampling-priority",
                    "x-datadog-sampled",
                    "origin",
                    "access-control-request-method",
                    "meow-entity-id",
                    "meow-device-id",
                    "meow-bank-account-id",
                ],
            ),
            create_default_stage=True,
            disable_execute_api_endpoint=False,
        )
        Tags.of(self.api_gateway).add("_custom_id_", "webapi")

        """ web-api integration """
        self.web_api_integration = aws_apigatewayv2_integrations.HttpAlbIntegration(
            id="local-http-integration",
            listener=web_api_lb_listener,
            method=aws_apigatewayv2.HttpMethod.ANY,
            secure_server_name=web_api_service_domain,
            parameter_mapping=aws_apigatewayv2.ParameterMapping()
                .append_header(
                    name="x-request-id",
                    value=aws_apigatewayv2.MappingValue.context_variable(variable_name="requestId"),
                )
                .append_header(
                    name="x-request-protocol",
                    value=aws_apigatewayv2.MappingValue.context_variable(variable_name="protocol"),
                )
                .append_header(
                    name="x-authorizer-sub",
                    value=aws_apigatewayv2.MappingValue.context_variable(
                        variable_name="authorizer.sub"
                    ),
                )
                .append_header(
                    name="x-cognito-sub",
                    value=aws_apigatewayv2.MappingValue.context_variable(
                        variable_name="authorizer.claims.sub"
                    ),
                )
                .append_header(
                    name="x-cognito-client-id",
                    value=aws_apigatewayv2.MappingValue.context_variable(
                        variable_name="authorizer.claims.client_id"
                    ),
                )
                .append_header(
                    name="x-cognito-issuer",
                    value=aws_apigatewayv2.MappingValue.context_variable(
                        variable_name="authorizer.claims.iss"
                    ),
                )
                .append_header(
                    # HTTP API is including the source IP in the "forwarded" header.
                    # AWS WAF is not able to understand this header's format,
                    # so we include the source IP in a custom header.
                    name="x-meow-forwarded-for",
                    value=aws_apigatewayv2.MappingValue.context_variable(
                        variable_name="identity.sourceIp"
                    ),
                )
                .append_header(
                    name="x-user-agent",
                    value=aws_apigatewayv2.MappingValue.context_variable(
                        variable_name="identity.userAgent"
                    ),
                ),
        )


        """ Cognito Authorizer """
        cognito_authorizer = aws_apigatewayv2_authorizers.HttpJwtAuthorizer(
            id="local-cognito-authorizer-v2",
            authorizer_name="local-cognito-authorizer-v2",
            jwt_audience=[user_pool_client.user_pool_client_id],
            jwt_issuer=f"http://localhost.localstack.cloud:4566/{user_pool.user_pool_id}",
        )
        """ Add routes """
        # unauthenticated route for OPTIONS
        self.api_gateway.add_routes(
            path="/{proxy+}",
            authorization_scopes=None,
            authorizer=None,
            methods=[aws_apigatewayv2.HttpMethod.OPTIONS],
            integration=self.web_api_integration,
        )
        # catch all routes for API gateway. require all requests to be authenticated
        self.api_gateway.add_routes(
            path="/{proxy+}",
            authorization_scopes=["aws.cognito.signin.user.admin"],
            authorizer=cognito_authorizer,
            methods=[
                aws_apigatewayv2.HttpMethod.GET,
                aws_apigatewayv2.HttpMethod.POST,
                aws_apigatewayv2.HttpMethod.PUT,
                aws_apigatewayv2.HttpMethod.DELETE,
                aws_apigatewayv2.HttpMethod.PATCH,
            ],
            integration=self.web_api_integration,
        )
        unauthenticated_routes = [
            ("/account/invitations/accept", [aws_apigatewayv2.HttpMethod.PUT]),
            ("/onboarding/business/signer/{token}", [aws_apigatewayv2.HttpMethod.GET, aws_apigatewayv2.HttpMethod.POST]),
            (
                "/onboarding/business/upload-documents/{token}",
                [aws_apigatewayv2.HttpMethod.POST, aws_apigatewayv2.HttpMethod.GET],
            ),
            (
                "/onboarding/business/upload-documents/{token}/{kyb_info_id}",
                [aws_apigatewayv2.HttpMethod.DELETE],
            ),
        ]
        # allow accessing /docs on dev environments. Dev api is behind a VPN
        unauthenticated_routes.append(("/health", [aws_apigatewayv2.HttpMethod.GET]))
        unauthenticated_routes.append(("/docs", [aws_apigatewayv2.HttpMethod.GET]))
        unauthenticated_routes.append(("/openapi.json", [aws_apigatewayv2.HttpMethod.GET]))
        for unauthenticated_route in unauthenticated_routes:
            self.api_gateway.add_routes(
                path=unauthenticated_route[0],
                methods=unauthenticated_route[1],
                authorization_scopes=None,
                authorizer=None,
                integration=self.web_api_integration,
            )


app = App()

cognito_stack = AuthStack(
    scope=app,
    construct_id="cognito",
    env=local_env,
)

web_api_service_stack = WebApiServiceStack(
    scope=app,
    construct_id="web-api",
    service_name="web-api",
    env=local_env,
)
LocalHttpApiStack(
    scope=app,
    construct_id="local-http-api",
    user_pool=cognito_stack.user_pool,
    user_pool_client=cognito_stack.user_pool_client,
    web_api_lb_listener=web_api_service_stack.web_api_fargate_service.listener,
    web_api_service_domain="web-api-service",
    env=local_env,
)

app.synth()
