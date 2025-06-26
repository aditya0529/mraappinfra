import aws_cdk as core
import aws_cdk.assertions as assertions

from sw_refapp_mra_app_infra_code_main_aws.sw_refapp_mra_app_infra_code_main_aws_stack import SwRefappMraAppInfraCodeMainAwsStack

# example tests. To run these tests, uncomment this file along with the example
# resource in sw_refapp_mra_app_infra_code_main_aws/sw_refapp_mra_app_infra_code_main_aws_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = SwRefappMraAppInfraCodeMainAwsStack(app, "sw-refapp-mra-app-infra-code-main-aws")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
