""" Module for ElbAccessLogsDisabled """

import json

import boto3
from reflex_core import AWSRule, subscription_confirmation


class ElbAccessLogsDisabled(AWSRule):
    """ Rule to detect when an ELB does not have logging enabled or logging is disabled. """

    elb_client = boto3.client("elb")
    alb_client = boto3.client("elbv2")

    def __init__(self, event):
        super().__init__(event)
        self.load_balancer_type = None
        self.load_balancer_name = None
        self.load_balancer_arn = None

    def extract_event_data(self, event):
        """ Extract required event data """

        if event["detail"]["eventName"] == "CreateLoadBalancer":
            if event["detail"]["requestParameters"].get("type"):
                self.load_balancer_type = event["detail"]["requestParameters"].get(
                    "type"
                )
            else:
                self.load_balancer_type = "classic"

            if self.load_balancer_type == "classic":
                self.load_balancer_name = event["detail"]["requestParameters"][
                    "loadBalancerName"
                ]
            else:
                self.load_balancer_name = event["detail"]["responseElements"][
                    "loadBalancers"
                ][0]["loadBalancerName"]
        else:
            if event["detail"]["requestParameters"].get("loadBalancerArn"):
                self.load_balancer_arn = event["detail"]["requestParameters"].get(
                    "loadBalancerArn"
                )
                self.load_balancer_type = "application"
            else:
                self.load_balancer_name = event["detail"]["requestParameters"].get(
                    "loadBalancerName"
                )
                self.load_balancer_type = "classic"

    def resource_compliant(self):
        """
        Determine if the resource is compliant with your rule.

        Return True if it is compliant, and False if it is not.
        """
        is_compliant = True
        if self.load_balancer_type == "classic":
            attribute_describe = elb_client.describe_load_balancer_attributes(
                LoadBalancerName=self.load_balancer_name
            )["LoadBalancerAttributes"]
            is_compliant = attribute_describe["AccessLog"]["Enabled"]
        else:
            if self.load_balancer_name:
                self.load_balancer_arn = alb_client.describe_load_balancers(
                    Names=[self.load_balancer_name]
                )["LoadBalancers"][0]["LoadBalancerArn"]
            attribute_describe = alb_client.describe_load_balancer_attributes(
                LoadBalancerArn=self.load_balancer_arn
            )
            attributes = attribute_describe["Attributes"]
            for attribute in attributes:
                if attribute.get("Key") == "access_logs.s3.enabled":
                    if attribute.get("Value") == "false":
                        is_compliant = False
        return is_compliant

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """

        return f"The load balancer {self.load_balancer_name} has access logs disabled."


def lambda_handler(event, _):
    """ Handles the incoming event """
    event_payload = json.loads(event["Records"][0]["body"])
    if subscription_confirmation.is_subscription_confirmation(event_payload):
        subscription_confirmation.confirm_subscription(event_payload)
        return
    rule = ElbAccessLogsDisabled(event_payload)
    rule.run_compliance_rule()
