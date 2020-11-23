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

    def extract_event_data(self, event):
        """ Extract required event data """

        self.load_balancer_name = event["detail"]["responseElements"]["loadBalancers"][0]["loadBalancerName"]


    def resource_compliant(self):
        """
        Determine if the resource is compliant with your rule.

        Return True if it is compliant, and False if it is not.
        """
        # TODO: Implement a check for determining if the resource is compliant

        lb_describe = alb_client.describe_load_balancers(Names=[self.load_balancer_name])
        lb_arn = lb_describe['LoadBalancers'][0]['LoadBalancerArn']
        arn_describe = alb_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
        attributes = arn_describe['Attributes']
        for attribute in attributes:
            if attribute.get('Key') == 'access_logs.s3.enabled':
                if attribute.get('Value') == 'false':
                    print('alert value is false!!!')

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