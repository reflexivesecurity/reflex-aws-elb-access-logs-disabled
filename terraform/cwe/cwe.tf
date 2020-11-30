module "cwe" {
  source           = "git::https://github.com/reflexivesecurity/reflex-engine.git//modules/cwe?ref=v2.1.3"
  name        = "ElbAccessLogsDisabled"
  description = "Rule to find ELBs or ALBs created without access logs"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.elasticloadbalancing"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "elasticloadbalancing.amazonaws.com"
    ],
    "eventName": [
      "CreateLoadBalancer",
      "ModifyLoadBalancerAttributes"
    ]
  }
}
PATTERN
}
