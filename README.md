# elb-access-logs-disabled

This rule detects when access logs are disabled or not enabled within an ELB. Supports both classic and advanced load balancers.

## Usage

To use this rule either add it to your `reflex.yaml` configuration file:

```
rules:
  - elb-access-logs-disabled:
      version: latest
```

or add it directly to your Terraform:

```
...

module "elb-access-logs-disabled-cwe" {
  source            = "git::https://github.com/reflexivesecurity/elb-access-logs-disabled.git//terraform/cwe?ref=latest"
}

module "elb-access-logs-disabled" {
  source            = "git::https://github.com/reflexivesecurity/elb-access-logs-disabled.git?ref=latest"
  sns_topic_arn     = module.central-sns-topic.arn
  reflex_kms_key_id = module.reflex-kms-key.key_id
}

...
```

Note: The `sns_topic_arn` and `reflex_kms_key_id` example values shown here assume you generated resources with `reflex build`. If you are using the Terraform on its own you need to provide your own valid values.

## Contributing
If you are interested in contributing, please review [our contribution guide](https://docs.reflexivesecurity.com/about/contributing.html).

## License
This Reflex rule is made available under the MPL 2.0 license. For more information view
the [LICENSE](https://github.com/reflexivesecurity/elb-access-logs-disabled/blob/master/LICENSE)
