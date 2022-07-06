package ecs

var terraformNoPublicEgressGoodExamples = []string{
	`
resource "alicloud_security_group_rule" "good_example" {
  cidr_ip           = "10.0.0.0/16"
  description       = "the bad example of alicloud_security_group_rule"
  ip_protocol       = "all"
  nic_type          = "internet"
  policy            = "accept"
  port_range        = "-1/-1"
  priority          = "1"
  security_group_id = "your_security_group_id"
  type              = "egress"
}
`,
}

var terraformNoPublicEgressBadExamples = []string{
	`
resource "alicloud_security_group_rule" "bad_example" {
  cidr_ip           = "0.0.0.0/0"
  description       = "the good example of alicloud_security_group_rule"
  ip_protocol       = "all"
  nic_type          = "internet"
  policy            = "accept"
  port_range        = "-1/-1"
  priority          = "1"
  security_group_id = "your_security_group_id"
  type              = "egress"
}
`,
}

var terraformNoPublicEgressLinks = []string{
	`https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/security_group_rule`,
}

var terraformNoPublicEgressRemediationMarkdown = ``
