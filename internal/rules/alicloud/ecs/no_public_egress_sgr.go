package ecs

import (
	"github.com/aquasecurity/defsec/internal/cidr"
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPublicEgressSgr = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AliCloud-0001",
		Provider:    providers.AliCloudProvider,
		Service:     "ecs",
		ShortCode:   "no-public-egress-sgr",
		Summary:     "An egress security group rule allows traffic to /0.",
		Explanation: "Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.",
		Impact:      "The port is exposed for egress to the internet",
		Resolution:  "Set a more restrictive cidr range",

		Links: []string{
			"https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/security_group_rule",
			"https://help.aliyun.com/document_detail/51170.html",
		},
		Severity: severity.Critical,
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicEgressGoodExamples,
			BadExamples:         terraformNoPublicEgressBadExamples,
			RemediationMarkdown: terraformNoPublicEgressRemediationMarkdown,
			Links:               terraformNoPublicEgressLinks,
		},
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.AliCloud.Ecs.SecurityGroups {
			for _, rule := range group.EgressRules {
				var failed bool
				if cidr.IsPublic(rule.CidrIp.Value()) && rule.Policy.EqualTo("accept") {
					failed = true
					results.Add(
						"Security group rule allows egress to multiple public internet addresses.",
						rule.CidrIp,
					)
				}
				if !failed {
					results.AddPassed(&group)
				}
			}
		}
		return
	},
)
