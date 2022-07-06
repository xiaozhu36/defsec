package ecs

import (
	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/alicloud/ecs"
	"github.com/aquasecurity/defsec/test/testutil"
	"testing"
)

func TestSecurityAdapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []ecs.SecurityGroup
	}{
		{
			name: "defined",
			terraform: `
			resource "alicloud_security_group" "default" {
			  description = "the alicloud_security_group used for tfsec."
			  name = "tfsec_test"
			}
			resource "alicloud_security_group_rule" "allow_all_tcp1" {
  			  description       = "the description of alicloud_security_group_rule1"
			  type              = "egress"
			  ip_protocol       = "tcp"
			  nic_type          = "internet"
			  policy            = "accept"
			  port_range        = "1/65535"
			  priority          = 1
			  security_group_id = alicloud_security_group.default.id
			  cidr_ip           = "0.0.0.0/0"
			}
			resource "alicloud_security_group_rule" "allow_all_tcp2" {
  			  description       = "the description of alicloud_security_group_rule2"
			  type              = "egress"
			  ip_protocol       = "tcp"
			  nic_type          = "internet"
			  policy            = "accept"
			  port_range        = "1/65535"
			  priority          = 1
			  security_group_id = "raw security group id"
			  cidr_ip           = "0.0.0.0/0"
			}
`,
			expected: []ecs.SecurityGroup{
				{
					Metadata:    types.NewTestMetadata(),
					Name:        types.String("tfsec_test", types.NewTestMetadata()),
					Description: types.String("the alicloud_security_group used for tfsec.", types.NewTestMetadata()),
					EgressRules: []ecs.SecurityGroupRule{
						{
							Type:        types.String("egress", types.NewTestMetadata()),
							Protocol:    types.String("tcp", types.NewTestMetadata()),
							Policy:      types.String("accept", types.NewTestMetadata()),
							Description: types.String("the description of alicloud_security_group_rule1", types.NewTestMetadata()),
							CidrIp:      types.String("0.0.0.0/0", types.NewTestMetadata()),
						},
					},
				},
				{
					Metadata: types.NewTestMetadata(),
					EgressRules: []ecs.SecurityGroupRule{
						{
							Type:        types.String("egress", types.NewTestMetadata()),
							Protocol:    types.String("tcp", types.NewTestMetadata()),
							Policy:      types.String("accept", types.NewTestMetadata()),
							Description: types.String("the description of alicloud_security_group_rule2", types.NewTestMetadata()),
							CidrIp:      types.String("0.0.0.0/0", types.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for i := range tests {
		testCase := tests[i]
		t.Run(testCase.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, testCase.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, testCase.expected, adapted.SecurityGroups)
		})

	}
}
