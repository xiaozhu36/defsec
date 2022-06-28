package ecs

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/alicloud/ecs"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCheckNoPublicEgress(t *testing.T) {
	tests := []struct {
		name     string
		input    ecs.ECS
		expected bool
	}{
		{
			name: "Firewall egress rule with a public destination addresses",
			input: ecs.ECS{
				SecurityGroups: []ecs.SecurityGroup{
					{
						Metadata: types.NewTestMetadata(),
						EgressRules: []ecs.SecurityGroupRule{
							{
								Metadata: types.NewTestMetadata(),
								Policy:   types.String("accept", types.NewTestMetadata()),
								CidrIp:   types.String("0.0.0.0/0", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall egress rule without a public destination addresses",
			input: ecs.ECS{
				SecurityGroups: []ecs.SecurityGroup{
					{
						Metadata: types.NewTestMetadata(),
						EgressRules: []ecs.SecurityGroupRule{
							{
								Metadata: types.NewTestMetadata(),
								Policy:   types.String("accept", types.NewTestMetadata()),
								CidrIp:   types.String("10.0.0.0/16", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AliCloud.Ecs = test.input
			results := CheckNoPublicEgressSgr.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicEgressSgr.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
