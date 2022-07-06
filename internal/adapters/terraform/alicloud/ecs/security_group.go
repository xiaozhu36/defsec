package ecs

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/alicloud/ecs"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/google/uuid"
)

func adaptSecurityGroups(modules terraform.Modules) []ecs.SecurityGroup {
	securityGroups := make([]ecs.SecurityGroup, 0)
	store := make(map[string]*ecs.SecurityGroup, 0)
	blocks := modules.GetResourcesByType("alicloud_security_group")

	for _, b := range blocks {
		securityGroup := ecs.SecurityGroup{
			Metadata:     b.GetMetadata(),
			Name:         b.GetAttribute("name").AsStringValueOrDefault("", b),
			Description:  b.GetAttribute("description").AsStringValueOrDefault("", b),
			IngressRules: nil,
			EgressRules:  nil,
		}
		store[b.ID()] = &securityGroup
	}

	for _, ruleBlock := range modules.GetResourcesByType("alicloud_security_group_rule") {
		rule, securityGroupId := adaptSecurityGroupRule(ruleBlock)
		if v, exist := store[securityGroupId.Value()]; exist {
			securityGroupRuleHelper(v, rule)
			continue
		}
		obj := ecs.SecurityGroup{
			Metadata: types.NewUnmanagedMetadata(),
		}
		securityGroupRuleHelper(&obj, rule)
		store[uuid.NewString()] = &obj
	}

	for _, securityGroup := range store {
		securityGroups = append(securityGroups, *securityGroup)
	}

	return securityGroups
}

func securityGroupRuleHelper(group *ecs.SecurityGroup, rule ecs.SecurityGroupRule) {
	if rule.Type.EqualTo("ingress") {
		group.IngressRules = append(group.IngressRules, rule)
	} else if rule.Type.EqualTo("egress") {
		group.EgressRules = append(group.EgressRules, rule)
	}
}

func adaptSecurityGroupRule(b *terraform.Block) (ecs.SecurityGroupRule, types.StringValue) {
	rule := ecs.SecurityGroupRule{
		Metadata:    b.GetMetadata(),
		Type:        b.GetAttribute("type").AsStringValueOrDefault("", b),
		Policy:      b.GetAttribute("policy").AsStringValueOrDefault("", b),
		Description: b.GetAttribute("description").AsStringValueOrDefault("", b),
		Protocol:    b.GetAttribute("ip_protocol").AsStringValueOrDefault("", b),
		CidrIp:      b.GetAttribute("cidr_ip").AsStringValueOrDefault("", b),
	}
	return rule, b.GetAttribute("security_group_id").AsStringValueOrDefault("", b)
}
