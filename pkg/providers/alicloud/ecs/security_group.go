package ecs

import "github.com/aquasecurity/defsec/internal/types"

type SecurityGroup struct {
	types.Metadata
	Name         types.StringValue
	Description  types.StringValue
	IngressRules []SecurityGroupRule
	EgressRules  []SecurityGroupRule
}

type SecurityGroupRule struct {
	types.Metadata
	Type            types.StringValue
	Policy          types.StringValue
	Description     types.StringValue
	Protocol        types.StringValue
	CidrIp          types.StringValue
	SecurityGroupId types.StringValue
}
