package ecs

import (
	"github.com/aquasecurity/defsec/pkg/providers/alicloud/ecs"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) ecs.ECS {
	return ecs.ECS{
		SecurityGroups: adaptSecurityGroups(modules),
	}
}
