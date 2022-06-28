package alicloud

import (
	"github.com/aquasecurity/defsec/internal/adapters/terraform/alicloud/ecs"
	"github.com/aquasecurity/defsec/pkg/providers/alicloud"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) alicloud.AliCloud {
	return alicloud.AliCloud{
		Ecs: ecs.Adapt(modules),
	}
}
