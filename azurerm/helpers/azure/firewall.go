package azure

import "github.com/hashicorp/terraform/helper/schema"

func expandArmFirewallSet(r *schema.Set) *[]string {
	result := make([]string, 0)
	for _, v := range r.List() {
		s := v.(string)
		result = append(result, s)
	}
	return &result
}
