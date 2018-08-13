package azurerm

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2018-04-01/network"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

func resourceArmFirewallApplicationRuleCollection() *schema.Resource {
	return &schema.Resource{
		Create: resourceArmFirewallApplicationRuleCollectionCreateUpdate,
		Read:   resourceArmFirewallApplicationRuleCollectionRead,
		Update: resourceArmFirewallApplicationRuleCollectionCreateUpdate,
		Delete: resourceArmFirewallApplicationRuleCollectionDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"azure_firewall_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"resource_group_name": resourceGroupNameSchema(),

			"priority": {
				Type:     schema.TypeInt,
				Required: true,
			},

			"action": {
				Type:     schema.TypeString,
				Required: true,
				ValidateFunc: validation.StringInSlice([]string{
					string(network.AzureFirewallRCActionTypeAllow),
					string(network.AzureFirewallRCActionTypeDeny),
				}, true),
				DiffSuppressFunc: ignoreCaseDiffSuppressFunc,
			},

			"rule": {
				Type:     schema.TypeSet,
				Required: true,
				MinItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"description": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"source_addresses": {
							Type:     schema.TypeSet,
							Required: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Set:      schema.HashString,
						},
						"target_urls": {
							Type:     schema.TypeSet,
							Required: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Set:      schema.HashString,
						},
						"protocols": {
							Type:     schema.TypeSet,
							Required: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"port": {
										Type:     schema.TypeInt,
										Optional: true,
									},
									"type": {
										Type:     schema.TypeString,
										Required: true,
										ValidateFunc: validation.StringInSlice([]string{
											string(network.AzureFirewallApplicationRuleProtocolTypeHTTP),
											string(network.AzureFirewallApplicationRuleProtocolTypeHTTPS),
										}, true),
									},
								},
							},
							DiffSuppressFunc: ignoreCaseDiffSuppressFunc,
							Set:              schema.HashString,
						},
					},
				},
			},
		},
	}
}

func resourceArmFirewallApplicationRuleCollectionCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).azureFirewallsClient
	ctx := meta.(*ArmClient).StopContext

	resourceGroup := d.Get("resource_group_name").(string)
	name := d.Get("name").(string)
	firewallName := d.Get("azure_firewall_name").(string)

	azureRMLockByName(firewallName, azureFirewallResourceName)
	defer azureRMUnlockByName(firewallName, azureFirewallResourceName)

	firewall, err := client.Get(ctx, resourceGroup, firewallName)
	if err != nil {
		return fmt.Errorf("Error retrieving Azure Firewall %q (Resource Group %q): %+v", firewallName, resourceGroup, err)
	}

	ipConfigs := fixArmFirewallIPConfiguration(&firewall)
	firewall.AzureFirewallPropertiesFormat.IPConfigurations = &ipConfigs

	newFwRuleCol := expandArmFirewallApplicationRuleCollection(d)
	ruleCollections := append(*firewall.AzureFirewallPropertiesFormat.ApplicationRuleCollections, newFwRuleCol)
	existingCollection, index, exists := findArmFirewallApplicationRuleCollectionByName(&firewall, name)
	if exists {
		if name == *existingCollection.Name {
			ruleCollections = append(ruleCollections[:index], ruleCollections[index+1:]...)
		}
	}
	firewall.AzureFirewallPropertiesFormat.ApplicationRuleCollections = &ruleCollections

	future, err := client.CreateOrUpdate(ctx, resourceGroup, firewallName, firewall)
	if err != nil {
		return fmt.Errorf("Error creating/updating application rule collection %q in Azure Firewall %q (Resource Group %q): %+v", name, firewallName, resourceGroup, err)
	}

	err = future.WaitForCompletionRef(ctx, client.Client)
	if err != nil {
		return fmt.Errorf("Error waiting for creation/update of application rule collection %q in Azure Firewall %q (Resource Group %q): %+v", name, firewallName, resourceGroup, err)
	}

	read, err := client.Get(ctx, resourceGroup, firewallName)
	if err != nil {
		return fmt.Errorf("Error retrieving Azure Firewall %q (Resource Group %q): %+v", firewallName, resourceGroup, err)
	}

	if read.ID == nil {
		return fmt.Errorf("Cannot read Azure Firewall %q (Resource Group %q) ID", firewallName, resourceGroup)
	}

	var collectionID string
	for _, collection := range *read.AzureFirewallPropertiesFormat.ApplicationRuleCollections {
		if *collection.Name == name {
			collectionID = *collection.ID
		}
	}
	d.SetId(collectionID)

	return resourceArmFirewallApplicationRuleCollectionRead(d, meta)
}

func resourceArmFirewallApplicationRuleCollectionRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).azureFirewallsClient
	ctx := meta.(*ArmClient).StopContext

	resourceGroup := d.Get("resource_group_name").(string)
	name := d.Get("name").(string)
	fwName := d.Get("azure_firewall_name").(string)

	firewall, err := client.Get(ctx, resourceGroup, fwName)
	if err != nil {
		if utils.ResponseWasNotFound(firewall.Response) {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Error retrieving Azure Firewall %q (Resource Group %q): %+v", name, resourceGroup, err)
	}

	collection, _, exists := findArmFirewallApplicationRuleCollectionByName(&firewall, name)
	if !exists {
		d.SetId("")
		return nil
	}

	d.Set("name", collection.Name)
	d.Set("action", string(collection.AzureFirewallApplicationRuleCollectionPropertiesFormat.Action.Type))
	d.Set("priority", collection.AzureFirewallApplicationRuleCollectionPropertiesFormat.Priority)
	if rules := collection.AzureFirewallApplicationRuleCollectionPropertiesFormat.Rules; rules != nil {
		flattenedRules := flattenArmFirewallApplicationRules(rules)
		if err := d.Set("rule", flattenedRules); err != nil {
			return fmt.Errorf("Error setting `rule`: %+v", err)
		}
	}

	return nil
}

func resourceArmFirewallApplicationRuleCollectionDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).azureFirewallsClient
	ctx := meta.(*ArmClient).StopContext

	id, err := parseAzureResourceID(d.Id())
	if err != nil {
		return err
	}
	name := d.Get("name").(string)
	resourceGroup := id.ResourceGroup
	firewallName := id.Path["azureFirewalls"]

	azureRMLockByName(firewallName, azureFirewallResourceName)
	defer azureRMUnlockByName(firewallName, azureFirewallResourceName)

	firewall, err := client.Get(ctx, resourceGroup, firewallName)
	if err != nil {
		return fmt.Errorf("Error making Read request on Azure Firewall %q (Resource Group %q): %+v", firewallName, resourceGroup, err)
	}
	_, _, exists := findArmFirewallApplicationRuleCollectionByName(&firewall, name)
	if !exists {
		return nil
	}
	updatedCollections := removeArmFirewallApplicationRuleCollectionByName(&firewall, name)
	firewall.AzureFirewallPropertiesFormat.ApplicationRuleCollections = updatedCollections

	ipConfigs := fixArmFirewallIPConfiguration(&firewall)
	firewall.AzureFirewallPropertiesFormat.IPConfigurations = &ipConfigs

	future, err := client.CreateOrUpdate(ctx, resourceGroup, firewallName, firewall)
	if err != nil {
		return fmt.Errorf("Error deleting application rule collection %q from Azure Firewall %q (Resource Group %q): %+v", name, firewallName, resourceGroup, err)
	}

	err = future.WaitForCompletionRef(ctx, client.Client)
	if err != nil {
		return fmt.Errorf("Error waiting for deletion of application rule collection %q from Azure Firewall %q (Resource Group %q): %+v", name, firewallName, resourceGroup, err)
	}

	return nil
}

func expandArmFirewallApplicationRuleCollection(d *schema.ResourceData) network.AzureFirewallApplicationRuleCollection {
	name := d.Get("name").(string)
	action := network.AzureFirewallRCActionType(d.Get("action").(string))
	rules := expandArmFirewallApplicationRules(d)
	properties := network.AzureFirewallApplicationRuleCollectionPropertiesFormat{
		Action: &network.AzureFirewallRCAction{
			Type: action,
		},
		Priority: utils.Int32(int32(d.Get("priority").(int))),
		Rules:    &rules,
	}
	col := network.AzureFirewallApplicationRuleCollection{
		Name: &name,
		AzureFirewallApplicationRuleCollectionPropertiesFormat: &properties,
	}
	return col
}

func findArmFirewallApplicationRuleCollectionByName(firewall *network.AzureFirewall, name string) (*network.AzureFirewallApplicationRuleCollection, int, bool) {
	for i, collection := range *firewall.AzureFirewallPropertiesFormat.ApplicationRuleCollections {
		if collection.Name != nil && *collection.Name == name {
			return &collection, i, true
		}
	}
	return nil, -1, false
}

func removeArmFirewallApplicationRuleCollectionByName(firewall *network.AzureFirewall, name string) *[]network.AzureFirewallApplicationRuleCollection {
	collections := *firewall.AzureFirewallPropertiesFormat.ApplicationRuleCollections
	for i, collection := range collections {
		if collection.Name != nil && *collection.Name == name {
			collections = append(collections[:i], collections[i+1:]...)
			continue
		}
	}
	return &collections
}

func expandArmFirewallApplicationRules(d *schema.ResourceData) []network.AzureFirewallApplicationRule {
	nwRules := d.Get("rule").(*schema.Set).List()
	rules := make([]network.AzureFirewallApplicationRule, 0)

	for _, nwRule := range nwRules {
		rule := nwRule.(map[string]interface{})

		name := rule["name"].(string)
		description := rule["description"].(string)
		sourceAddresses := rule["source_addresses"].(*schema.Set)
		destinationAddresses := rule["destination_addresses"].(*schema.Set)
		destinationPorts := rule["destination_ports"].(*schema.Set)
		protocols := rule["protocols"].(*schema.Set)
		ruleToAdd := network.AzureFirewallApplicationRule{
			Name:                 &name,
			Description:          utils.String(description),
			SourceAddresses:      expandArmFirewallSet(sourceAddresses),
			DestinationAddresses: expandArmFirewallSet(destinationAddresses),
			DestinationPorts:     expandArmFirewallSet(destinationPorts),
		}
		nrProtocols := make([]network.AzureFirewallApplicationRuleProtocol, 0)
		for _, v := range protocols.List() {
			s := network.AzureFirewallApplicationRuleProtocol(v.(string))
			nrProtocols = append(nrProtocols, s)
		}
		ruleToAdd.Protocols = &nrProtocols
		rules = append(rules, ruleToAdd)
	}

	return rules
}

func flattenArmFirewallApplicationRules(rules *[]network.AzureFirewallApplicationRule) []map[string]interface{} {
	result := make([]map[string]interface{}, 0)
	if rules == nil {
		return result
	}
	for _, rule := range *rules {
		fwRule := make(map[string]interface{})
		if rule.Name != nil {
			fwRule["name"] = *rule.Name
		}
		if rule.Description != nil {
			fwRule["description"] = *rule.Description
		}
		if rule.SourceAddresses != nil {
			fwRule["source_addresses"] = sliceToSet(*rule.SourceAddresses)
		}
		if rule.DestinationAddresses != nil {
			fwRule["destination_addresses"] = sliceToSet(*rule.DestinationAddresses)
		}
		if rule.DestinationPorts != nil {
			fwRule["destination_ports"] = sliceToSet(*rule.DestinationPorts)
		}
		protocols := make([]string, 0)
		if rule.Protocols != nil {
			for _, protocol := range *rule.Protocols {
				protocols = append(protocols, string(protocol))
			}
		}
		fwRule["protocols"] = sliceToSet(protocols)
		result = append(result, fwRule)
	}
	return result
}
