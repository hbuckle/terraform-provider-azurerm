package azurerm

import (
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2018-08-01/network"
	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestAccAzureRMFirewallNatRuleCollection_basic(t *testing.T) {
	resourceName := "azurerm_firewall_nat_rule_collection.test"
	ri := acctest.RandInt()
	location := testLocation()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMFirewallDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAzureRMFirewallNatRuleCollection_basic(ri, location),
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMFirewallNatRuleCollectionExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", "acctestarc"),
					resource.TestCheckResourceAttr(resourceName, "priority", "100"),
					resource.TestCheckResourceAttr(resourceName, "action", "Snat"),
					resource.TestCheckResourceAttr(resourceName, "translated_address", "10.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, "translated_port", "443"),
					resource.TestCheckResourceAttr(resourceName, "rule.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule.0.name", "rule1"),
					resource.TestCheckResourceAttr(resourceName, "rule.0.source_addresses.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule.0.destination_addresses.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule.0.destination_ports.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule.0.protocols.#", "1"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAzureRMFirewallNatRuleCollection_updatedName(t *testing.T) {
	resourceName := "azurerm_firewall_nat_rule_collection.test"
	ri := acctest.RandInt()
	location := testLocation()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMFirewallDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAzureRMFirewallNatRuleCollection_basic(ri, location),
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMFirewallNatRuleCollectionExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", "acctestarc"),
					resource.TestCheckResourceAttr(resourceName, "priority", "100"),
					resource.TestCheckResourceAttr(resourceName, "action", "Snat"),
					resource.TestCheckResourceAttr(resourceName, "rule.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule.0.name", "rule1"),
				),
			},
			{
				Config: testAccAzureRMFirewallNatRuleCollection_updatedName(ri, location),
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMFirewallNatRuleCollectionExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", "acctestarc"),
					resource.TestCheckResourceAttr(resourceName, "priority", "100"),
					resource.TestCheckResourceAttr(resourceName, "action", "Snat"),
					resource.TestCheckResourceAttr(resourceName, "rule.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "rule.0.name", "rule2"),
				),
			},
		},
	})
}

func TestAccAzureRMFirewallNatRuleCollection_multipleRuleCollections(t *testing.T) {
	firstRule := "azurerm_firewall_nat_rule_collection.test"
	secondRule := "azurerm_firewall_nat_rule_collection.test_add"
	ri := acctest.RandInt()
	location := testLocation()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMFirewallDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAzureRMFirewallNatRuleCollection_basic(ri, location),
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMFirewallNatRuleCollectionExists(firstRule),
					resource.TestCheckResourceAttr(firstRule, "name", "acctestarc"),
					resource.TestCheckResourceAttr(firstRule, "priority", "100"),
					resource.TestCheckResourceAttr(firstRule, "action", "Snat"),
					resource.TestCheckResourceAttr(firstRule, "rule.#", "1"),
				),
			},
			{
				Config: testAccAzureRMFirewallNatRuleCollection_multiple(ri, location),
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMFirewallNatRuleCollectionExists(firstRule),
					resource.TestCheckResourceAttr(firstRule, "name", "acctestarc"),
					resource.TestCheckResourceAttr(firstRule, "priority", "100"),
					resource.TestCheckResourceAttr(firstRule, "action", "Snat"),
					resource.TestCheckResourceAttr(firstRule, "rule.#", "1"),
					testCheckAzureRMFirewallNatRuleCollectionExists(secondRule),
					resource.TestCheckResourceAttr(secondRule, "name", "acctestarc_add"),
					resource.TestCheckResourceAttr(secondRule, "priority", "200"),
					resource.TestCheckResourceAttr(secondRule, "action", "Dnat"),
					resource.TestCheckResourceAttr(secondRule, "rule.#", "1"),
				),
			},
			{
				Config: testAccAzureRMFirewallNatRuleCollection_basic(ri, location),
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMFirewallNatRuleCollectionExists(firstRule),
					resource.TestCheckResourceAttr(firstRule, "name", "acctestarc"),
					resource.TestCheckResourceAttr(firstRule, "priority", "100"),
					resource.TestCheckResourceAttr(firstRule, "action", "Snat"),
					resource.TestCheckResourceAttr(firstRule, "rule.#", "1"),
					testCheckAzureRMFirewallNatRuleCollectionDoesNotExist("azurerm_firewall.test", "acctestarc_add"),
				),
			},
		},
	})
}

func TestAccAzureRMFirewallNatRuleCollection_update(t *testing.T) {
	firstResourceName := "azurerm_firewall_nat_rule_collection.test"
	secondResourceName := "azurerm_firewall_nat_rule_collection.test_add"
	ri := acctest.RandInt()
	location := testLocation()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMFirewallDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAzureRMFirewallNatRuleCollection_multiple(ri, location),
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMFirewallNatRuleCollectionExists(firstResourceName),
					resource.TestCheckResourceAttr(firstResourceName, "name", "acctestarc"),
					resource.TestCheckResourceAttr(firstResourceName, "priority", "100"),
					resource.TestCheckResourceAttr(firstResourceName, "action", "Snat"),
					resource.TestCheckResourceAttr(firstResourceName, "rule.#", "1"),
					testCheckAzureRMFirewallNatRuleCollectionExists(secondResourceName),
					resource.TestCheckResourceAttr(secondResourceName, "name", "acctestarc_add"),
					resource.TestCheckResourceAttr(secondResourceName, "priority", "200"),
					resource.TestCheckResourceAttr(secondResourceName, "action", "Dnat"),
					resource.TestCheckResourceAttr(secondResourceName, "rule.#", "1"),
				),
			},
			{
				Config: testAccAzureRMFirewallNatRuleCollection_multipleUpdate(ri, location),
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMFirewallNatRuleCollectionExists(firstResourceName),
					resource.TestCheckResourceAttr(firstResourceName, "name", "acctestarc"),
					resource.TestCheckResourceAttr(firstResourceName, "priority", "300"),
					resource.TestCheckResourceAttr(firstResourceName, "action", "Dnat"),
					resource.TestCheckResourceAttr(firstResourceName, "rule.#", "1"),
					testCheckAzureRMFirewallNatRuleCollectionExists(secondResourceName),
					resource.TestCheckResourceAttr(secondResourceName, "name", "acctestarc_add"),
					resource.TestCheckResourceAttr(secondResourceName, "priority", "400"),
					resource.TestCheckResourceAttr(secondResourceName, "action", "Snat"),
					resource.TestCheckResourceAttr(secondResourceName, "rule.#", "1"),
				),
			},
		},
	})
}

func TestAccAzureRMFirewallNatRuleCollection_disappears(t *testing.T) {
	resourceName := "azurerm_firewall_nat_rule_collection.test"
	ri := acctest.RandInt()
	location := testLocation()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMFirewallDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAzureRMFirewallNatRuleCollection_basic(ri, location),
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMFirewallNatRuleCollectionExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", "acctestarc"),
					resource.TestCheckResourceAttr(resourceName, "priority", "100"),
					resource.TestCheckResourceAttr(resourceName, "action", "Snat"),
					resource.TestCheckResourceAttr(resourceName, "rule.#", "1"),
					testCheckAzureRMFirewallNatRuleCollectionDisappears(resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccAzureRMFirewallNatRuleCollection_multipleRules(t *testing.T) {
	resourceName := "azurerm_firewall_nat_rule_collection.test"
	ri := acctest.RandInt()
	location := testLocation()

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMFirewallDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAzureRMFirewallNatRuleCollection_basic(ri, location),
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMFirewallNatRuleCollectionExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", "acctestarc"),
					resource.TestCheckResourceAttr(resourceName, "priority", "100"),
					resource.TestCheckResourceAttr(resourceName, "action", "Snat"),
					resource.TestCheckResourceAttr(resourceName, "rule.#", "1"),
				),
			},
			{
				Config: testAccAzureRMFirewallNatRuleCollection_multipleRules(ri, location),
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMFirewallNatRuleCollectionExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", "acctestarc"),
					resource.TestCheckResourceAttr(resourceName, "priority", "100"),
					resource.TestCheckResourceAttr(resourceName, "action", "Snat"),
					resource.TestCheckResourceAttr(resourceName, "rule.#", "2"),
				),
			},
			{
				Config: testAccAzureRMFirewallNatRuleCollection_basic(ri, location),
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMFirewallNatRuleCollectionExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", "acctestarc"),
					resource.TestCheckResourceAttr(resourceName, "priority", "100"),
					resource.TestCheckResourceAttr(resourceName, "action", "Snat"),
					resource.TestCheckResourceAttr(resourceName, "rule.#", "1"),
				),
			},
		},
	})
}

func testCheckAzureRMFirewallNatRuleCollectionExists(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Ensure we have enough information in state to look up in API
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Not found: %s", resourceName)
		}

		name := rs.Primary.Attributes["name"]
		firewallName := rs.Primary.Attributes["azure_firewall_name"]
		resourceGroup := rs.Primary.Attributes["resource_group_name"]

		client := testAccProvider.Meta().(*ArmClient).azureFirewallsClient
		ctx := testAccProvider.Meta().(*ArmClient).StopContext
		read, err := client.Get(ctx, resourceGroup, firewallName)
		if err != nil {
			return err
		}

		found := false
		for _, collection := range *read.AzureFirewallPropertiesFormat.NatRuleCollections {
			if *collection.Name == name {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("Expected NAT Rule Collection %q (Firewall %q / Resource Group %q) to exist but it didn't", name, firewallName, resourceGroup)
		}

		return nil
	}
}

func testCheckAzureRMFirewallNatRuleCollectionDoesNotExist(resourceName string, collectionName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Ensure we have enough information in state to look up in API
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Not found: %s", resourceName)
		}

		firewallName := rs.Primary.Attributes["name"]
		resourceGroup := rs.Primary.Attributes["resource_group_name"]

		client := testAccProvider.Meta().(*ArmClient).azureFirewallsClient
		ctx := testAccProvider.Meta().(*ArmClient).StopContext
		read, err := client.Get(ctx, resourceGroup, firewallName)
		if err != nil {
			return err
		}

		for _, collection := range *read.AzureFirewallPropertiesFormat.NatRuleCollections {
			if *collection.Name == collectionName {
				return fmt.Errorf("NAT Rule Collection %q exists in Firewall %q: %+v", collectionName, firewallName, collection)
			}
		}

		return nil
	}
}

func testCheckAzureRMFirewallNatRuleCollectionDisappears(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Ensure we have enough information in state to look up in API
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Not found: %s", resourceName)
		}

		name := rs.Primary.Attributes["name"]
		firewallName := rs.Primary.Attributes["azure_firewall_name"]
		resourceGroup := rs.Primary.Attributes["resource_group_name"]

		client := testAccProvider.Meta().(*ArmClient).azureFirewallsClient
		ctx := testAccProvider.Meta().(*ArmClient).StopContext
		read, err := client.Get(ctx, resourceGroup, firewallName)
		if err != nil {
			return err
		}

		rules := make([]network.AzureFirewallNatRuleCollection, 0)
		for _, collection := range *read.AzureFirewallPropertiesFormat.NatRuleCollections {
			if *collection.Name != name {
				rules = append(rules, collection)
			}
		}

		read.AzureFirewallPropertiesFormat.NatRuleCollections = &rules
		future, err := client.CreateOrUpdate(ctx, resourceGroup, firewallName, read)
		if err != nil {
			return fmt.Errorf("Error removing NAT Rule Collection from Firewall: %+v", err)
		}

		err = future.WaitForCompletionRef(ctx, client.Client)
		if err != nil {
			return fmt.Errorf("Error waiting for the removal of NAT Rule Collection from Firewall: %+v", err)
		}

		_, err = client.Get(ctx, resourceGroup, firewallName)
		return err
	}
}

func testAccAzureRMFirewallNatRuleCollection_basic(rInt int, location string) string {
	template := testAccAzureRMFirewall_basic(rInt, location)
	return fmt.Sprintf(`
%s

resource "azurerm_firewall_nat_rule_collection" "test" {
  name                = "acctestarc"
  azure_firewall_name = "${azurerm_firewall.test.name}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  priority            = 100
  action              = "Snat"

  rule {
    name = "rule1"

    source_addresses = [
      "1.1.1.1",
    ]

    destination_addresses = [
      "2.2.2.2",
    ]

    destination_ports = [
      "8080",
    ]

    protocols = [
      "TCP",
    ]

    translated_address = "10.0.0.1"

    translated_port = "443"
  }
}
`, template)
}

func testAccAzureRMFirewallNatRuleCollection_updatedName(rInt int, location string) string {
	template := testAccAzureRMFirewall_basic(rInt, location)
	return fmt.Sprintf(`
%s

resource "azurerm_firewall_nat_rule_collection" "test" {
  name                = "acctestarc"
  azure_firewall_name = "${azurerm_firewall.test.name}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  priority            = 100
  action              = "Snat"

  rule {
    name = "rule2"

    source_addresses = [
      "1.1.1.1",
    ]

    destination_addresses = [
      "2.2.2.2",
    ]

    destination_ports = [
      "8080",
    ]

    protocols = [
      "TCP",
    ]

    translated_address = "10.0.0.1"

    translated_port = "443"
  }
}
`, template)
}

func testAccAzureRMFirewallNatRuleCollection_multiple(rInt int, location string) string {
	template := testAccAzureRMFirewall_basic(rInt, location)
	return fmt.Sprintf(`
%s

resource "azurerm_firewall_nat_rule_collection" "test" {
  name                = "acctestarc"
  azure_firewall_name = "${azurerm_firewall.test.name}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  priority            = 100
  action              = "Snat"

  rule {
    name = "rule1"

    source_addresses = [
      "1.1.1.1",
    ]

    destination_addresses = [
      "2.2.2.2",
    ]

    destination_ports = [
      "8080",
    ]

    protocols = [
      "TCP",
    ]

    translated_address = "10.0.0.1"

    translated_port = "443"
  }
}

resource "azurerm_firewall_nat_rule_collection" "test_add" {
  name                = "acctestarc_add"
  azure_firewall_name = "${azurerm_firewall.test.name}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  priority            = 200
  action              = "Dnat"

  rule {
    name = "rule1add"

    source_addresses = [
      "3.3.3.3",
    ]

    destination_addresses = [
      "4.4.4.4",
    ]

    destination_ports = [
      "5050",
    ]

    protocols = [
      "UDP",
    ]

    translated_address = "192.168.0.5"

    translated_port = "9001"
  }
}
`, template)
}

func testAccAzureRMFirewallNatRuleCollection_multipleUpdate(rInt int, location string) string {
	template := testAccAzureRMFirewall_basic(rInt, location)
	return fmt.Sprintf(`
%s

resource "azurerm_firewall_nat_rule_collection" "test" {
  name                = "acctestarc"
  azure_firewall_name = "${azurerm_firewall.test.name}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  priority            = 300
  action              = "Dnat"

  rule {
    name = "rule1"

    source_addresses = [
      "1.1.1.1",
    ]

    destination_addresses = [
      "2.2.2.2",
    ]

    destination_ports = [
      "8080",
    ]

    protocols = [
      "TCP",
    ]

    translated_address = "10.0.0.1"

    translated_port = "443"
  }
}

resource "azurerm_firewall_nat_rule_collection" "test_add" {
  name                = "acctestarc_add"
  azure_firewall_name = "${azurerm_firewall.test.name}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  priority            = 400
  action              = "Snat"

  rule {
    name = "rule1add"

    source_addresses = [
      "3.3.3.3",
    ]

    destination_addresses = [
      "4.4.4.4",
    ]

    destination_ports = [
      "5050",
    ]

    protocols = [
      "UDP",
    ]

    translated_address = "192.168.0.5"

    translated_port = "9001"
  }
}
`, template)
}

func testAccAzureRMFirewallNatRuleCollection_multipleRules(rInt int, location string) string {
	template := testAccAzureRMFirewall_basic(rInt, location)
	return fmt.Sprintf(`
%s

resource "azurerm_firewall_nat_rule_collection" "test" {
  name                = "acctestarc"
  azure_firewall_name = "${azurerm_firewall.test.name}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  priority            = 100
  action              = "Snat"

  rule {
    name = "rule1"

    source_addresses = [
      "8.8.8.8",
    ]

    destination_addresses = [
      "8.8.4.4",
    ]

    destination_ports = [
      "443",
    ]

    protocols = [
      "TCP",
    ]

    translated_address = "10.1.1.1"

    translated_port = "80"
	}
	
	rule {
    name = "rule2"

    source_addresses = [
      "3.3.3.3",
    ]

    destination_addresses = [
      "4.4.4.4",
    ]

    destination_ports = [
      "5050",
    ]

    protocols = [
      "UDP",
    ]

    translated_address = "192.168.0.5"

    translated_port = "9001"
  }
}
`, template)
}
