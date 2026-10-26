# Tests for the NSG management-port gate rule. Run with: conftest verify -p policy
package main

import rego.v1

# A safe baseline rule; each failing fixture changes one thing.
nsg_safe_rule := {
	"name": "allow-https",
	"access": "Allow",
	"direction": "Inbound",
	"source_address_prefix": "Internet",
	"source_address_prefixes": [],
	"destination_port_range": "443",
	"destination_port_ranges": [],
}

# Fixture: one NSG with inline rules (named nsg_plan: helpers share package main).
nsg_plan(rules) := {"resource_changes": [{
	"address": "azurerm_network_security_group.example",
	"type": "azurerm_network_security_group",
	"change": {"actions": ["create"], "after": {"security_rule": rules}},
}]}

# Fixture: one standalone rule resource.
nsg_rule_plan(rule) := {"resource_changes": [{
	"address": "azurerm_network_security_rule.example",
	"type": "azurerm_network_security_rule",
	"change": {"actions": ["create"], "after": rule},
}]}

# Passing fixtures
test_allows_https_from_internet if {
	count(deny) == 0 with input as nsg_plan([nsg_safe_rule])
}

test_allows_ssh_from_private_range if {
	count(deny) == 0 with input as nsg_plan([object.union(nsg_safe_rule, {"destination_port_range": "22", "source_address_prefix": "10.0.0.0/8"})])
}

test_allows_ssh_deny_rule if {
	count(deny) == 0 with input as nsg_plan([object.union(nsg_safe_rule, {"destination_port_range": "22", "access": "Deny"})])
}

test_allows_outbound_ssh if {
	count(deny) == 0 with input as nsg_plan([object.union(nsg_safe_rule, {"destination_port_range": "22", "direction": "Outbound"})])
}

test_allows_range_without_mgmt_ports if {
	count(deny) == 0 with input as nsg_plan([object.union(nsg_safe_rule, {"destination_port_range": "8000-8080"})])
}

# Failing fixtures
test_denies_ssh_from_internet if {
	count(deny) == 1 with input as nsg_plan([object.union(nsg_safe_rule, {"destination_port_range": "22"})])
}

test_denies_rdp_from_star if {
	count(deny) == 1 with input as nsg_plan([object.union(nsg_safe_rule, {"destination_port_range": "3389", "source_address_prefix": "*"})])
}

# The seed estate's exact shape: ports as a LIST, source "Internet". One rule, two ports = two findings.
test_denies_seed_shape_port_list if {
	seed := object.union(nsg_safe_rule, {"destination_port_range": "", "destination_port_ranges": ["22", "3389"]})
	count(deny) == 2 with input as nsg_plan([seed])
}

test_denies_any_port if {
	count(deny) == 2 with input as nsg_plan([object.union(nsg_safe_rule, {"destination_port_range": "*"})])
}

# Ranges: the case the Azure Policy rule cannot evaluate
test_denies_range_containing_ssh if {
	count(deny) == 1 with input as nsg_plan([object.union(nsg_safe_rule, {"destination_port_range": "20-30"})])
}

test_denies_source_list_with_internet if {
	r := object.union(nsg_safe_rule, {"destination_port_range": "22", "source_address_prefix": "", "source_address_prefixes": ["10.0.0.0/8", "0.0.0.0/0"]})
	count(deny) == 1 with input as nsg_plan([r])
}

test_denies_standalone_rule_resource if {
	count(deny) == 1 with input as nsg_rule_plan(object.union(nsg_safe_rule, {"destination_port_range": "3389"}))
}

test_ignores_nsg_delete if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "azurerm_network_security_group.example",
		"type": "azurerm_network_security_group",
		"change": {"actions": ["delete"], "after": null},
	}]}
}

test_message_cites_control if {
	some msg in deny with input as nsg_plan([object.union(nsg_safe_rule, {"destination_port_range": "22"})])
	contains(msg, "SC-7")
}