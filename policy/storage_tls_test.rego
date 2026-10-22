# Tests for the storage minimum-TLS gate rule. Run with: conftest verify -p policy
# Each fixture is a minimal fake Terraform plan with one storage account.
package main

import rego.v1

plan(tls) := {"resource_changes": [{
	"address": "azurerm_storage_account.example",
	"type": "azurerm_storage_account",
	"name": "example",
	"change": {"after": {
		"min_tls_version": tls,
		"allow_nested_items_to_be_public": false,
		"shared_access_key_enabled": false,
	}},
}]}

# Passing fixtures: modern TLS is allowed.
test_allows_tls12 if {
	count(deny) == 0 with input as plan("TLS1_2")
}

test_allows_tls13 if {
	count(deny) == 0 with input as plan("TLS1_3")
}

# Failing fixtures: each weak version is denied, and the message names the control.
test_denies_tls10 if {
	count(deny) == 1 with input as plan("TLS1_0")
}

test_denies_tls11 if {
	count(deny) == 1 with input as plan("TLS1_1")
}

test_message_cites_control if {
	some msg in deny with input as plan("TLS1_0")
	contains(msg, "SC-8")
}

# Deleting a storage account has no "after" state and must not trip the rule.
test_ignores_deletes if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "azurerm_storage_account.example",
		"type": "azurerm_storage_account",
		"name": "example",
		"change": {"after": null},
	}]}
}