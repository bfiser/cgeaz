# Tests for the broad-role gate rule. Run with: conftest verify -p policy
# Each fixture is a minimal fake Terraform plan with one role assignment.
package main

import rego.v1

# Named rbac_plan so it does not collide with other test helpers (plan, app_plan):
# every file in policy/ shares package main.
rbac_plan(after) := rbac_plan_actions(["create"], after)

rbac_plan_actions(actions, after) := {"resource_changes": [{
	"address": "azurerm_role_assignment.example",
	"type": "azurerm_role_assignment",
	"change": {"actions": actions, "after": after},
}]}

sub_role(guid) := sprintf("/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/%s", [guid])

# Passing fixtures: granular roles, by name or by ID
test_allows_granular_role_by_name if {
	count(deny) == 0 with input as rbac_plan({"role_definition_name": "Security Reader"})
}

test_allows_granular_role_by_id if {
	count(deny) == 0 with input as rbac_plan({"role_definition_id": sub_role("39bc4728-0917-49c7-9d2c-d95423bc2eb4")})
}

# "Storage Account Contributor" contains the word Contributor but is a different, scoped role.
test_allows_similarly_named_role if {
	count(deny) == 0 with input as rbac_plan({"role_definition_name": "Storage Account Contributor"})
}

# Failing fixtures by name (the original two, plus the two the original missed)
test_denies_owner_by_name if {
	count(deny) == 1 with input as rbac_plan({"role_definition_name": "Owner"})
}

test_denies_contributor_by_name if {
	count(deny) == 1 with input as rbac_plan({"role_definition_name": "Contributor"})
}

test_denies_uaa_by_name if {
	count(deny) == 1 with input as rbac_plan({"role_definition_name": "User Access Administrator"})
}

test_denies_rbac_admin_by_name if {
	count(deny) == 1 with input as rbac_plan({"role_definition_name": "Role Based Access Control Administrator"})
}

# The bypass: same roles granted by GUID
test_denies_owner_by_id if {
	count(deny) == 1 with input as rbac_plan({"role_definition_id": sub_role("8e3af657-a8ff-443c-a75c-2fe8c4bcb635")})
}

test_denies_contributor_by_id_any_case if {
	count(deny) == 1 with input as rbac_plan({"role_definition_id": upper(sub_role("b24988ac-6180-42a0-ab88-20f7382dd24c"))})
}

# Replacing an Owner grant re-creates it, so it is still a grant
test_denies_owner_on_replace if {
	count(deny) == 1 with input as rbac_plan_actions(["delete", "create"], {"role_definition_name": "Owner"})
}

# Removing access is never a violation
test_ignores_delete if {
	count(deny) == 0 with input as rbac_plan_actions(["delete"], null)
}

test_message_cites_control if {
	some msg in deny with input as rbac_plan({"role_definition_name": "Owner"})
	contains(msg, "AC-6")
}