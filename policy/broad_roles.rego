# Gate rule: no broad role grants sneak into governance code — not even yours,
# not even at 2 AM with a deadline.
#
# Hardened (federal track, companion to Custom 3): the original checked only
# role_definition_name for Owner/Contributor. That missed User Access
# Administrator and RBAC Administrator (both can grant any role, including
# Owner), and it could be bypassed entirely by granting a role by its GUID
# (role_definition_id) instead of its name. Both gaps are closed here.
# 800-53: AC-6, AC-6(5), AC-2(7)
package main

import rego.v1

broad_roles := {
	"Owner",
	"Contributor",
	"User Access Administrator",
	"Role Based Access Control Administrator",
}

# Built-in role GUIDs are identical in every tenant, so listing them is safe
# (no tenant- or subscription-specific values in code).
broad_role_ids := {
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635", # Owner
	"b24988ac-6180-42a0-ab88-20f7382dd24c", # Contributor
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", # User Access Administrator
	"f58310d9-a9f6-439a-9e8d-f62e7b41a168", # Role Based Access Control Administrator
}

# Role assignments being created or replaced (a pure delete removes access: not a violation).
role_grants contains rc if {
	some rc in input.resource_changes
	rc.type == "azurerm_role_assignment"
	rc.change.actions[_] != "delete"
}

# 1. Broad role granted by name.
deny contains msg if {
	some rc in role_grants
	rc.change.after.role_definition_name in broad_roles
	msg := sprintf("%s: %s at any scope is not a whitelist — use a granular role [800-53 AC-6]", [rc.address, rc.change.after.role_definition_name])
}

# 2. Broad role granted by ID (the bypass). When a grant uses the name, Terraform
# marks the ID "known after apply", so it is absent here and not double-counted.
deny contains msg if {
	some rc in role_grants
	id := rc.change.after.role_definition_id
	is_string(id)
	some guid in broad_role_ids
	endswith(lower(id), guid)
	msg := sprintf("%s: role_definition_id ends in %s, a broad built-in role — use a granular role [800-53 AC-6]", [rc.address, guid])
}