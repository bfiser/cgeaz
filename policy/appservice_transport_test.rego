# Tests for the App Service transport gate rule. Run with: conftest verify -p policy
# Each fixture is a minimal fake Terraform plan with one Function app.
package main

import rego.v1

# Named app_plan (not plan) so it does not collide with storage_tls_test.rego's
# plan(tls) helper: every file here shares one package, so names must be unique.
app_plan(after) := {"resource_changes": [{
	"address": "azurerm_linux_function_app.example",
	"type": "azurerm_linux_function_app",
	"change": {"actions": ["update"], "after": after},
}]}

# A fully hardened app: the passing baseline every failing fixture changes one thing in.
hardened := {
	"https_only": true,
	"site_config": [{"minimum_tls_version": "1.2", "scm_minimum_tls_version": "1.2", "ftps_state": "Disabled"}],
}

# Replace one site_config setting in the hardened baseline.
with_site(field, value) := object.union(hardened, {"site_config": [object.union(hardened.site_config[0], {field: value})]})

# Passing fixtures
test_allows_hardened_app if {
	count(deny) == 0 with input as app_plan(hardened)
}

test_allows_ftps_only if {
	count(deny) == 0 with input as app_plan(with_site("ftps_state", "FtpsOnly"))
}

test_allows_tls13 if {
	count(deny) == 0 with input as app_plan(with_site("minimum_tls_version", "1.3"))
}

# Failing fixtures: each weakness on its own is exactly one denial
test_denies_http if {
	count(deny) == 1 with input as app_plan(object.union(hardened, {"https_only": false}))
}

test_denies_missing_https_only if {
	count(deny) == 1 with input as app_plan(object.remove(hardened, ["https_only"]))
}

test_denies_weak_app_tls if {
	count(deny) == 1 with input as app_plan(with_site("minimum_tls_version", "1.0"))
}

test_denies_weak_scm_tls if {
	count(deny) == 1 with input as app_plan(with_site("scm_minimum_tls_version", "1.1"))
}

test_denies_plain_ftp if {
	count(deny) == 1 with input as app_plan(with_site("ftps_state", "AllAllowed"))
}

# The seed estate's app (HTTP, TLS 1.0, plain FTP) fails three separate ways
test_seed_like_app_fails_three_ways if {
	seed := {
		"https_only": false,
		"site_config": [{"minimum_tls_version": "1.0", "scm_minimum_tls_version": "1.2", "ftps_state": "AllAllowed"}],
	}
	count(deny) == 3 with input as app_plan(seed)
}

# Deleting an app is not a violation
test_ignores_delete if {
	count(deny) == 0 with input as {"resource_changes": [{
		"address": "azurerm_linux_function_app.example",
		"type": "azurerm_linux_function_app",
		"change": {"actions": ["delete"], "after": null},
	}]}
}

test_message_cites_control if {
	some msg in deny with input as app_plan(object.union(hardened, {"https_only": false}))
	contains(msg, "SC-8")
}