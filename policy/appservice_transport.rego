# Gate rule (federal track, Custom 2): App Service apps must enforce encrypted transport.
# Mirrors Azure Policy cge-appservice-secure-transport so a weak app is stopped in CI,
# before it reaches Azure. Defense in depth: gate (before deploy) + policy (after).
# 800-53: SC-8, SC-8(1), SC-23, IA-5(1)   CSF 2.0: PR.DS-02
#
# Note: Terraform uses the same names as Azure here ("1.2", not "TLS1_2"), and
# site_config is a block, so the plan stores it as a one-item list.
package main

import rego.v1

# Every Terraform resource type that creates an App Service site (web apps AND Function apps).
app_types := {
	"azurerm_linux_web_app",
	"azurerm_windows_web_app",
	"azurerm_linux_function_app",
	"azurerm_windows_function_app",
}

weak_app_tls := {"1.0", "1.1"}

# App Service changes that will exist after apply. A delete has after = null,
# so it is skipped (deleting an insecure app is not a violation).
app_changes contains rc if {
	some rc in input.resource_changes
	rc.type in app_types
	rc.change.after != null
}

# 1. Plain HTTP served. object.get treats a missing https_only as false (weak).
deny contains msg if {
	some rc in app_changes
	object.get(rc.change.after, "https_only", false) != true
	msg := sprintf("%s: App Service apps must be HTTPS-only (https_only is not true) [800-53 SC-8]", [rc.address])
}

# 2. App minimum TLS below 1.2.
deny contains msg if {
	some rc in app_changes
	some sc in rc.change.after.site_config
	sc.minimum_tls_version in weak_app_tls
	msg := sprintf("%s: App Service minimum TLS must be 1.2 or higher (minimum_tls_version is %s) [800-53 SC-8]", [rc.address, sc.minimum_tls_version])
}

# 3. SCM/Kudu deployment site minimum TLS below 1.2 (a separate, often-missed setting).
deny contains msg if {
	some rc in app_changes
	some sc in rc.change.after.site_config
	sc.scm_minimum_tls_version in weak_app_tls
	msg := sprintf("%s: SCM (deployment) site minimum TLS must be 1.2 or higher (scm_minimum_tls_version is %s) [800-53 SC-8]", [rc.address, sc.scm_minimum_tls_version])
}

# 4. Plain FTP allowed (credentials sent in clear text). FtpsOnly and Disabled pass.
deny contains msg if {
	some rc in app_changes
	some sc in rc.change.after.site_config
	sc.ftps_state == "AllAllowed"
	msg := sprintf("%s: plain FTP must be disabled (ftps_state is AllAllowed; use FtpsOnly or Disabled) [800-53 IA-5(1)]", [rc.address])
}