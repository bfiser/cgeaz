# Gate rule (federal track, Custom 1): storage accounts must require TLS 1.2+.
# Mirrors Azure Policy cge-storage-min-tls12 so a weak-TLS account is stopped
# in CI, before it ever reaches Azure. Defense in depth: gate + guardrail.
# 800-53: SC-8, SC-8(1)   CSF 2.0: PR.DS-02
package main

import rego.v1

# TLS versions considered too weak for data in transit.
weak_tls := {"TLS1_0", "TLS1_1"}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	rc.change.after.min_tls_version in weak_tls
	msg := sprintf("%s: storage accounts must require TLS 1.2 or higher (min_tls_version is %s) [800-53 SC-8]", [rc.address, rc.change.after.min_tls_version])
}