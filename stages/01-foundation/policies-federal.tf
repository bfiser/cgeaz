# --- Custom 1: Storage accounts must declare TLS 1.2 or higher ---
# 800-53: SC-8, SC-8(1) (transmission confidentiality and integrity)
# CSF 2.0: PR.DS-02 (data in transit)
# Why custom: Azure retired TLS 1.0/1.1 for storage on 2026-02-03 and now
# enforces 1.2 at the service; new accounts are upgraded automatically.
# During the first live run of seed-estate.sh (2026-10-22), a TLS1_0 request
# came back TLS1_2; upstream removed the claim afterward (VALIDATION-LOG F22).
# But accounts created before the retirement can still DECLARE TLS1_0
# (stgrcseed19778 does). Defender no longer assesses it; an auditor reading
# configuration would. This control keeps declared configuration truthful
# and catches regressions.
#
# BLAST RADIUS
#   Audit (default): changes nothing; non-compliant accounts are reported.
#   Deny: blocks creating or updating any storage account that declares
#     minimum TLS below 1.2. Existing non-compliant accounts (today: the
#     hand-built seed account) cannot be updated at all until fixed.
#   Could break: little at the service level, since Azure already enforces
#     TLS 1.2. The real risk is operational: a Deny would block unrelated
#     updates to a non-compliant account until its declared TLS is raised.
#   Rollback: set storage_tls_policy_effect back to "Audit" (one-line PR).

resource "azurerm_policy_definition" "storage_min_tls" {
  name         = "cge-storage-min-tls12" # stable ID in Azure; the "cge-" prefix marks it as ours
  display_name = "Storage accounts must require TLS 1.2 or higher"
  policy_type  = "Custom"
  mode         = "Indexed" # evaluate only resource types that support tags and location (storage accounts do)

  # Defined at the sandbox management group, not a subscription, so any
  # subscription added under mg-grc-sandbox can use it with no code change.
  management_group_id = azurerm_management_group.sandbox.id

  # Framework mapping stored on the definition itself, so it is visible in the
  # portal and in exports, and travels with the policy.
  metadata = jsonencode({
    category    = "Storage"
    nist_800_53 = ["SC-8", "SC-8(1)"]
    csf_2_0     = ["PR.DS-02"]
  })

  # The effect is a parameter, not hardcoded, so escalating Audit -> Deny is a
  # one-value change made through a reviewed PR, never an edit to the rule.
  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit" # new controls start in Audit: measure first, block once the estate is clean
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [ # ALL of these must be true for the policy to fire
        { field = "type", equals = "Microsoft.Storage/storageAccounts" },
        {
          anyOf = [ # ANY of these makes the account non-compliant
            # No TLS setting at all: older accounts default to TLS 1.0, so missing counts as weak.
            { field = "Microsoft.Storage/storageAccounts/minimumTlsVersion", exists = "false" },
            # Set, but to anything other than a modern version. Listing TLS1_3 means this
            # rule will not need changing as TLS 1.3 becomes available.
            { field = "Microsoft.Storage/storageAccounts/minimumTlsVersion", notIn = ["TLS1_2", "TLS1_3"] }
          ]
        }
      ]
    }
    then = { effect = "[parameters('effect')]" } # whatever effect the assignment passes in
  })
}