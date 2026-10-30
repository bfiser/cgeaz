# --- The collector Function App: timer-triggered Python, managed identity, zero keys. ---
# One app for collectors, a separate app (stage 04) for reporting: the Function App is
# the identity boundary, and no identity both writes evidence and generates reports.

# Internal plumbing storage for the Functions runtime (NOT the evidence store —
# that account has shared keys disabled; this one is the app's own scratch space).
resource "azurerm_storage_account" "func_internal" {
  name                            = "stgrcfunc${random_string.suffix.result}"
  resource_group_name             = local.evidence_rg
  location                        = var.functions_location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  tags                            = local.common_tags
}

resource "azurerm_service_plan" "collectors" {
  name                = "asp-grc-collectors-${var.environment}"
  resource_group_name = local.evidence_rg
  location            = var.functions_location
  os_type             = "Linux"
  sku_name            = "Y1" # Consumption: pay per execution. Pennies.
  tags                = local.common_tags
}

resource "azurerm_linux_function_app" "collectors" {
  name                       = "func-grc-collectors-${random_string.suffix.result}"
  resource_group_name        = local.evidence_rg
  location                   = var.functions_location
  service_plan_id            = azurerm_service_plan.collectors.id
  storage_account_name       = azurerm_storage_account.func_internal.name
  storage_account_access_key = azurerm_storage_account.func_internal.primary_access_key

  identity {
    type = "SystemAssigned"
  }

  # Encrypted transport (Custom 2; 800-53 SC-8): redirect plain HTTP to HTTPS.
  https_only = true

  site_config {
    application_stack {
      python_version = "3.11"
    }

    # Declared explicitly, even though they match today's defaults, so the code
    # itself is the evidence and a future provider default change can't weaken them.
    minimum_tls_version     = "1.2"      # app endpoint (800-53 SC-8)
    scm_minimum_tls_version = "1.2"      # SCM/Kudu deployment endpoint (SC-8)
    ftps_state              = "Disabled" # no FTP at all; deploys use zip/OIDC (IA-5(1))
  }

  app_settings = {
    "COSMOS_ENDPOINT"                = azurerm_cosmosdb_account.evidence.endpoint
    "COSMOS_DATABASE"                = azurerm_cosmosdb_sql_database.grc.name
    "SUBSCRIPTION_ID"                = local.subscription
    "ROOT_MANAGEMENT_GROUP"          = local.root_mg_name # where the role-assignment walk starts
    "SCM_DO_BUILD_DURING_DEPLOYMENT" = "true"
    # ENABLE_ORYX_BUILD intentionally omitted: `az functionapp deployment source config-zip
    # --build-remote` deletes it on every deploy (it's redundant with SCM_DO_BUILD_DURING_DEPLOYMENT),
    # so declaring it here caused recurring drift. Found 2026-10-28 (CLI: "Removing ENABLE_ORYX_BUILD").
  }

  tags = local.common_tags
}

# --- The collector identity's whitelist: read posture, write evidence. Nothing else. ---

# Security Reader at the subscription: read Defender assessments, change nothing.
resource "azurerm_role_assignment" "collector_security_reader" {
  scope                = "/subscriptions/${local.subscription}"
  role_definition_name = "Security Reader"
  principal_id         = azurerm_linux_function_app.collectors.identity[0].principal_id
}

# Cosmos data-plane write. "Cosmos DB Built-in Data Contributor" (00000000-0000-0000-0000-000000000002)
# is a Cosmos-native data-plane role, not an ARM role — control plane vs data plane, again.
resource "azurerm_cosmosdb_sql_role_assignment" "collector_cosmos_write" {
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  role_definition_id  = "${azurerm_cosmosdb_account.evidence.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = azurerm_linux_function_app.collectors.identity[0].principal_id
  scope               = azurerm_cosmosdb_account.evidence.id
}

# --- Role-assignment snapshots (federal track: AC-2, AC-2(3), AC-6) ---
# Why: Custom 3 (Azure Policy) proved it cannot see grants made AT a management
# group, including the most powerful ones (Owner at mg-grc, CI Contributor at
# mg-grc). This collector walks the whole hierarchy daily and stores one record
# per role assignment per day, so access reviews have history.

locals {
  root_mg_id   = data.terraform_remote_state.foundation.outputs.root_management_group_id
  root_mg_name = data.terraform_remote_state.foundation.outputs.root_management_group_name
}

# Own container. Partition key = the subscription for anything at or below a
# subscription; "mg:<name>" for management-group grants. Access reviews query
# one subscription at a time, and MG grants form their own small partition.
resource "azurerm_cosmosdb_sql_container" "role_assignments" {
  name                = "roleAssignments"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/scopeRoot"]
}

# Least privilege: a custom role with exactly the four read actions the collector
# uses. Built-in Reader would grant */read on every resource in the hierarchy.
resource "azurerm_role_definition" "role_assignment_reader" {
  name        = "GRC Role Assignment Reader"
  scope       = local.root_mg_id
  description = "Read-only: list management groups and role assignments/definitions for access-review snapshots. Nothing else."

  permissions {
    actions = [
      "Microsoft.Management/managementGroups/read",             # the root group itself
      "Microsoft.Management/managementGroups/descendants/read", # discover child groups + subscriptions (no hardcoded list)
      "Microsoft.Authorization/roleAssignments/read",           # who has what, where
      "Microsoft.Authorization/roleDefinitions/read",           # resolve role GUIDs to names
    ]
    not_actions = []
  }

  assignable_scopes = [local.root_mg_id] # can only ever be granted inside this hierarchy
}

# Granted at the root, so it inherits to every management group and subscription below.
resource "azurerm_role_assignment" "collector_role_reader" {
  scope              = local.root_mg_id
  role_definition_id = azurerm_role_definition.role_assignment_reader.role_definition_resource_id
  principal_id       = azurerm_linux_function_app.collectors.identity[0].principal_id
}

# --- Policy findings into the POA&M (federal track: CA-5, CA-7) ---
# Security Reader cannot query Azure Policy states (verified 2026-10-30). One purpose per
# role, same pattern as the role-assignment reader: exactly two actions, only in mg-grc.
resource "azurerm_role_definition" "policy_state_reader" {
  name        = "GRC Policy State Reader"
  scope       = local.root_mg_id
  description = "Read-only: query Azure Policy compliance states and read policy definitions (display name + 800-53 metadata) for the POA&M."

  permissions {
    actions = [
      "Microsoft.PolicyInsights/policyStates/queryResults/action", # the query is a POST, hence /action; it only reads
      "Microsoft.Authorization/policyDefinitions/read",            # display names + nist_800_53 metadata
    ]
    not_actions = []
  }

  assignable_scopes = [local.root_mg_id]
}

resource "azurerm_role_assignment" "collector_policy_state_reader" {
  scope              = local.root_mg_id
  role_definition_id = azurerm_role_definition.policy_state_reader.role_definition_resource_id
  principal_id       = azurerm_linux_function_app.collectors.identity[0].principal_id
}