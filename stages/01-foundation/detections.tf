# Detection as code (federal track: AU-2, AU-6, AU-12, AC-2, CM-3, SI-4).
#
# Findings that shaped this file (2026-10-30 .. 11-02):
#   1. The subscription Activity Log routing (ds-activity-to-law) was hand-made in Lab 2 and
#      not in Terraform: if deleted, every detection here goes silently blind. -> imported below.
#   2. Only the SUBSCRIPTION log was exported. Policy lives at management-group scope, so
#      10+ days of changes to my own policies never reached the workspace. -> MG export below.
#   3. The "KQL tripwire" the pipeline described (drift.yml: "Detector 2") was never deployed
#      anywhere. -> governance_tamper rule below, plus two federal-track detections.
# Queries live in detections/*.kql and are rendered with templatefile(), so the query tested
# by hand (scripts/render_kql.py) is exactly the query each alert rule runs.

# --- 1. Subscription Activity Log -> GRC workspace (adopted, not recreated) ---

import {
  to = azurerm_monitor_diagnostic_setting.subscription_activity
  id = "${data.azurerm_subscription.current.id}|ds-activity-to-law"
}

resource "azurerm_monitor_diagnostic_setting" "subscription_activity" {
  name                       = "ds-activity-to-law"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.grc.id

  # Imported unchanged (2026-11-02), then narrowed (2026-11-03): Administrative + Policy now come ONLY
  # from the MG export below, which also carries every subscription under mg-grc. Exporting them here
  # too stored each subscription event twice (dup ratio 1.0 before the MG export, 2.0 after).
  # One source per category. Residual risk: if the MG export is removed, subscription admin logs stop;
  # it is Terraform-managed, so the daily drift run detects that (defense in depth).
  enabled_log { category = "Security" }
  enabled_log { category = "Alert" }
}

# --- 2. Management-group Activity Log -> same workspace ---
# One setting on the TOP management group covers nested groups (mg-grc-sandbox).
# azurerm's diagnostic-setting resource uses an API version that management groups reject
# (verified: BadRequest on 2021-05-01-preview), so this uses azapi with the documented
# management-group API version (2020-01-01-preview), the same pattern stage 02 uses for
# what azurerm can't reach.

resource "azapi_resource" "mg_activity_log" {
  type      = "Microsoft.Insights/diagnosticSettings@2020-01-01-preview"
  name      = "ds-mg-activity-to-law"
  parent_id = azurerm_management_group.grc.id

  schema_validation_enabled = false # the management-group variant isn't in azapi's embedded schema

  body = {
    properties = {
      workspaceId = azurerm_log_analytics_workspace.grc.id
      logs = [
        { category = "Administrative", enabled = true }, # policy, role, and other control-plane writes
        { category = "Policy", enabled = true },         # policy engine events at MG scope
      ]
    }
  }
}

# --- 3. Scheduled query rules ---

locals {
  kql_vars = {
    timezone    = var.business_timezone
    start_hour  = var.business_hours_start
    end_hour    = var.business_hours_end
    home_issuer = "https://sts.windows.net/${data.azurerm_subscription.current.tenant_id}/"
  }

  detections = {
    offhours_human_changes = {
      name        = "cge-offhours-human-changes"
      display     = "Off-hours human changes and credential reads"
      description = "Human (email/UPN) writes, deletes, and key listing outside business hours. AU-6, AC-2(12)."
      frequency   = "PT1H"
      window      = "PT2H"
      severity    = 2
      controls    = "AU-6 AC-2(12)"
    }
    external_identity_activity = {
      name        = "cge-external-identity-activity"
      display     = "Activity by external identities (daily digest)"
      description = "Any activity authenticated by an identity provider other than this tenant (guests, B2B). AC-2, AC-2(12)."
      frequency   = "P1D"
      window      = "P1D"
      severity    = 3
      controls    = "AC-2 AC-2(12)"
    }
    governance_tamper = {
      name        = "cge-governance-tamper"
      display     = "Governance change: policy, RBAC, log routing, or alert rules"
      description = "Writes/deletes to policy, role assignments/definitions, diagnostic settings, and scheduled query rules. AU-6, CM-3, SI-4."
      frequency   = "PT15M"
      window      = "PT1H"
      severity    = 1
      controls    = "AU-6 CM-3 SI-4"
    }
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detections" {
  for_each = local.detections

  name                 = each.value.name
  display_name         = each.value.display
  description          = each.value.description
  resource_group_name  = azurerm_resource_group.sandbox.name
  location             = azurerm_log_analytics_workspace.grc.location
  scopes               = [azurerm_log_analytics_workspace.grc.id]
  evaluation_frequency = each.value.frequency
  window_duration      = each.value.window
  severity             = each.value.severity
  enabled              = true

  # Each firing is recorded in Azure Monitor alerts (the evidence). No action group yet:
  # the owner address is a role placeholder; production would route to an on-call group.
  auto_mitigation_enabled = false

  criteria {
    query                   = templatefile("${path.module}/detections/${each.key}.kql", local.kql_vars)
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0 # any matching row is an alert

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  tags = {
    env      = var.environment
    purpose  = "cge-az-labs"
    controls = each.value.controls
  }
}
