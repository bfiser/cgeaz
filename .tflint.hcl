# Tier 0 lint (rubric Dim 1). Versions pinned; plugin signature verified by tflint --init.
config {
  call_module_type = "none"
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"   # includes terraform_unused_declarations (the 2026-10-26 wiring lesson)
}

plugin "azurerm" {
  enabled = true
  version = "0.33.0"
  source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}
