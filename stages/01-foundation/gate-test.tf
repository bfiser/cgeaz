# Deliberately non-compliant: should be blocked by the compliance gate
resource "azurerm_storage_account" "gate_test" {
  name                            = "stgrcgatetest01"
  resource_group_name             = azurerm_resource_group.sandbox.name
  location                        = azurerm_resource_group.sandbox.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  shared_access_key_enabled       = true
}