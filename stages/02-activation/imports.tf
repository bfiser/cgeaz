# Found 2026-11-05 (final checks): Defender for Key Vault was Standard in Azure (enabled before
# stage 02 managed it) but missing from state, so plan wanted to CREATE it. Nobody noticed because
# stage 02 was not in the drift/gate matrix (fixed in the same PR). Adopt, don't recreate (CM-3, CM-8).
import {
  to = azurerm_security_center_subscription_pricing.baseline["KeyVaults"]
  id = "${data.azurerm_subscription.current.id}/providers/Microsoft.Security/pricings/KeyVaults"
}
