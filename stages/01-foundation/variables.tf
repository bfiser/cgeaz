variable "location" {
  description = "Azure region for foundation resources."
  type        = string
  default     = "eastus"
}

variable "owner_email" {
  description = "Owner tag applied to governed resource groups; the POA&M generator resolves finding owners from it."
  type        = string
}

variable "environment" {
  description = "Environment name used in tags and resource names."
  type        = string
  default     = "dev"
}

variable "tag_policy_effect" {
  description = "Effect for the require-env-tag policy (Audit while onboarding, Deny once clean)."
  type        = string
  default     = "Audit"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.tag_policy_effect)
    error_message = "tag_policy_effect must be Audit, Deny, or Disabled."
  }
}

variable "public_blob_policy_effect" {
  description = "Effect for the deny-public-blob-access policy. This one has earned Deny."
  type        = string
  default     = "Deny"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.public_blob_policy_effect)
    error_message = "public_blob_policy_effect must be Audit, Deny, or Disabled."
  }
}

# Escalation knob for Custom 1 (storage minimum TLS, 800-53 SC-8).
# Audit while new; raise to Deny by PR once no non-compliant accounts remain.
variable "storage_tls_policy_effect" {
  description = "Effect for the storage minimum-TLS policy (Audit while new; Deny once the estate is clean)."
  type        = string
  default     = "Audit"

  # Reject typos at plan time ("deny", "Audti") instead of failing inside Azure.
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.storage_tls_policy_effect)
    error_message = "storage_tls_policy_effect must be Audit, Deny, or Disabled."
  }
}

variable "appservice_transport_policy_effect" {
  description = "Effect for the App Service transport-security policy (Audit while new; Deny once the estate is clean)."
  type        = string
  default     = "Audit"

  # Reject typos at plan time instead of failing inside Azure.
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.appservice_transport_policy_effect)
    error_message = "appservice_transport_policy_effect must be Audit, Deny, or Disabled."
  }
}

variable "appservice_tls_ftps_policy_effect" {
  description = "Effect for the App Service TLS/FTPS policy (AuditIfNotExists or Disabled; it cannot Deny)."
  type        = string
  default     = "AuditIfNotExists"

  # Reject typos at plan time. Deny is deliberately not allowed: AINE has no Deny form.
  validation {
    condition     = contains(["AuditIfNotExists", "Disabled"], var.appservice_tls_ftps_policy_effect)
    error_message = "appservice_tls_ftps_policy_effect must be AuditIfNotExists or Disabled."
  }
}