# ==============================================================================
# Input Variables for Palo Alto Networks Configuration
# ==============================================================================

variable "panos_hostname" {
  description = "Palo Alto Firewall or Panorama IP/Hostname"
  type        = string
  default     = "192.168.1.1"
}

variable "panos_username" {
  description = "Palo Alto Administrator Username"
  type        = string
  default     = "admin"
}

variable "panos_password" {
  description = "Palo Alto Administrator Password (leave blank if using API key)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "panos_api_key" {
  description = "Palo Alto XML API Key (optional alternative to username/password)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "panos_vsys" {
  description = "Target Virtual System (vsys) name on the Palo Alto Firewall"
  type        = string
  default     = "vsys1"
}

variable "panos_device_group" {
  description = "Target Device Group (used if deploying via Panorama)"
  type        = string
  default     = "shared"
}
