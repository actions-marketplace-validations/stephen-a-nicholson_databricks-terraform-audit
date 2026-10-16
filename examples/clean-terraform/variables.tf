variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "tags" {
  description = "Tags applied to every resource"
  type        = map(string)
  default = {
    Environment = "production"
    Owner       = "platform-team"
    CostCentre  = "CC-1234"
    Project     = "lakehouse"
  }
}
