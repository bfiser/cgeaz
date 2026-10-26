# Gate rule (federal track, Custom 4): NSG rules must not open management ports
# (SSH 22, RDP 3389) to the internet. Mirrors Azure Policy cge-nsg-no-internet-mgmt-ports.
# Defense in depth: this gate also understands port RANGES (e.g. "20-30" includes 22),
# which the Azure Policy rule does not evaluate (documented limit there).
# 800-53: SC-7, SC-7(5), AC-17   CSF 2.0: PR.IR-01
package main

import rego.v1

nsg_mgmt_ports := {22, 3389}

# Sources that mean "anyone on the internet" (compared lowercase).
nsg_internet_sources := {"*", "internet", "0.0.0.0/0", "::/0", "any"}

# Every security rule being created or changed, in either form Terraform supports:
# inline in an NSG (security_rule blocks) or as a standalone azurerm_network_security_rule.
nsg_rules contains [rc.address, rule] if {
	some rc in input.resource_changes
	rc.type == "azurerm_network_security_group"
	rc.change.after != null
	some rule in object.get(rc.change.after, "security_rule", [])
}

nsg_rules contains [rc.address, rc.change.after] if {
	some rc in input.resource_changes
	rc.type == "azurerm_network_security_rule"
	rc.change.after != null
}

# Source is the internet, in the single-value or list form.
nsg_open_to_internet(rule) if lower(object.get(rule, "source_address_prefix", "")) in nsg_internet_sources

nsg_open_to_internet(rule) if {
	some p in object.get(rule, "source_address_prefixes", [])
	lower(p) in nsg_internet_sources
}

# All destination port specs on the rule, from the single-value and list forms.
nsg_port_specs(rule) := {p | p := object.get(rule, "destination_port_range", ""); p != ""} | {p | some p in object.get(rule, "destination_port_ranges", [])}

# Does a port spec ("*", "22", or "20-30") include this port?
nsg_covers(spec, _) if spec == "*"

nsg_covers(spec, port) if {
	not contains(spec, "-")
	spec != "*"
	to_number(spec) == port
}

nsg_covers(spec, port) if {
	contains(spec, "-")
	bounds := split(spec, "-")
	to_number(bounds[0]) <= port
	port <= to_number(bounds[1])
}

deny contains msg if {
	some [addr, rule] in nsg_rules
	lower(rule.access) == "allow"
	lower(rule.direction) == "inbound"
	nsg_open_to_internet(rule)
	some spec in nsg_port_specs(rule)
	some port in nsg_mgmt_ports
	nsg_covers(spec, port)
	msg := sprintf("%s: rule '%s' allows port %d from the internet (spec %s); use Bastion/JIT or a private source [800-53 SC-7, AC-17]", [addr, rule.name, port, spec])
}