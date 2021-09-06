"""
Firewall project
"""

from ipaddress import IPv4Network


class FirewallRule():
  def __init__(self, cidrs, protocol_ports, action="allow"):
    self.cidrs = cidrs
    self.protocol_ports = protocol_ports
    self.action = action

    for cidr in cidrs:
      check_cidr = IPv4Network(cidr)
