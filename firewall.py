"""
Firewall rule object
"""

from ipaddress import IPv4Network


supported_protocols = ["tcp", "udp"]
supported_actions = ["allow", "deny"]


class FirewallRule():
  """Base firewall rule object. Requires the following arguments:

  cidrs: A list of strings in CIDR notation. Example: ["10.0.0.0/24"]

  protocol_ports: A dict of protocols (tcp or udp) that map to a list of ports,
    represented as strings of either integers between 0 and 65535, or
    a range in form of "25-50". ex:
    protocol_ports = {
      "tcp": [
        "22",
        "443",
        "8080-8090"
      ],
      "udp": [
        "1000"
      ]
    }

  action: Action to take for firewall rule (either "allow" or "deny")
  """
  def __init__(self, cidrs, protocol_ports, action):
    # Perform basic type checking on properties
    self.__check_cidrs(cidrs)
    self.__check_protocol_ports(protocol_ports)
    self.__check_action(action)

    self.__cidrs = cidrs
    self.__protocol_ports = protocol_ports
    self.__action = action

  def __check_cidrs(self, cidrs):
    for cidr in cidrs:
      check_cidr = IPv4Network(cidr)

  def __check_protocol_ports(self, protocol_ports):
    for protocol, ports in protocol_ports.items():
      if protocol not in supported_protocols:
        raise ValueError(
          f"{protocol} not in supported types: {supported_protocols}"
        )
      for port in ports:
        psplit = port.split("-")
        try:
          assert(len(psplit) in range(1, 3))
          assert(all([int(n) in range(0, 65535) for n in psplit])) 
          assert(int(psplit[0]) <= int(psplit[-1]))
        except:
          raise AttributeError(
            "Ports must be a list of strings of either "
            "integers between 0-65535, or a range in the format of \"5-10\"."
          )

  def __check_action(self, action):
    if action not in supported_actions:
      raise AttributeError(
        f"{action} must be one of the following: {supported_actions}"
      )

  @property
  def cidrs(self):
    return self.__cidrs

  @property
  def protocol_ports(self):
    return self.__protocol_ports

  @property
  def action(self):
    return self.__action

  @cidrs.setter
  def cidrs(self, cidrs):
    self.__check_cidrs(cidrs)
    self.__cidrs = cidrs

  @protocol_ports.setter
  def protocol_ports(self, protocol_ports):
    self.__check_protocol_ports(protocol_ports)
    self.__protocol_ports = protocol_ports

  @action.setter
  def action(self, action):
    self.__check_action(action)
    self.__action = action
