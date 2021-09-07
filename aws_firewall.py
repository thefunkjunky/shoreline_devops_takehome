"""
Applies firewall rules to AWS resources
"""

import boto3


def check_firewall_exists(firewall_rule, aws_configs):
  """Checks if the given firewall exists or not"""
  pass

def create_rule_group(client, firewall_rule, aws_configs):
  """Creates an AWS Network Firewall rule group"""

  stateless_rules = []

  protocol_map = {
    "tcp": 6,
    "udp": 17
  }

  actions_map = {
    "allow": "aws:pass",
    "deny": "aws:drop"
  }

  name = aws_configs["rule_group"]
  priority = aws_configs["priority_start"]
  capacity = 1

  sources = [
    {"AddressDefinition": cidr} for cidr in firewall_rule.cidrs
  ]

  capacity *= len(sources) * len(firewall_rule.protocol_ports)

  for protocol, ports in firewall_rule.protocol_ports.items():
    capacity *= len(ports)
    port_ranges = []
    for port_range in ports:
      port_split = port_range.split("-")
      port_ranges.append(
        {
          "FromPort": int(port_split[0]),
          "ToPort": int(port_split[-1])
        }
      )

    rule = {
      "Priority": priority,
      "RuleDefinition": {
        "Actions": [actions_map[firewall_rule.action]],
        "MatchAttributes": {
          "Sources": sources,
          "DestinationPorts": port_ranges,
          "Protocols": [protocol_map[protocol]]
        }
      }
    }
    stateless_rules.append(rule)
    priority += aws_configs["priority_jump"]

  if capacity == 0:
    capacity = 1

  if "add_to_capacity" in aws_configs:
    capacity += aws_configs["add_to_capacity"]

  print(f"Creating AWS Firewall rule group {aws_configs['rule_group']}...")
  response = client.create_rule_group(
    Capacity=capacity,
    Type="STATELESS",
    RuleGroupName=aws_configs["rule_group"],
    RuleGroup={
      "RulesSource": {
        "StatelessRulesAndCustomActions": {
          "StatelessRules": stateless_rules
        }
      }
    }
  )
  return response



def apply_aws_firewall(firewall_rule, aws_configs):
  """Creates/updates AWS Network Firewall with firewall rule"""
  client = boto3.client("network-firewall")
  rule_group_response = create_rule_group(client, firewall_rule, aws_configs)

