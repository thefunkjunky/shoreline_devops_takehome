"""
Applies firewall rules to AWS resources
"""

import boto3


def check_firewall_exists(firewall_rule, aws_configs):
  """Checks if the given firewall exists or not"""
  pass


def create_firewall_policy(client, rule_group_arns, aws_configs):
  """Creates an AWS Network Firewall policy"""
  rule_groups = []
  priority = aws_configs["priority_start"]
  for arn in rule_group_arns:
    rule_groups.append(
      {
        "ResourceArn": arn,
        "Priority": priority
      }
    )
    priority += aws_configs["priority_jump"]

  print(f"Creating AWS Firewall policy {aws_configs['policy']}")
  response = client.create_firewall_policy(
    FirewallPolicyName=aws_configs["policy"],
    FirewallPolicy={
      "StatelessRuleGroupReferences": rule_groups,
      "StatelessDefaultActions": ["aws:drop"],
      "StatelessFragmentDefaultActions": ["aws:drop"]
    }
  )
  return response

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

  sources_capacity = len(sources) if len(sources) > 0 else 1
  protocols_capacity = len(sources) if len(firewall_rule.protocol_ports) > 0 else 1

  capacity *= sources_capacity * protocols_capacity

  for protocol, ports in firewall_rule.protocol_ports.items():
    ports_capacity = len(ports) if len(ports) > 0 else 1
    capacity *= ports_capacity
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
  rule_group_arn = rule_group_response["RuleGroupResponse"]["RuleGroupArn"]
  policy_response = create_firewall_policy(client, [rule_group_arn], aws_configs)
