"""
Applies firewall rules to AWS resources
"""

import boto3

protocol_map = {
  "tcp": 6,
  "udp": 17
}

actions_map = {
  "allow": "aws:pass",
  "deny": "aws:drop"
}


def init_aws_client():
  """Initializes and returns AWS boto3 client object"""
  client = boto3.client("network-firewall")
  return client


def create_firewall(client, firewall_name, firewall_configs):
  """Creates an AWS Network Firewall"""
  subnets = [{"SubnetId": subnet} for subnet in firewall_configs["subnet_ids"]]
  policy_response = client.describe_firewall_policy(
    FirewallPolicyName=firewall_configs["policy"]
  )
  policy_arn = policy_response["FirewallPolicyResponse"]["FirewallPolicyArn"]
  response = client.create_firewall(
    FirewallName=firewall_name,
    FirewallPolicyArn=firewall_configs["policy"],
    VpcId=firewall_configs["vpc_id"],
    SubnetMappings=subnets
  )


def create_firewall_policy(client, policy_name, policy_configs):
  """Creates an AWS Network Firewall policy"""
  rule_groups = []
  rule_group_arns = []
  for group, rule_config in policy_configs["rule_groups"].items():
    group_response = client.describe_rule_group(
      RuleGroupName=group
    )
    arn = group_response["RuleGroupResponse"]["RuleGroupArn"]
    rule_groups.append(
      {
        "ResourceArn": arn,
        "Priority": rule_config["priority"]
      }
    )

  print(f"Creating AWS Firewall policy {policy_name}")
  response = client.create_firewall_policy(
    FirewallPolicyName=policy_name,
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



def apply_aws_rule_group(client, firewall_rule, aws_configs):
  """Creates/updates AWS Network Firewall rule groups"""
  try:
    rule_group_response = client.describe_rule_group(
      RuleGroupName=aws_configs["rule_group"]
    )
  except:
    rule_group_response = create_rule_group(client, firewall_rule, aws_configs)
  rule_group_arn = rule_group_response["RuleGroupResponse"]["RuleGroupArn"]


def apply_aws_firewall_resources(client, firewall_configs):
  """Creates/updates AWS Firewall policies and firewalls"""
  for policy, policy_config in firewall_configs["policies"].items():  
    policy_response = create_firewall_policy(client, policy, policy_config)
  for firewall, firewall_config in firewall_configs["firewalls"].items():
    firewall_response = create_firewall(client, firewall, firewall_config)
