"""
Applies firewall rules to AWS resources
"""

import boto3
import botocore

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


def get_firewall(client, firewall_name):
  """Returns GET response for AWS Networking Firewall"""
  response = client.describe_firewall(
    FirewallName=firewall_name,
  )
  return response


def get_policy(client, policy_name):
  """Returns GET response for AWS Networking policy"""
  response = client.describe_firewall_policy(
    FirewallPolicyName=policy_name,
  )
  return response


def get_rule_group(client, rule_group_name):
  """Returns GET response for AWS Networking rule group"""
  response = client.describe_rule_group(
    RuleGroupName=rule_group_name,
    Type="STATELESS"
  )
  return response


def apply_firewall(client, firewall_name, firewall_configs):
  """Creates/updates an AWS Network Firewall"""
  subnets = [{"SubnetId": subnet} for subnet in firewall_configs["subnet_ids"]]
  policy_response = get_policy(client, firewall_configs["policy"])
  policy_arn = policy_response["FirewallPolicyResponse"]["FirewallPolicyArn"]

  # Check if firewall exists and updates the policy if necessary
  try:
    get_firewall_response = get_firewall(client, firewall_name)
    print(f"AWS Firewall {firewall_name} already exists.")
    current_policy_arn = get_firewall_response["Firewall"]["FirewallPolicyArn"]
    if current_policy_arn != policy_arn:
      print("Updating policy association...")
      # This needs retry/backoff logic in case UpdateToken is in use
      update_token = get_firewall_response["UpdateToken"]
      update_response = client.associate_firewall_policy(
        UpdateToken=update_token,
        FirewallName=firewall_name,
        FirewallPolicyArn=policy_arn
      )
      return update_response
    else:
      print(f"Policy on AWS Firewall {firewall_name} hasn't changed, skipping...")
      return None
  except client.exceptions.ResourceNotFoundException:
    print(f"Creating AWS Firewall {firewall_name}...")

  response = client.create_firewall(
    FirewallName=firewall_name,
    FirewallPolicyArn=policy_arn,
    VpcId=firewall_configs["vpc_id"],
    SubnetMappings=subnets
  )
  return response


def apply_firewall_policy(client, policy_name, policy_configs):
  """Creates/updates an AWS Network Firewall policy"""
  rule_groups = []
  rule_group_arns = []
  for group, rule_config in policy_configs["rule_groups"].items():
    get_group_response = get_rule_group(client, group)
    arn = get_group_response["RuleGroupResponse"]["RuleGroupArn"]
    rule_groups.append(
      {
        "ResourceArn": arn,
        "Priority": rule_config["priority"]
      }
    )

  # Check if policy exists and updates it
  try:
    get_response = get_policy(client, policy_name)
    print(f"AWS Firewall policy {policy_name} already exists. Updating...")
    # This needs retry/backoff logic in case UpdateToken is in use
    update_token = get_response["UpdateToken"]
    response = client.update_firewall_policy(
      UpdateToken=update_token,
      FirewallPolicyName=policy_name,
      FirewallPolicy={
        "StatelessRuleGroupReferences": rule_groups,
        "StatelessDefaultActions": ["aws:drop"],
        "StatelessFragmentDefaultActions": ["aws:drop"]
      }
    )
    return response
  except client.exceptions.ResourceNotFoundException:
    print(f"Creating AWS Firewall policy {policy_name}...")
    
  response = client.create_firewall_policy(
    FirewallPolicyName=policy_name,
    FirewallPolicy={
      "StatelessRuleGroupReferences": rule_groups,
      "StatelessDefaultActions": ["aws:drop"],
      "StatelessFragmentDefaultActions": ["aws:drop"]
    }
  )
  return response


def apply_rule_group(client, firewall_rule, aws_configs):
  """Creates/updates an AWS Network Firewall rule group"""

  stateless_rules = []

  name = aws_configs["rule_group"]
  priority = aws_configs["priority_start"]
  capacity = 1

  sources = [
    {"AddressDefinition": cidr} for cidr in firewall_rule.cidrs
  ]

  sources_capacity = len(sources) if len(sources) > 0 else 1
  protocols_capacity = len(sources) if len(firewall_rule.protocol_ports) > 0 else 1

  # I don't understand this, but it seems to work
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

  # Check if rule group exists and updates it
  try:
    get_response = get_rule_group(client, name)
    print(f"AWS Firewall rule group {name} exists. Updating...")
    update_token = get_response["UpdateToken"]
    response = client.update_rule_group(
      UpdateToken=update_token,
      RuleGroupName=name,
      Type="STATELESS",
      RuleGroup={
        "RulesSource": {
          "StatelessRulesAndCustomActions": {
            "StatelessRules": stateless_rules
          }
        }
      }
    )
    return response
  except client.exceptions.ResourceNotFoundException:
    print(f"Creating AWS Firewall rule group {name}...")

  response = client.create_rule_group(
    Capacity=capacity,
    Type="STATELESS",
    RuleGroupName=name,
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
  rule_group_response = apply_rule_group(client, firewall_rule, aws_configs)


def apply_aws_firewall_resources(client, firewall_configs):
  """Creates/updates AWS Firewall policies and firewalls"""
  for policy, policy_config in firewall_configs["policies"].items():
    policy_response = apply_firewall_policy(client, policy, policy_config)
  for firewall, firewall_config in firewall_configs["firewalls"].items():
    firewall_response = apply_firewall(client, firewall, firewall_config)
