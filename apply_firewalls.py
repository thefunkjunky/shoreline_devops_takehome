#!/usr/bin/env python3

import argparse

import yaml

from firewall import FirewallRule
from gcloud_firewall import get_creds_project, init_gcloud_client, apply_gcloud_firewall
from aws_firewall import init_aws_client, apply_aws_rule_group, apply_aws_firewall_resources


def apply_gcloud_rule(client, firewall_rule, project, gcloud_configs):
  """Parses and applies firewall rules for Google Cloud"""
  for network, configs in gcloud_configs["networks"].items():
    apply_gcloud_firewall(client, firewall_rule, project, network, configs)


def apply_aws_rule(client, firewall_rule, aws_configs):
  """Parses and applies firewall rules for AWS"""
  if "network_firewall" in aws_configs:
    apply_aws_rule_group(client, firewall_rule, aws_configs["network_firewall"])


def main():
  """Apply firewalls rules"""

  parser = argparse.ArgumentParser(
    description="Apply firewall rules to multiple providers"
  )
  parser.add_argument("config", type=str,
    help="YAML config file for firewall rules."
  )
  args = parser.parse_args()

  with open(args.config, "r") as f:
    firewall_configs = yaml.safe_load(f)

  aws_client = None
  gcloud_client = None

  for firewall_name, configs in firewall_configs["firewall_rules"].items():
    firewall_rule = FirewallRule(
      cidrs=configs["cidrs"],
      protocol_ports=configs["protocol_ports"],
      action=configs["action"]
    )
    if "gcloud" in configs["providers"]:
      if not gcloud_client:
        gcloud_credentials, gcloud_project = get_creds_project()
        gcloud_client = init_gcloud_client(gcloud_credentials)
      apply_gcloud_rule(gcloud_client, firewall_rule, gcloud_project, configs["providers"]["gcloud"])

    if "aws" in configs["providers"]:
      if not aws_client:
        aws_client = init_aws_client()
      apply_aws_rule(aws_client, firewall_rule, configs["providers"]["aws"])

  if "aws" in firewall_configs["additional_provider_configs"]:
    apply_aws_firewall_resources(aws_client, firewall_configs["additional_provider_configs"]["aws"])


if __name__ == '__main__':
  main()
