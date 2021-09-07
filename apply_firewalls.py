#!/usr/bin/env python3

import argparse

import yaml

from firewall import FirewallRule
from gcloud_firewall import apply_gcloud_firewall
from aws_firewall import apply_aws_firewall


def apply_gcloud_config(firewall_rule, gcloud_configs):
  """Parses and applies firewall rules for Google Cloud"""
  for network, configs in gcloud_configs["networks"].items():
    apply_gcloud_firewall(firewall_rule, network, configs)


def apply_aws_config(firewall_rule, aws_configs):
  """Parses and applies firewall rules for AWS"""
  if "network_firewall" in aws_configs:
    apply_aws_firewall(firewall_rule, aws_configs["network_firewall"])


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

  for firewall_name, firewall_config in firewall_configs["firewall_rules"].items():
    firewall_rule = FirewallRule(
      cidrs=firewall_config["cidrs"],
      protocol_ports=firewall_config["protocol_ports"],
      action=firewall_config["action"]
    )
    if "gcloud" in firewall_config["providers"]:
      apply_gcloud_config(firewall_rule, firewall_config["providers"]["gcloud"])

    if "aws" in firewall_config["providers"]:
      apply_aws_config(firewall_rule, firewall_config["providers"]["aws"])



if __name__ == '__main__':
  main()