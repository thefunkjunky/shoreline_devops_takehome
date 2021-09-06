"""
Inserts/modifies firewall rule to gcloud VPC
"""

import google
import gcloud_config_helper
from google.cloud.compute_v1.services.firewalls import FirewallsClient
from google.cloud.compute_v1.types import Firewall, Allowed, Denied
from google.api_core.exceptions import NotFound


def gen_gcloud_firewall(firewall_rule, network_url, configs):
  """Generates a Google Cloud Firewall object"""
  allowed = []
  denied = []

  if firewall_rule.action == "allow":
    for protocol, ports in firewall_rule.protocol_ports.items():
      allowed.append(
        Allowed(
          I_p_protocol=protocol,
          ports=ports
        )
      )
  elif firewall_rule.action == "deny":
    for protocol, ports in firewall_rule.protocol_ports.items():
      denied.append(
        Denied(
          I_p_protocol=protocol,
          ports=ports
        )
      )
  firewall = Firewall(
      **configs,
      allowed=allowed,
      denied=denied,
      network=network_url,
      source_ranges=firewall_rule.cidrs
    )
  return firewall


def check_firewall_exists(client, project, firewall_name):
  """Checks if firewall already exists"""
  try:
    _ = client.get(
      project=project,
      firewall=firewall_name
    )
    firewall_exists = True
  except NotFound:
    firewall_exists = False

  return firewall_exists


def apply_gcloud_firewall(firewall_rule, network, configs):
  if gcloud_config_helper.on_path():
    credentials, project = gcloud_config_helper.default()
  else:
    credentials, project = google.auth.default()

  network_url = f"projects/{project}/global/networks/{network}"

  client = FirewallsClient(credentials=credentials)

  firewall_name = configs["name"]

  firewall = gen_gcloud_firewall(firewall_rule, network_url, configs)
  firewall_exists = check_firewall_exists(client, project, firewall_name)

  if firewall_exists:
    print(f"Updating existing firewall {firewall_name} in gcloud project {project}...")
    client.update(
      project=project,
      firewall=firewall_name,
      firewall_resource=firewall
    )
  else:
    print(f"Creating firewall rule {firewall_name} in gcloud project {project}...")
    client.insert(
      project=project,
      firewall_resource=firewall
    )
