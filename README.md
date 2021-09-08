# shoreline_devops_takehome
Take home project for Shoreline devops position.

Iterates through a list of base firewall rules and applies them
to multiple providers.  Supports GCP Firewalls and AWS Networking Firewalls.

## Installation/Execution
1. Create Python3 virtual environment
```bash
# python3 -m venv venv
```
2. Source virtual environment
```bash
# source venv/bin/activate
```
3. Install dependencies
```bash
(venv)# pip install -r requirements.txt 
```
4. Execute script against firewall YAML config
```bash
(venv)# python apply_firewalls.py firewalls.yaml
```

## Setup

Before the script can be run, the firewall rules YAML and your provider environments must be configured.

### Firewall config YAML
The firewalls YAML contains both the firewalls rules and relevant provider configurations.  Example:
```yaml
firewall_rules:
  firewall001:
    action: allow
    cidrs:
      - 10.1.0.0/21
      - 192.168.0.0/23
    protocol_ports:
      tcp:
        - "22"
        - "80"
        - "443-8080"
      udp:
        - "5555"
        - "90-180"
    providers:
      gcloud:
        networks:
          temp-interview-vpc:
            name: firewall-001
            description: "A test firewall rule"
            priority: 1000
            target_service_accounts: []
            target_tags:
              - test-firewall  
      aws:
        network_firewall:
          rule_group: firewall-test-group
          priority_start: 100
          priority_jump: 100
          add_to_capacity: 10

additional_provider_configs:
  aws:
    policies:
      firewall-test-policy:
        rule_groups:
          firewall-test-group:
            priority: 100
    firewalls:
      test-firewall:
        vpc_id: vpc-00000000000000
        subnet_ids:
          - subnet-00000000000000000
          - subnet-058d0000000000000
        policy: firewall-test-policy

```

The `firewall_rules` section is a hash map of each ruleset with a unique name as the key, followed by the following parameters:
- action: Either "allow" or "deny"
- cidrs: A list of CIDR blocks
- protocol_ports: A map of protocols (tcp and udp) to ports (strings representing single integers, or a range of integers.)
- providers: which providers to apply the firewall rules to, along with their relative configurations. "gcloud" and "aws" currently supported. More information is available below.

Due to the limitations of this structure, configurations for resources that must be decoupled from each individual firewall rule are located separately in the `additional_provider_configs` section.  More information is provided below.

### Provider configuration
#### Google Cloud
To use Google Cloud as a provider, credentials and a project must be configured.  The script first checks to see if these are configured on a local `gcloud` cli installation.  If no gcloud configuration is found, it will then attempt to locate credentials using the Application Default Credentials. This is typically set up by creating a service account with the necessary roles, exporting the service account key to the target machine, and setting the `GOOGLE_APPLICATION_CREDENTIALS` environment variable to the key file location. See https://cloud.google.com/docs/authentication/production

An example of the firewall configuration for the gcloud provider is provided above. The keys under `networks` represents a gcloud vpc network name, and the values set the firewall rules.  Of these, only `name` is required.

Because of good API/library design and a relatively flat structure for firewalls, it is possible to configure most available firewall options by simply adding the desired parameters to the YAML provider map.  All of these key:value pairs will be unpacked and loaded as-is into the client library object.  For a list of available fields, see https://googleapis.dev/python/compute/0.5.0/compute_v1/types.html#google.cloud.compute_v1.types.Firewall.

#### AWS
AWS providers utilize the active profile (`AWS_PROFILE=`) and the associated config/credentials in the `~/.aws` directory. See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html.

The AWS provider currently offers limited compatibility with AWS Network Firewalls.  Plans to additionally support Security Groups, another type of firewall, were abandoned due to time constraints.

Due to the fact that AWS Networking Firewalls utilize several different components that often have one-to-many relationships with each other, configurations are limited and some had to be decoupled from the firewall rules into their own data structure, located in `additional_provider_configs`.  For the current implementation, the provider config on each firewall ruleset is used to generate or update AWS Networking Firewall rule groups, and policies and firewalls are configured in the `additional_provider_configs`.  See YAML above for an example of these configs.

Documentation regarding these resources can be found here: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/network-firewall.html
https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html

## Discussion
This project highlighted the difficulties in designing data structures that can be used across multiple platforms.  Ultimately the core structure needs to be relatively simple to ensure compatibility between all platforms, but it does so at the cost of limiting the unique features of each platform that can be utilized.

1. "How do you map the network rules to each platform i.e. how are the rules applied on each platform and to what types of resources on that platform?"

  - `GCloud`: Each firewall is associated with a vpc network. All defined protocols and rules are included in a single stateful firewall object.  By default the firewall will be applied to all GCE, GKE, app engine flex nodes, instance groups, or other resources that live on the network.  Source/Destination targets can easily, flexibly, and dynamically be assigned via the use of tagging and/or service accounts.  These rules cannot be used for serverless or managed resources that do not utilize VPC networking, nor does it offer the ability to manage inheritable firewall policies that span across an organization.

  - `AWS`: There are multiple firewall products that provide some differing and overlapping functionality. The two main products used for this are Security Groups, and VPC Networking Firewalls.  I only had time to implement the latter. The Networking Firewall provides broad protections at the point of a VPC's subnets in each availability zone, where it lives. By default it will apply to every resource on the VPC, including EC2 instances, SQL database nodes, EKS, etc (no serverless). Once created, routing tables must be updated to point to the firewall on each subnet, which I do not believe is handled by the APIs used in this script. Firewalls are associated with a firewall policy, which can be shared between multiple firewalls.  Each policy, in turn, is associated with a number of firewall rule groups.  Each rule group can be either stateful or stateless (only stateless is supported here), and offers a number of options for routing traffic.  The script creates or updates rule groups per firewall rule.  Rule groups are then assigned to policies, which have to be created and managed separately from the firewall rules.  Firewalls themselves also have to be managed separately, and are assigned a policy which applies all of its rule groups based on their priority settings.

2. "What are the differences between the platforms from a networking perspective? How does this impact your ability to create an abstraction across the platforms?":

  - Gcloud: Much better designed and programmatic.  Firewall rules are consolidated into a single object with relatively flat design, which means that configuring it doesn't require the management of multiple separate resources. However, this also means that rules can't be independently managed and shared across multiple firewalls without the use of inheritable policies, which this script doesn't support. Firewall rules can be dynamically filtered and routed to a fine degree of precision via the use of tagging or service accounts, which are very intuitive and easy to manage. Routing tables are unnecessary to manage, as the firewall doesn't live on any subnets.  It filters by subnet simply as another field of filtering rules, which can be updated later or discarded entirely. The firewall is stateful by default, which means that response traffic for outgoing requests are automatically allowed through without the need for creating custom deep-packet inspection rules. I could go on.

  - AWS: Networking Firewalls are much more hands-on, which makes setup and maintenance a pain. Offers more flexibility over decoupled resources that can be shared with other resources, and independently managed. Offers a lot more options for defining rulesets from a traditional networking admin perspective, but less flexible in terms of targeting specific resources without the need for complex stateful deep-packet inspection rules. Good for those who desire a traditional approach to networking, not great for those who value ease of automation and programmatic control. Firewall is locked to the subnets it was created on and cannot be changed. Routing tables have to be updated to route traffic to the firewalls. Separate resources with one-to-many relationships prevent the ability to use a data structure that starts with the firewall rules and moves outward in terms of resource definitions, as configuring these resources for each rule will clobber and conflict with configurations for the same resources elsewhere. I could go on.

  The takeaway here is that the more similar the products are, the more overlap that can be abstracted.  Differences between them require different logic to handle, which  limits the ability to effectively leverage their unique features and best-practices.

3. "How fine grained do you provide control over network flow? How would you go about extending this for finer grain control?  Per instance? Per group? Per network? "

  - Both platforms support egress rules, which are unsupported by this script.
  - Both platforms support more protocols than this script allows for.
  - GCP: Supports fine grained control over sources and destinations via tagging and service accounts. These tags can be applied from single instances up to entire groups. Rules are limited to a single network, but can be applied to inheritable policies at both the project and organization level (not supported here).
  - GCP: Script offers broad coverage over the API, so many features can be used.
  - AWS: Offers far more options for stateless and stateful rules than this script is designed to deal with. Fine grained control per instance/group is primarily handled with clunky CIDR definitions, which should generally be avoided due to their static and opaque nature.  Stateful rules can be used to filter traffic based on domains, which is not supported in the script. For finer grained control at the instance, group, or load balancer level, it is highly advised to use security groups instead.  These are not only easier to use, but they also offer more dynamic control over sources and targets, as firewall rules can be applied to other security groups instead of static IP addresses.
  - AWS: Firewall rules can be shared with other firewalls across multiple networks in a given project due to the decoupled nature of rule groups and policies.  Applying a single policy or rule group to multiple firewalls across different networks is not only possible, but allows for one to update all of them simultaneously by modifying a single rule group or policy.  However, there is no clear way to apply firewall policies across multiple accounts in an organization, or even different AWS regions in a single account.

## Final Thoughts
Ultimately, I think the entire approach here is ill-advised.  It is difficult to implement, and cannot fully leverage each platform's unique strengths and best practices.  Furthermore, it is dangerously close to running afoul of IaC principles, which are paramount in infrastructure design and implementation principles.

Instead, I would recommend using Terraform to define and manage the infrastructure.  One could create a data struture that contains similar parameters as the firewall object in this code, which can then be consumed by modules that manage the firewall resources for each different provider. That way you are still gleaning the benefits of abstracted data, but with better support for the different platforms and a sound IaC implementation, without the need to write all the API logic yourself.

## Author
- Garrett Anderson <garrett@devnull.rip>
