# linode_custom
Custom Linode Image Deployment
Utilization: Run on debian or ubuntu systems with curl and jq
Load the Stackscript in to Linode system
Follow the prompts in the instance.config
chmod +x instance.sh
run instance.sh

Current Needs:
  - Check VPC name against global vpc names before start and return error if found in another region that is not the current region
  - Validate subnet, if subnet exists, move on.
  - Multithread the instance, disk and configuration creation
  - Add mgmt vlan for install time for private image servers
