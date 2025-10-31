# linode_custom
## Custom Linode Image Deployment
- Utilization: Run on debian or ubuntu systems with curl and jq
- Load the Stackscript in to Linode system
- Follow the prompts in the instance.config
- chmod +x instance.sh
- run instance.sh

Current Needs:
  - Fix bug in umlti_instance, add wait for disk "status": "ready" before committing configs.
      -- Change loop to create multiple loops 1 for each activity
      -- Add change to multi to build all instance shells first and populate var as $instance_number
  - Add mgmt vlan for install time for private image servers
