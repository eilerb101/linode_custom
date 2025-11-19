# OpenSense HA Deployment on Linode
## Opensense HA Deployment leverages the following components on Linode
- 1 Placement Group
- 2 VLANs
- 2 Instances with public Interfaces
- A Linode Object Storage Bucket
  - A qcow2 image for OPNSense Active Instance
    - Startup script in /usr/local/etc/rc.syshook.d/start
    - The Linode Metadata service for LAN, WAN and BGP reconfiguration 
  - A qcow2 image for OPNSense Standby Instance
    - Startup script in /usr/local/etc/rc.syshook.d/start
    - The Linode Metadata service for LAN, WAN and BGP reconfiguration
- Linode IP Sharing from Active to Standby
- A single Stackscript for Alpine 3.22 that images the Linode with the OPNSense qcow2 images
- A Single bash script (debian based) to create the instances and send data to the Stackscript

## Directions for use:
- Download opnsense_ha_deploy.sh on to a debian based system with jq and curl
- `chmod +x opnsense_ha_deploy.sh`
- Download opnsense.config
- `vi opnsense.config` and make the following changes:
