# Source: proxmox

## Setup
You need to have a source section in your `settings.ini` file with following type:
```ini
type = proxmox
```
All options for this source are described in the [settings-example.ini](../settings-example.ini) file.

If you have multiple Proxmox instances just add another source with the same type in the **same** file.

***IMPORTANT:*** For Proxmox source you should define the var `cluster_site_relation` which maps a Proxmox cluster to an
existing Site in NetBox. If undefined a placeholder site will be created.

### Proxmox user / API token
You can authenticate using a username/password or a Proxmox API token.

**Password auth**
* Use a user with sufficient permissions to read cluster, nodes, and VM information.

**Token auth**
* Set `token_name` and `token_value` and keep `password` unset.
* The configured `username` must include the realm (e.g., `user@pam`).

### VM IP collection
For QEMU VMs, IP addresses are collected via the guest agent (`network-get-interfaces`).
Make sure the QEMU guest agent is installed and running if you want IPs for QEMU VMs.
For LXC containers, IPs are taken from the container network config.
