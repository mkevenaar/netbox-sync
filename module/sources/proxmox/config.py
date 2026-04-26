# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2025 Ricardo Bartels. All rights reserved.
#
#  netbox-sync.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

import re
from ipaddress import ip_address

from module.common.misc import quoted_split
from module.config import source_config_section_name
from module.config.base import ConfigBase
from module.config.option import ConfigOption
from module.config.group import ConfigOptionGroup
from module.sources.common.config import *
from module.sources.common.permitted_subnets import PermittedSubnets
from module.sources.common.handle_vlan import FilterVLANByID, FilterVLANByName
from module.common.logging import get_logger
from module.common.support import normalize_mac_address

log = get_logger()


class ProxmoxConfig(ConfigBase):

    section_name = source_config_section_name
    source_name = None
    source_name_example = "my-proxmox-example"

    def __init__(self):
        self.options = [
            ConfigOption(**config_option_enabled_definition),

            ConfigOption(**{**config_option_type_definition, "config_example": "proxmox"}),

            ConfigOption("host_fqdn",
                         str,
                         description="host name / IP address of the Proxmox API endpoint",
                         config_example="pve.example.com",
                         mandatory=True),

            ConfigOption("port",
                         int,
                         description="TCP port to connect to",
                         default_value=8006),

            ConfigOption("username",
                         str,
                         description="username to use to log into Proxmox",
                         config_example="root@pam",
                         mandatory=True),

            ConfigOption("password",
                         str,
                         description="password to use to log into Proxmox (optional if API token is used)",
                         config_example="super-secret",
                         sensitive=True),

            ConfigOption("realm",
                         str,
                         description="authentication realm if not part of the username",
                         default_value="pam"),

            ConfigOption("token_name",
                         str,
                         description="API token name (optional, requires token_value)",
                         config_example="netbox-sync"),

            ConfigOption("token_value",
                         str,
                         description="API token secret (optional, requires token_name)",
                         sensitive=True),

            ConfigOption("validate_tls_certs",
                         bool,
                         description="""Enforces TLS certificate validation.
                         If the Proxmox API uses a valid TLS certificate then this option should be set
                         to 'true' to ensure a secure connection.""",
                         default_value=False),

            ConfigOption("timeout",
                         int,
                         description="timeout for Proxmox API requests",
                         default_value=30),

            ConfigOption("cluster_name",
                         str,
                         description="""override the cluster name reported by Proxmox.
                         If unset and Proxmox does not report a cluster name, host_fqdn is used.""",
                         config_example="My-Proxmox-Cluster"),

            ConfigOption("cluster_type",
                         str,
                         description="NetBox cluster type name",
                         default_value="Proxmox VE"),

            ConfigOption("host_device_type",
                         str,
                         description="NetBox device type model for Proxmox nodes",
                         removed=True,
                         deprecation_message="This setting is no longer used; Proxmox host device type "
                                             "and manufacturer are not set."),

            ConfigOption("host_device_manufacturer",
                         str,
                         description="NetBox manufacturer for Proxmox nodes",
                         removed=True,
                         deprecation_message="This setting is no longer used; Proxmox host device type "
                                             "and manufacturer are not set."),

            ConfigOption("include_qemu",
                         bool,
                         description="include QEMU virtual machines",
                         default_value=True),

            ConfigOption("include_lxc",
                         bool,
                         description="include LXC containers",
                         default_value=True),

            ConfigOption("collect_vm_ips",
                         bool,
                         description="collect VM IPs (QEMU guest agent / LXC config)",
                         default_value=True),

            ConfigOption("collect_node_interfaces",
                         bool,
                         description="collect Proxmox node interfaces and IPs",
                         default_value=True),

            ConfigOption("sync_proxmox_tags",
                         bool,
                         description="sync Proxmox VM tags to NetBox",
                         default_value=True),

            ConfigOption("track_vm_host",
                         bool,
                         description="add the Proxmox host as VM device reference (NetBox >= 3.3)",
                         default_value=False),

            ConfigOption(**config_option_permitted_subnets_definition),

            ConfigOptionGroup(title="filter",
                              description="""filters can be used to include/exclude certain objects from importing
                              into NetBox. Include filters are checked first and exclude filters after.
                              An object name has to pass both filters to be synced to NetBox.
                              If a filter is unset it will be ignored. Filters are all treated as regex expressions!
                              If more then one expression should match, a '|' needs to be used
                              """,
                              config_example="""Example: (exclude all VMs with "replica" in their name
                              and all VMs starting with "backup"): vm_exclude_filter = .*replica.*|^backup.*""",
                              options=[
                                  ConfigOption("cluster_exclude_filter",
                                               str,
                                               description="""If a cluster is excluded from sync then ALL VMs and HOSTS
                                               inside the cluster will be ignored!"""),
                                  ConfigOption("cluster_include_filter", str),
                                  ConfigOption("node_exclude_filter",
                                               str,
                                               description="This will only include/exclude the node, not the VM"),
                                  ConfigOption("node_include_filter", str),
                                  ConfigOption("vm_exclude_filter",
                                               str, description="simply include/exclude VMs"),
                                  ConfigOption("vm_include_filter", str)
                              ]),

            ConfigOptionGroup(title="relations",
                              options=[
                                  ConfigOption("cluster_site_relation",
                                               str,
                                               description="""\
                                               This option defines which Proxmox cluster is part of a NetBox site.
                                               This is done with a comma separated key = value list.
                                                 key: defines the cluster name as regex
                                                 value: defines the NetBox site name (use quotes if name contains commas)
                                               The keyword "<NONE>" can be used as a value.
                                               """,
                                               config_example="Cluster_NYC = New York, Cluster_MultiSite = <NONE>"),
                                  ConfigOption("host_site_relation",
                                               str,
                                               description="""Same as cluster site but on node level.
                                               If unset it will fall back to cluster_site_relation""",
                                               config_example="pve-nyc.* = New York, pve-ffm.* = Frankfurt"),
                                  ConfigOption("cluster_tenant_relation",
                                               str,
                                               description="""\
                                               This option defines which cluster/host/VM belongs to which tenant.
                                               This is done with a comma separated key = value list.
                                                 key: defines a hosts/VM name as regex
                                                 value: defines the NetBox tenant name (use quotes if name contains commas)
                                               """,
                                               config_example="Cluster_NYC.* = Customer A"),
                                  ConfigOption("host_tenant_relation", str, config_example="pve-01.* = Infrastructure"),
                                  ConfigOption("vm_tenant_relation", str, config_example="grafana.* = Infrastructure"),
                                  ConfigOption("host_platform_relation",
                                               str,
                                               description="""\
                                               This option defines custom platforms for Proxmox nodes.
                                               This is done with a comma separated key = value list.
                                                 key: defines a platform name as regex
                                                 value: defines the desired NetBox platform name""",
                                               config_example="Proxmox VE 8.* = Proxmox VE 8"),
                                  ConfigOption("vm_platform_relation", str,
                                               config_example="l26 = Linux, win10 = Windows 10"),
                                  ConfigOption("host_role_relation",
                                               str,
                                               description="""\
                                               Define the NetBox device role used for nodes. The default is
                                               set to "Server". This is done with a comma separated key = value list.
                                                 key: defines host(s) name as regex
                                                 value: defines the NetBox role name (use quotes if name contains commas)
                                               """,
                                               default_value=".* = Server"),
                                  ConfigOption("vm_role_relation",
                                               str,
                                               description="""\
                                               Define the NetBox device role used for VMs. This is done with a
                                               comma separated key = value list, same as 'host_role_relation'.
                                                 key: defines VM(s) name as regex
                                                 value: defines the NetBox role name (use quotes if name contains commas)
                                               """,
                                               config_example=".* = Server"),
                                  ConfigOption("cluster_tag_relation",
                                               str,
                                               description="""\
                                               Define NetBox tags which are assigned to a cluster, host or VM. This is
                                               done with a comma separated key = value list.
                                                 key: defines a hosts/VM name as regex
                                                 value: defines the NetBox tag (use quotes if name contains commas)
                                               """,
                                               config_example="Cluster_NYC.* = Infrastructure"),
                                  ConfigOption("host_tag_relation", str, config_example="pve-01.* = Infrastructure"),
                                  ConfigOption("vm_tag_relation", str, config_example="grafana.* = Infrastructure")
                              ]),

            ConfigOption("dns_name_lookup",
                         bool,
                         description="""Perform a reverse lookup for all collected IP addresses.
                         If a dns name was found it will be added to the IP address object in NetBox
                         """,
                         default_value=True),

            ConfigOption("custom_dns_servers",
                         str,
                         description="use custom DNS server to do the reverse lookups",
                         config_example="192.168.1.11, 192.168.1.12"),

            ConfigOption("set_primary_ip",
                         str,
                         description="""\
                         define how the primary IPs should be set
                         possible values:

                           always:     will remove primary IP from the object where this address is
                                       currently set as primary and moves it to new object

                           when-undefined:
                                       only sets primary IP if undefined, will cause ERRORs if same IP is
                                       assigned more then once to different hosts and IP is set as the
                                       objects primary IP

                           never:      don't set any primary IPs, will cause the same ERRORs
                                       as "when-undefined"
                         """,
                         default_value="when-undefined"),

            ConfigOption("skip_offline_vms",
                         bool,
                         description="""\
                         Skip virtual machines which are reported as offline.
                         ATTENTION: this option will keep purging stopped VMs if activated!
                         """,
                         default_value=False),

            ConfigOption("strip_host_domain_name",
                         bool,
                         description="""strip domain part from host name before syncing device to NetBox.
                         Host filters and host relations are still matched against the full host name
                         (FQDN) first and then the stripped name.""",
                         default_value=False),

            ConfigOption("strip_vm_domain_name",
                         bool,
                         description="strip domain part from VM name before syncing VM to NetBox",
                         default_value=False),

            ConfigOption("overwrite_device_interface_name",
                         bool,
                         description="""define if the name of the device interface discovered overwrites the
                         interface name in NetBox. The interface will only be matched by identical MAC address""",
                         default_value=True),

            ConfigOption("overwrite_vm_interface_name",
                         bool,
                         description="""define if the name of the VM interface discovered overwrites the
                         interface name in NetBox. The interface will only be matched by identical MAC address""",
                         default_value=True),

            ConfigOption("overwrite_device_platform",
                         bool,
                         description="""define if the platform of the device discovered overwrites the device
                         platform in NetBox.""",
                         default_value=True),

            ConfigOption("overwrite_vm_platform",
                         bool,
                         description="""define if the platform of the VM discovered overwrites the VM
                         platform in NetBox.""",
                         default_value=True),

            ConfigOption(**config_option_ip_tenant_inheritance_order_definition),

            ConfigOption("host_nic_exclude_by_mac_list",
                         str,
                         description="""defines a comma separated list of MAC addresses which should be excluded
                         from sync. Any host NIC with a matching MAC address will be excluded from sync.
                         """,
                         config_example="AA:BB:CC:11:22:33, 66:77:88:AA:BB:CC"
                         ),

            ConfigOption("vm_disk_and_ram_in_decimal",
                         bool,
                         description="""In NetBox version 4.1.0 and newer the VM disk and RAM values are displayed
                         in power of 10 instead of power of 2. If this values is set to true 4GB of RAM will be
                         set to a value of 4000 megabyte. If set to false 4GB of RAM will be reported as 4096MB.
                         The same behavior also applies for VM disk sizes.""",
                         default_value=True
                         ),

            ConfigOptionGroup(title="VLAN syncing",
                              description="""\
                              These options control if VLANs are sync to NetBox or if some VLANs are excluded from sync.
                              The exclude options can contain the site name as well (site-name/vlan). Site names and VLAN
                              names can be regex expressions. VLAN IDs can be single IDs or ranges.
                              """,
                              options=[
                                  ConfigOption("disable_vlan_sync",
                                               bool,
                                               description="disables syncing of any VLANs visible in Proxmox to NetBox",
                                               default_value=False),
                                  ConfigOption("vlan_sync_exclude_by_name",
                                               str,
                                               config_example="New York/Storage, Backup, Tokio/DMZ, Madrid/.*"),
                                  ConfigOption("vlan_sync_exclude_by_id",
                                               str,
                                               config_example="Frankfurt/25, 1023-1042"),
                                  ConfigOption("vlan_group_relation_by_name",
                                               str,
                                               description="""adds a relation to assign VLAN groups to matching VLANs
                                               by name. Same matching rules as the exclude_by_name option uses are applied.
                                               If name and id relations are defined, the name relation takes precedence.
                                               Fist match wins. Only newly discovered VLANs which are not present in
                                               NetBox will be assigned a VLAN group. Supported scopes for a VLAN group
                                               are "site", "site-group", "cluster" and "cluster-group". Scopes are buggy
                                               in NetBox https://github.com/netbox-community/netbox/issues/18706
                                               """,
                                               config_example="London/Vlan_.* = VLAN Group 1, Tokio/Vlan_.* = VLAN Group 2"),
                                  ConfigOption("vlan_group_relation_by_id",
                                               str,
                                               description="""adds a relation to assign VLAN groups to matching VLANs by ID.
                                               Same matching rules as the exclude_by_id option uses are applied.
                                               Fist match wins.  Only newly discovered VLANs which are not present in
                                               NetBox will be assigned a VLAN group.
                                               """,
                                               config_example="1023-1042 = VLAN Group 1, Tokio/2342 = VLAN Group 2")
                              ])
        ]

        super().__init__()

    def validate_options(self):

        for option in self.options:

            if option.value is None:
                continue

            if "filter" in option.key:

                re_compiled = None
                try:
                    re_compiled = re.compile(option.value)
                except Exception as e:
                    log.error(f"Problem parsing regular expression for '{self.source_name}.{option.key}': {e}")
                    self.set_validation_failed()

                option.set_value(re_compiled)

                continue

            if "relation" in option.key and "vlan_group_relation" not in option.key:

                relation_data = list()

                relation_type = option.key.split("_")[1]

                for relation in quoted_split(option.value):

                    object_name = relation.split("=")[0].strip(' "')
                    relation_name = relation.split("=")[1].strip(' "')

                    if len(object_name) == 0 or len(relation_name) == 0:
                        log.error(f"Config option '{relation}' malformed got '{object_name}' for "
                                  f"object name and '{relation_name}' for {relation_type} name.")
                        self.set_validation_failed()
                        continue

                    try:
                        re_compiled = re.compile(object_name)
                    except Exception as e:
                        log.error(f"Problem parsing regular expression '{object_name}' for '{relation}': {e}")
                        self.set_validation_failed()
                        continue

                    relation_data.append({
                        "object_regex": re_compiled,
                        "assigned_name": relation_name
                    })

                option.set_value(relation_data)

                continue

            if option.key == "set_primary_ip":
                if option.value not in ["always", "when-undefined", "never"]:
                    log.error(f"Primary IP option '{option.key}' value '{option.value}' invalid.")
                    self.set_validation_failed()

            if option.key == "custom_dns_servers":

                dns_name_lookup = self.get_option_by_name("dns_name_lookup")

                if not isinstance(dns_name_lookup, ConfigOption) or dns_name_lookup.value is False:
                    continue

                custom_dns_servers = quoted_split(option.value)

                tested_custom_dns_servers = list()
                for custom_dns_server in custom_dns_servers:
                    try:
                        tested_custom_dns_servers.append(str(ip_address(custom_dns_server)))
                    except ValueError:
                        log.error(f"Config option 'custom_dns_servers' value '{custom_dns_server}' "
                                  f"does not appear to be an IP address.")
                        self.set_validation_failed()

                option.set_value(tested_custom_dns_servers)

                continue

            if option.key == "ip_tenant_inheritance_order":

                option.set_value(quoted_split(option.value))

                for ip_tenant_inheritance in option.value:
                    if ip_tenant_inheritance not in ["device", "prefix", "disabled"]:
                        log.error(f"Config value '{ip_tenant_inheritance}' invalid for "
                                  f"config option 'ip_tenant_inheritance_order'!")
                        self.set_validation_failed()

                if len(option.value) > 2:
                    log.error("Config option 'ip_tenant_inheritance_order' can contain only 2 items max")
                    self.set_validation_failed()

            if option.key == "host_nic_exclude_by_mac_list":

                value_list = list()

                for mac_address in quoted_split(option.value) or list():

                    normalized_mac_address = normalize_mac_address(mac_address)

                    if len(f"{normalized_mac_address}") != 17:
                        log.error(f"MAC address '{mac_address}' for 'host_nic_exclude_by_mac_list' invalid.")
                        self.set_validation_failed()
                    else:
                        value_list.append(normalized_mac_address)

                option.set_value(value_list)

            if option.key in ["vlan_sync_exclude_by_name", "vlan_sync_exclude_by_id",
                              "vlan_group_relation_by_name", "vlan_group_relation_by_id"]:

                if option.key == "vlan_sync_exclude_by_name":
                    filter_class = FilterVLANByName
                    filter_type = "exclude"
                elif option.key == "vlan_group_relation_by_name":
                    filter_class = FilterVLANByName
                    filter_type = "group relation"
                elif option.key == "vlan_sync_exclude_by_id":
                    filter_class = FilterVLANByID
                    filter_type = "exclude"
                elif option.key == "vlan_group_relation_by_id":
                    filter_class = FilterVLANByID
                    filter_type = "group relation"
                else:
                    raise ValueError(f"unhandled config option {option.key}")

                value_list = list()

                for single_option_value in quoted_split(option.value) or list():

                    relation_name = None
                    object_name = single_option_value.split("=")[0].strip(' "')

                    if "relation" in option.key:

                        if "=" not in single_option_value:
                            log.error(f"Config option '{option.key}' malformed, got {single_option_value} but "
                                      f"needs key = value relation.")
                            self.set_validation_failed()
                            continue

                        relation_name = single_option_value.split("=")[1].strip(' "')

                        if relation_name is not None and len(relation_name) == 0:
                            log.error(f"Config option '{option.key}' malformed, got '{object_name}' as "
                                      f"object name and relation name was empty.")
                            self.set_validation_failed()
                            continue

                    vlan_filter = filter_class(object_name, filter_type)

                    if not vlan_filter.is_valid():
                        self.set_validation_failed()
                        continue

                    if "relation" in option.key:
                        value_list.append((vlan_filter, relation_name))
                    else:
                        value_list.append(vlan_filter)

                option.set_value(value_list)

        password = self.get_option_by_name("password")
        token_name = self.get_option_by_name("token_name")
        token_value = self.get_option_by_name("token_value")

        if token_name is not None and token_name.value is not None and \
                (token_value is None or token_value.value is None):
            log.error("Config option 'token_name' requires 'token_value' to be set.")
            self.set_validation_failed()

        if token_value is not None and token_value.value is not None and \
                (token_name is None or token_name.value is None):
            log.error("Config option 'token_value' requires 'token_name' to be set.")
            self.set_validation_failed()

        if (password is None or password.value is None) and \
                (token_value is None or token_value.value is None):
            log.error("Either 'password' or 'token_name'/'token_value' must be set for Proxmox authentication.")
            self.set_validation_failed()

        permitted_subnets_option = self.get_option_by_name("permitted_subnets")

        if permitted_subnets_option is not None:
            permitted_subnets = PermittedSubnets(permitted_subnets_option.value)
            if permitted_subnets.validation_failed is True:
                self.set_validation_failed()

            permitted_subnets_option.set_value(permitted_subnets)

# EOF
