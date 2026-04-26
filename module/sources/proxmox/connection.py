# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2025 Ricardo Bartels. All rights reserved.
#
#  netbox-sync.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

import re
from itertools import zip_longest
from ipaddress import ip_interface, ip_address, ip_network

from packaging import version

from module.sources.common.source_base import SourceBase
from module.sources.proxmox.config import ProxmoxConfig
from module.common.logging import get_logger, DEBUG3
from module.common.misc import grab, get_string_or_none, plural
from module.common.support import normalize_mac_address
from module.netbox.inventory import NetBoxInventory
from module.netbox import *

proxmoxer_available = True
try:
    # noinspection PyUnresolvedReferences
    from proxmoxer import ProxmoxAPI
except ImportError:
    proxmoxer_available = False

log = get_logger()


class ProxmoxHandler(SourceBase):
    """
    Source class to import data from a Proxmox instance and add/update NetBox objects.
    """

    dependent_netbox_objects = [
        NBTag,
        NBManufacturer,
        NBDeviceType,
        NBPlatform,
        NBClusterType,
        NBClusterGroup,
        NBDeviceRole,
        NBSite,
        NBSiteGroup,
        NBCluster,
        NBDevice,
        NBVM,
        NBVMInterface,
        NBInterface,
        NBIPAddress,
        NBPrefix,
        NBTenant,
        NBVRF,
        NBVLAN,
        NBVLANGroup,
        NBCustomField,
        NBVirtualDisk,
        NBMACAddress
    ]

    source_type = "proxmox"

    def __init__(self, name=None):

        if name is None:
            raise ValueError(f"Invalid value for attribute 'name': '{name}'.")

        self.inventory = NetBoxInventory()
        self.name = name

        # parse settings
        settings_handler = ProxmoxConfig()
        settings_handler.source_name = self.name
        self.settings = settings_handler.parse()

        self.set_source_tag()
        self.site_name = f"Proxmox: {name}"

        if self.settings.enabled is False:
            log.info(f"Source '{name}' is currently disabled. Skipping")
            return

        if proxmoxer_available is False:
            log.error("Python module 'proxmoxer' missing. Please install proxmoxer to use Proxmox sources.")
            return

        self.proxmox = None
        self.cluster_status = list()
        self.cluster_node_map = dict()
        self.cluster_name = None
        self.processed_vm_names = dict()
        self.storage_content_cache = dict()

        if self.create_api_session() is False:
            log.info(f"Source '{name}' is currently unavailable. Skipping")
            return

        self.init_successful = True

    def create_api_session(self):
        """
        Initialize API session with Proxmox

        Returns
        -------
        bool: if initialization was successful or not
        """

        if self.proxmox is not None:
            return True

        if proxmoxer_available is False:
            return False

        log.debug(f"Starting Proxmox API connection to '{self.settings.host_fqdn}'")

        user = self.settings.username
        if user is not None and "@" not in user and self.settings.realm is not None:
            user = f"{user}@{self.settings.realm}"

        connection_params = {
            "host": self.settings.host_fqdn,
            "user": user,
            "port": self.settings.port,
            "verify_ssl": self.settings.validate_tls_certs
        }

        if self.settings.token_name is not None and self.settings.token_value is not None:
            connection_params.update({
                "token_name": self.settings.token_name,
                "token_value": self.settings.token_value
            })
        else:
            connection_params.update({
                "password": self.settings.password
            })

        if self.settings.timeout is not None:
            connection_params["timeout"] = self.settings.timeout

        try:
            self.proxmox = ProxmoxAPI(**connection_params)
            # simple test call
            _ = self.proxmox.version.get()
        except Exception as e:
            log.error(f"Unable to connect to Proxmox API '{self.settings.host_fqdn}': {e}")
            self.proxmox = None
            return False

        log.info(f"Successfully connected to Proxmox API '{self.settings.host_fqdn}'")

        return True

    def finish(self):
        # proxmoxer uses stateless requests, no explicit close required
        return

    def apply(self):
        """
        Main source handler method. This method is called for each source from "main" program
        to retrieve data from it source and apply it to the NetBox inventory.

        Every update of new/existing objects fot this source has to happen here.
        """

        if self.proxmox is None:
            return

        log.info(f"Query data from Proxmox: '{self.settings.host_fqdn}'")

        self.update_basic_data()

        # query cluster status
        self.cluster_status = self.get_cluster_status()
        self.cluster_node_map = {
            grab(x, "name"): x for x in self.cluster_status if grab(x, "type") == "node" and grab(x, "name") is not None
        }

        self.cluster_name = self.get_cluster_name()

        # add cluster
        nb_cluster = self.add_cluster()
        if nb_cluster is None:
            log.error("Unable to create Proxmox cluster object. Skipping source.")
            return

        # iterate over nodes
        for node in self.get_nodes():

            node_name = get_string_or_none(grab(node, "node", fallback=grab(node, "name")))
            if node_name is None:
                continue

            nb_device = self.add_node(node, nb_cluster)
            if nb_device is None:
                continue

            if self.settings.include_qemu is True:
                self.add_qemu_vms(node_name, nb_cluster, nb_device)

            if self.settings.include_lxc is True:
                self.add_lxc_vms(node_name, nb_cluster, nb_device)

    @staticmethod
    def passes_filter(name, include_filter, exclude_filter):
        """
        checks if object name passes a defined object filter.
        """

        if include_filter is not None and not include_filter.match(name):
            log.debug(f"Object '{name}' did not match include filter '{include_filter.pattern}'. Skipping")
            return False

        if exclude_filter is not None and exclude_filter.match(name):
            log.debug(f"Object '{name}' matched exclude filter '{exclude_filter.pattern}'. Skipping")
            return False

        return True

    @staticmethod
    def passes_filter_by_names(names, include_filter, exclude_filter):
        """
        checks if any submitted object name passes a defined object filter.
        """

        filtered_names = list()
        for name in names or list():
            this_name = get_string_or_none(name)
            if this_name is not None:
                filtered_names.append(this_name)

        if len(filtered_names) == 0:
            return False

        if include_filter is not None and not any(include_filter.match(x) for x in filtered_names):
            log.debug(f"Object names '{', '.join(filtered_names)}' did not match include filter "
                      f"'{include_filter.pattern}'. Skipping")
            return False

        if exclude_filter is not None and any(exclude_filter.match(x) for x in filtered_names):
            log.debug(f"Object names '{', '.join(filtered_names)}' matched exclude filter "
                      f"'{exclude_filter.pattern}'. Skipping")
            return False

        return True

    def get_site_name(self, object_type, object_name, cluster_name=""):
        """
        Return a site name for a NBCluster or NBDevice depending on config options
        host_site_relation and cluster_site_relation
        """

        if object_type not in [NBCluster, NBDevice]:
            raise ValueError(f"Object must be a '{NBCluster.name}' or '{NBDevice.name}'.")

        object_name_log = object_name
        if isinstance(object_name, list) and len(object_name) > 0:
            object_name_log = object_name[0]

        log.debug2(f"Trying to find site name for {object_type.name} '{object_name_log}'")

        relation_name = "host_site_relation" if object_type == NBDevice else "cluster_site_relation"

        site_name = self.get_object_relation(object_name, relation_name)

        if object_type == NBDevice and site_name is None:
            site_name = self.get_site_name(NBCluster, cluster_name)
            if site_name is not None:
                log.debug2(f"Found a matching cluster site for {object_name_log}, using site '{site_name}'")

        if site_name is None:
            site_name = self.site_name
            log.debug(f"No site relation for '{object_name_log}' found, using default site '{site_name}'")

        if object_type == NBCluster and site_name == "<NONE>":
            site_name = None
            log.debug2(f"Site relation for '{object_name_log}' set to None")

        return site_name

    def get_object_relation(self, name, relation, fallback=None):
        """
        Resolve relation mapping based on regex.
        """

        names_to_check = list()
        if isinstance(name, list):
            for this_name in name:
                name_value = get_string_or_none(this_name)
                if name_value is not None and name_value not in names_to_check:
                    names_to_check.append(name_value)
        else:
            name_value = get_string_or_none(name)
            if name_value is not None:
                names_to_check.append(name_value)

        relation_is_tag = grab(f"{relation}".split("_"), "1") == "tag"

        for this_name in names_to_check:
            resolved_list = list()
            for single_relation in grab(self.settings, relation, fallback=list()):
                object_regex = single_relation.get("object_regex")
                if object_regex.match(this_name):
                    resolved_name = single_relation.get("assigned_name")
                    log.debug2(f"Found a matching {relation} '{resolved_name}' ({object_regex.pattern}) "
                               f"for {this_name}")
                    resolved_list.append(resolved_name)

            if relation_is_tag is True:
                if len(resolved_list) > 0:
                    return resolved_list
                continue

            if len(resolved_list) >= 1:
                resolved_name = resolved_list[0]
                if len(resolved_list) > 1:
                    log.debug(f"Found {len(resolved_list)} matches for {this_name} in {relation}. "
                              f"Using first on: {resolved_name}")

                return resolved_name

        if relation_is_tag is True:
            return list()

        return fallback

    def get_object_based_on_macs(self, object_type, mac_list=None):
        """
        Try to find a NetBox object based on list of MAC addresses.
        """

        object_to_return = None

        if object_type not in [NBDevice, NBVM]:
            raise ValueError(f"Object must be a '{NBVM.name}' or '{NBDevice.name}'.")

        if mac_list is None or not isinstance(mac_list, list) or len(mac_list) == 0:
            return

        interface_typ = NBInterface if object_type == NBDevice else NBVMInterface

        objects_with_matching_macs = dict()
        matching_object = None

        for interface in self.inventory.get_all_items(interface_typ):

            if grab(interface, "data.mac_address") in mac_list:

                matching_object = grab(interface, f"data.{interface.secondary_key}")
                if not isinstance(matching_object, (NBDevice, NBVM)):
                    continue

                log.debug2("Found matching MAC '%s' on %s '%s'" %
                           (grab(interface, "data.mac_address"), object_type.name,
                            matching_object.get_display_name(including_second_key=True)))

                if objects_with_matching_macs.get(matching_object) is None:
                    objects_with_matching_macs[matching_object] = 1
                else:
                    objects_with_matching_macs[matching_object] += 1

        num_devices_witch_matching_macs = len(objects_with_matching_macs.keys())

        if num_devices_witch_matching_macs == 1:
            object_to_return = list(objects_with_matching_macs.keys())[0]

        elif num_devices_witch_matching_macs > 1:

            log.debug2(f"Found {num_devices_witch_matching_macs} {object_type.name}s with matching MAC addresses")

            first_choice, second_choice = \
                sorted(objects_with_matching_macs, key=objects_with_matching_macs.get, reverse=True)[0:2]

            first_choice_matches = objects_with_matching_macs.get(first_choice)
            second_choice_matches = objects_with_matching_macs.get(second_choice)

            log.debug2(f"The top candidate {first_choice.get_display_name()} with {first_choice_matches} matches")
            log.debug2(f"The second candidate {second_choice.get_display_name()} with {second_choice_matches} matches")

            matching_ratio = first_choice_matches / second_choice_matches

            if matching_ratio >= 2.0:
                log.debug2(f"The matching ratio of {matching_ratio} is high enough "
                           f"to select {first_choice.get_display_name()} as desired {object_type.name}")
                object_to_return = first_choice
            else:
                log.debug2("Both candidates have a similar amount of "
                           "matching interface MAC addresses. Using NONE of them!")

        return object_to_return

    def get_object_based_on_primary_ip(self, object_type, primary_ip4=None, primary_ip6=None):
        """
        Try to find a NBDevice or NBVM based on the primary IP address.
        """

        def _matches_device_primary_ip(device_primary_ip, ip_needle):

            ip = None
            if device_primary_ip is not None and ip_needle is not None:
                if isinstance(device_primary_ip, dict):
                    ip = grab(device_primary_ip, "address")

                elif isinstance(device_primary_ip, int):
                    ip = self.inventory.get_by_id(NBIPAddress, nb_id=device_primary_ip)
                    ip = grab(ip, "data.address")

                if ip is not None and ip.split("/")[0] == ip_needle:
                    return True

            return False

        if object_type not in [NBDevice, NBVM]:
            raise ValueError(f"Object must be a '{NBVM.name}' or '{NBDevice.name}'.")

        if primary_ip4 is None and primary_ip6 is None:
            return

        if primary_ip4 is not None:
            primary_ip4 = str(primary_ip4).split("/")[0]

        if primary_ip6 is not None:
            primary_ip6 = str(primary_ip6).split("/")[0]

        for device in self.inventory.get_all_items(object_type):

            if _matches_device_primary_ip(grab(device, "data.primary_ip4"), primary_ip4) is True:
                log.debug2(f"Found existing host '{device.get_display_name()}' "
                           f"based on the primary IPv4 '{primary_ip4}'")
                return device

            if _matches_device_primary_ip(grab(device, "data.primary_ip6"), primary_ip6) is True:
                log.debug2(f"Found existing host '{device.get_display_name()}' "
                           f"based on the primary IPv6 '{primary_ip6}'")
                return device

    def add_device_vm_to_inventory(self, object_type, object_data, pnic_data=None, vnic_data=None,
                                   nic_ips=None, p_ipv4=None, p_ipv6=None, disk_data=None):
        """
        Add/update device/VM object in inventory based on gathered data.
        """

        if object_type not in [NBDevice, NBVM]:
            raise ValueError(f"Object must be a '{NBVM.name}' or '{NBDevice.name}'.")

        if nic_ips is None:
            nic_ips = dict()

        if log.level == DEBUG3:
            log.debug3("function: add_device_vm_to_inventory")
            log.debug3(f"Object type {object_type}")

        device_vm_object = self.inventory.get_by_data(object_type, data=object_data)

        if device_vm_object is None:
            mac_source_data = vnic_data if object_type == NBVM else pnic_data
            nic_macs = [x.get("mac_address") for x in (mac_source_data or dict()).values() if x.get("mac_address")]
            device_vm_object = self.get_object_based_on_macs(object_type, nic_macs)

        if device_vm_object is None and object_data.get("serial") is not None:
            device_vm_object = self.inventory.get_by_data(object_type, data={"serial": object_data.get("serial")})

        if device_vm_object is None:
            device_vm_object = self.get_object_based_on_primary_ip(object_type, p_ipv4, p_ipv6)

        if device_vm_object is None and object_type == NBDevice:
            object_name = object_data.get("name")
            if object_name is not None:
                matched_devices = [
                    device for device in self.inventory.get_all_items(NBDevice)
                    if f"{grab(device, 'data.name')}".lower() == f"{object_name}".lower()
                ]
                if len(matched_devices) == 1:
                    device_vm_object = matched_devices[0]
                    log.debug2(f"Found existing device '{device_vm_object.get_display_name()}' "
                               f"by name only for '{object_name}'")
                elif len(matched_devices) > 1:
                    log.warning(f"Found {len(matched_devices)} devices named '{object_name}' across sites. "
                                f"Skipping name-only match.")

        if device_vm_object is None:
            object_name = object_data.get(object_type.primary_key)
            log.debug(f"No existing {object_type.name} object for {object_name}. Creating a new {object_type.name}.")
            device_vm_object = self.inventory.add_object(object_type, data=object_data, source=self)
        else:
            if object_type == NBVM and self.settings.overwrite_vm_platform is False and \
                    object_data.get("platform") is not None:
                del object_data["platform"]

            if object_type == NBDevice and self.settings.overwrite_device_platform is False and \
                    object_data.get("platform") is not None:
                del object_data["platform"]

            device_vm_object.update(data=object_data, source=self)

        # update VM disk data information
        if version.parse(self.inventory.netbox_api_version) >= version.parse("3.7.0") and \
                object_type == NBVM and disk_data is not None and len(disk_data) > 0:

            disk_zip_list = zip_longest(
                sorted(device_vm_object.get_virtual_disks(), key=lambda x: grab(x, "data.name")),
                sorted(disk_data, key=lambda x: x.get("name")),
                fillvalue="X")

            for existing, discovered in disk_zip_list:
                if existing == "X":
                    self.inventory.add_object(NBVirtualDisk, source=self,
                                              data={**discovered, **{"virtual_machine": device_vm_object}})
                elif discovered == "X":
                    log.info(f"{existing.name} '{existing.get_display_name(including_second_key=True)}' has been deleted")
                    existing.deleted = True
                else:
                    existing.update(data=discovered, source=self)

        # compile all nic data into one dictionary
        if object_type == NBVM:
            nic_data = vnic_data or dict()
        else:
            nic_data = {**(pnic_data or dict()), **(vnic_data or dict())}

        nic_object_dict = self.map_object_interfaces_to_current_interfaces(device_vm_object, nic_data)

        primary_ipv4_object = None
        primary_ipv6_object = None

        if p_ipv4 is not None:
            try:
                primary_ipv4_object = ip_interface(p_ipv4)
            except ValueError:
                log.error(f"Primary IPv4 ({p_ipv4}) does not appear to be a valid IP address (needs included suffix).")

        if p_ipv6 is not None:
            try:
                primary_ipv6_object = ip_interface(p_ipv6)
            except ValueError:
                log.error(f"Primary IPv6 ({p_ipv6}) does not appear to be a valid IP address (needs included suffix).")

        for int_name, int_data in nic_data.items():

            if nic_object_dict.get(int_name) is not None:
                if object_type == NBDevice and self.settings.overwrite_device_interface_name is False:
                    del int_data["name"]
                if object_type == NBVM and self.settings.overwrite_vm_interface_name is False:
                    del int_data["name"]

            nic_object, ip_address_objects = self.add_update_interface(nic_object_dict.get(int_name), device_vm_object,
                                                                       int_data, nic_ips.get(int_name, list()))

            for ip_object in ip_address_objects:

                if ip_object is None:
                    continue

                ip_interface_object = ip_interface(grab(ip_object, "data.address"))

                if ip_interface_object not in [primary_ipv4_object, primary_ipv6_object]:
                    continue

                set_this_primary_ip = False
                ip_version = ip_interface_object.ip.version
                if self.settings.set_primary_ip == "always":

                    for object_type_loop in [NBDevice, NBVM]:

                        if ip_object.is_new is True:
                            break

                        for devices_vms in self.inventory.get_all_items(object_type_loop):

                            this_primary_ip = grab(devices_vms, f"data.primary_ip{ip_version}")

                            if devices_vms == device_vm_object:
                                continue

                            if this_primary_ip == ip_object:
                                devices_vms.unset_attribute(f"primary_ip{ip_version}")

                    set_this_primary_ip = True

                elif self.settings.set_primary_ip != "never" and \
                        grab(device_vm_object, f"data.primary_ip{ip_version}") is None:
                    set_this_primary_ip = True

                if set_this_primary_ip is True:

                    log.debug(f"Setting IP '{grab(ip_object, 'data.address')}' as primary IPv{ip_version} for "
                              f"'{device_vm_object.get_display_name()}'")
                    device_vm_object.update(data={f"primary_ip{ip_version}": ip_object})

        return device_vm_object
    def update_basic_data(self):
        """
        Adds/updates source tag and ensures basic NetBox objects.
        """

        self.inventory.add_update_object(NBTag, data={
            "name": self.source_tag,
            "description": f"Marks objects synced from Proxmox '{self.name}' "
                           f"({self.settings.host_fqdn}) to this NetBox Instance."
        })

        proxmox_custom_field_group = "Proxmox"
        proxmox_custom_fields = [
            {
                "name": "proxmox_qemu_agent",
                "label": "QEMU Guest Agent",
                "object_types": ["virtualization.virtualmachine"],
                "type": "boolean",
                "required": False,
                "group_name": proxmox_custom_field_group,
                "description": "Proxmox QEMU Guest Agent"
            },
            {
                "name": "proxmox_start_at_boot",
                "label": "Start at Boot",
                "object_types": ["virtualization.virtualmachine"],
                "type": "boolean",
                "required": False,
                "group_name": proxmox_custom_field_group,
                "description": "Proxmox Start at Boot Option"
            },
            {
                "name": "proxmox_unprivileged_container",
                "label": "Unprivileged Container",
                "object_types": ["virtualization.virtualmachine"],
                "type": "boolean",
                "required": False,
                "group_name": proxmox_custom_field_group,
                "description": "Proxmox Unprivileged Container"
            },
            {
                "name": "proxmox_vm_id",
                "label": "VM ID",
                "object_types": ["virtualization.virtualmachine"],
                "type": "integer",
                "required": False,
                "group_name": proxmox_custom_field_group,
                "description": "Proxmox Virtual Machine or Container ID"
            }
        ]

        for custom_field_data in proxmox_custom_fields:
            custom_field = self.add_update_custom_field(custom_field_data)
            group_name = custom_field_data.get("group_name")
            if group_name and grab(custom_field, "data.group_name") != group_name:
                custom_field.update(data={"group_name": group_name}, source=self)

        this_site_object = self.inventory.get_by_data(NBSite, data={"name": self.site_name})

        if this_site_object is not None:
            this_site_object.update(data={
                "name": self.site_name,
                "comments": f"A default virtual site created to house objects "
                            "that have been synced from this Proxmox instance "
                            "and have no predefined site assigned."
            })

        server_role_object = self.inventory.get_by_data(NBDeviceRole, data={"name": "Server"})

        if server_role_object is not None:
            role_data = {"name": "Server", "vm_role": True}
            if server_role_object.is_new is True:
                role_data["color"] = "9e9e9e"

            server_role_object.update(data=role_data)

    def get_cluster_status(self):
        try:
            return self.proxmox.cluster.status.get()
        except Exception as e:
            log.warning(f"Unable to retrieve Proxmox cluster status: {e}")
            return list()

    def get_cluster_name(self):
        if self.settings.cluster_name is not None:
            return self.settings.cluster_name

        for status in self.cluster_status:
            if grab(status, "type") == "cluster":
                cluster_name = get_string_or_none(grab(status, "name"))
                if cluster_name is not None:
                    return cluster_name

        host_fqdn = get_string_or_none(self.settings.host_fqdn)
        if host_fqdn is not None:
            return host_fqdn

        return f"Proxmox-{self.name}"

    def add_cluster(self):
        cluster_name = self.cluster_name

        if self.passes_filter(cluster_name,
                              self.settings.cluster_include_filter,
                              self.settings.cluster_exclude_filter) is False:
            log.info(f"Cluster '{cluster_name}' excluded by filter. Skipping source.")
            return None

        site_name = self.get_site_name(NBCluster, cluster_name)
        tenant_name = self.get_object_relation(cluster_name, "cluster_tenant_relation")
        cluster_tags = self.get_object_relation(cluster_name, "cluster_tag_relation")

        cluster_type_name = self.settings.cluster_type
        self.inventory.add_update_object(NBClusterType, data={"name": cluster_type_name})

        data = {
            "name": cluster_name,
            "type": {"name": cluster_type_name}
        }

        if site_name is not None:
            data["site"] = {"name": site_name}
        if tenant_name is not None:
            data["tenant"] = {"name": tenant_name}
        if len(cluster_tags) > 0:
            data["tags"] = cluster_tags

        cluster_object = self.inventory.add_update_object(NBCluster, data=data, source=self)

        return cluster_object

    def get_nodes(self):
        try:
            return self.proxmox.nodes.get()
        except Exception as e:
            log.error(f"Unable to retrieve Proxmox nodes: {e}")
            return list()

    def get_node_status(self, node_name):
        try:
            return self.proxmox.nodes(node_name).status.get()
        except Exception as e:
            log.warning(f"Unable to retrieve status for node '{node_name}': {e}")
            return dict()

    def get_node_network(self, node_name):
        try:
            return self.proxmox.nodes(node_name).network.get()
        except Exception as e:
            log.warning(f"Unable to retrieve network interfaces for node '{node_name}': {e}")
            return list()

    @staticmethod
    def netmask_to_prefix(netmask):
        if netmask is None:
            return None

        try:
            return ip_network(f"0.0.0.0/{netmask}").prefixlen
        except ValueError:
            try:
                return int(netmask)
            except ValueError:
                return None

    def build_ip_address(self, address, cidr=None, netmask=None):
        if address is None:
            return None

        address = str(address).strip()
        if "/" in address:
            return address

        prefix = None
        if cidr is not None:
            try:
                prefix = int(cidr)
            except (TypeError, ValueError):
                prefix = None

        if prefix is None:
            prefix = self.netmask_to_prefix(netmask)

        if prefix is None:
            try:
                ip_a = ip_address(address)
                prefix = 32 if ip_a.version == 4 else 128
            except ValueError:
                return None

        return f"{address}/{prefix}"

    def add_node(self, node, nb_cluster):

        api_node_name = get_string_or_none(grab(node, "node", fallback=grab(node, "name")))
        if api_node_name is None:
            return None

        short_node_name = api_node_name.split(".")[0]

        # Proxmox often reports short node names only; derive an FQDN candidate from source host_fqdn.
        node_name_fqdn = None
        if "." in api_node_name:
            node_name_fqdn = api_node_name
        else:
            source_host_fqdn = get_string_or_none(self.settings.host_fqdn)
            source_host_fqdn_is_ip = False
            if source_host_fqdn is not None:
                try:
                    ip_address(source_host_fqdn)
                    source_host_fqdn_is_ip = True
                except ValueError:
                    pass

            if source_host_fqdn is not None and "." in source_host_fqdn and source_host_fqdn_is_ip is False:
                source_short_name = source_host_fqdn.split(".")[0]
                source_domain_suffix = source_host_fqdn[len(source_short_name):]
                if source_domain_suffix.startswith("."):
                    if api_node_name == source_short_name:
                        node_name_fqdn = source_host_fqdn
                    else:
                        node_name_fqdn = f"{api_node_name}{source_domain_suffix}"

        node_name = node_name_fqdn or api_node_name
        if self.settings.strip_host_domain_name is True:
            node_name = short_node_name

        host_names_to_match = list()
        for host_name in [api_node_name, node_name_fqdn, short_node_name, node_name]:
            if host_name is not None and host_name not in host_names_to_match:
                host_names_to_match.append(host_name)

        if self.passes_filter_by_names(host_names_to_match,
                                       self.settings.node_include_filter,
                                       self.settings.node_exclude_filter) is False:
            return None

        node_status = grab(node, "status", fallback="")
        node_online = grab(node, "online")
        if node_online is None:
            node_online = 1 if f"{node_status}".lower() == "online" else 0

        status = "active" if node_online == 1 else "offline"

        site_name = self.get_site_name(NBDevice, host_names_to_match, self.cluster_name)
        tenant_name = self.get_object_relation(host_names_to_match, "host_tenant_relation")
        role_name = self.get_object_relation(host_names_to_match, "host_role_relation", fallback="Server")
        host_tags = self.get_object_relation(host_names_to_match, "host_tag_relation")

        node_status_details = self.get_node_status(api_node_name)
        host_platform_candidates = self.get_host_platform_candidates(node_status_details)
        platform = None
        if len(host_platform_candidates) > 0:
            platform = self.get_object_relation(host_platform_candidates,
                                                "host_platform_relation",
                                                fallback=host_platform_candidates[0])

        host_data = {
            "name": node_name,
            "device_role": {
                "name": role_name
            },
            "status": status,
            "cluster": nb_cluster
        }

        if site_name is not None:
            host_data["site"] = {"name": site_name}
        if tenant_name is not None:
            host_data["tenant"] = {"name": tenant_name}
        if platform is not None:
            host_data["platform"] = {"name": platform}
        if len(host_tags) > 0:
            host_data["tags"] = host_tags

        pnic_data = dict()
        nic_ips = dict()
        primary_ipv4 = None
        primary_ipv6 = None

        if self.settings.collect_node_interfaces is True:
            pnic_data, nic_ips = self.parse_node_interfaces(api_node_name)

            preferred_ip = grab(self.cluster_node_map.get(api_node_name), "ip")
            if preferred_ip is None and short_node_name != api_node_name:
                preferred_ip = grab(self.cluster_node_map.get(short_node_name), "ip")
            if preferred_ip is None and node_name_fqdn is not None and node_name_fqdn != api_node_name:
                preferred_ip = grab(self.cluster_node_map.get(node_name_fqdn), "ip")
            primary_ipv4, primary_ipv6 = self.pick_primary_ips(nic_ips, preferred_ip)

        device_object = self.add_device_vm_to_inventory(NBDevice, host_data, pnic_data=pnic_data,
                                                        vnic_data=dict(), nic_ips=nic_ips,
                                                        p_ipv4=primary_ipv4, p_ipv6=primary_ipv6)

        return device_object

    def parse_node_interfaces(self, node_name):

        pnic_data = dict()
        nic_ips = dict()

        def _extract_mac_address(iface_data):
            mac_keys = ["hwaddr", "macaddr", "mac", "link_address", "linkaddr", "address"]
            for key in mac_keys:
                value = grab(iface_data, key)
                if value is None:
                    continue
                value = str(value).strip()
                if re.fullmatch(r"[0-9A-Fa-f]{12}", value) or \
                        re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", value):
                    return normalize_mac_address(value)
            return None

        for iface in self.get_node_network(node_name):

            iface_name = get_string_or_none(grab(iface, "iface"))
            if iface_name is None or iface_name.lower() == "lo":
                continue

            iface_type = get_string_or_none(grab(iface, "type"))
            iface_type_lower = f"{iface_type}".lower()

            mac_address = _extract_mac_address(iface)
            if mac_address is not None and mac_address in (self.settings.host_nic_exclude_by_mac_list or list()):
                continue

            netbox_type = "other"
            if iface_type_lower in ["bridge", "bond", "vlan", "ovsbridge", "ovs", "tap", "veth", "vxlan"]:
                netbox_type = "virtual"

            description_parts = list()
            if iface_type is not None:
                description_parts.append(f"type: {iface_type}")

            bridge_ports = get_string_or_none(grab(iface, "bridge_ports"))
            if bridge_ports is not None:
                description_parts.append(f"ports: {bridge_ports}")

            slaves = get_string_or_none(grab(iface, "slaves"))
            if slaves is not None:
                description_parts.append(f"slaves: {slaves}")

            iface_data = {
                "name": iface_name,
                "enabled": bool(grab(iface, "active", fallback=True)),
                "type": netbox_type
            }

            if mac_address is not None:
                iface_data["mac_address"] = mac_address

            if len(description_parts) > 0:
                iface_data["description"] = ", ".join(description_parts)

            pnic_data[iface_name] = iface_data

            nic_ips[iface_name] = list()

            address = self.build_ip_address(grab(iface, "address"), grab(iface, "cidr"), grab(iface, "netmask"))
            if address is not None and self.settings.permitted_subnets.permitted(address, iface_name):
                nic_ips[iface_name].append(address)

            address6 = self.build_ip_address(grab(iface, "address6"), grab(iface, "cidr6"), grab(iface, "netmask6"))
            if address6 is not None and self.settings.permitted_subnets.permitted(address6, iface_name):
                nic_ips[iface_name].append(address6)

        return pnic_data, nic_ips

    @staticmethod
    def pick_primary_ips(nic_ips, preferred_ip=None):
        primary_ipv4 = None
        primary_ipv6 = None

        if preferred_ip is not None:
            for ips in nic_ips.values():
                for ip in ips:
                    if ip.split("/")[0] != preferred_ip:
                        continue
                    try:
                        ip_obj = ip_interface(ip)
                    except ValueError:
                        continue
                    if ip_obj.version == 4:
                        primary_ipv4 = ip
                    elif ip_obj.version == 6:
                        primary_ipv6 = ip

        for ips in nic_ips.values():
            for ip in ips:
                try:
                    ip_obj = ip_interface(ip)
                except ValueError:
                    continue
                if ip_obj.version == 4 and primary_ipv4 is None:
                    primary_ipv4 = ip
                if ip_obj.version == 6 and primary_ipv6 is None:
                    primary_ipv6 = ip

        return primary_ipv4, primary_ipv6

    @staticmethod
    def parse_proxmox_storage_value(value):
        if not isinstance(value, str):
            return None

        parts = [x.strip() for x in value.split(",") if x.strip() != ""]
        if len(parts) == 0:
            return None

        source = parts[0]
        options = dict()
        for part in parts[1:]:
            if "=" in part:
                key, option_value = part.split("=", 1)
                options[key.strip()] = option_value.strip()
            else:
                options[part.strip()] = True

        storage = None
        volume = None
        path = None
        if ":" in source:
            storage, volume = source.split(":", 1)
        else:
            path = source

        return {
            "storage": storage,
            "volume": volume,
            "path": path,
            "options": options
        }

    @staticmethod
    def parse_proxmox_size_to_mib(value):
        if value is None:
            return None

        if isinstance(value, (int, float)):
            if value <= 0:
                return None
            return float(value) / (1024 * 1024)

        value = str(value).strip()
        if value == "":
            return None

        match = re.match(r"^([0-9]*\.?[0-9]+)\s*([KMGTPE]?)\s*(?:i?B)?$", value, re.IGNORECASE)
        if match is None:
            return None

        size_value = float(match.group(1))
        unit = match.group(2).upper()

        multipliers = {
            "": 1 / (1024 * 1024),
            "K": 1 / 1024,
            "M": 1,
            "G": 1024,
            "T": 1024 * 1024,
            "P": 1024 * 1024 * 1024,
            "E": 1024 * 1024 * 1024 * 1024
        }

        return size_value * multipliers.get(unit, 1)

    def parse_proxmox_disk_size(self, size_value):
        size_mib = self.parse_proxmox_size_to_mib(size_value)
        if size_mib is None:
            return None

        size_mb = int(size_mib)
        if size_mb < 1:
            size_mb = 1

        if self.settings.vm_disk_and_ram_in_decimal:
            size_mb = int(size_mb / 1024 * 1000)
            if size_mb < 1:
                size_mb = 1

        return size_mb

    @staticmethod
    def build_disk_description(parsed_disk, option_keys):
        if parsed_disk is None:
            return None

        description_parts = list()
        storage = parsed_disk.get("storage")
        volume = parsed_disk.get("volume")
        path = parsed_disk.get("path")

        if storage is not None:
            description_parts.append(f"{storage}:{volume}")
        elif path is not None:
            description_parts.append(path)

        options = parsed_disk.get("options", dict())
        for option_key in option_keys:
            if option_key in options:
                description_parts.append(f"{option_key}={options.get(option_key)}")

        if len(description_parts) == 0:
            return None

        return ", ".join(description_parts)

    def get_storage_content(self, node_name, storage):
        if node_name is None or storage is None:
            return list()

        cache_key = f"{node_name}|{storage}"
        if cache_key in self.storage_content_cache:
            return self.storage_content_cache.get(cache_key, list())

        try:
            content = self.proxmox.nodes(node_name).storage(storage).content.get()
        except Exception as e:
            log.debug(f"Unable to retrieve storage content for '{storage}' on '{node_name}': {e}")
            content = list()

        if not isinstance(content, list):
            content = list()

        self.storage_content_cache[cache_key] = content
        return content

    def get_disk_size_from_storage(self, node_name, parsed_disk):
        storage = parsed_disk.get("storage")
        volume = parsed_disk.get("volume")
        if storage is None or volume is None:
            return None

        content = self.get_storage_content(node_name, storage)
        if len(content) == 0:
            return None

        volid = f"{storage}:{volume}"
        for item in content:
            if grab(item, "volid") != volid:
                continue
            return self.parse_proxmox_disk_size(grab(item, "size"))

        return None

    def get_qemu_disk_data(self, node_name, vm_config, vm_name=None):
        disk_data = list()
        if not isinstance(vm_config, dict):
            return disk_data

        for key, value in vm_config.items():
            if not isinstance(key, str):
                continue

            if re.match(r"^(ide|sata|scsi|virtio)\d+$", key) is None:
                continue

            parsed_disk = self.parse_proxmox_storage_value(value)
            if parsed_disk is None:
                continue

            if parsed_disk.get("options", dict()).get("media") == "cdrom":
                continue

            size_mb = self.parse_proxmox_disk_size(parsed_disk.get("options", dict()).get("size"))
            if size_mb is None:
                size_mb = self.get_disk_size_from_storage(node_name, parsed_disk)
            if size_mb is None:
                if vm_name is not None:
                    log.debug2(f"Skipping disk '{key}' for VM '{vm_name}'. Unable to determine size.")
                continue

            description = self.build_disk_description(
                parsed_disk,
                ["format", "cache", "discard", "ssd", "iothread", "aio", "backup", "replicate", "ro"]
            )

            disk_entry = {
                "name": key,
                "size": size_mb
            }
            if description is not None:
                disk_entry["description"] = description

            disk_data.append(disk_entry)

        return disk_data

    def get_lxc_disk_data(self, node_name, vm_config, vm_name=None):
        disk_data = list()
        if not isinstance(vm_config, dict):
            return disk_data

        for key, value in vm_config.items():
            if not isinstance(key, str):
                continue

            if key != "rootfs" and re.match(r"^mp\d+$", key) is None:
                continue

            parsed_disk = self.parse_proxmox_storage_value(value)
            if parsed_disk is None:
                continue

            size_mb = self.parse_proxmox_disk_size(parsed_disk.get("options", dict()).get("size"))
            if size_mb is None:
                size_mb = self.get_disk_size_from_storage(node_name, parsed_disk)
            if size_mb is None:
                if vm_name is not None:
                    log.debug2(f"Skipping disk '{key}' for VM '{vm_name}'. Unable to determine size.")
                continue

            description = self.build_disk_description(
                parsed_disk,
                ["mp", "backup", "replicate", "ro"]
            )

            disk_entry = {
                "name": key,
                "size": size_mb
            }
            if description is not None:
                disk_entry["description"] = description

            disk_data.append(disk_entry)

        return disk_data
    def parse_qemu_net(self, net_string):
        if not isinstance(net_string, str):
            return dict()

        data = dict()
        parts = [x.strip() for x in net_string.split(",") if x.strip() != ""]
        for part in parts:
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            data[key.strip()] = value.strip()

        qemu_models = [
            "virtio", "e1000", "e1000e", "rtl8139", "vmxnet3", "ne2k_pci", "i82551", "i82557b", "i82559er",
            "pcnet"
        ]

        model = None
        mac = None
        for key in list(data.keys()):
            if key in qemu_models:
                model = key
                mac = data.pop(key)
                break

        if mac is None:
            for key in list(data.keys()):
                candidate = data.get(key)
                if candidate is not None and ":" in candidate:
                    model = key
                    mac = data.pop(key)
                    break

        data["model"] = model
        data["mac"] = mac

        return data

    def parse_lxc_net(self, net_string):
        if not isinstance(net_string, str):
            return dict()

        data = dict()
        parts = [x.strip() for x in net_string.split(",") if x.strip() != ""]
        for part in parts:
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            data[key.strip()] = value.strip()

        return {
            "name": data.get("name"),
            "mac": data.get("hwaddr"),
            "bridge": data.get("bridge"),
            "tag": data.get("tag"),
            "ip": data.get("ip"),
            "ip6": data.get("ip6")
        }

    @staticmethod
    def parse_proxmox_tags(tag_string):
        if not isinstance(tag_string, str):
            return list()

        tag_list = list()
        for tag in re.split(r"[;,]", tag_string):
            tag = tag.strip()
            if len(tag) > 0:
                tag_list.append(tag)

        return tag_list

    @staticmethod
    def parse_proxmox_bool(value):
        if value is None:
            return False

        if isinstance(value, bool):
            return value

        if isinstance(value, int):
            return value != 0

        value = str(value).strip().lower()
        if value == "":
            return False

        value = value.split(",", 1)[0].strip()
        if "=" in value:
            value = value.split("=", 1)[1].strip()

        if value in ["1", "true", "yes", "on", "enabled"]:
            return True
        if value in ["0", "false", "no", "off", "disabled"]:
            return False

        try:
            return int(value) != 0
        except ValueError:
            return False

    @staticmethod
    def map_vm_status(status):
        if status is None:
            return "offline"

        status = str(status).lower()

        if status in ["running", "started", "online"]:
            return "active"
        if status in ["stopped", "shutdown", "offline"]:
            return "offline"
        if status in ["paused", "suspended", "freeze", "frozen"]:
            return "staged"
        if status in ["crashed", "unknown", "error"]:
            return "failed"

        return "active"

    @staticmethod
    def get_host_platform_candidates(node_status_details):
        """
        Return candidate platform names for a Proxmox host.
        """

        candidates = list()

        pve_version = get_string_or_none(grab(node_status_details, "pveversion"))
        if pve_version is not None:
            version_match = re.search(r"/(\d+\.\d+(?:\.\d+)?)", pve_version)
            if version_match is not None:
                candidates.append(f"Proxmox VE {version_match.group(1)}")
            candidates.append(pve_version)

        kernel_version = get_string_or_none(grab(node_status_details, "kversion"))
        if kernel_version is not None:
            candidates.append(kernel_version)

        unique_candidates = list()
        for candidate in candidates:
            if candidate not in unique_candidates:
                unique_candidates.append(candidate)

        return unique_candidates

    @staticmethod
    def get_vm_ostype_candidates(ostype):
        """
        Return candidate platform names derived from Proxmox VM ostype.
        """

        ostype = get_string_or_none(ostype)
        if ostype is None:
            return list()

        ostype_map = {
            "l24": "Linux 2.4 Kernel",
            "l26": "Linux 6.x - 2.6 Kernel",
            "win11": "Windows 11/2022/2025",
            "win10": "Windows 10/2016/2019",
            "win8": "Windows 8.x/2012/2012r2",
            "win7": "Windows 7/2008r2",
            "wvista": "Windows Vista/2008",
            "wxp": "Windows XP/2003",
            "w2k": "Windows 2000",
            "w2k3": "Windows XP/2003",
            "w2k8": "Windows Vista/2008",
            "solaris": "Solaris Kernel",
            "other": "Other"
        }

        candidates = list()
        mapped_ostype = ostype_map.get(ostype)
        if mapped_ostype is not None:
            candidates.append(mapped_ostype)
        candidates.append(ostype)

        unique_candidates = list()
        for candidate in candidates:
            if candidate not in unique_candidates:
                unique_candidates.append(candidate)

        return unique_candidates

    def get_qemu_guest_platform_candidates(self, node_name, vm_id):
        """
        Return candidate platform names from QEMU guest agent OS info.
        """

        if vm_id is None:
            return list()

        try:
            os_info = self.proxmox.nodes(node_name).qemu(vm_id).agent("get-osinfo").get()
        except Exception:
            return list()

        os_info_result = grab(os_info, "result", fallback=os_info)
        if not isinstance(os_info_result, dict):
            return list()

        candidates = list()
        for key in ["pretty-name", "name", "id"]:
            candidate = get_string_or_none(grab(os_info_result, key))
            if candidate is not None:
                candidates.append(candidate)

        version_id = get_string_or_none(grab(os_info_result, "version-id"))
        if version_id is not None and len(candidates) > 0:
            name_with_version = f"{candidates[0]} {version_id}"
            if name_with_version not in candidates:
                candidates.insert(0, name_with_version)

        unique_candidates = list()
        for candidate in candidates:
            if candidate not in unique_candidates:
                unique_candidates.append(candidate)

        return unique_candidates

    def add_qemu_vms(self, node_name, nb_cluster, nb_device):
        try:
            vms = self.proxmox.nodes(node_name).qemu.get()
        except Exception as e:
            log.warning(f"Unable to retrieve QEMU VMs for node '{node_name}': {e}")
            return

        log.debug("Proxmox returned '%d' QEMU VM%s on node '%s'" %
                  (len(vms), plural(len(vms)), node_name))

        for vm in vms:
            self.add_qemu_vm(node_name, vm, nb_cluster, nb_device)

    def add_lxc_vms(self, node_name, nb_cluster, nb_device):
        try:
            vms = self.proxmox.nodes(node_name).lxc.get()
        except Exception as e:
            log.warning(f"Unable to retrieve LXC containers for node '{node_name}': {e}")
            return

        log.debug("Proxmox returned '%d' LXC VM%s on node '%s'" %
                  (len(vms), plural(len(vms)), node_name))

        for vm in vms:
            self.add_lxc_vm(node_name, vm, nb_cluster, nb_device)
    def add_qemu_vm(self, node_name, vm, nb_cluster, nb_device):
        vm_id = grab(vm, "vmid")
        try:
            vm_status = self.proxmox.nodes(node_name).qemu(vm_id).status.current.get()
        except Exception:
            vm_status = vm

        try:
            vm_config = self.proxmox.nodes(node_name).qemu(vm_id).config.get()
        except Exception as e:
            log.warning(f"Unable to retrieve QEMU config for VM '{vm_id}' on '{node_name}': {e}")
            vm_config = dict()

        name = get_string_or_none(grab(vm_config, "name", fallback=grab(vm_status, "name")))
        if name is None:
            name = f"qemu-{vm_id}"

        if self.settings.strip_vm_domain_name is True and "." in name:
            name = name.split(".")[0]

        if self.passes_filter(name,
                              self.settings.vm_include_filter,
                              self.settings.vm_exclude_filter) is False:
            return

        status = self.map_vm_status(grab(vm_status, "status"))
        if status != "active" and self.settings.skip_offline_vms is True:
            return

        cluster_full_name = self.cluster_name
        if name in self.processed_vm_names.get(cluster_full_name, list()):
            log.warning(f"Virtual machine '{name}' for cluster '{cluster_full_name}' already parsed. Skipping")
            return

        if self.processed_vm_names.get(cluster_full_name) is None:
            self.processed_vm_names[cluster_full_name] = list()
        self.processed_vm_names[cluster_full_name].append(name)

        site_name = nb_cluster.get_site_name()
        if site_name is None:
            site_name = self.get_site_name(NBCluster, self.cluster_name)

        vm_memory = grab(vm_status, "maxmem")
        if vm_memory is not None:
            vm_memory = int(vm_memory / 1024 / 1024)
        else:
            vm_memory = grab(vm_config, "memory", fallback=0)

        if self.settings.vm_disk_and_ram_in_decimal is True and vm_memory is not None:
            vm_memory = int(vm_memory / 1024 * 1000)

        vm_vcpus = grab(vm_config, "cores", fallback=1)
        vm_sockets = grab(vm_config, "sockets", fallback=1)
        try:
            vm_vcpus = float(vm_vcpus) * float(vm_sockets)
        except (TypeError, ValueError):
            vm_vcpus = float(vm_vcpus or 1)

        vm_data = {
            "name": name,
            "cluster": nb_cluster,
            "status": status,
            "memory": int(vm_memory or 0),
            "vcpus": vm_vcpus
        }

        custom_fields = {
            "proxmox_qemu_agent": self.parse_proxmox_bool(grab(vm_config, "agent")),
            "proxmox_start_at_boot": self.parse_proxmox_bool(grab(vm_config, "onboot")),
            "proxmox_unprivileged_container": False
        }
        if vm_id is not None:
            try:
                custom_fields["proxmox_vm_id"] = int(vm_id)
            except (TypeError, ValueError):
                pass
        vm_data["custom_fields"] = custom_fields

        if version.parse(self.inventory.netbox_api_version) >= version.parse("3.3.0"):
            vm_data["site"] = {"name": site_name}
            if self.settings.track_vm_host and nb_device is not None:
                vm_data["device"] = nb_device

        if version.parse(self.inventory.netbox_api_version) < version.parse("3.7.0"):
            vm_disk = grab(vm_status, "maxdisk")
            if vm_disk is not None:
                vm_disk = int(vm_disk / 1024 / 1024)
                if self.settings.vm_disk_and_ram_in_decimal is True:
                    vm_disk = int(vm_disk / 1024 * 1000)
                vm_data["disk"] = vm_disk

        if version.parse(self.inventory.netbox_api_version) >= version.parse("4.1.0"):
            serial = None
            smbios = get_string_or_none(grab(vm_config, "smbios1"))
            if smbios is not None:
                for part in smbios.split(","):
                    if part.startswith("uuid="):
                        serial = part.split("=", 1)[1]
                        break
            if serial is None and vm_id is not None:
                serial = str(vm_id)
            if serial is not None:
                vm_data["serial"] = serial

        qemu_platform_candidates = list()
        qemu_platform_candidates.extend(self.get_vm_ostype_candidates(grab(vm_config, "ostype")))
        if status == "active" and self.parse_proxmox_bool(grab(vm_config, "agent")) is True:
            qemu_platform_candidates.extend(self.get_qemu_guest_platform_candidates(node_name, vm_id))

        platform = None
        if len(qemu_platform_candidates) > 0:
            platform = self.get_object_relation(qemu_platform_candidates,
                                                "vm_platform_relation",
                                                fallback=qemu_platform_candidates[0])
        if platform is not None:
            vm_data["platform"] = {"name": platform}

        role_name = self.get_object_relation(name, "vm_role_relation")
        if role_name is not None:
            vm_data["role"] = {"name": role_name}

        tenant_name = self.get_object_relation(name, "vm_tenant_relation")
        if tenant_name is not None:
            vm_data["tenant"] = {"name": tenant_name}

        vm_tags = self.get_object_relation(name, "vm_tag_relation")
        if self.settings.sync_proxmox_tags is True:
            vm_tags.extend(self.parse_proxmox_tags(grab(vm_config, "tags", fallback="")))
        if len(vm_tags) > 0:
            vm_data["tags"] = vm_tags

        vm_comment = get_string_or_none(grab(vm_config, "description"))
        if vm_comment is not None:
            vm_data["comments"] = vm_comment

        disk_data = self.get_qemu_disk_data(node_name, vm_config, name)

        vnic_data = dict()
        nic_ips = dict()
        mac_to_name = dict()

        for key, value in vm_config.items():
            if not f"{key}".startswith("net"):
                continue

            parsed = self.parse_qemu_net(value)
            mac_address = normalize_mac_address(parsed.get("mac"))
            int_name = f"{key}"

            description_parts = list()
            if parsed.get("model") is not None:
                description_parts.append(parsed.get("model"))
            if parsed.get("bridge") is not None:
                description_parts.append(f"bridge {parsed.get('bridge')}")
            if parsed.get("tag") is not None:
                description_parts.append(f"tag {parsed.get('tag')}")
            if parsed.get("trunks") is not None:
                description_parts.append(f"trunks {parsed.get('trunks')}")

            vnic_data[int_name] = {
                "name": int_name,
                "virtual_machine": None,
                "enabled": True if status == "active" else False,
                "mac_address": mac_address
            }

            if len(description_parts) > 0:
                vnic_data[int_name]["description"] = ", ".join(description_parts)

            nic_ips[int_name] = list()

            if mac_address is not None:
                mac_to_name[mac_address] = int_name

        if self.settings.collect_vm_ips is True:
            self.collect_qemu_agent_ips(node_name, vm_id, mac_to_name, vnic_data, nic_ips)

        primary_ipv4, primary_ipv6 = self.pick_primary_ips(nic_ips)

        self.add_device_vm_to_inventory(NBVM, vm_data, vnic_data=vnic_data, nic_ips=nic_ips,
                                        p_ipv4=primary_ipv4, p_ipv6=primary_ipv6, disk_data=disk_data)

        return

    def collect_qemu_agent_ips(self, node_name, vm_id, mac_to_name, vnic_data, nic_ips):
        try:
            agent_data = self.proxmox.nodes(node_name).qemu(vm_id).agent("network-get-interfaces").get()
        except Exception:
            return

        interfaces = grab(agent_data, "result", fallback=agent_data)
        if not isinstance(interfaces, list):
            return

        for interface in interfaces:

            int_name = get_string_or_none(grab(interface, "name"))
            if int_name is None or int_name.lower() == "lo":
                continue

            mac_address = normalize_mac_address(grab(interface, "hardware-address"))

            mapped_name = None
            if mac_address is not None:
                mapped_name = mac_to_name.get(mac_address)

            if mapped_name is None:
                mapped_name = int_name
                if mapped_name not in vnic_data:
                    vnic_data[mapped_name] = {
                        "name": mapped_name,
                        "virtual_machine": None,
                        "enabled": True,
                        "mac_address": mac_address
                    }
                    nic_ips[mapped_name] = list()

            for ip_addr in grab(interface, "ip-addresses", fallback=list()):

                ip_address_text = grab(ip_addr, "ip-address")
                prefix = grab(ip_addr, "prefix")

                if ip_address_text is None or prefix is None:
                    continue

                ip_text = f"{ip_address_text}/{prefix}"

                if self.settings.permitted_subnets.permitted(ip_text, interface_name=mapped_name) is False:
                    continue

                nic_ips[mapped_name].append(ip_text)
    def add_lxc_vm(self, node_name, vm, nb_cluster, nb_device):
        vm_id = grab(vm, "vmid")
        try:
            vm_status = self.proxmox.nodes(node_name).lxc(vm_id).status.current.get()
        except Exception:
            vm_status = vm

        try:
            vm_config = self.proxmox.nodes(node_name).lxc(vm_id).config.get()
        except Exception as e:
            log.warning(f"Unable to retrieve LXC config for VM '{vm_id}' on '{node_name}': {e}")
            vm_config = dict()

        name = get_string_or_none(grab(vm_config, "hostname", fallback=grab(vm_status, "name")))
        if name is None:
            name = f"lxc-{vm_id}"

        if self.settings.strip_vm_domain_name is True and "." in name:
            name = name.split(".")[0]

        if self.passes_filter(name,
                              self.settings.vm_include_filter,
                              self.settings.vm_exclude_filter) is False:
            return

        status = self.map_vm_status(grab(vm_status, "status"))
        if status != "active" and self.settings.skip_offline_vms is True:
            return

        cluster_full_name = self.cluster_name
        if name in self.processed_vm_names.get(cluster_full_name, list()):
            log.warning(f"Virtual machine '{name}' for cluster '{cluster_full_name}' already parsed. Skipping")
            return

        if self.processed_vm_names.get(cluster_full_name) is None:
            self.processed_vm_names[cluster_full_name] = list()
        self.processed_vm_names[cluster_full_name].append(name)

        site_name = nb_cluster.get_site_name()
        if site_name is None:
            site_name = self.get_site_name(NBCluster, self.cluster_name)

        vm_memory = grab(vm_status, "maxmem")
        if vm_memory is not None:
            vm_memory = int(vm_memory / 1024 / 1024)
        else:
            vm_memory = grab(vm_config, "memory", fallback=0)

        if self.settings.vm_disk_and_ram_in_decimal is True and vm_memory is not None:
            vm_memory = int(vm_memory / 1024 * 1000)

        vm_vcpus = grab(vm_config, "cores", fallback=1)
        try:
            vm_vcpus = float(vm_vcpus)
        except (TypeError, ValueError):
            vm_vcpus = 1

        vm_data = {
            "name": name,
            "cluster": nb_cluster,
            "status": status,
            "memory": int(vm_memory or 0),
            "vcpus": vm_vcpus
        }

        custom_fields = {
            "proxmox_qemu_agent": False,
            "proxmox_start_at_boot": self.parse_proxmox_bool(grab(vm_config, "onboot")),
            "proxmox_unprivileged_container": self.parse_proxmox_bool(grab(vm_config, "unprivileged"))
        }
        if vm_id is not None:
            try:
                custom_fields["proxmox_vm_id"] = int(vm_id)
            except (TypeError, ValueError):
                pass
        vm_data["custom_fields"] = custom_fields

        if version.parse(self.inventory.netbox_api_version) >= version.parse("3.3.0"):
            vm_data["site"] = {"name": site_name}
            if self.settings.track_vm_host and nb_device is not None:
                vm_data["device"] = nb_device

        if version.parse(self.inventory.netbox_api_version) < version.parse("3.7.0"):
            vm_disk = grab(vm_status, "maxdisk")
            if vm_disk is not None:
                vm_disk = int(vm_disk / 1024 / 1024)
                if self.settings.vm_disk_and_ram_in_decimal is True:
                    vm_disk = int(vm_disk / 1024 * 1000)
                vm_data["disk"] = vm_disk

        if version.parse(self.inventory.netbox_api_version) >= version.parse("4.1.0") and vm_id is not None:
            vm_data["serial"] = str(vm_id)

        lxc_platform_candidates = self.get_vm_ostype_candidates(grab(vm_config, "ostype"))
        platform = None
        if len(lxc_platform_candidates) > 0:
            platform = self.get_object_relation(lxc_platform_candidates,
                                                "vm_platform_relation",
                                                fallback=lxc_platform_candidates[0])
        if platform is not None:
            vm_data["platform"] = {"name": platform}

        role_name = self.get_object_relation(name, "vm_role_relation")
        if role_name is not None:
            vm_data["role"] = {"name": role_name}

        tenant_name = self.get_object_relation(name, "vm_tenant_relation")
        if tenant_name is not None:
            vm_data["tenant"] = {"name": tenant_name}

        vm_tags = self.get_object_relation(name, "vm_tag_relation")
        if self.settings.sync_proxmox_tags is True:
            vm_tags.extend(self.parse_proxmox_tags(grab(vm_config, "tags", fallback="")))
        if len(vm_tags) > 0:
            vm_data["tags"] = vm_tags

        vm_comment = get_string_or_none(grab(vm_config, "description"))
        if vm_comment is not None:
            vm_data["comments"] = vm_comment

        disk_data = self.get_lxc_disk_data(node_name, vm_config, name)

        vnic_data = dict()
        nic_ips = dict()

        for key, value in vm_config.items():
            if not f"{key}".startswith("net"):
                continue

            parsed = self.parse_lxc_net(value)

            int_name = parsed.get("name") or f"{key}"
            mac_address = normalize_mac_address(parsed.get("mac"))

            description_parts = list()
            if parsed.get("bridge") is not None:
                description_parts.append(f"bridge {parsed.get('bridge')}")
            if parsed.get("tag") is not None:
                description_parts.append(f"tag {parsed.get('tag')}")

            vnic_data[int_name] = {
                "name": int_name,
                "virtual_machine": None,
                "enabled": True if status == "active" else False,
                "mac_address": mac_address
            }

            if len(description_parts) > 0:
                vnic_data[int_name]["description"] = ", ".join(description_parts)

            nic_ips[int_name] = list()

            if self.settings.collect_vm_ips is True:
                for ip_key in [parsed.get("ip"), parsed.get("ip6")]:
                    if ip_key is None:
                        continue
                    ip_key_lower = str(ip_key).lower()
                    if ip_key_lower in ["dhcp", "auto", "manual"]:
                        continue
                    ip_address_value = self.build_ip_address(ip_key)
                    if ip_address_value is None:
                        continue
                    if self.settings.permitted_subnets.permitted(ip_address_value, interface_name=int_name) is False:
                        continue
                    nic_ips[int_name].append(ip_address_value)

        primary_ipv4, primary_ipv6 = self.pick_primary_ips(nic_ips)

        self.add_device_vm_to_inventory(NBVM, vm_data, vnic_data=vnic_data, nic_ips=nic_ips,
                                        p_ipv4=primary_ipv4, p_ipv6=primary_ipv6, disk_data=disk_data)

        return

# EOF
