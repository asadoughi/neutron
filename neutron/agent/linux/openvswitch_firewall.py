# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014, Amir Sadoughi, Rackspace US, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo.config import cfg

from neutron.agent import firewall
from neutron.agent.linux import ovs_lib
from neutron.common import constants
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

SECURITY_GROUPS_DROP_ALL_PRIORITY = 5
SECURITY_GROUPS_ARP_PRIORITY = 6
SECURITY_GROUPS_RULES_PRIORITY = 7

INGRESS_DIRECTION = 'ingress'
EGRESS_DIRECTION = 'egress'

FIREWALL_COOKIE = 0x2


class OVSFirewallDriver(firewall.FirewallDriver):
    """Driver which enforces security groups through Open vSwitch flows."""

    def __init__(self):
        self._filtered_ports = {}
        self._vif_ports = {}
        self.root_helper = cfg.CONF.AGENT.root_helper
        self.int_br = ovs_lib.OVSBridge(cfg.CONF.OVS.integration_bridge,
                                        self.root_helper,
                                        cookie=FIREWALL_COOKIE)
        self._deferred = False

    @property
    def ports(self):
        return self._filtered_ports

    def apply_port_filter(self, port):
        pass

    def _add_base_flows(self, port, vif_port):
        self.int_br.add_flow(
            priority=SECURITY_GROUPS_DROP_ALL_PRIORITY,
            dl_src=port["mac_address"],
            actions="drop")

        self.int_br.add_flow(
            priority=SECURITY_GROUPS_DROP_ALL_PRIORITY,
            dl_dst=port["mac_address"],
            actions="drop")

        for fixed_ip in port['fixed_ips']:
            # Broadcast ARP
            self.int_br.add_flow(
                priority=SECURITY_GROUPS_ARP_PRIORITY,
                dl_src=port["mac_address"],
                # dl_dst="ff:ff:ff:ff:ff:ff",
                proto="arp",
                nw_src=fixed_ip,
                actions="normal")
            # in_port=vif_port.ofport, ovs-neutron-agent del-flows with this
            # nw_proto=1, not processed
            # arp_sha=port["mac_address"], not processed
            # arp_tha="00:00:00:00:00:00", not processed

            # Broadcast ARP Response
            self.int_br.add_flow(
                priority=SECURITY_GROUPS_ARP_PRIORITY,
                dl_dst=port["mac_address"],
                proto="arp",
                nw_dst=fixed_ip,
                actions="output:%s" % vif_port.ofport)
            # in_port(19),eth(src=00:50:56:c0:00:01,
            # get ofport/mac of int-phy-br
            # nw_proto=2,
            # arp_sha=00:50:56:c0:00:01,
            # arp_tha=port["mac_address"],

    def _remove_flows(self, port, vif_port):
        if int(vif_port.ofport) != -1:
            self.int_br.delete_flows(in_port=port.ofport)

    def _add_rules_flows(self, port, vif_port):
        rules = port['security_group_rules']
        for rule in rules:
            ethertype = rule['ethertype']
            direction = rule['direction']
            protocol = rule.get('protocol')
            port_range_min = rule.get('port_range_min')
            port_range_max = rule.get('port_range_max')
            source_ip_prefix = rule.get('source_ip_prefix')
            source_port_range_min = rule.get('source_port_range_min')
            source_port_range_max = rule.get('source_port_range_max')
            dest_ip_prefix = rule.get('dest_ip_prefix')

            flow = dict(priority=SECURITY_GROUPS_RULES_PRIORITY)
            if (direction == EGRESS_DIRECTION):
                flow["dl_src"] = port["mac_address"]
                flow["actions"] = "normal"
            elif (direction == INGRESS_DIRECTION):
                flow["dl_dst"] = port["mac_address"]
                flow["actions"] = "output:%s" % vif_port.ofport

            if protocol:
                if protocol == "icmp" and ethertype == constants.IPv6:
                    flow["proto"] = "icmpv6"
                else:
                    flow["proto"] = protocol

            if port_range_min and port_range_max:
                if port_range_min == port_range_max:
                    flow["tp_dst"] = port_range_min
                else:
                    # TODO(amir-sadoughi) !@# handle wide range
                    pass

            if source_port_range_min and source_port_range_max:
                if source_port_range_min == source_port_range_max:
                    flow["tp_src"] = source_port_range_min
                else:
                    # TODO(amir-sadoughi) !@# handle wide range
                    pass

            if dest_ip_prefix:
                flow["nw_dst"] = dest_ip_prefix

            if source_ip_prefix:
                flow["nw_src"] = source_ip_prefix

            for fixed_ip in port['fixed_ips']:
                if (direction == EGRESS_DIRECTION):
                    flow["nw_src"] = fixed_ip
                elif (direction == INGRESS_DIRECTION):
                    flow["nw_dst"] = fixed_ip

                # LOG.debug(_("AMIR rule %s flow %s"), (rule, flow))
                self.int_br.add_flow(**flow)

    def prepare_port_filter(self, port):
        # LOG.debug(_("AMIR Preparing device (%s) filter: %s"), (port['device']
        # ,
        #           port))
        vif_port = self.int_br.get_vif_port_by_id(port['device'])
        self._remove_flows(port, vif_port)
        self._add_base_flows(port, vif_port)
        self._add_rules_flows(port, vif_port)
        self._filtered_ports[port['device']] = port
        self._vif_ports[port['device']] = vif_port

    def update_port_filter(self, port):
        # LOG.debug(_("AMIR Updating device (%s) filter: %s"), (port['device'],
        #           port))
        if port['device'] not in self._filtered_ports:
            LOG.info(_('Attempted to update port filter which is not '
                       'filtered %s'), port['device'])
            return

        old_port = self._filtered_ports[port['device']]
        old_vif_port = self._vif_ports[port['device']]
        self._remove_flows(old_port, old_vif_port)

        vif_port = self.int_br.get_vif_port_by_id(port['device'])
        self._add_base_flows(port, vif_port)
        self._add_rules_flows(port, vif_port)
        self._filtered_ports[port['device']] = port
        self._vif_ports[port['device']] = vif_port

    def remove_port_filter(self, port):
        # LOG.debug(_("AMIR Removing device (%s) filter: %s"), (port['device'],
        #           port))
        if not self._filtered_ports.get(port['device']):
            LOG.info(_('Attempted to remove port filter which is not '
                       'filtered %r'), port)
            return
        self._remove_flows(port)
        self._filtered_ports.pop(port['device'])
        self._vif_ports.pop(port['device'])

    def filter_defer_apply_on(self):
        # LOG.debug(_("AMIR defer_apply_on"))
        if not self._deferred:
            self.int_br.defer_apply_on()
            self._deferred = True

    def filter_defer_apply_off(self):
        # LOG.debug(_("AMIR defer_apply_off"))
        if self._deferred:
            self.int_br.defer_apply_off()
            self._deferred = False
