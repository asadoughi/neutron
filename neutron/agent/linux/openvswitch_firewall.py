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


class OVSFirewallDriver(firewall.FirewallDriver):
    """Driver which enforces security groups through Open vSwitch flows."""

    def __init__(self):
        self._filtered_ports = {}
        self.root_helper = cfg.CONF.AGENT.root_helper
        self.int_br = ovs_lib.OVSBridge(cfg.CONF.OVS.integration_bridge,
                                        self.root_helper)

    @property
    def ports(self):
        return self._filtered_ports

    def apply_port_filter(self, port):
        pass

    def _add_base_flows(self, port, vif_port):
        for fixed_ip in port['fixed_ips']:
            self.int_br.add_flow(
                priority=SECURITY_GROUPS_DROP_ALL_PRIORITY,
                nw_src=fixed_ip,
                actions="drop")
            self.int_br.add_flow(
                priority=SECURITY_GROUPS_DROP_ALL_PRIORITY,
                nw_dst=fixed_ip,
                actions="drop")

            # TODO: refactor into more strict subset
            self.int_br.add_flow(
                priority=SECURITY_GROUPS_ARP_PRIORITY,
                proto="arp",
                nw_src=fixed_ip,
                actions="normal")
            self.int_br.add_flow(
                priority=SECURITY_GROUPS_ARP_PRIORITY,
                proto="arp",
                nw_dst=fixed_ip,
                actions="output:%s" % vif_port.ofport)

    def _remove_flows(self, port):
        for fixed_ip in port['fixed_ips']:
            self.int_br.delete_flows(nw_src=fixed_ip)
            self.int_br.delete_flows(nw_dst=fixed_ip)
            self.int_br.delete_flows(proto="arp", nw_src=fixed_ip)
            self.int_br.delete_flows(proto="arp", nw_dst=fixed_ip)

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
            if direction == EGRESS_DIRECTION:
                flow["actions"] = "normal"
            elif direction == INGRESS_DIRECTION:
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
                    # TODO !@# handle wide range
                    pass

            if source_port_range_min and source_port_range_max:
                if source_port_range_min == source_port_range_max:
                    flow["tp_src"] = source_port_range_min
                else:
                    # TODO !@# handle wide range
                    pass

            if dest_ip_prefix:
                flow["nw_dst"] = dest_ip_prefix

            if source_ip_prefix:
                flow["nw_src"] = source_ip_prefix

            for fixed_ip in port['fixed_ips']:
                if direction == EGRESS_DIRECTION:
                    flow["nw_src"] = fixed_ip
                elif direction == INGRESS_DIRECTION:
                    flow["nw_dst"] = fixed_ip

                self.int_br.add_flow(**flow)

    def prepare_port_filter(self, port):
        LOG.debug(_("AMIR Preparing device (%s) filter: %s"), port['device'],
                  port)
        self._remove_flows(port)
        vif_port = self.int_br.get_vif_port_by_id(port['device'])
        self._add_base_flows(port, vif_port)
        self._add_rules_flows(port, vif_port)
        self._filtered_ports[port['device']] = port

    def update_port_filter(self, port):
        LOG.debug(_("AMIR Updating device (%s) filter: %s"), port['device'],
                  port)
        if port['device'] not in self._filtered_ports:
            LOG.info(_('Attempted to update port filter which is not '
                       'filtered %s'), port['device'])
            return

        old_port = self._filtered_ports[port['device']]
        self._remove_flows(old_port)
        vif_port = self.int_br.get_vif_port_by_id(port['device'])
        self._add_base_flows(port, vif_port)
        self._add_rules_flows(port, vif_port)
        self._filtered_ports[port['device']] = port

    def remove_port_filter(self, port):
        LOG.debug(_("AMIR Removing device (%s) filter: %s"), port['device'],
                  port)
        if not self._filtered_ports.get(port['device']):
            LOG.info(_('Attempted to remove port filter which is not '
                       'filtered %r'), port)
            return
        self._remove_flows(port)
        self._filtered_ports.pop(port['device'])

    def filter_defer_apply_on(self):
        LOG.debug(_("AMIR defer_apply_on"))
        #self.int_br.defer_apply_on()
        pass

    def filter_defer_apply_off(self):
        LOG.debug(_("AMIR defer_apply_off"))
        #self.int_br.defer_apply_off()
        pass
