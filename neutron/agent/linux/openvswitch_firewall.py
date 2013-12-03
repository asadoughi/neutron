from oslo.config import cfg

from neutron.agent import firewall
from neutron.agent.linux import ovs_lib
from neutron.common import utils as q_utils
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class OVSFirewallDriver(firewall.FirewallDriver):
    """Driver which enforces security groups through Open vSwitch flows."""

    def __init__(self):
        self._filtered_ports = {}
        self.root_helper = cfg.CONF.AGENT.root_helper
        self.int_br = ovs_lib.OVSBridge(cfg.CONF.OVS.integration_bridge,
                                        self.root_helper)
        try:
            bridge_mappings = q_utils.parse_mappings(
                cfg.CONF.OVS.bridge_mappings)
        except ValueError as e:
            raise ValueError(_("Parsing bridge_mappings failed: %s.") % e)

        for physical_network, bridge in bridge_mappings.iteritems():
            br = ovs_lib.OVSBridge(bridge, self.root_helper)
            self.phys_brs[physical_network] = br

    @property
    def ports(self):
        return self._filtered_ports

    def apply_port_filter(self, port):
        pass

    def prepare_port_filter(self, port):
        LOG.debug(_("Preparing device (%s) filter: %s"), port['device'], port)
        self._filtered_ports[port['device']] = port

    def update_port_filter(self, port):
        LOG.debug(_("Updating device (%s) filter: %s"), port['device'], port)
        if port['device'] not in self._filtered_ports:
            LOG.info(_('Attempted to update port filter which is not '
                       'filtered %s'), port['device'])
            return
        self._filtered_ports[port['device']] = port

    def remove_port_filter(self, port):
        LOG.debug(_("Removing device (%s) filter: %s"), port['device'], port)
        if not self._filtered_ports.get(port['device']):
            LOG.info(_('Attempted to remove port filter which is not '
                       'filtered %r'), port)
            return
        self._filtered_ports.pop(port['device'], None)

    def filter_defer_apply_on(self):
        self.int_br.defer_apply_on()
        for br in self.phys_brs.value():
            br.defer_apply_on()

    def filter_defer_apply_off(self):
        self.int_br.defer_apply_off()
        for br in self.phys_brs.value():
            br.defer_apply_off()
