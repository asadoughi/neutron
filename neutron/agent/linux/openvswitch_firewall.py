from neutron.agent import firewall
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class OVSFirewallDriver(firewall.FirewallDriver):
    """Driver which enforces security groups through Open vSwitch flows."""

    def __init__(self):
        self.filtered_ports = {}

    @property
    def ports(self):
        LOG.debug(_("~!~"))
        return self.filtered_ports

    def apply_port_filter(self, port):
        pass

    def prepare_port_filter(self, port):
        LOG.debug(_("%s"), port)
        self.filtered_ports[port['device']] = port

    def update_port_filter(self, port):
        LOG.debug(_("%s"), port)
        if port['device'] not in self.filtered_ports:
            LOG.info(_('Attempted to update port filter which is not '
                       'filtered %s'), port['device'])
            return
        self.filtered_ports[port['device']] = port

    def remove_port_filter(self, port):
        LOG.debug(_("%s"), port)
        if not self.filtered_ports.get(port['device']):
            LOG.info(_('Attempted to remove port filter which is not '
                       'filtered %r'), port)
            return
        self.filtered_ports.pop(port['device'], None)

    def filter_defer_apply_on(self):
        LOG.debug(_("~!~"))

    def filter_defer_apply_off(self):
        LOG.debug(_("~!~"))
