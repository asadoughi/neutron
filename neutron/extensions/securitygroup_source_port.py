# Copyright (c) 2014 OpenStack Foundation
# All rights reserved.
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

from neutron.api import extensions
from neutron.extensions import securitygroup


EXTENDED_ATTRIBUTES_2_0 = {
    securitygroup.SECURITY_GROUP_RULES: {
        'source_port_range_min': {
            'allow_post': True, 'allow_put': False,
            'convert_to': securitygroup.convert_validate_port_value,
            'default': None, 'is_visible': True},
        'source_port_range_max': {
            'allow_post': True, 'allow_put': False,
            'convert_to': securitygroup.convert_validate_port_value,
            'default': None, 'is_visible': True}
    }
}


class Securitygroup_source_port(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "security-group-source-port"

    @classmethod
    def get_alias(cls):
        return "security-group-source-port"

    @classmethod
    def get_description(cls):
        return ("Extension of the security groups extension to specify source "
                "port range.")

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/ext/neutron/"
                "securitygroups-source-port/api/v1.0")

    @classmethod
    def get_updated(cls):
        return "2013-04-15T10:00:00-00:00"

    def get_required_extensions(self):
        return ["security-group"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return dict(EXTENDED_ATTRIBUTES_2_0.items())
        else:
            return {}
