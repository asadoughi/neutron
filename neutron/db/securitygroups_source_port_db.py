# Copyright 2014 OpenStack Foundation  All rights reserved.
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

import sqlalchemy as sa

from neutron.db import db_base_plugin_v2
from neutron.db import securitygroups_db as sgdb
from neutron.db import securitygroups_rpc_base as sg_db_rpc

setattr(sgdb.SecurityGroupRule, 'source_port_range_min', sa.Column(sa.Integer))
setattr(sgdb.SecurityGroupRule, 'source_port_range_max', sa.Column(sa.Integer))


class SecurityGroupSourcePort(sgdb.SecurityGroupDbMixin):
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        'security_group_rules', ['_extend_security_group_rule_dict'])

    def _extend_security_group_rule_dict(self, res, sec_group_rule):
        res['source_port_range_min'] = sec_group_rule['source_port_range_min']
        res['source_port_range_max'] = sec_group_rule['source_port_range_max']

    def _check_for_duplicate_rules(self, context, sgr):
        for rulebody in sgr:
            rule = rulebody['security_group_rule']
            rule['source_port_range_min'] = rule.get('source_port_range_min')
            rule['source_port_range_max'] = rule.get('source_port_range_max')
        return super(SecurityGroupSourcePort, self)._check_for_duplicate_rules(
            context, sgr)

    def _validate_security_group_rules(self, context, security_group_rule):
        sclass = super(SecurityGroupSourcePort, self)
        for rules in security_group_rule['security_group_rules']:
            rule = rules.get('security_group_rule')
            self._validate_port_range(
                rule, 'source_port_range_min', 'source_port_range_max')
        return sclass._validate_security_group_rules(
            context, security_group_rule)

    def _create_security_group_rule_model(self, id, tenant_id, rule):
        sclass = super(SecurityGroupSourcePort, self)
        model = sclass._create_security_group_rule_model(id, tenant_id, rule)
        model.update(dict(
            source_port_range_min=rule.get('source_port_range_min'),
            source_port_range_max=rule.get('source_port_range_max')))
        return model

    def _make_security_group_rule_filter_dict(self, security_group_rule):
        sclass = super(SecurityGroupSourcePort, self)
        res = sclass._make_security_group_rule_filter_dict(security_group_rule)
        sgr = security_group_rule['security_group_rule']
        include_if_present = ['source_port_range_max', 'source_port_range_min']
        for key in include_if_present:
            value = sgr.get(key)
            if value:
                res[key] = [value]
        return res


class SecGrpSrcPortServerRpcMixin(sg_db_rpc.SecurityGroupServerRpcMixin,
                                  SecurityGroupSourcePort):
    pass
