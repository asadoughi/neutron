# Copyright 2014 OpenStack Foundation
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
#

"""Add source-port-range-{min,max} to security groups

Revision ID: 4ddbe01fba06
Revises: 6be312499f9
Create Date: 2014-04-15 21:48:55.724208

"""

# revision identifiers, used by Alembic.
revision = '4ddbe01fba06'
down_revision = '6be312499f9'

migration_for_plugins = [
    'neutron.plugins.ml2.plugin.Ml2Plugin',
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.add_column(
        'securitygrouprules',
        sa.Column('source_port_range_max', sa.Integer(), nullable=True))
    op.add_column(
        'securitygrouprules',
        sa.Column('source_port_range_min', sa.Integer(), nullable=True))


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_column('securitygrouprules', 'source_port_range_min')
    op.drop_column('securitygrouprules', 'source_port_range_max')
