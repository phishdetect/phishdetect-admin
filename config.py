#!/usr/bin/env python3
# PhishDetect
# Copyright (C) 2018  Claudio Guarnieri
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import yaml

config_local = os.path.join(os.getenv('HOME'), '.phishdetect.conf')
config_paths = [
    os.path.join(os.getcwd(), 'phishdetect.conf'),
    config_local,
]

def load_config():
    found_config = None
    for config_path in config_paths:
        if not os.path.exists(config_path):
            continue

        found_config = config_path

    if not found_config:
        return None

    with open(found_config, 'r') as handle:
        return yaml.load(handle)

def save_config(config):
    with open(config_local, 'w') as handle:
        yaml.dump(config, handle, default_flow_style=False)

config = load_config()
