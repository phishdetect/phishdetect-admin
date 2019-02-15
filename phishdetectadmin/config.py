#!/usr/bin/env python3
# PhishDetect
# Copyright (c) 2018-2019 Claudio Guarnieri.
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

storage_folder = os.path.join(os.getenv('HOME'), '.config', 'phishdetect')
config_path = os.path.join(storage_folder, 'config')
archived_events_path = os.path.join(storage_folder, 'events')

def load_config():
    if not os.path.exists(config_path):
        return None

    with open(config_path, 'r') as handle:
        return yaml.load(handle)

def save_config(config):
    with open(config_path, 'w') as handle:
        yaml.dump(config, handle, default_flow_style=False)

def load_archived_events():
    archived_events = []
    if not os.path.exists(archived_events_path):
        return archived_events

    with open(archived_events_path, 'r') as handle:
        for line in handle:
            line = line.strip()
            if line == "":
                continue

            archived_events.append(line)

    return archived_events

def archive_event(uuid):
    uuid = uuid.strip()

    archived_events = load_archived_events()
    if uuid in archived_events:
        return

    with open(archived_events_path, 'a') as handle:
        handle.write('{}\n'.format(uuid))
