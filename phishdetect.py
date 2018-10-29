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

import requests

from config import config

def get_events():
    url = '{}/api/events/fetch/'.format(config['node'])
    res = requests.post(url, json={'key': config['key']})
    return res.json()

def add_indicators(indicators_type, indicators, tags=[]):
    data = {
        'type': indicators_type,
        'indicators': indicators,
        'tags': tags,
        'key': config['key']
    }

    url = '{}/api/indicators/add/'.format(config['node'])
    res = requests.post(url, json=data)
    return res.json()
