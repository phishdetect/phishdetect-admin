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

import requests

from .const import *
from . import session

def get_events():
    url = '{}{}'.format(session.__node__['host'], NODE_EVENTS_FETCH)
    res = requests.post(url, json={'key': session.__node__['key']})
    return res.json()

def get_raw_messages():
    url = '{}{}'.format(session.__node__['host'], NODE_RAW_FETCH)
    res = requests.post(url, json={'key': session.__node__['key']})
    return res.json()

def get_raw_details(uuid):
    url = '{}{}'.format(session.__node__['host'], NODE_RAW_DETAILS)
    res = requests.post(url, json={'key': session.__node__['key'], 'uuid': uuid})
    return res.json()

def add_indicators(indicators_type, indicators, tags=[]):
    data = {
        'type': indicators_type,
        'indicators': indicators,
        'tags': tags,
        'key': session.__node__['key']
    }

    url = '{}{}'.format(session.__node__['host'], NODE_INDICATORS_ADD)
    res = requests.post(url, json=data)
    return res.json()

def get_indicator_details(indicator):
    data = {
        'indicator': indicator,
        'key': session.__node__['key']
    }

    url = '{}{}'.format(session.__node__['host'], NODE_INDICATORS_DETAILS)
    res = requests.post(url, json=data)
    return res.json()
