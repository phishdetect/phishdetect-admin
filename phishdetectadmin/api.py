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
    url = '{}{}?key={}'.format(session.__node__['host'],
        NODE_EVENTS_FETCH, session.__node__['key'])
    res = requests.get(url)
    return res.json()

def get_raw_messages():
    url = '{}{}?key={}'.format(session.__node__['host'],
        NODE_RAW_FETCH, session.__node__['key'])
    res = requests.get(url)
    return res.json()

def get_raw_details(uuid):
    url = '{}{}/{}/?key={}'.format(session.__node__['host'],
        NODE_RAW_DETAILS, uuid, session.__node__['key'])
    res = requests.get(url)
    return res.json()

def add_indicators(indicators_type, indicators, tags=[]):
    data = {
        'type': indicators_type,
        'indicators': indicators,
        'tags': tags,
    }

    url = '{}{}?key={}'.format(session.__node__['host'],
        NODE_INDICATORS_ADD, session.__node__['key'])
    res = requests.post(url, json=data)
    return res.json()

def get_indicator_details(indicator):
    url = '{}{}/{}/?key={}'.format(session.__node__['host'],
        NODE_INDICATORS_DETAILS, indicator, session.__node__['key'])
    res = requests.get(url)
    return res.json()

def get_users_pending():
    url = '{}{}?key={}'.format(session.__node__['host'],
        NODE_USERS_PENDING, session.__node__['key'])
    res = requests.get(url)
    return res.json()

def get_users_active():
    url = '{}{}?key={}'.format(session.__node__['host'],
        NODE_USERS_ACTIVE, session.__node__['key'])
    res = requests.get(url)
    return res.json()

def activate_user(api_key):
    url = '{}{}/{}/?key={}'.format(session.__node__['host'],
        NODE_USERS_ACTIVATE, api_key, session.__node__['key'])
    res = requests.get(url)
    return res.json()

def deactivate_user(api_key):
    url = '{}{}/{}/?key={}'.format(session.__node__['host'],
        NODE_USERS_DEACTIVATE, api_key, session.__node__['key'])
    res = requests.get(url)
    return res.json()
