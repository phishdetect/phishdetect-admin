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

import datetime
from flask import Flask, render_template, request, redirect, url_for

from .config import load_config, save_config, load_archived_events, archive_event
from .utils import get_indicator_type, clean_indicator, extract_domain
from .api import get_events, add_indicators, get_indicator_details
from .api import get_raw_messages, get_raw_details
from . import session

app = Flask(__name__)

@app.route('/conf/', methods=['GET', 'POST'])
def conf():
    if request.method == 'GET':
        nodes = []
        config = load_config()
        if config:
            nodes = config['nodes']

        return render_template('conf.html', page='Configuration', nodes=nodes)
    elif request.method == 'POST':
        host = request.form.get('host')
        key = request.form.get('key')

        if host == "" or key == "":
            return redirect(url_for('conf'))

        config = load_config()
        if not config:
            config = {'nodes': []}

        config['nodes'].append({
            'host': host,
            'key': key,
        })
        save_config(config)

        return redirect(url_for('index'))

@app.route('/node/', methods=['GET', 'POST'])
def node():
    config = load_config()
    if request.method == 'GET':
        if not config:
            return redirect(url_for('conf'))

        nodes = config['nodes']
        return render_template('node.html', page='Node Selection', nodes=nodes)
    elif request.method == 'POST':
        host = request.form.get('host')

        key = ''
        for node in config['nodes']:
            if node['host'] == host:
                key = node['key']
                break

        session.__node__ = {
            'host': host,
            'key': key,
        }

        return redirect(url_for('index'))

@app.route('/')
def index():
    if not session.__node__:
        return redirect(url_for('node'))

    return redirect(url_for('events'))

@app.route('/events/archive')
def events_archive():
    if not session.__node__:
        return redirect(url_for('node'))

    uuid = request.args.get('uuid', None)
    if not uuid:
        return redirect(url_for('events'))

    archive_event(uuid)

    return redirect(url_for('events'))


@app.route('/events/')
def events():
    if not session.__node__:
        return redirect(url_for('node'))

    try:
        results = get_events()
    except Exception as e:
        return render_template('error.html',
            msg="The connection to the PhishDetect Node failed: {}".format(e))

    if results and 'error' in results:
        return render_template('error.html',
            msg="Unable to fetch events: {}".format(results['error']))

    archived = request.args.get('archived', None)

    archived_events = load_archived_events()
    final = []
    for result in results:
        patterns = [
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%dT%H:%M:%S.%f%Z',
            '%Y-%m-%dT%H:%M:%S.%fZ',
        ]

        date = None
        for pattern in patterns:
            try:
                date = datetime.datetime.strptime(result['datetime'], pattern)
            except ValueError:
                continue
            else:
                break

        if date:
            result['datetime'] = date.strftime("%Y-%m-%d %H:%M:%S %Z")

        if archived:
            if result['uuid'] in archived_events:
                final.append(result)
        else:
            if result['uuid'] not in archived_events:
                final.append(result)

    final.reverse()

    return render_template('events.html',
        node=session.__node__['host'], page='Events', events=final, archived=archived)

@app.route('/indicators/', methods=['GET', 'POST'])
def indicators():
    if not session.__node__:
        return redirect(url_for('node'))

    # Get the form to add indicators.
    if request.method == 'GET':
        ioc = request.args.get('ioc', None)
        if ioc:
            ioc = extract_domain(ioc)

        return render_template('indicators.html', indicators=ioc, page='Indicators')
    # Process new indicators to be added.
    elif request.method == 'POST':
        indicators_string = request.form.get('indicators', "")
        tags_string = request.form.get('tags', "")

        indicators_string = indicators_string.strip()
        tags_string = tags_string.strip()

        if indicators_string == "":
            return render_template('indicators.html',
                page='Indicators',
                error="You didn't provide a valid list of indicators")

        if tags_string == "":
            tags = []
        else:
            tags = [t.lower().strip() for t in tags_string.split(',')]

        domain_indicators = []
        email_indicators = []
        for indicator in indicators_string.split():
            indicator_clean = clean_indicator(indicator)

            if get_indicator_type(indicator_clean) == 'email':
                email_indicators.append(indicator_clean)
            elif get_indicator_type(indicator_clean) == 'domain':
                domain_indicators.append(indicator_clean)

        domain_results = {}
        email_results = {}

        total = 0
        try:
            if domain_indicators:
                domain_results = add_indicators('domain', domain_indicators, tags)
                total += domain_results['counter']

            if email_indicators:
                email_results = add_indicators('email', email_indicators, tags)
                total += email_results['counter']
        except Exception as e:
            return render_template('error.html',
                msg="The connection to the PhishDetect Node failed: {}".format(e))

        if 'error' in domain_results or 'error' in email_results:
            return render_template('indicators.html',
                page='Indicators', error=results['error'],
                tags=tags_string, indicators=indicators_string)

        msg = "Added {} new indicators successfully!".format(total)
        return render_template('success.html', msg=msg)

@app.route('/indicator/<string:ioc>', methods=['GET',])
def indicator(ioc):
    if not session.__node__:
        return redirect(url_for('node'))

    details = get_indicator_details(ioc)
    return render_template('indicator.html',
        node=session.__node__['host'], page='Indicator Details', details=details)

@app.route('/raws/', methods=['GET',])
def raws():
    if not session.__node__:
        return redirect(url_for('node'))

    results = get_raw_messages()
    results.reverse()

    if 'error' in results:
        return render_template('error.html',
            msg="Unable to fetch raw messages: {}".format(results['error']))

    return render_template('raws.html',
        node=session.__node__['host'], page='Raw Messages', messages=results)

@app.route('/raw/<string:uuid>', methods=['GET',])
def raw(uuid):
    if not session.__node__:
        return redirect(url_for('node'))

    results = get_raw_details(uuid)
    if 'error' in results:
        return render_template('error.html',
            msg="Unable to fetch raw message details: {}".format(results['error']))

    return render_template('raw.html',
        node=session.__node__['host'], page='Raw Message', message=results)
