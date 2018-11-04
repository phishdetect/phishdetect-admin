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

from flask import Flask, render_template, request, redirect, url_for

from phishdetectadmin.const import *
from phishdetectadmin.config import config, load_config, save_config
from phishdetectadmin.utils import get_indicator_type
from phishdetectadmin.api import get_events, add_indicators

app = Flask(__name__,
    template_folder='/usr/share/phishdetect-admin/templates')

@app.route('/conf', methods=['GET', 'POST'])
def conf():
    global config

    if request.method == 'GET':
        return render_template('conf.html',
            page='Configuration', node=config.get('node', ''),
            key=config.get('key', ''))
    elif request.method == 'POST':
        node = request.form.get('node')
        key = request.form.get('key')

        if node == "" or key == "":
            return redirect(url_for('conf'))

        config = {
            'node': node,
            'key': key,
        }
        save_config(config)

        return redirect(url_for('index'))

@app.route('/')
def index():
    if not config:
        return redirect(url_for('conf'))

    return redirect(url_for('events'))

@app.route('/events')
def events():
    if not config:
        return redirect(url_for('conf'))

    results = get_events()

    try:
        results = get_events()
    except Exception as e:
        return render_template('error.html',
            node=config['node'],
            msg="The connection to the PhishDetect Node failed: {}".format(e))

    if results and 'error' in results:
        return render_template('error.html',
            node=config['node'],
            msg="Unable to fetch events: {}".format(results['error']))

    return render_template('events.html',
        node=config['node'], page='Events', events=results)

@app.route('/indicators', methods=['GET', 'POST'])
def indicators():
    if not config:
        return redirect(url_for('conf'))

    # Get the form to add indicators.
    if request.method == 'GET':
        return render_template('indicators.html',
            node=config['node'], page='Indicators')
    # Process new indicators to be added.
    elif request.method == 'POST':
        indicators_string = request.form.get('indicators', "")
        tags_string = request.form.get('tags', "")

        indicators_string = indicators_string.strip()
        tags_string = tags_string.strip()

        if indicators_string == "":
            return render_template('indicators.html',
                node=config['node'], page='Indicators',
                error="You didn't provide a valid list of indicators")

        if tags_string == "":
            tags = []
        else:
            tags = [t.lower().strip() for t in tags_string.split(',')]

        domain_indicators = []
        email_indicators = []
        for indicator in indicators_string.split():
            indicator = indicator.replace('[.]', '.')
            indicator = indicator.replace('[@]', '@')

            if get_indicator_type(indicator) == 'email':
                email_indicators.append(indicator)
            elif get_indicator_type(indicator) == 'domain':
                domain_indicators.append(indicator)

        domain_results = {}
        email_results = {}

        try:
            if domain_indicators:
                domain_results = add_indicators('domain', domain_indicators, tags)

            if email_indicators:
                email_results = add_indicators('email', email_indicators, tags)
        except Exception as e:
            return render_template('error.html',
                node=config['node'],
                msg="The connection to the PhishDetect Node failed: {}".format(e))

        if 'error' in domain_results or 'error' in email_results:
            return render_template('indicators.html',
                node=config['node'], page='Indicators', error=results['error'],
                tags=tags_string, indicators=indicators_string)

        return render_template('success.html',
            node=config['node'], msg="Any new indicators were added successfully")
