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

from const import *
from config import config, load_config, save_config
from phishdetect import get_events

app = Flask(__name__)

@app.route('/conf', methods=['POST', 'GET'])
def conf():
    global config

    if request.method == 'GET':
        return render_template('conf.html')
    elif request.method == 'POST':
        node = request.form.get('node')
        key = request.form.get('key')

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

    events = get_events()

    return render_template('events.html', events=events)

if __name__ == '__main__':
    app.run()
