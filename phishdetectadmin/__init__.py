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
import random
import threading
import webbrowser

from .app import app
from .config import storage_folder

def logo():
    print("""
         _     _     _         _      _            _   
        | |   (_)   | |       | |    | |          | |  
   _ __ | |__  _ ___| |__   __| | ___| |_ ___  ___| |_ 
  | '_ \\| '_ \\| / __| '_ \\ / _` |/ _ \\ __/ _ \\/ __| __|
  | |_) | | | | \\__ \\ | | | (_| |  __/ ||  __/ (__| |_ 
  | .__/|_| |_|_|___/_| |_|\\__,_|\\___|\\__\\___|\\___|\\__|
  | |                                                  
  |_|

This is an administration utility for PhishDetect Nodes.
A browser page will be launched in few seconds.
You can find more information about PhishDetect at: https://phishdetect.io
    """)

def main():
    logo()
    
    # We make sure we have the configuration folder.
    if not os.path.exists(storage_folder):
        os.makedirs(storage_folder)

    # We randomize a port number to run Flask on.
    port = 5000 + random.randint(0, 999)
    url = 'http://127.0.0.1:{}'.format(port)

    # We launch a browser with some delay.
    threading.Timer(1.25, lambda: webbrowser.open(url) ).start()

    # We launch the Flask app.
    app.run(port=port, debug=False)

if __name__ == '__main__':
    main()
