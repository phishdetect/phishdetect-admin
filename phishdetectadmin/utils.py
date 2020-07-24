#!/usr/bin/env python3
# PhishDetect
# Copyright (c) 2018-2020 Claudio Guarnieri.
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

import re
import smtplib
from urllib.parse import urlparse

from .config import load_config

def extract_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc

def send_email(recipient, subject, message):
    config = load_config()

    if "smtp_host" not in config or config["smtp_host"].strip() == "":
        return

    server = smtplib.SMTP(config["smtp_host"], 587)
    server.ehlo()
    server.starttls()
    server.login(config["smtp_user"], config["smtp_pass"])

    msg_text = """\
From: PhishDetect <{}>
To: {}
Subject: {}

{}
""".format(config["smtp_user"], recipient, subject, message)

    server.sendmail(config["smtp_user"], recipient, msg_text)
    server.close()
