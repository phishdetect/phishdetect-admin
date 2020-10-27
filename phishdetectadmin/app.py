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

import io
import datetime
import phishdetect
from flask import Flask, render_template, request, redirect, url_for
from flask import send_file, send_from_directory

from .config import load_config, save_config, load_archived_alerts, archive_alert
from .utils import extract_domain, send_email
from . import session

app = Flask(__name__, static_url_path="")

#==============================================================================
# Static
#==============================================================================
@app.route("/js/<path:path>")
def js(path):
    return send_from_directory("js", path)

@app.route("/css/<path:path>")
def css(path):
    return send_from_directory("css", path)

#==============================================================================
# Configuration
#==============================================================================
@app.route("/conf/", methods=["GET"])
def conf():
    return render_template("conf.html", page="Configuration",
                           config=load_config(),
                           current_node=session.__node__)

@app.route("/conf/node/", methods=["POST"])
def conf_node():
    host = request.form.get("host")
    key = request.form.get("key")

    if host == "" or key == "":
        return redirect(url_for("conf"))

    config = load_config()
    if not config:
        config = {"nodes": []}

    config["nodes"].append({
        "host": host.rstrip("/"),
        "key": key,
    })
    save_config(config)

    return redirect(url_for("index"))

@app.route("/conf/smtp/", methods=["POST"])
def conf_smtp():
    smtp_host = request.form.get("smtp_host")
    smtp_user = request.form.get("smtp_user")
    smtp_pass = request.form.get("smtp_pass")

    if smtp_host == "" or smtp_user == "" or smtp_pass == "":
        return redirect(url_for("conf"))

    config = load_config()
    if not config:
        config = {"node": []}

    config["smtp_host"] = smtp_host
    config["smtp_user"] = smtp_user
    config["smtp_pass"] = smtp_pass

    save_config(config)

    return redirect(url_for("conf"))

@app.route("/node/", methods=["GET", "POST"])
def node():
    config = load_config()
    if request.method == "GET":
        if not config:
            return redirect(url_for("conf"))

        nodes = config["nodes"]

        return render_template("node.html", page="Node Selection", nodes=nodes,
                               current_node=session.__node__)
    elif request.method == "POST":
        host = request.form.get("host")

        key = ""
        for node in config["nodes"]:
            if node["host"] == host:
                key = node["key"]
                break

        session.__node__ = {
            "host": host,
            "key": key,
        }

        return redirect(url_for("index"))

#==============================================================================
# Index
#==============================================================================
@app.route("/")
def index():
    if not session.__node__:
        return redirect(url_for("node"))

    return redirect(url_for("alerts"))

#==============================================================================
# Alerts
#==============================================================================
@app.route("/alerts/")
def alerts():
    if not session.__node__:
        return redirect(url_for("node"))

    try:
        pd = phishdetect.PhishDetect(host=session.__node__["host"],
            api_key=session.__node__["key"])
        results = pd.alerts.fetch()
    except Exception as e:
        return render_template("error.html",
                               msg="The connection to the PhishDetect Node failed: {}".format(e),
                               current_node=session.__node__)

    if results and "error" in results:
        return render_template("error.html",
                               msg="Unable to fetch alerts: {}".format(results["error"]),
                               current_node=session.__node__)

    archived = request.args.get("archived", None)

    archived_alerts = load_archived_alerts()
    final = []
    for result in results:
        patterns = [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S.%f%Z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
        ]

        date = None
        for pattern in patterns:
            try:
                date = datetime.datetime.strptime(result["datetime"], pattern)
            except ValueError:
                continue
            else:
                break

        if date:
            result["datetime"] = date.strftime("%Y-%m-%d %H:%M:%S %Z")

        if archived:
            if result["uuid"] in archived_alerts:
                final.append(result)
        else:
            if result["uuid"] not in archived_alerts:
                final.append(result)

    return render_template("alerts.html",
                           page="Alerts",
                           alerts=final, archived=archived,
                           current_node=session.__node__)

@app.route("/alerts/archive")
def alerts_archive():
    if not session.__node__:
        return redirect(url_for("node"))

    uuid = request.args.get("uuid", None)
    if not uuid:
        return redirect(url_for("alerts"))

    archive_alert(uuid)

    return redirect(url_for("alerts"))

#==============================================================================
# Indicators
#==============================================================================
@app.route("/indicators/pending/", methods=["GET", "POST"])
def indicators_pending():
    if not session.__node__:
        return redirect(url_for("node"))

    if request.method == "GET":
        pd = phishdetect.PhishDetect(host=session.__node__["host"],
                                     api_key=session.__node__["key"])

        iocs = pd.indicators.get_pending()
        return render_template("indicators_list.html", iocs=iocs,
                               status="pending",
                               page="Pending Indicators",
                               current_node=session.__node__)

@app.route("/indicators/disabled/", methods=["GET", "POST"])
def indicators_disabled():
    if not session.__node__:
        return redirect(url_for("node"))

    if request.method == "GET":
        pd = phishdetect.PhishDetect(host=session.__node__["host"],
                                     api_key=session.__node__["key"])

        iocs = pd.indicators.get_disabled()
        return render_template("indicators_list.html", iocs=iocs,
                               status="disabled",
                               page="Disabled Indicators",
                               current_node=session.__node__)

@app.route("/indicators/enable/", methods=["POST"])
def indicators_enable():
    content = request.json
    iocs = content["iocs"]

    pd = phishdetect.PhishDetect(host=session.__node__["host"],
                                 api_key=session.__node__["key"])
    result = pd.indicators.enable(iocs)
    if "error" in result:
        return abort(Response(result["error"]))

    return ("", 200)

@app.route("/indicators/disable/", methods=["POST"])
def indicators_disable():
    content = request.json
    iocs = content["iocs"]

    pd = phishdetect.PhishDetect(host=session.__node__["host"],
                                 api_key=session.__node__["key"])
    result = pd.indicators.disable(iocs)
    if "error" in result:
        return abort(Response(result["error"]))

    return ("", 200)

@app.route("/indicators/add/", methods=["GET", "POST"])
def indicators_add():
    if not session.__node__:
        return redirect(url_for("node"))

    # Get the form to add indicators.
    if request.method == "GET":
        ioc = request.args.get("ioc", None)
        if ioc:
            ioc = extract_domain(ioc)

        return render_template("indicators_add.html", indicators=ioc,
                               page="Add Indicators",
                               current_node=session.__node__)
    # Process new indicators to be added.
    elif request.method == "POST":
        enabled = bool(request.form.get("enabled", False))
        indicators_string = request.form.get("indicators", "")
        tags_string = request.form.get("tags", "")

        indicators_string = indicators_string.strip()
        tags_string = tags_string.strip()

        if indicators_string == "":
            return render_template("indicators_add.html",
                                   page="Add Indicators",
                                   error="You didn't provide a valid list of indicators",
                                   current_node=session.__node__)

        if tags_string == "":
            tags = []
        else:
            tags = [t.lower().strip() for t in tags_string.split(",")]

        indicators = [i.lower().strip() for i in indicators_string.split()]

        try:
            pd = phishdetect.PhishDetect(host=session.__node__["host"],
                                         api_key=session.__node__["key"])

            results = pd.indicators.add(indicators=indicators, tags=tags,
                                        enabled=enabled)
        except Exception as e:
            return render_template("error.html",
                                   msg="The connection to the PhishDetect Node failed: {}".format(e),
                                   current_node=session.__node__)

        if "error" in results:
            return render_template("indicators_add.html",
                                   page="Indicators", error=results["error"],
                                   tags=tags_string, indicators=indicators_string,
                                   current_node=session.__node__)

        msg = "Added {} new indicators successfully!".format(results["counter"])
        return render_template("success.html", msg=msg)

@app.route("/indicators/view/<string:sha256>/", methods=["GET",])
def indicators_view(sha256):
    if not session.__node__:
        return redirect(url_for("node"))

    pd = phishdetect.PhishDetect(host=session.__node__["host"],
                                 api_key=session.__node__["key"])
    details = pd.indicators.details(sha256)

    return render_template("indicator.html",
                           page="Indicator Details", details=details,
                           current_node=session.__node__)

#==============================================================================
# Reports
#==============================================================================
@app.route("/reports/", methods=["GET",])
def reports():
    if not session.__node__:
        return redirect(url_for("node"))

    pd = phishdetect.PhishDetect(host=session.__node__["host"],
                                 api_key=session.__node__["key"])
    results = pd.reports.fetch()

    if "error" in results:
        return render_template("error.html",
                               msg="Unable to fetch reports: {}".format(results["error"]),
                               current_node=session.__node__)

    return render_template("reports.html",
                           page="Reports", reports=results,
                           current_node=session.__node__)

@app.route("/reports/view/<string:uuid>/", methods=["GET",])
def report_view(uuid):
    if not session.__node__:
        return redirect(url_for("node"))

    pd = phishdetect.PhishDetect(host=session.__node__["host"],
                                 api_key=session.__node__["key"])
    results = pd.reports.details(uuid=uuid)
    if "error" in results:
        return render_template("error.html",
                               msg="Unable to fetch report details: {}".format(results["error"]),
                               current_node=session.__node__)

    return render_template("report.html",
                           page="Report", report=results,
                           current_node=session.__node__)

@app.route("/reports/download/<string:uuid>/", methods=["GET",])
def report_download(uuid):
    if not session.__node__:
        return redirect(url_for("node"))

    pd = phishdetect.PhishDetect(host=session.__node__["host"],
                                 api_key=session.__node__["key"])
    results = pd.reports.details(uuid=uuid)
    if "error" in results:
        return render_template("error.html",
                               msg="Unable to fetch report details: {}".format(results["error"]),
                               current_node=session.__node__)

    content = results["content"]
    if content.strip() == "":
        return render_template("error.html",
                               msg="The fetched message seems empty",
                               current_node=session.__node__)

    mem = io.BytesIO()
    mem.write(content.encode("utf-8"))
    mem.seek(0)

    if results["type"] == "email":
        mimetype = "message/rfc822"
        filename = "{}.eml".format(results["uuid"])
    else:
        mimetype = "text/plain"
        filename = "{}.txt".format(results["uuid"])

    return send_file(mem, mimetype=mimetype, as_attachment=True,
                     attachment_filename=filename)

#==============================================================================
# Users
#==============================================================================
@app.route("/users/", methods=["GET",])
def users_pending():
    if not session.__node__:
        return redirect(url_for("node"))

    pd = phishdetect.PhishDetect(host=session.__node__["host"],
                                 api_key=session.__node__["key"])
    results = pd.users.get_pending()
    if "error" in results:
        return render_template("error.html",
                               msg="Unable to fetch pending users: {}".format(results["error"]),
                               current_node=session.__node__)

    return render_template("users_pending.html",
                           page="Users", users=results,
                           current_node=session.__node__)

@app.route("/users/active/", methods=["GET",])
def users_active():
    if not session.__node__:
        return redirect(url_for("node"))

    pd = phishdetect.PhishDetect(host=session.__node__["host"],
                                 api_key=session.__node__["key"])
    results = pd.users.get_active()
    if "error" in results:
        return render_template("error.html",
                               msg="Unable to fetch users: {}".format(results["error"]),
                               current_node=session.__node__)

    return render_template("users_active.html",
                           page="Users", users=results,
                           current_node=session.__node__)

@app.route("/users/activate/<string:uuid>/", methods=["GET",])
def users_activate(uuid):
    if not session.__node__:
        return redirect(url_for("node"))

    # First we get the pending users (before activating the current).
    pd = phishdetect.PhishDetect(host=session.__node__["host"],
                                 api_key=session.__node__["key"])
    results = pd.users.get_pending()
    if "error" in results:
        return render_template("error.html",
                               msg="Unable to fetch pending users: {}".format(users["error"]),
                               current_node=session.__node__)

    # Then we activate the user.
    result = pd.users.activate(uuid)
    if "error" in result:
        return render_template("error.html",
                               msg="Unable to activate user: {}".format(result["error"]),
                               current_node=session.__node__)

    email = None
    for user in results:
        if uuid == user["uuid"]:
            email = user["email"]
            break

    if not email:
        return render_template("error.html",
                               msg="User not found",
                               current_node=session.__node__)

    message = "Your PhishDetect secret token has been activated!"

    try:
        send_email(email, "Your PhishDetect secret token has been activated", message)
    except Exception as e:
        return render_template("error.html",
                               msg="Failed to send email to user: {}".format(e),
                               current_node=session.__node__)

    return render_template("success.html",
                           msg="The user has been activated successfully",
                           current_node=session.__node__)

@app.route("/users/deactivate/<string:uuid>/", methods=["GET",])
def users_deactivate(uuid):
    if not session.__node__:
        return redirect(url_for("node"))

    # First we get the pending users (before activating the current).
    pd = phishdetect.PhishDetect(host=session.__node__["host"],
                                 api_key=session.__node__["key"])
    results = pd.users.get_active()
    if "error" in results:
        return render_template("error.html",
                               msg="Unable to fetch pending users: {}".format(users["error"]),
                               current_node=session.__node__)

    # Then we activate the user.
    result = pd.users.deactivate(uuid)
    if "error" in result:
        return render_template("error.html",
                               msg="Unable to deactivate user: {}".format(result["error"]),
                               current_node=session.__node__)

    email = None
    for user in results:
        if uuid == user["uuid"]:
            email = user["email"]
            break

    if not email:
        return render_template("error.html", msg="User not found",
                               current_node=session.__node__)

    message = "Your PhishDetect secret token has been deactivated!\n\
If you have any questions, please contact your PhishDetect Node administrator."

    try:
        send_email(email, "Your PhishDetect secret token has been deactivated", message)
    except Exception as e:
        return render_template("error.html",
                               msg="Failed to send email to user: {}".format(e),
                               current_node=session.__node__)

    return render_template("success.html",
                           msg="The user has been deactivated successfully",
                           current_node=session.__node__)
