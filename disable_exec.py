from flask import Flask, jsonify, request
import base64
import json
import re
import sys
import os
import logging

logging.basicConfig(format="[%(levelname)s][%(asciitime)s] %(message)s")
logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))
PORT = os.environ.get("AUTHZ_PORT", 9090)
plugin = Flask(__name__)
plugin.debug = not not os.environ.get("PLUGIN_DEBUG")

@plugin.route("/Plugin.Activate", methods=["POST"])
def activate():
    return jsonify({"Implements": ["authz"]})

@plugin.route("/AuthZPlugin.AuthZReq", methods=["POST"])
def auth_z_req():
    request_data = json.loads(request.data)
    if re.match(r'.+/exec$', request_data.get("RequestUri")):
        if json.loads(base64.b64decode(request_data.get("RequestBody"))).get("User") in [None, 0, "root"]:
            return jsonify({
                "Allow": False,
                "Msg": "\rExec endpoint is disabled"
            })
    return jsonify({"Allow": True})

@plugin.route("/AuthZPlugin.AuthZRes", methods=["POST"])
def auth_z_res():
    return jsonify({"Allow": True})

plugin.run(port=PORT)