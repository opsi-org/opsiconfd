# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
:copyright: uib GmbH <info@uib.de>
:license: GNU Affero General Public License version 3
"""

import os
import json
import copy
import base64
import sqlite3
import random
import string
import hashlib
import datetime
import subprocess
from urllib.parse import urlparse

import aiohttp

from .logging import logger
from .config import config, set_config_in_config_file
from .utils import get_node_name, get_random_string, running_in_docker

API_KEY_NAME = "opsiconfd"

GRAFANA_DATASOURCE_TEMPLATE = {
	"orgId": 1,
	"name": "opsiconfd",
	"type": "grafana-simple-json-datasource",
	"typeLogoUrl": "public/plugins/grafana-simple-json-datasource/img/simpleJson_logo.svg",
	"access": "proxy",
	"url": None,
	"password": "",
	"user": "",
	"database": "",
	"basicAuth": True,
	"isDefault": True,
	"jsonData": {
		"tlsSkipVerify": True
	},
	#"basicAuthUser": "user",
	#"secureJsonData": {
	#	"basicAuthPassword": "pass"
	#},
	"readOnly": False
}

GRAFANA_DASHBOARD_TEMPLATE = {
	"id": None,
	"uid": "opsiconfd_main",
	"annotations": {
		"list": [
			{
			"builtIn": 1,
			"datasource": "-- Grafana --",
			"enable": True,
			"hide": True,
			"iconColor": "rgba(0, 211, 255, 1)",
			"name": "Annotations & Alerts",
			"type": "dashboard"
			}
		]
	},
	"timezone": "browser", # "utc", "browser" or "" (default)
	"title": "opsiconfd main dashboard",
	"editable": True,
	"gnetId": None,
	"graphTooltip": 0,
	"links": [],
	"panels": [],
	"refresh": "1m",
	"schemaVersion": 22,
	"version": 12,
	"style": "dark",
	"tags": [],
	"templating": {
		"list": []
	},
	"time": {
		"from": "now-5m",
		"to": "now"
	},
	"timepicker": {
		"refresh_intervals": [
			"1s",
			"5s",
			"10s",
			"30s",
			"1m",
			"5m",
			"15m",
			"30m",
			"1h",
			"2h",
			"1d"
		]
	},
	"variables": {
		"list": []
	}
}

GRAFANA_GRAPH_PANEL_TEMPLATE = {
	"aliasColors": {},
	"bars": False,
	"dashLength": 10,
	"dashes": False,
	"datasource": "opsiconfd",
	"decimals": 0,
	"description": "",
	"fill": 1,
	"fillGradient": 0,
	"gridPos": {
		"h": 12,
		"w": 8,
		"x": 0,
		"y": 0
	},
	"hiddenSeries": False,
	"id": None,
	"legend": {
		"alignAsTable": True,
		"avg": True,
		"current": True,
		"hideEmpty": True,
		"hideZero": False,
		"max": True,
		"min": True,
		"show": True,
		"total": False,
		"values": True
	},
	"lines": True,
	"linewidth": 1,
	"nullPointMode": "null",
	"options": {
		"dataLinks": []
	},
	"percentage": False,
	"pointradius": 2,
	"points": False,
	"renderer": "flot",
	"seriesOverrides": [],
	"spaceLength": 10,
	"stack": True,
	"steppedLine": False,
	"targets": [],
	"thresholds": [],
	"timeFrom": None,
	"timeRegions": [],
	"timeShift": None,
	"title": "",
	"tooltip": {
		"shared": True,
		"sort": 0,
		"value_type": "individual"
	},
	"type": "graph",
	"xaxis": {
		"buckets": None,
		"mode": "time",
		"name": None,
		"show": True,
		"values": []
	},
	"yaxes": [
		{
			"format": "short",
			"label": None,
			"logBase": 1,
			"max": None,
			"min": None,
			"show": True
		},
		{
			"format": "short",
			"label": None,
			"logBase": 1,
			"max": None,
			"min": None,
			"show": True
		}
	],
	"yaxis": {
		"align": False,
		"alignLevel": None
	}
}

GRAFANA_HEATMAP_PANEL_TEMPLATE = {
	"datasource": "opsiconfd",
	"description": "",
	"gridPos": {
		"h": 12,
		"w": 8,
		"x": 0,
		"y": 0
	},
	"id": None,
	"targets": [],
	"timeFrom": None,
	"timeShift": None,
	"title": "Duration of remote procedure calls",
	"type": "heatmap",
	"heatmap": {},
	"cards": {
		"cardPadding": None,
		"cardRound": None
	},
	"color": {
		"mode": "opacity",
		"cardColor": "#73BF69",
		"colorScale": "sqrt",
		"exponent": 0.5,
		#"colorScheme": "interpolateSpectral",
		"min": None
	},
		"legend": {
		"show": False
	},
	"dataFormat": "timeseries",
	"yBucketBound": "auto",
	"reverseYBuckets": False,
	"xAxis": {
		"show": True
	},
	"yAxis": {
		"show": True,
		"format": "s",
		"decimals": 2,
		"logBase": 2,
		"splitFactor": None,
		"min": "0",
		"max": None
	},
	"xBucketSize": None,
	"xBucketNumber": None,
	"yBucketSize": None,
	"yBucketNumber": None,
	"tooltip": {
		"show": False,
		"showHistogram": False
	},
	"highlightCards": True,
	"hideZeroBuckets": False,
	"tooltipDecimals": 0
}

class GrafanaPanelConfig: # pylint: disable=too-few-public-methods
	def __init__(self, type="graph", title="", units=["short", "short"], decimals=0, stack=False, yaxis_min = "auto"): # pylint: disable=dangerous-default-value, too-many-arguments, redefined-builtin
		self.type = type
		self.title = title
		self.units = units
		self.decimals = decimals
		self.stack = stack
		self._template = ""
		self.yaxis_min = yaxis_min
		if self.type == "graph":
			self._template = GRAFANA_GRAPH_PANEL_TEMPLATE
		elif self.type == "heatmap":
			self._template = GRAFANA_HEATMAP_PANEL_TEMPLATE

	def get_panel(self, id=1, x=0, y=0): # pylint: disable=redefined-builtin, invalid-name
		panel = copy.deepcopy(self._template)
		panel["id"] = id
		panel["gridPos"]["x"] = x
		panel["gridPos"]["y"] = y
		panel["title"] = self.title
		if self.type == "graph":
			panel["stack"] = self.stack
			panel["decimals"] = self.decimals
			for i, unit in enumerate(self.units):
				panel["yaxes"][i]["format"] = unit
		elif self.type == "heatmap":
			panel["yAxis"]["format"] = self.units[0]
			panel["tooltipDecimals"] = self.decimals
		if self.yaxis_min != "auto":
			for axis in panel["yaxes"]:
				axis["min"] = self.yaxis_min
		return panel


def setup_grafana():
	grafana_plugin_dir = "/var/lib/grafana/plugins"
	grafana_cli = "/usr/sbin/grafana-cli"
	grafana_db = "/var/lib/grafana/grafana.db"
	plugin_id = "grafana-simple-json-datasource"

	url = urlparse(config.grafana_internal_url)
	if url.hostname not in ("localhost", "127.0.0.1", "::1"):
		return
	if not os.path.exists(grafana_cli):
		return
	for f in (grafana_plugin_dir, grafana_db): # pylint: disable=invalid-name
		if not os.path.exists(f):
			raise FileNotFoundError(f"'{f}' not found")
	if not os.path.exists(os.path.join(grafana_plugin_dir, plugin_id)):
		logger.notice("Setup grafana plugin %s", plugin_id)
		for cmd in (
			["grafana-cli", "plugins", "install", plugin_id],
			["service", "grafana-server", "restart"]
		):
			out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=15)
			logger.debug("output of command %s: %s", cmd, out)

	if url.username is not None:
		return

	create_opsiconfd_user(grafana_db)


async def create_or_update_api_key_by_api(admin_username: str, admin_password: str):
	auth = aiohttp.BasicAuth(admin_username, admin_password)
	async with aiohttp.ClientSession(auth=auth) as session:
		resp = await session.get(f"{config.grafana_internal_url}/api/auth/keys")
		for key in await resp.json():
			if key["name"] == API_KEY_NAME:
				await session.delete(f"{config.grafana_internal_url}/api/auth/keys/{key['id']}")
		json = {"name": API_KEY_NAME, "role":"Admin", "secondsToLive": None} # pylint: disable=redefined-outer-name
		resp = await session.post(f"{config.grafana_internal_url}/api/auth/keys", json=json)
		api_key = (await resp.json())["key"]
		return api_key

def create_or_update_api_key_in_grafana_db(db_file: str):
	key = "".join(random.choices(string.ascii_letters + string.digits, k=32))

	conn = sqlite3.connect(db_file)
	cur = conn.cursor()
	cur.execute("SELECT id FROM org")
	res = cur.fetchone()
	if not res:
		raise RuntimeError(f"Failed to get org_id from {db_file}")
	org_id = res[0]

	db_key = hashlib.pbkdf2_hmac("sha256", key.encode("ascii"), API_KEY_NAME.encode("utf-8"), 10000, 50)
	now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

	cur.execute("SELECT id FROM api_key WHERE org_id = ? AND name = ?", [org_id, API_KEY_NAME])
	res = cur.fetchone()
	if res:
		cur.execute(
			"UPDATE api_key SET key = ?, role = ?, updated = ? WHERE id = ?",
			[db_key.hex(), "Admin", now, res[0]]
		)
	else:
		cur.execute(
			"INSERT INTO api_key(org_id, name, key, role, created, updated, expires) VALUES (?, ?, ?, ?, ?, ?, ?)",
			[org_id, API_KEY_NAME, db_key.hex(), "Admin", now, now, None]
		)


	conn.commit()
	conn.close()

	api_key = {
		"id": org_id,
		"n": API_KEY_NAME,
		"k": key
	}
	return base64.b64encode(json.dumps(api_key).encode("utf-8")).decode("utf-8")

def create_opsiconfd_user(db_file: str):
	logger.notice("Setup grafana opsiconfd user")

	conn = sqlite3.connect(db_file)
	cur = conn.cursor()

	cur.execute(
		"SELECT id FROM user WHERE user.login='opsiconfd';"
	)
	user_id = cur.fetchone()

	if not user_id:
		pw = get_random_string(8) # pylint: disable=invalid-name
		pw_hash = hashlib.pbkdf2_hmac("sha256", pw.encode("ascii"), API_KEY_NAME.encode("utf-8"), 10000, 50).hex()
		now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
		cur.execute(
			"INSERT INTO user(version, login, password, email, org_id, is_admin, salt, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			[0,"opsiconfd", pw_hash, "opsiconfd@opsi", 1, 1, API_KEY_NAME, now, now]
		)
		cur.execute(
			"SELECT id FROM user WHERE user.login='opsiconfd';"
		)
		user_id = cur.fetchone()
		cur.execute(
			"INSERT INTO org_user(org_id, user_id, role, created, updated) VALUES (?, ?, ?, ?, ?)",
			[1, user_id[0], "Admin", now, now]
		)
		conn.commit()
		conn.close()

		url = urlparse(config.grafana_internal_url)
		grafana_internal_url = f"{url.scheme}://opsiconfd:{pw}@{url.hostname}:{url.port}{url.path}"
		set_config_in_config_file("grafana-internal-url", grafana_internal_url)
		config.reload()

grafana_data_source_url = None # pylint: disable=invalid-name
def get_grafana_data_source_url():
	global grafana_data_source_url # pylint: disable=invalid-name, global-statement
	if not grafana_data_source_url:
		if config.grafana_data_source_url:
			grafana_data_source_url = config.grafana_data_source_url
		else:
			scheme = "http"
			if config.ssl_server_key and config.ssl_server_cert:
				scheme = "https"
			addr = "localhost"
			if running_in_docker():
				addr = get_node_name()
			grafana_data_source_url = f"{scheme}://{addr}:{config.port}"
	return grafana_data_source_url
