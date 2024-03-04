# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
grafana
"""

import codecs
import copy
import datetime
import hashlib
import os
import re
import sqlite3
import string
import subprocess
from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncGenerator, Generator
from urllib.parse import quote, unquote, urlparse

import aiohttp
import requests
from configupdater import ConfigUpdater
from packaging.version import Version
from requests.auth import AuthBase, HTTPBasicAuth

from opsiconfd.config import config
from opsiconfd.logging import logger, secret_filter
from opsiconfd.utils import get_random_string

API_KEY_NAME = "opsiconfd"
GRAFANA_CLI = "/usr/sbin/grafana-cli"
GRAFANA_DB = "/var/lib/grafana/grafana.db"
GRAFANA_INI = "/etc/grafana/grafana.ini"
PLUGIN_DIR = "/var/lib/grafana/plugins"
PLUGIN_ID = "grafana-simple-json-datasource"
PLUGIN_MIN_VERSION = "1.4.2"

GRAFANA_DASHBOARD_UID = "opsiconfd_main"

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
	"isDefault": False,
	"jsonData": {"tlsSkipVerify": True},
	"readOnly": False,
}

GRAFANA_DASHBOARD_TEMPLATE: dict[str, Any] = {
	"id": None,
	"uid": GRAFANA_DASHBOARD_UID,
	"annotations": {
		"list": [
			{
				"builtIn": 1,
				"datasource": "-- Grafana --",
				"enable": True,
				"hide": True,
				"iconColor": "rgba(0, 211, 255, 1)",
				"name": "Annotations & Alerts",
				"type": "dashboard",
			}
		]
	},
	"timezone": "browser",  # "utc", "browser" or "" (default)
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
	"templating": {"list": []},
	"time": {"from": "now-5m", "to": "now"},
	"timepicker": {"refresh_intervals": ["1s", "5s", "10s", "30s", "1m", "5m", "15m", "30m", "1h", "2h", "1d"]},
	"variables": {"list": []},
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
	"gridPos": {"h": 12, "w": 8, "x": 0, "y": 0},
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
		"values": True,
	},
	"lines": True,
	"linewidth": 1,
	"nullPointMode": "null",
	"options": {"dataLinks": []},
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
	"tooltip": {"shared": True, "sort": 0, "value_type": "individual"},
	"type": "graph",
	"xaxis": {"buckets": None, "mode": "time", "name": None, "show": True, "values": []},
	"yaxes": [
		{"format": "short", "label": None, "logBase": 1, "max": None, "min": None, "show": True},
		{"format": "short", "label": None, "logBase": 1, "max": None, "min": None, "show": True},
	],
	"yaxis": {"align": False, "alignLevel": None},
}

GRAFANA_HEATMAP_PANEL_TEMPLATE = {
	"datasource": "opsiconfd",
	"description": "",
	"gridPos": {"h": 12, "w": 8, "x": 0, "y": 0},
	"id": None,
	"targets": [],
	"timeFrom": None,
	"timeShift": None,
	"title": "Duration of remote procedure calls",
	"type": "heatmap",
	"heatmap": {},
	"cards": {"cardPadding": None, "cardRound": None},
	"color": {
		"mode": "opacity",
		"cardColor": "#73BF69",
		"colorScale": "sqrt",
		"exponent": 0.5,
		# "colorScheme": "interpolateSpectral",
		"min": None,
	},
	"legend": {"show": False},
	"dataFormat": "timeseries",
	"yBucketBound": "auto",
	"reverseYBuckets": False,
	"xAxis": {"show": True},
	"yAxis": {"show": True, "format": "s", "decimals": 2, "logBase": 2, "splitFactor": None, "min": "0", "max": None},
	"xBucketSize": None,
	"xBucketNumber": None,
	"yBucketSize": None,
	"yBucketNumber": None,
	"tooltip": {"show": False, "showHistogram": False},
	"highlightCards": True,
	"hideZeroBuckets": False,
	"tooltipDecimals": 0,
}


class GrafanaPanelConfig:
	def __init__(
		self,
		type: str = "graph",
		title: str = "",
		units: list[str] | None = None,
		decimals: int = 0,
		stack: bool = False,
		yaxis_min: int | str = "auto",
	) -> None:
		self.type = type
		self.title = title
		self.units = units or ["short", "short"]
		self.decimals = decimals
		self.stack = stack
		self._template = {}
		self.yaxis_min = yaxis_min
		if self.type == "graph":
			self._template = GRAFANA_GRAPH_PANEL_TEMPLATE
		elif self.type == "heatmap":
			self._template = GRAFANA_HEATMAP_PANEL_TEMPLATE  # type: ignore[assignment]

	def get_panel(self, panel_id: int = 1, pos_x: int = 0, pos_y: int = 0) -> dict[str, Any]:
		panel = copy.deepcopy(self._template)
		panel["id"] = panel_id
		panel["gridPos"]["x"] = pos_x  # type: ignore[index]
		panel["gridPos"]["y"] = pos_y  # type: ignore[index]
		panel["title"] = self.title
		if self.type == "graph":
			panel["stack"] = self.stack
			panel["decimals"] = self.decimals
			for i, unit in enumerate(self.units):
				panel["yaxes"][i]["format"] = unit  # type: ignore[index]
		elif self.type == "heatmap":
			panel["yAxis"]["format"] = self.units[0]  # type: ignore[index]
			panel["tooltipDecimals"] = self.decimals
		if self.yaxis_min != "auto":
			for axis in panel["yaxes"]:  # type: ignore[attr-defined]
				axis["min"] = self.yaxis_min
		return panel


def grafana_is_local() -> bool:
	url = urlparse(config.grafana_internal_url)
	if url.hostname not in ("localhost", "127.0.0.1", "::1"):
		return False

	for path in (GRAFANA_CLI, GRAFANA_DB):
		if not os.path.exists(path):
			return False

	return True


class HTTPBearerAuth(AuthBase):
	def __init__(self, token: str) -> None:
		self.token = token

	def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
		r.headers["authorization"] = f"Bearer {self.token}"
		return r


@contextmanager
def grafana_admin_session() -> Generator[tuple[str, requests.Session], None, None]:
	auth: HTTPBearerAuth | HTTPBasicAuth | None = None
	url = urlparse(config.grafana_internal_url)
	if url.username is not None:
		if url.password is None:
			# Username only, assuming this is an api key
			logger.debug("Using api key for grafana authorization")
			auth = HTTPBearerAuth(url.username)
		else:
			logger.debug("Using username %s and password grafana authorization", url.username)
			auth = HTTPBasicAuth(url.username, unquote(url.password))

	try:
		session = requests.Session()
		session.auth = auth
		session.verify = config.ssl_trusted_certs
		if not config.grafana_verify_cert:
			session.verify = False

		yield f"{url.scheme}://{url.hostname}:{url.port}", session
	finally:
		session.close()


@asynccontextmanager
async def async_grafana_session(
	username: str | None = None, password: str | None = None
) -> AsyncGenerator[tuple[str, aiohttp.ClientSession], None]:
	auth = None
	headers = None
	if username is not None:
		if password is None:
			# Username only, assuming this is an api key
			logger.debug("Using api key for grafana authorization")
			headers = {"Authorization": f"Bearer {username}"}
		else:
			logger.debug("Using username %s and password grafana authorization", username)
			auth = aiohttp.BasicAuth(username, password)

	connector = aiohttp.TCPConnector(verify_ssl=config.grafana_verify_cert)

	url = urlparse(config.grafana_internal_url)
	async with aiohttp.ClientSession(connector=connector, auth=auth, headers=headers) as session:
		yield f"{url.scheme}://{url.hostname}:{url.port}", session


@asynccontextmanager
async def async_grafana_admin_session() -> AsyncGenerator[tuple[str, aiohttp.ClientSession], None]:
	url = urlparse(config.grafana_internal_url)
	async with async_grafana_session(url.username, unquote(url.password)) as (base_url, session):
		yield (base_url, session)


def setup_grafana() -> None:
	logger.info("Setup grafana")

	if not grafana_is_local():
		logger.debug("Grafana is not local, skipping setup")
		return

	set_grafana_root_url()

	plugin_action = "install"
	if os.path.exists(PLUGIN_DIR):
		manifest = os.path.join(PLUGIN_DIR, PLUGIN_ID, "MANIFEST.txt")
		if os.path.exists(manifest):
			with codecs.open(manifest, "r", "utf-8") as file:
				match = re.search(r'"version"\s*:\s*"([^"]+)"', file.read())
				if match:
					plugin_version = match.group(1)
					logger.debug("Grafana plugin %s version: %s", PLUGIN_ID, plugin_version)
					if Version(plugin_version) < Version(PLUGIN_MIN_VERSION):
						logger.notice("Grafana plugin %s version %s to old", PLUGIN_ID, plugin_version)
						plugin_action = "upgrade"
					else:
						plugin_action = ""
	else:
		logger.warning("Grafana plugin dir %r not found", PLUGIN_DIR)

	if plugin_action:
		try:
			logger.notice("Setup grafana plugin %s (%s)", PLUGIN_ID, plugin_action)
			for cmd in (
				["grafana-cli", "plugins", plugin_action, PLUGIN_ID],
				["service", "grafana-server", "restart"],
			):
				out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=20)
				logger.debug("output of command %s: %s", cmd, out)
		except subprocess.CalledProcessError as err:
			logger.warning("Could not %s grafana plugin via grafana-cli: %s", plugin_action, err)

	if urlparse(config.grafana_internal_url).username is not None:
		with grafana_admin_session() as (base_url, session):
			try:
				response = session.get(f"{base_url}/api/users/lookup", params={"loginOrEmail": "opsiconfd"}, timeout=3)
			except requests.RequestException as err:
				logger.warning("Failed to connect to grafana api %r: %s", base_url, err)
				return

			logger.debug("Grafana opsiconfd user lookup response: %s - %s", response.status_code, response.text)
			if response.status_code == 200:
				return

	create_opsiconfd_user(recreate=True)


def create_opsiconfd_user(recreate: bool = False) -> None:
	logger.notice("Setup grafana opsiconfd user")

	con = sqlite3.connect(GRAFANA_DB)
	cur = con.cursor()
	try:
		cur.execute("SELECT id FROM user WHERE user.login='opsiconfd';")
		user_id = cur.fetchone()

		if user_id and not recreate:
			return

		if user_id:
			cur.execute("DELETE FROM org_user WHERE user_id = ?", [user_id[0]])
			cur.execute("DELETE FROM user WHERE id = ?", [user_id[0]])

		password = get_random_string(16, alphabet=string.ascii_letters + string.digits)
		secret_filter.add_secrets(password)

		pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), API_KEY_NAME.encode("utf-8"), 10000, 50).hex()
		now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
		cur.execute(
			"INSERT INTO user(version, login, password, email, org_id, is_admin, salt, created, updated) "
			"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			[0, "opsiconfd", pw_hash, "opsiconfd@opsi", 1, 1, API_KEY_NAME, now, now],
		)
		cur.execute("SELECT id FROM user WHERE user.login='opsiconfd';")
		user_id = cur.fetchone()
		cur.execute(
			"INSERT INTO org_user(org_id, user_id, role, created, updated) VALUES (?, ?, ?, ?, ?)", [1, user_id[0], "Admin", now, now]
		)
		con.commit()

		url = urlparse(config.grafana_internal_url)
		password = quote(password)
		secret_filter.add_secrets(password)
		grafana_internal_url = f"{url.scheme}://opsiconfd:{password}@{url.hostname}:{url.port}{url.path}"
		config.grafana_internal_url = grafana_internal_url
		config.set_config_in_config_file("grafana-internal-url", grafana_internal_url)
		config.reload()
	finally:
		con.close()


async def create_dashboard_user() -> tuple[str, str]:
	username = "opsidashboard"
	async with async_grafana_admin_session() as (base_url, session):
		try:
			response = await session.get(f"{base_url}/api/users/lookup", params={"loginOrEmail": username})
			if response.status not in (200, 404):
				response.raise_for_status()
		except aiohttp.ClientError as err:
			raise RuntimeError(f"Failed to connect to grafana api {base_url!r}: {err}") from err

		password = get_random_string(16, alphabet=string.ascii_letters + string.digits)
		if response.status == 404:
			logger.debug("Create new user %s", username)
			data = {"name": username, "email": f"{username}@admin", "login": username, "password": password}
			response = await session.post(f"{base_url}/api/admin/users", json=data)
			if response.status != 200:
				raise RuntimeError(f"Failed to create user {username!r}: {response.status} - {await response.text()}")
		else:
			logger.debug("Change password of user %s", username)
			data = {"password": password}
			user_id = (await response.json()).get("id")
			response = await session.put(f"{base_url}/api/admin/users/{user_id}/password", json=data)
			if response.status != 200:
				raise RuntimeError(f"Failed to update password for user {username!r}: {response.status} - {await response.text()}")

		return username, password


def set_grafana_root_url() -> None:
	root_url = r"%(protocol)s://%(domain)s:%(http_port)s/grafana"

	grafana_config = ConfigUpdater()
	data = "[DEFAULT]\n"
	with open(GRAFANA_INI, "r", encoding="utf-8") as config_file:
		data += config_file.read()
	grafana_config.read_string(data)

	for section in grafana_config.sections():
		if section == "server":
			continue
		if grafana_config[section].has_option("root_url"):
			logger.notice("Removing root_url from %s in section '%s'", GRAFANA_INI, section)
			del grafana_config[section]["root_url"]

	if grafana_config["server"].has_option("root_url"):
		if grafana_config["server"]["root_url"].value == root_url:
			return
		logger.notice("Changing root_url in %s", GRAFANA_INI)
		grafana_config["server"]["root_url"].value = root_url
	else:
		logger.notice("Adding root_url to %s", GRAFANA_INI)
		grafana_config["server"].insert_at(0).option("root_url", root_url)
	data = str(grafana_config)

	with open(GRAFANA_INI, "w", encoding="utf-8") as config_file:
		config_file.write(data.split("\n", 1)[1])

	logger.notice("Restart grafana server")
	try:
		proc = subprocess.run(["systemctl", "is-active", "--quiet", "grafana-server.service"], shell=False, check=False)
		if proc.returncode == 0:
			# grafana-server is running
			proc = subprocess.run(["systemctl", "restart", "grafana-server.service"], shell=False, check=True)
	except (FileNotFoundError, subprocess.CalledProcessError) as err:
		logger.warning(err)
