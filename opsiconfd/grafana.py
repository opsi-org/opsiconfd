# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
grafana
"""

import codecs
import datetime
import hashlib
import os
import re
import sqlite3
import subprocess
from contextlib import asynccontextmanager, contextmanager
from typing import AsyncGenerator, Generator, Tuple, Union
from urllib.parse import urlparse

import aiohttp
import requests
from packaging.version import Version
from requests.auth import AuthBase, HTTPBasicAuth

from .config import config
from .logging import logger, secret_filter
from .utils import get_random_string

API_KEY_NAME = "opsiconfd"
GRAFANA_CLI = "/usr/sbin/grafana-cli"
GRAFANA_DB = "/var/lib/grafana/grafana.db"
PLUGIN_DIR = "/var/lib/grafana/plugins"
PLUGIN_ID = "grafana-simple-json-datasource"
PLUGIN_MIN_VERSION = "1.4.2"


def grafana_is_local() -> bool:
	url = urlparse(config.grafana_internal_url)
	if url.hostname not in ("localhost", "127.0.0.1", "::1"):
		return False

	for path in (GRAFANA_CLI, GRAFANA_DB):  # pylint: disable=loop-global-usage
		if not os.path.exists(path):  # pylint: disable=dotted-import-in-loop
			return False

	return True


class HTTPBearerAuth(AuthBase):  # pylint: disable=too-few-public-methods
	def __init__(self, token: str) -> None:
		self.token = token

	def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
		r.headers["authorization"] = f"Bearer {self.token}"
		return r


@contextmanager
def grafana_admin_session() -> Generator[Tuple[str, requests.Session], None, None]:
	auth: Union[HTTPBearerAuth, HTTPBasicAuth, None] = None
	url = urlparse(config.grafana_internal_url)
	if url.username is not None:
		if url.password is None:
			# Username only, assuming this is an api key
			logger.debug("Using api key for grafana authorization")
			auth = HTTPBearerAuth(url.username)
		else:
			logger.debug("Using username %s and password grafana authorization", url.username)
			auth = HTTPBasicAuth(url.username, url.password)

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
) -> AsyncGenerator[Tuple[str, aiohttp.ClientSession], None]:
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
async def async_grafana_admin_session() -> AsyncGenerator[Tuple[str, aiohttp.ClientSession], None]:
	url = urlparse(config.grafana_internal_url)
	async with async_grafana_session(url.username, url.password) as (base_url, session):
		yield (base_url, session)


def setup_grafana() -> None:  # pylint: disable=too-many-branches
	logger.info("Setup grafana")

	if not grafana_is_local():
		logger.debug("Grafana is not local, skipping setup")
		return

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
				["grafana-cli", "plugins", plugin_action, PLUGIN_ID],  # pylint: disable=loop-global-usage
				["service", "grafana-server", "restart"],
			):
				out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=20)  # pylint: disable=dotted-import-in-loop
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

		password = get_random_string(8)
		secret_filter.add_secrets(password)

		pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("ascii"), API_KEY_NAME.encode("utf-8"), 10000, 50).hex()
		now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
		cur.execute(
			"INSERT INTO user(version, login, password, email, org_id, is_admin, salt, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			[0, "opsiconfd", pw_hash, "opsiconfd@opsi", 1, 1, API_KEY_NAME, now, now],
		)
		cur.execute("SELECT id FROM user WHERE user.login='opsiconfd';")
		user_id = cur.fetchone()
		cur.execute(
			"INSERT INTO org_user(org_id, user_id, role, created, updated) VALUES (?, ?, ?, ?, ?)", [1, user_id[0], "Admin", now, now]
		)
		con.commit()

		url = urlparse(config.grafana_internal_url)
		grafana_internal_url = f"{url.scheme}://opsiconfd:{password}@{url.hostname}:{url.port}{url.path}"
		config.grafana_internal_url = grafana_internal_url
		config.set_config_in_config_file("grafana-internal-url", grafana_internal_url)
		config.reload()
	finally:
		con.close()


async def create_dashboard_user() -> Tuple[str, str]:
	username = "opsidashboard"
	async with async_grafana_admin_session() as (base_url, session):
		try:
			response = await session.get(f"{base_url}/api/users/lookup", params={"loginOrEmail": username})
			if response.status not in (200, 404):
				response.raise_for_status()
		except aiohttp.ClientError as err:
			raise RuntimeError(f"Failed to connect to grafana api {base_url!r}: {err}") from err

		password = get_random_string(16)
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
