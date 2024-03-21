# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.setup.backend
"""

import os
import re
import string
import time
from pathlib import Path

import OPSI.Backend.File  # type: ignore[import-untyped]
from OPSI.Backend.Replicator import BackendReplicator  # type: ignore[import-untyped]
from opsicommon.objects import OpsiConfigserver
from rich import print as rich_print
from rich.prompt import Confirm, Prompt

from opsiconfd.backend import get_mysql
from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.backend.mysql.cleanup import cleanup_database
from opsiconfd.backend.mysql.schema import (
	create_database,
	drop_database,
	update_database,
)
from opsiconfd.config import (
	DEPOT_DIR,
	FQDN,
	REPOSITORY_DIR,
	WORKBENCH_DIR,
	config,
	get_configserver_id,
	get_depotserver_id,
	get_server_role,
	opsi_config,
)
from opsiconfd.logging import logger, secret_filter
from opsiconfd.utils import get_ip_addresses, get_random_string


def setup_mysql_user(root_mysql: MySQLConnection, mysql: MySQLConnection) -> None:
	address = mysql.address = root_mysql.address
	mysql.database = root_mysql.database
	mysql.password = "opsi" if config._pytest else get_random_string(16, alphabet=string.ascii_letters + string.digits)
	secret_filter.add_secrets(mysql.password)
	if address.startswith("/"):  # Unix socket
		address = "localhost"
	logger.info("Creating MySQL user %r and granting all rights on %r", mysql.username, mysql.database)
	with root_mysql.session() as session:
		session.execute(f"CREATE USER IF NOT EXISTS '{mysql.username}'@'{address}'")
		try:
			session.execute(f"ALTER USER '{mysql.username}'@'{address}' IDENTIFIED WITH mysql_native_password BY '{mysql.password}'")
		except Exception as err:
			logger.debug(err)
			try:
				session.execute(f"ALTER USER '{mysql.username}'@'{address}' IDENTIFIED BY '{mysql.password}'")
			except Exception as err2:
				logger.debug(err2)
				session.execute(f"SET PASSWORD FOR '{mysql.username}'@'{address}' = PASSWORD('{mysql.password}')")
		session.execute(f"GRANT ALL ON {mysql.database}.* TO '{mysql.username}'@'{address}'")
		session.execute("FLUSH PRIVILEGES")
		logger.notice("MySQL user %r created and privileges set", mysql.username)

	mysql.update_config_file()


def setup_mysql_connection(interactive: bool = False, force: bool = False) -> None:
	error: Exception | None = None

	mysql = MySQLConnection()
	if not force:
		for _ in range(4):
			try:
				with mysql.connection():
					# OK
					return
			except Exception as err:
				logger.info("Failed to connect to MySQL database: %s", err)
				error = err
				if not interactive and "connection refused" in str(err).lower():
					# MySQL server starting up after upgrade?
					logger.info("Retry connection in 3 seconds")
					time.sleep(2.5)
					continue
				break

	mysql_root = MySQLConnection()
	auto_try = False
	if not force and mysql_root.address in ("localhost", "127.0.0.1", "::1") or mysql_root.address.startswith("/"):
		# Try unix socket connection as user root
		address = "localhost"
		for unix_socket in ("/run/mysql/mysqld.sock", "/run/mysql/mysql.sock", "/var/lib/mysql/mysql.sock", "/var/run/mysqld/mysqld.sock"):
			if Path(unix_socket).exists():
				logger.info("MySQL socket found at %s", unix_socket)
				address = unix_socket
				break
		auto_try = True
		mysql_root.address = address
		mysql_root.database = mysql_root.database or "opsi"
		mysql_root.username = "root"
		mysql_root.password = os.environ.get("MYSQL_ROOT_PASSWORD", "")
		logger.info("Trying to connect to local MySQL database as %s", mysql_root.username)

	while True:
		if not auto_try:
			if not interactive:
				raise error  # type: ignore[misc]
			if error:
				error_str = str(error).split("\n", 1)[0]
				match = re.search(r"(\(\d+,\s.*)", error_str)
				if match:
					error_str = match.group(1).strip("()")
				rich_print(f"[b][red]Failed to connect to MySQL database[/red]: {error_str}[/b]")
			if not Confirm.ask("Do you want to configure the MySQL database connection?"):
				raise error  # type: ignore[misc]
			mysql_root.address = Prompt.ask("Enter MySQL server address", default=mysql_root.address, show_default=True)
			mysql_root.database = Prompt.ask("Enter MySQL database", default=mysql_root.database, show_default=True)
			mysql_root.username = Prompt.ask("Enter MySQL admin username", default="root", show_default=True)
			mysql_root.password = Prompt.ask("Enter MySQL admin password", password=True)
			secret_filter.add_secrets(mysql_root.password)
			if force:
				mysql.username = Prompt.ask("Enter MySQL username for opsiconfd", default=mysql.username, show_default=True)
		try:
			with mysql_root.connection():
				if not auto_try:
					rich_print("[b][green]MySQL admin connection established[/green][/b]")
					rich_print("[b]Setting up MySQL user[/b]")
				setup_mysql_user(mysql_root, mysql)
				if not auto_try:
					rich_print("[b][green]MySQL user setup successful[/green][/b]")
				break
		except Exception as err:
			if not auto_try:
				error = err

		auto_try = False
		mysql_root = MySQLConnection()


def setup_mysql(interactive: bool = False, explicit: bool = False, force: bool = False) -> None:
	setup_mysql_connection(interactive=interactive, force=force)

	mysql = MySQLConnection()
	if interactive and force:
		rich_print(f"[b]Creating MySQL database {mysql.database!r} on {mysql.address!r}[/b]")
	try:
		mysql.connect()
		create_database(mysql)
	except Exception as err:
		if interactive and force:
			rich_print(f"[b][red]Failed to create MySQL database: {err}[/red][/b]")
		raise
	if interactive and force:
		rich_print("[b][green]MySQL database created successfully[/green][/b]")

	if interactive and force:
		rich_print("[b]Updating MySQL database[/b]")
	try:
		update_database(mysql, force=explicit)
	except Exception as err:
		if interactive and force:
			rich_print(f"[b][red]Failed to update MySQL database: {err}[/red][/b]")
		raise
	if interactive and force:
		rich_print("[b][green]MySQL database updated successfully[/green][/b]")

	if interactive and force:
		rich_print("[b]Cleaning up MySQL database[/b]")
	try:
		cleanup_database(mysql)
	except Exception as err:
		if interactive and force:
			rich_print(f"[b][red]Failed to cleanup MySQL database: {err}[/red][/b]")
		raise
	if interactive and force:
		rich_print("[b][green]MySQL database cleaned up successfully[/green][/b]")


def file_mysql_migration() -> None:
	dipatch_conf = Path(config.dispatch_config_file)
	if not dipatch_conf.exists():
		return

	file_backend_used = False
	for line in dipatch_conf.read_text(encoding="utf-8").split("\n"):
		line = line.strip()
		if not line or line.startswith("#") or ":" not in line:
			continue
		if "file" in line.split(":", 1)[1]:
			file_backend_used = True
			break
	if not file_backend_used:
		dipatch_conf.rename(dipatch_conf.with_suffix(".conf.old"))
		return

	logger.notice("Converting File to MySQL backend, please wait...")
	config_server_id = opsi_config.get("host", "id")
	OPSI.Backend.File.getfqdn = lambda: config_server_id

	file_backend = OPSI.Backend.File.FileBackend()
	config_servers = file_backend.host_getObjects(type="OpsiConfigserver")

	if not config_servers:
		depot_servers = file_backend.host_getObjects(type="OpsiDepotserver")
		if len(depot_servers) > 1:
			error = (
				"Cannot convert File to MySQL backend:\n"
				f"Configserver {file_backend.__serverId!r} not found in File backend.\n"
				f"Depot servers in File backend are: {', '.join(d.id for d in depot_servers)}.\n"
				f"Set host.id in {opsi_config.config_file!r} to one of these IDs and retry."
			)
			logger.error(error)
			raise ValueError(error)

		config_server_id = depot_servers[0].id
		config_servers = file_backend.host_getObjects(type="OpsiConfigserver")
		opsi_config.set("host", "id", config_server_id, persistent=True)

	from opsiconfd.backend import get_unprotected_backend

	backend = get_unprotected_backend()
	with backend.events_disabled():
		mysql = get_mysql()
		mysql.connect()
		drop_database(mysql)
		create_database(mysql)
		mysql.disconnect()
		mysql.connect()
		update_database(mysql, force=True)

		with mysql.disable_unique_hardware_addresses():
			backend_replicator = BackendReplicator(readBackend=file_backend, writeBackend=backend, cleanupFirst=False)
			backend_replicator.replicate(audit=False)

		dipatch_conf.rename(dipatch_conf.with_suffix(".conf.old"))


def setup_backend_configserver(force_server_id: str | None = None) -> None:
	file_mysql_migration()

	from opsiconfd.backend import get_unprotected_backend

	configserver_id = force_server_id or get_configserver_id()

	backend = get_unprotected_backend()
	with backend.events_disabled():
		conf_servers = backend.host_getObjects(type="OpsiConfigserver")
		if not conf_servers:
			logger.notice("Creating config server %r", configserver_id)

			ip_address = None
			network_address = None
			for addr in get_ip_addresses():
				if addr["interface"] == "lo":
					continue
				if not ip_address or addr["family"] == "ipv4":
					# Prefer IPv4
					ip_address = addr["address"]
					network_address = addr["network"]

			conf_servers = [
				OpsiConfigserver(
					id=configserver_id,
					opsiHostKey=None,
					depotLocalUrl=f"file://{DEPOT_DIR}",
					depotRemoteUrl=f"smb://{FQDN}/opsi_depot",
					depotWebdavUrl=f"webdavs://{FQDN}:4447/depot",
					repositoryLocalUrl=f"file://{REPOSITORY_DIR}",
					repositoryRemoteUrl=f"webdavs://{FQDN}:4447/repository",
					workbenchLocalUrl=f"file://{WORKBENCH_DIR}",
					workbenchRemoteUrl=f"smb://{FQDN}/opsi_workbench",
					description=None,
					notes=None,
					hardwareAddress=None,
					ipAddress=ip_address,
					inventoryNumber=None,
					networkAddress=network_address,
					maxBandwidth=0,
					isMasterDepot=True,
					masterDepotId=None,
				)
			]
			backend.host_createObjects(conf_servers)
		elif conf_servers[0].id != configserver_id:
			if force_server_id:
				logger.notice("Renaming configserver from %r to %r, do not abort", conf_servers[0].id, configserver_id)
				backend.host_renameOpsiDepotserver(conf_servers[0].id, configserver_id)
				opsi_config.set("host", "id", configserver_id, persistent=True)
			else:
				raise ValueError(
					f"Config server ID {conf_servers[0].id!r} in database differs from "
					f"host.id {configserver_id!r} in /etc/opsi/opsi.conf. "
					f"Please change host.id in /etc/opsi/opsi.conf to {conf_servers[0].id!r} "
					"or use `opsiconfd setup --rename-server` to fix this issue."
				)
		backend.exit()

		opsi_config.set("host", "key", conf_servers[0].opsiHostKey, persistent=True)


def setup_backend_depotserver(force_server_id: str | None = None) -> None:
	if not force_server_id:
		return
	depotserver_id = get_depotserver_id()
	if depotserver_id == force_server_id:
		return

	from opsiconfd.backend import get_unprotected_backend

	backend = get_unprotected_backend()
	backend.host_renameOpsiDepotserver(depotserver_id, force_server_id)
	backend.exit()

	opsi_config.set("host", "id", force_server_id, persistent=True)
	opsi_config.write_config_file()


def setup_backend(force_server_id: str | None = None) -> None:
	if get_server_role() == "configserver":
		setup_backend_configserver(force_server_id)
	else:
		setup_backend_depotserver(force_server_id)
