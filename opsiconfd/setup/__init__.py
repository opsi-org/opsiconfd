# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd - setup
"""

import json
import sys
import time
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID

from opsicommon.client.opsiservice import ServiceClient
from opsicommon.exceptions import OpsiServiceConnectionError
from opsicommon.objects import OpsiDepotserver
from opsicommon.types import forceHostId
from rich import print as rich_print
from rich.prompt import Confirm, Prompt

from opsiconfd import __version__
from opsiconfd.backend import new_service_client
from opsiconfd.config import DEPOT_DIR, FQDN, REPOSITORY_DIR, WORKBENCH_DIR, config, get_server_role, opsi_config
from opsiconfd.dhcpd import setup_dhcpd
from opsiconfd.grafana import setup_grafana
from opsiconfd.logging import logger
from opsiconfd.metrics.statistics import setup_metric_downsampling
from opsiconfd.redis import delete_recursively, redis_client
from opsiconfd.setup.backend import setup_backend, setup_mysql
from opsiconfd.setup.configs import setup_configs
from opsiconfd.setup.files import cleanup_log_files, setup_file_permissions, setup_files
from opsiconfd.setup.samba import setup_samba
from opsiconfd.setup.sudo import setup_sudoers
from opsiconfd.setup.system import set_unprivileged_port_start, setup_limits, setup_systemd, setup_users_and_groups
from opsiconfd.ssl import fetch_server_cert, setup_ssl, store_local_server_cert, store_local_server_key
from opsiconfd.utils import opsiconfd_running, restart_opsiconfd
from opsiconfd.utils.user import user_set_credentials


def restart_opsiconfd_if_running() -> None:
	if not opsiconfd_running():
		return
	rich_print("[b]Restarting opsiconfd[/b]")
	restart_opsiconfd()


def setup_redis() -> None:
	# Delete obsolete keys
	for delete_key in (
		"status",
		f"{config.redis_key('stats')}:client:failed_auth",
		f"{config.redis_key('stats')}:client:num_http_request",
		f"{config.redis_key('stats')}:client:sum_http_request",
		f"{config.redis_key('stats')}:client:sum_http_request_number",
	):
		delete_recursively(delete_key)


def setup_depotserver(unattended_configuration: dict | None = None) -> bool:
	with ServiceClient(
		opsi_config.get("service", "url"),
		verify="accept_all",
		ca_cert_file=config.ssl_ca_cert,
		jsonrpc_create_objects=True,
		jsonrpc_create_methods=True,
	) as service:
		while True:
			try:
				if not unattended_configuration:
					if not Confirm.ask("Do you want to register this server as a depotserver?"):
						return False
				else:
					rich_print(f"Registering server as depotserver with unattended configuration '{unattended_configuration}'")
					key_list = ["configserver", "username", "password", "depot_id", "description"]
					for key in key_list:
						if key not in unattended_configuration:
							raise ValueError(f"Missing unattended configuration '{key}' in {unattended_configuration}")

				url = urlparse(service.base_url)
				hostname = url.hostname
				if hostname in ("127.0.0.1", "::1", "localhost"):
					hostname = ""
				if unattended_configuration:
					inp = unattended_configuration["configserver"]
				else:
					inp = Prompt.ask("Enter opsi server address or service url", default=hostname, show_default=True)
				if not inp:
					raise ValueError(f"Invalid address {inp!r}")
				service.set_addresses(inp)
				if unattended_configuration:
					service.username = unattended_configuration["username"]
					service.password = unattended_configuration["password"]
				else:
					service.username = Prompt.ask("Enter username for service connection", default=service.username, show_default=True)
					service.password = Prompt.ask(f"Enter password for {service.username!r}", password=True)

				rich_print(f"[b]Connecting to service {service.base_url!r}[/b]")
				service.connect()
				rich_print(f"[b][green]Connected to service as {service.username!r}[/green][/b]")
				break
			except KeyboardInterrupt:
				print("")
				return False
			except Exception as err:
				if unattended_configuration:
					raise
				rich_print(f"[b][red]Failed to connect to opsi service[/red]: {err}[/b]")

		depot_id = opsi_config.get("host", "id")
		depot = OpsiDepotserver(id=depot_id)
		while True:
			try:
				if unattended_configuration:
					inp = unattended_configuration["depot_id"]
				else:
					inp = Prompt.ask("Enter ID of the depot", default=depot.id, show_default=True) or ""
				depot.setId(inp)

				hosts = service.host_getObjects(id=depot.id)  # type: ignore[attr-defined]
				if hosts:
					depot = hosts[0]
					if depot.getType() != "OpsiDepotserver":
						if not Confirm.ask(f"[b][red]Host {depot.id} already exists, but is a {depot.getType()!r}, continue?[red][/b]"):
							return False
						depot = OpsiDepotserver.fromHash({k: v for k, v in depot.to_hash().items() if k != "type"})

				depot.isMasterDepot = True
				if unattended_configuration:
					depot.description = unattended_configuration["description"]
				else:
					depot.description = Prompt.ask("Enter a description for the depot", default=depot.description, show_default=True) or ""
				depot.depotLocalUrl = f"file://{DEPOT_DIR}"
				depot.depotRemoteUrl = depot.depotRemoteUrl or f"smb://{FQDN}/opsi_depot"
				depot.depotWebdavUrl = depot.depotWebdavUrl or f"webdavs://{FQDN}:4447/depot"
				depot.repositoryLocalUrl = f"file://{REPOSITORY_DIR}"
				depot.repositoryRemoteUrl = depot.repositoryRemoteUrl or f"webdavs://{FQDN}:4447/repository"
				depot.workbenchLocalUrl = f"file://{WORKBENCH_DIR}"
				depot.workbenchRemoteUrl = depot.workbenchRemoteUrl or f"smb://{FQDN}/opsi_workbench"
				try:
					depot.systemUUID = str(UUID(Path("/sys/class/dmi/id/product_uuid").read_text(encoding="ascii").strip()))
				except Exception as err:
					if unattended_configuration:
						raise
					logger.debug(err)

				rich_print("[b]Registering depot[/b]")
				service.host_createObjects([depot])  # type: ignore[attr-defined]
				service.fetch_opsi_ca()
				(srv_crt, srv_key) = fetch_server_cert(service)
				store_local_server_key(srv_key)
				store_local_server_cert(srv_crt)

				rich_print("[b][green]Depot succesfully registered[/green][/b]")

				depot = service.host_getObjects(id=depot.id)[0]  # type: ignore[attr-defined]

				opsi_config.set("host", "server-role", "depotserver")
				opsi_config.set("host", "id", depot_id)
				opsi_config.set("host", "key", depot.opsiHostKey)
				opsi_config.set("service", "url", service.base_url)
				opsi_config.write_config_file()

				configs = service.config_getObjects(id="clientconfig.depot.id")  # type: ignore[attr-defined]
				if configs and depot.id not in configs[0].defaultValues:
					configs[0].defaultValues.append(depot.id)
					service.config_updateObjects(configs)  # type: ignore[attr-defined]

				return True
			except KeyboardInterrupt:
				print("")
				return False
			except Exception as err:
				rich_print(f"[b][red]Failed to register depot[/red]: {err}[/b]")


def setup(explicit: bool = True) -> None:
	"""
	explicit: called as "opsiconfd setup"?
	"""
	logger.notice("Running opsiconfd setup")
	register_depot = getattr(config, "register_depot", False)
	set_depot_user_password = getattr(config, "set_depot_user_password", False)
	configure_mysql = getattr(config, "configure_mysql", False)
	interactive = (not getattr(config, "non_interactive", False)) and sys.stdout.isatty() and explicit
	new_server_id = None
	rename_server = getattr(config, "rename_server", False)
	if rename_server:
		if "backend" in config.skip_setup:
			config.skip_setup.remove("backend")
		if isinstance(rename_server, str):
			new_server_id = forceHostId(rename_server)
		else:
			new_server_id = opsi_config.get("host", "id")

	if register_depot:
		unattended_configuration = None
		unattended_str = getattr(config, "unattended", None)
		if unattended_str:
			rich_print("[b]unattended is set[/b]")
			unattended_configuration = json.loads(unattended_str)

		if not setup_depotserver(unattended_configuration):
			return

	if set_depot_user_password:
		if isinstance(set_depot_user_password, str):
			password = set_depot_user_password
		else:
			password = Prompt.ask(
				f"Enter the password for the user '{opsi_config.get('depot_user', 'username')}'", password=True, show_default=False
			)
		if not password:
			logger.error("Can not use empty password!")
			return

		user_set_credentials(opsi_config.get("depot_user", "username"), password)
		rich_print(f"Password for user {opsi_config.get('depot_user', 'username')} set.")
		return

	if get_server_role() == "depotserver":
		for attempt in range(1, 6):
			service_client = new_service_client(f"opsiconfd depotserver {__version__} connection test")
			try:
				service_client.connect()
				service_client.disconnect()
				break
			except OpsiServiceConnectionError as err:
				if attempt >= 5:
					raise
				logger.warning("%s (attempt %d, retry in 5 seconds)", err, attempt)
				time.sleep(5)

	backend_available = True
	if get_server_role() == "configserver" or configure_mysql:
		try:
			setup_mysql(interactive=interactive, explicit=explicit, force=configure_mysql)
			opsi_config.set("host", "server-role", "configserver", persistent=True)
		except Exception as err:
			# This can happen during package installation
			# where backend config files are missing
			logger.debug(err, exc_info=True)
			log_func = logger.error if interactive else logger.warning
			log_func(
				"Failed to setup MySQL: %s\nPlease use `opsiconfd setup --configure-mysql` to configure the MySQL connection manually.", err
			)
			backend_available = False
			if not explicit:
				raise

		if configure_mysql:
			return

	if config.skip_setup:
		logger.notice("Skipping setup tasks: %s", ", ".join(config.skip_setup))

	if "backend" not in config.skip_setup and backend_available:
		try:
			setup_backend(new_server_id)
		except Exception as err:
			# This can happen during package installation
			# where backend config files are missing
			logger.warning("Failed to setup backend: %s", err, exc_info=True)
			backend_available = False

	if "limits" not in config.skip_setup:
		setup_limits()

	if "users" not in config.skip_setup and "groups" not in config.skip_setup:
		setup_users_and_groups(interactive)

	if explicit and "systemd" not in config.skip_setup:
		setup_systemd()

	if config.run_as_user != "root" and config.port < 1024:
		set_unprivileged_port_start(config.port)

	if "files" not in config.skip_setup:
		setup_files()

	if "file_permissions" not in config.skip_setup:
		# Always correct file permissions (run_as_user could be changed)
		setup_file_permissions()

	if "log_files" not in config.skip_setup:
		cleanup_log_files()

	if "backend" not in config.skip_setup and backend_available:
		setup_configs()

	if "grafana" not in config.skip_setup:
		try:
			setup_grafana()
		except Exception as err:
			logger.warning("Failed to setup grafana: %s", err, exc_info=True)

	if "redis" not in config.skip_setup:
		try:
			setup_redis()
		except Exception as err:
			logger.warning("Failed to setup redis: %s", err, exc_info=True)

	if "metric_downsampling" not in config.skip_setup:
		try:
			setup_metric_downsampling()
		except Exception as err:
			logger.warning("Failed to setup redis downsampling: %s", err, exc_info=True)

	if "opsi_ca" not in config.skip_setup or "server_cert" not in config.skip_setup:
		try:
			setup_ssl()
		except Exception as err:
			# This can fail if fqdn is not valid
			logger.error("Failed to setup SSL: %s", err, exc_info=True)

	if "samba" not in config.skip_setup:
		try:
			setup_samba()
		except Exception as err:
			logger.error("Failed to setup samba: %s", err, exc_info=True)

	if "dhcpd" not in config.skip_setup:
		try:
			setup_dhcpd()
		except Exception as err:
			logger.error("Failed to setup dhcpd: %s", err, exc_info=True)

	if "sudoers" not in config.skip_setup:
		try:
			setup_sudoers()
		except Exception as err:
			logger.error("Failed to setup sudoers: %s", err, exc_info=True)

	if explicit and (register_depot or rename_server):
		restart_opsiconfd_if_running()
