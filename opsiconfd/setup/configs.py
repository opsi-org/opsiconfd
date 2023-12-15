# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd - setup
"""

from __future__ import annotations

import re
from collections import defaultdict
from subprocess import run
from typing import TYPE_CHECKING

from opsicommon.license import (
	OPSI_FREE_MODULE_IDS,
	OPSI_MODULE_IDS,
	OPSI_OBSOLETE_MODULE_IDS,
)
from opsicommon.objects import (  # type: ignore[import]
	BoolConfig,
	ConfigState,
	UnicodeConfig,
)

from opsiconfd.backend.rpc.obj_host import auto_fill_depotserver_urls
from opsiconfd.config import config, get_configserver_id, opsi_config
from opsiconfd.logging import logger
from opsiconfd.utils import running_in_docker

if TYPE_CHECKING:
	from opsiconfd.backend import UnprotectedBackend


def _get_windows_domain() -> str | None:
	try:
		# Could not fetch domain SID => exitcode 1
		# Do not check exitcode
		out = run(["net", "getdomainsid"], capture_output=True, check=False, encoding="utf-8").stdout
		match = re.search(r"SID for domain (\S+) is", out, flags=re.IGNORECASE)
		if not match:
			match = re.search(r"SID for local machine (\S+) is", out, flags=re.IGNORECASE)
		if match:
			return match.group(1)
	except Exception as err:  # pylint: disable=broad-except
		logger.info("Could not get domain: %s", err)
	return None


def _auto_correct_depot_urls(backend: UnprotectedBackend) -> None:
	# Auto-fill and correct URLs
	depots = backend.host_getObjects(type="OpsiDepotserver")
	for depot in depots:
		changed = auto_fill_depotserver_urls(depot)
		for attribute in ("depotRemoteUrl", "depotWebdavUrl", "repositoryRemoteUrl", "workbenchRemoteUrl"):
			value: str = getattr(depot, attribute)
			if not value:
				continue
			if ":///" in value:
				setattr(depot, attribute, value.replace(":///", "://", 1))
				changed = True
		if changed:
			with backend.events_disabled():
				backend.host_updateObject(depot)


def _cleanup_product_on_clients(backend: UnprotectedBackend) -> None:
	clients_on_depot = defaultdict(list)
	for entry in backend.configState_getClientToDepotserver(masterOnly=True):
		clients_on_depot[entry["depotId"]].append(entry["clientId"])

	all_product_ids = set(p["id"] for p in backend.product_getIdents(returnType="dict"))
	for depot_id, client_ids in clients_on_depot.items():
		if not client_ids:
			continue
		installed_product_ids = set(p["productId"] for p in backend.productOnDepot_getIdents(returnType="dict", depotId=depot_id))
		unavailable_product_ids = all_product_ids - installed_product_ids
		if not unavailable_product_ids:
			continue
		# Get all productOnClients with action set for unavailable product
		pocs = backend.productOnClient_getObjects(
			productId=list(unavailable_product_ids),
			clientId=client_ids,
			actionRequest=["setup", "uninstall", "update", "once", "always", "custom"],
		)
		if not pocs:
			continue
		for poc in pocs:
			poc.setActionRequest("none")

		logger.info("Setting action request of %d productOnClients to 'none' for unavailable product", len(pocs))
		with backend.events_disabled():
			backend.productOnClient_updateObjects(pocs)


def setup_configs() -> None:  # pylint: disable=too-many-statements,too-many-branches
	if opsi_config.get("host", "server-role") != "configserver":
		return

	# pylint: disable=import-outside-toplevel
	from opsiconfd.backend import get_unprotected_backend

	backend = get_unprotected_backend()

	config_ids = set(backend.config_getIdents(returnType="str"))
	depot_ids = backend.host_getIdents(returnType="str", type="OpsiDepotserver")
	configs = {c.id: c for c in backend.config_getObjects(id=["clientconfig.configserver.url"])}

	add_configs: list[BoolConfig | UnicodeConfig] = []
	add_config_states: list[ConfigState] = []

	_auto_correct_depot_urls(backend)
	_cleanup_product_on_clients(backend)

	conf = configs.get("clientconfig.configserver.url")
	if not conf or config.external_url not in conf.defaultValues or config.external_url not in conf.possibleValues:
		possible_values = []
		if conf and conf.possibleValues:
			possible_values = conf.possibleValues

		default_values = []
		if conf and conf.defaultValues:
			default_values = conf.defaultValues

		if not possible_values:
			possible_values = [config.external_url]
			default_values = [config.external_url]

		if config.external_url not in possible_values:
			possible_values.insert(0, config.external_url)
			if not default_values:
				default_values = [config.external_url]

		logger.info("Creating config 'clientconfig.configserver.url'")
		add_configs.append(
			UnicodeConfig(
				id="clientconfig.configserver.url",
				description="URL(s) of opsi config service(s) to use",
				possibleValues=possible_values,
				defaultValues=default_values,
				editable=True,
				multiValue=True,
			)
		)

	logger.info("Creating config 'clientconfig.depot.id'")
	add_configs.append(
		UnicodeConfig(
			id="clientconfig.depot.id",
			description="ID of the opsi depot to use",
			possibleValues=depot_ids,
			defaultValues=[get_configserver_id()],
			editable=False,
			multiValue=False,
		)
	)

	if "clientconfig.depot.dynamic" not in config_ids:
		logger.info("Creating config 'clientconfig.depot.dynamic'")
		add_configs.append(BoolConfig(id="clientconfig.depot.dynamic", description="Use dynamic depot selection", defaultValues=[False]))

	if "clientconfig.depot.selection_mode" not in config_ids:
		logger.info("Creating config 'clientconfig.depot.selection_mode'")
		add_configs.append(
			UnicodeConfig(
				id="clientconfig.depot.selection_mode",
				description="Depot selection mode.",
				possibleValues=["master_and_latency", "latency", "network_address", "network_address_best_match", "random"],
				defaultValues=["network_address"],
				editable=False,
				multiValue=False,
			)
		)

	if "clientconfig.depot.drive" not in config_ids:
		logger.info("Creating config 'clientconfig.depot.drive'")
		add_configs.append(
			UnicodeConfig(
				id="clientconfig.depot.drive",
				description="Drive letter for depot share",
				possibleValues=[
					"a:",
					"b:",
					"c:",
					"d:",
					"e:",
					"f:",
					"g:",
					"h:",
					"i:",
					"j:",
					"k:",
					"l:",
					"m:",
					"n:",
					"o:",
					"p:",
					"q:",
					"r:",
					"s:",
					"t:",
					"u:",
					"v:",
					"w:",
					"x:",
					"y:",
					"z:",
					"dynamic",
				],
				defaultValues=["p:"],
				editable=False,
				multiValue=False,
			)
		)

	if "clientconfig.depot.protocol" not in config_ids:
		logger.info("Creating config 'clientconfig.depot.protocol'")
		add_configs.append(
			UnicodeConfig(
				id="clientconfig.depot.protocol",
				description="Protocol to use when mounting an depot share on the client",
				possibleValues=["cifs", "webdav"],
				defaultValues=["webdav" if running_in_docker() else "cifs"],
				editable=False,
				multiValue=False,
			)
		)

	if "clientconfig.depot.protocol.netboot" not in config_ids:
		logger.info("Creating config 'clientconfig.depot.protocol.netboot'")
		add_configs.append(
			UnicodeConfig(
				id="clientconfig.depot.protocol.netboot",
				description="Protocol to use when mounting an depot share in netboot environment",
				possibleValues=["cifs", "webdav"],
				defaultValues=["webdav" if running_in_docker() else "cifs"],
				editable=False,
				multiValue=False,
			)
		)

	if "clientconfig.depot.user" not in config_ids:
		logger.info("Creating config 'clientconfig.depot.user'")

		depot_user = "pcpatch"
		domain = _get_windows_domain()
		if domain:
			depot_user = f"{domain}\\{depot_user}"
		logger.info("Using '%s' as clientconfig.depot.user", depot_user)
		add_configs.append(
			UnicodeConfig(
				id="clientconfig.depot.user",
				description="User for depot share",
				possibleValues=[],
				defaultValues=[depot_user],
				editable=True,
				multiValue=False,
			)
		)

	if "clientconfig.windows.domain" not in config_ids:
		logger.info("Creating config 'clientconfig.windows.domain'")
		domain = _get_windows_domain()
		add_configs.append(
			UnicodeConfig(
				id="clientconfig.windows.domain",
				description="Windows domain",
				possibleValues=[domain] if domain else [],
				defaultValues=[domain] if domain else [],
				editable=True,
				multiValue=False,
			)
		)

	if "opsiclientd.global.verify_server_cert" not in config_ids:
		logger.info("Creating config 'opsiclientd.global.verify_server_cert'")
		add_configs.append(
			BoolConfig(id="opsiclientd.global.verify_server_cert", description="Verify opsi server TLS certificates", defaultValues=[True])
		)

	if "opsiclientd.global.install_opsi_ca_into_os_store" not in config_ids:
		logger.info("Creating config 'opsiclientd.global.install_opsi_ca_into_os_store'")
		add_configs.append(
			BoolConfig(
				id="opsiclientd.global.install_opsi_ca_into_os_store",
				description="Automatically install opsi CA into operating systems certificate store",
				defaultValues=[True],
			)
		)

	if "opsiclientd.event_net_connection.active" not in config_ids:
		logger.info("Creating config 'opsiclientd.event_net_connection.active'")
		add_configs.append(
			BoolConfig(
				id="opsiclientd.event_net_connection.active",
				description="Trigger net_connection event if certain network interface is up",
				defaultValues=[False],
			)
		)

	if "opsiclientd.event_timer.active" not in config_ids:
		logger.info("Creating config 'opsiclientd.event_timer.active'")
		add_configs.append(
			BoolConfig(
				id="opsiclientd.event_timer.active",
				description="Periodically request cache update from configserver",
				defaultValues=[False],
			)
		)

	if "opsiclientd.event_gui_startup.active" not in config_ids:
		logger.info("Creating config 'opsiclientd.event_gui_startup.active'")
		add_configs.append(
			BoolConfig(
				id="opsiclientd.event_gui_startup.active",
				description="Run gui_startup event at system start",
				defaultValues=[True],
			)
		)

	if "opsiclientd.event_gui_startup{user_logged_in}.active" not in config_ids:
		logger.info("Creating config 'opsiclientd.event_gui_startup{user_logged_in}.active'")
		add_configs.append(
			BoolConfig(
				id="opsiclientd.event_gui_startup{user_logged_in}.active",
				description="Run gui_startup event at opsiclientd start if a user is logged in",
				defaultValues=[True],
			)
		)

	if "opsiclientd.config_service.permanent_connection" not in config_ids:
		logger.info("Creating config 'opsiclientd.config_service.permanent_connection'")
		add_configs.append(
			BoolConfig(
				id="opsiclientd.config_service.permanent_connection",
				description="Client should keep a permanent connection to the opsi messagebus",
				defaultValues=[True],
			)
		)

	if "opsi-linux-bootimage.append" not in config_ids:
		logger.info("Creating config 'opsi-linux-bootimage.append'")
		add_configs.append(
			UnicodeConfig(
				id="opsi-linux-bootimage.append",
				description="Extra options to append to kernel command line",
				possibleValues=[
					"acpi=off",
					"irqpoll",
					"noapic",
					"pci=nomsi",
					"vga=normal",
					"reboot=b",
					"mem=2G",
					"nomodeset",
					"ramdisk_size=2097152",
					"dhclienttimeout=N",
				],
				defaultValues=[""],
				editable=True,
				multiValue=True,
			)
		)

	if "license-management.use" not in config_ids:
		logger.info("Creating config 'license-management.use'")
		add_configs.append(BoolConfig(id="license-management.use", description="Activate license management", defaultValues=[False]))

	if "software-on-demand.active" not in config_ids:
		logger.info("Creating config 'software-on-demand.active'")
		add_configs.append(BoolConfig(id="software-on-demand.active", description="Activate software-on-demand", defaultValues=[False]))

	if "software-on-demand.product-group-ids" not in config_ids:
		logger.info("Creating config 'software-on-demand.product-group-ids'")
		add_configs.append(
			UnicodeConfig(
				id="software-on-demand.product-group-ids",
				description="Product group ids containing products which are allowed to be installed on demand",
				possibleValues=["software-on-demand"],
				defaultValues=["software-on-demand"],
				editable=True,
				multiValue=True,
			)
		)

	if "licensing.disable_warning_for_modules" not in config_ids:
		module_ids = sorted(set(OPSI_MODULE_IDS) - set(OPSI_FREE_MODULE_IDS) - set(OPSI_OBSOLETE_MODULE_IDS))
		logger.info("Creating config 'licensing.disable_warning_for_modules'")
		add_configs.append(
			UnicodeConfig(
				id="licensing.disable_warning_for_modules",
				description="Disable licensing warnings for these modules.",
				possibleValues=module_ids,
				defaultValues=[],
				editable=False,
				multiValue=True,
			)
		)

	if "licensing.client_limit_warning_percent" not in config_ids:
		logger.info("Creating config 'licensing.client_limit_warning_percent'")
		add_configs.append(
			UnicodeConfig(
				id="licensing.client_limit_warning_percent",
				description="Warn when this license utilization is reached.",
				possibleValues=["95"],
				defaultValues=["95"],
				editable=True,
				multiValue=False,
			)
		)

	if "licensing.client_limit_warning_absolute" not in config_ids:
		logger.info("Creating config 'licensing.client_limit_warning_absolute'")
		add_configs.append(
			UnicodeConfig(
				id="licensing.client_limit_warning_absolute",
				description="Warn when the number of available licenses reaches this value.",
				possibleValues=["5"],
				defaultValues=["5"],
				editable=True,
				multiValue=False,
			)
		)

	if "licensing.client_limit_warning_days" not in config_ids:
		logger.info("Creating config 'licensing.client_limit_warning_days'")
		add_configs.append(
			UnicodeConfig(
				id="licensing.client_limit_warning_days",
				description="Number of days from which warning is given before the licensing reaches a problematic state.",
				possibleValues=["30"],
				defaultValues=["30"],
				editable=True,
				multiValue=False,
			)
		)

	if add_configs:
		backend.config_createObjects(add_configs)
	if add_config_states:
		backend.configState_createObjects(add_config_states)

	# Delete obsolete configs
	remove_configs = []
	for config_id in config_ids:
		if config_id.endswith(".product.cache.outdated") or config_id in ("product_sort_algorithm", "clientconfig.dhcpd.filename"):
			logger.info("Removing config %r", config_id)
			remove_configs.append({"id": config_id})
	if remove_configs:
		backend.config_deleteObjects(remove_configs)
