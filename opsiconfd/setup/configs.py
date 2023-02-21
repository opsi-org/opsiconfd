# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd - setup
"""

import re
import subprocess

from opsicommon.objects import (  # type: ignore[import]
	BoolConfig,
	ConfigState,
	UnicodeConfig,
)

from opsiconfd.config import config, get_configserver_id, opsi_config
from opsiconfd.logging import logger


def _get_windows_domain() -> str | None:
	try:
		out = subprocess.run(["net", "getdomainsid"], capture_output=True, check=True).stdout.decode()
		match = re.search(r"domain\s(\S+)\s", out)
		if not match:
			match = re.search(r"machine\s(\S+)\s", out)
		if match:
			return match.group(1)
	except Exception as err:  # pylint: disable=broad-except
		logger.info("Could not get domain: %s", err)
	return None


def setup_configs() -> None:  # pylint: disable=too-many-statements,too-many-branches
	if opsi_config.get("host", "server-role") != "configserver":
		return

	# pylint: disable=import-outside-toplevel
	from opsiconfd.backend import get_unprotected_backend

	backend = get_unprotected_backend()

	config_ids = set(backend.config_getIdents(returnType="str"))
	depot_ids = backend.host_getIdents(returnType="str", type="OpsiDepotserver")

	add_configs: list[BoolConfig | UnicodeConfig] = []
	add_config_states: list[ConfigState] = []

	if "clientconfig.depot.user" not in config_ids:
		logger.info("Creating config: clientconfig.depot.user")

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

	if "clientconfig.configserver.url" not in config_ids:
		logger.info("Creating config: clientconfig.configserver.url")
		add_configs.append(
			UnicodeConfig(
				id="clientconfig.configserver.url",
				description="URL(s) of opsi config service(s) to use",
				possibleValues=[config.external_url],
				defaultValues=[config.external_url],
				editable=True,
				multiValue=True,
			)
		)

	logger.info("Creating config: clientconfig.depot.id")
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
		logger.info("Creating config: clientconfig.depot.dynamic")
		add_configs.append(BoolConfig(id="clientconfig.depot.dynamic", description="Use dynamic depot selection", defaultValues=[False]))

	if "clientconfig.depot.selection_mode" not in config_ids:
		logger.info("Creating config: clientconfig.depot.selection_mode")
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
		logger.info("Creating config: clientconfig.depot.drive")
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
		logger.info("Creating config: clientconfig.depot.protocol")
		add_configs.append(
			UnicodeConfig(
				id="clientconfig.depot.protocol",
				description="Protocol to use when mounting an depot share on the client",
				possibleValues=["cifs", "webdav"],
				defaultValues=["cifs"],
				editable=False,
				multiValue=False,
			)
		)

	if "clientconfig.depot.protocol.netboot" not in config_ids:
		logger.info("Creating config: clientconfig.depot.protocol.netboot")
		add_configs.append(
			UnicodeConfig(
				id="clientconfig.depot.protocol.netboot",
				description="Protocol to use when mounting an depot share in netboot environment",
				possibleValues=["cifs", "webdav"],
				defaultValues=["cifs"],
				editable=False,
				multiValue=False,
			)
		)

	if "clientconfig.windows.domain" not in config_ids:
		logger.info("Creating config: clientconfig.windows.domain")
		domain = _get_windows_domain()
		add_configs.append(
			UnicodeConfig(
				id="clientconfig.windows.domain",
				description="Windows domain",
				possibleValues=[],
				defaultValues=[domain] if domain else [],
				editable=True,
				multiValue=False,
			)
		)

	if "opsiclientd.global.verify_server_cert" not in config_ids:
		logger.info("Creating config: opsiclientd.global.verify_server_cert")
		add_configs.append(
			BoolConfig(id="opsiclientd.global.verify_server_cert", description="Verify opsi server TLS certificates", defaultValues=[True])
		)

	if "opsiclientd.global.install_opsi_ca_into_os_store" not in config_ids:
		logger.info("Creating config: opsiclientd.global.install_opsi_ca_into_os_store")
		add_configs.append(
			BoolConfig(
				id="opsiclientd.global.install_opsi_ca_into_os_store",
				description="Automatically install opsi CA into operating systems certificate store",
				defaultValues=[True],
			)
		)

	if "opsi-linux-bootimage.append" not in config_ids:
		logger.info("Creating config: opsi-linux-bootimage.append")
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
		logger.info("Creating config: license-management.use")
		add_configs.append(BoolConfig(id="license-management.use", description="Activate license management", defaultValues=[False]))

	if "software-on-demand.active" not in config_ids:
		logger.info("Creating config: software-on-demand.active")
		add_configs.append(BoolConfig(id="software-on-demand.active", description="Activate software-on-demand", defaultValues=[False]))

	if "software-on-demand.product-group-ids" not in config_ids:
		logger.info("Creating config: software-on-demand.product-group-ids")
		add_configs.append(
			UnicodeConfig(
				id="software-on-demand.product-group-ids",
				description=("Product group ids containing products which are " "allowed to be installed on demand"),
				possibleValues=["software-on-demand"],
				defaultValues=["software-on-demand"],
				editable=True,
				multiValue=True,
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