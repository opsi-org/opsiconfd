# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd - setup
"""

from __future__ import annotations

import re
from collections import defaultdict
from functools import lru_cache
from subprocess import run
from typing import TYPE_CHECKING

from opsicommon.license import (
	OPSI_FREE_MODULE_IDS,
	OPSI_MODULE_IDS,
	OPSI_OBSOLETE_MODULE_IDS,
)
from opsicommon.objects import (
	BoolConfig,
	ConfigState,
	UnicodeConfig,
)

from opsiconfd.backend.rpc.obj_host import auto_fill_depotserver_urls
from opsiconfd.config import config, get_configserver_id, get_server_role, opsi_config
from opsiconfd.logging import logger
from opsiconfd.utils import running_in_docker

if TYPE_CHECKING:
	from opsiconfd.backend import UnprotectedBackend


CHECK_DEFAULT_IGNORE_PRODUCTS = [
	"opsi-winst",
	"opsi-auto-update",
	"opsi-script",
	"shutdownwanted",
	"windows10-upgrade",
	"activate-win",
	"opsi-script-test",
	"opsi-bootimage-local",
	"opsi-uefi-netboot",
	"opsi-wan-config-on",
	"opsi-wan-config-off",
	"opsi-winpe",
	"win10-sysprep-app-update-blocker",
	"windomain",
	"hwaudit",
	"swaudit",
]


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
	except Exception as err:
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


def setup_configs() -> None:
	if get_server_role() != "configserver":
		return

	from opsiconfd.backend import get_unprotected_backend

	backend = get_unprotected_backend()

	config_ids = set(backend.config_getIdents(returnType="str"))
	depot_ids = backend.host_getIdents(returnType="str", type="OpsiDepotserver")
	configs = {c.id: c for c in backend.config_getObjects(id=["clientconfig.configserver.url"])}

	add_configs: list[BoolConfig | UnicodeConfig] = []
	add_config_states: list[ConfigState] = []
	remove_configs: list[dict[str, str]] = []

	try:
		_auto_correct_depot_urls(backend)
	except Exception as err:
		logger.error("Failed to auto-correct depot URLs: %s", err)
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
				possibleValues=["master_and_latency", "latency", "network_address", "random"],
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

		depot_user = opsi_config.get("depot_user", "username")
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

	if "opsiclientd.event_timer.active" not in config_ids:
		logger.info("Creating config 'opsiclientd.event_timer.active'")
		add_configs.append(
			BoolConfig(
				id="opsiclientd.event_timer.active",
				description="Activate opsiclientd timer event",
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

	if "opsiclientd.global.max_log_transfer_size" not in config_ids:
		logger.info("Creating config 'opsiclientd.global.max_log_transfer_size'")
		add_configs.append(
			UnicodeConfig(
				id="opsiclientd.global.max_log_transfer_size",
				description="Maximum size of opsiclientd log to transfer to the server in MB",
				possibleValues=["0.25", "0.5", "1", "2", "3", "4", "5"],
				defaultValues=["1"],
				editable=True,
				multiValue=False,
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

	if "opsiconfd.transfer.slots_opsiclientd_product_sync" not in config_ids:
		logger.info("Creating config 'opsiconfd.transfer.slots_opsiclientd_product_sync'")
		add_configs.append(
			UnicodeConfig(
				id="opsiconfd.transfer.slots_opsiclientd_product_sync",
				description="Maximum number of simultaneous product synchronizations",
				possibleValues=["10", "25", "50", "75", "100", "150", "200", "250", "300", "400", "500", "750", "1000"],
				defaultValues=["100"],
				editable=True,
				multiValue=False,
			)
		)

	# Bootimage configs
	@lru_cache
	def _get_legacy_append_values() -> dict[str, list[str]]:
		return {
			host_id: next(iter(conf.values()))
			for host_id, conf in backend.configState_getValues(config_ids="opsi-linux-bootimage.append", with_defaults=False).items()
		}

	if "netboot.host_identifiers" not in config_ids:
		logger.info("Creating config 'netboot.host_identifiers'")
		add_configs.append(
			UnicodeConfig(
				id="netboot.host_identifiers",
				description="Defines the identifiers used for host recognition on the boot server.",
				possibleValues=["system_uuid", "mac_address"],
				defaultValues=["system_uuid", "mac_address"],
				editable=False,
				multiValue=True,
			)
		)

	if "netboot.use_host_onetime_password" not in config_ids:
		logger.info("Creating config 'netboot.use_host_onetime_password'")
		add_configs.append(
			BoolConfig(
				id="netboot.use_host_onetime_password",
				description="Use a one-time password for host authentication?",
				defaultValues=[False],
			)
		)

	if "netboot.linux-bootimage.cmdline.quiet" not in config_ids:
		logger.info("Creating config 'netboot.linux-bootimage.cmdline.quiet'")
		add_configs.append(
			BoolConfig(
				id="netboot.linux-bootimage.cmdline.quiet",
				description="Hide most kernel and system messages on boot?",
				defaultValues=[True],
			)
		)

	if "netboot.linux-bootimage.cmdline.splash" not in config_ids:
		logger.info("Creating config 'netboot.linux-bootimage.cmdline.splash'")
		add_configs.append(
			BoolConfig(
				id="netboot.linux-bootimage.cmdline.splash",
				description="Show a graphical splash screen on boot?",
				defaultValues=[True],
			)
		)

	if "netboot.linux-bootimage.cmdline.loglevel" not in config_ids:
		logger.info("Creating config 'netboot.linux-bootimage.cmdline.loglevel'")
		add_configs.append(
			UnicodeConfig(
				id="netboot.linux-bootimage.cmdline.loglevel",
				description=(
					"Kernel log level to use on boot.\n"
					"0 (KERN_EMERG)   system is unusable\n"
					"1 (KERN_ALERT)   action must be taken immediately\n"
					"2 (KERN_CRIT)    critical conditions\n"
					"3 (KERN_ERR)     error conditions\n"
					"4 (KERN_WARNING) warning conditions\n"
					"5 (KERN_NOTICE)  normal but significant condition\n"
					"6 (KERN_INFO)    informational\n"
					"7 (KERN_DEBUG)   debug-level messages\n"
				),
				possibleValues=["0", "1", "2", "3", "4", "5", "6", "7"],
				defaultValues=["3"],
				editable=False,
				multiValue=False,
			)
		)

	if "netboot.linux-bootimage.cmdline.video" not in config_ids:
		logger.info("Creating config 'netboot.linux-bootimage.cmdline.video'")
		add_configs.append(
			UnicodeConfig(
				id="netboot.linux-bootimage.cmdline.video",
				description="Frame buffer configuration.\nSee https://www.kernel.org/doc/Documentation/fb/modedb.txt",
				possibleValues=["vesa:ywrap,mtrr"],
				defaultValues=["vesa:ywrap,mtrr"],
				editable=True,
				multiValue=False,
			)
		)

	if "netboot.linux-bootimage.cmdline.opsi_ui" not in config_ids:
		logger.info("Creating config 'netboot.linux-bootimage.cmdline.opsi_ui'")
		add_configs.append(
			UnicodeConfig(
				id="netboot.linux-bootimage.cmdline.opsi_ui",
				description="Choose to show either the opsi TUI or only opsi messages on the splash screen.",
				possibleValues=["splash", "tui"],
				defaultValues=["splash"],
				editable=False,
				multiValue=False,
			)
		)

	if "netboot.linux-bootimage.cmdline.lang" not in config_ids:
		logger.info("Creating config 'netboot.linux-bootimage.cmdline.lang'")
		add_configs.append(
			UnicodeConfig(
				id="netboot.linux-bootimage.cmdline.lang",
				description=("Locale to use for the opsi Linux bootimage."),
				possibleValues=["en_US", "de_DE", "fr_FR"],
				defaultValues=["en_US"],
				editable=True,
				multiValue=False,
			)
		)

	if "netboot.linux-bootimage.cmdline.vga" not in config_ids:
		logger.info("Creating config 'netboot.linux-bootimage.cmdline.vga'")
		add_configs.append(
			UnicodeConfig(
				id="netboot.linux-bootimage.cmdline.vga",
				description=(
					"Configure VGA resolution and color depth.\n\n"
					"| Color Depth | 800x600 | 1024x768 | 1152x864 | 1280x1024 | 1600x1200 |\n"
					"|-------------|---------|----------|----------|-----------|-----------|\n"
					"| 8 bit       | 771     | 773      | 353      | 775       | 796       |\n"
					"| 16 bit      | 788     | 791      | 355      | 794       | 798       |\n"
					"| 24 bit      | 789     | 792      |          | 795       | 799       |\n"
					"\n"
					"Use `normal` for 80×25 text mode without framebuffer."
				),
				possibleValues=["771", "773", "353", "775", "796", "788", "791", "355", "794", "798", "789", "792", "795", "799", "normal"],
				defaultValues=["791"],
				editable=True,
				multiValue=False,
			)
		)
		for host_id, values in _get_legacy_append_values().items():
			for val in values:
				if val.startswith("vga="):
					logger.info("Migrating legacy append value %r for host %r", val, host_id)
					val = val.removeprefix("vga=").strip()
					if val:
						add_config_states.append(
							ConfigState(
								configId="netboot.linux-bootimage.cmdline.vga",
								objectId=host_id,
								values=[val],
							)
						)
					break

	if "netboot.linux-bootimage.cmdline.pwh" not in config_ids:
		logger.info("Creating config 'netboot.linux-bootimage.cmdline.pwh'")
		add_configs.append(
			UnicodeConfig(
				id="netboot.linux-bootimage.cmdline.pwh",
				description=(
					"Root password for the bootimage. Accepts either a plain text password or a hash for /etc/shadow. "
					"Plain text passwords will be hashed automatically. Hashes must follow the format $<hash-type>$<salt>$<hash-value>."
				),
				possibleValues=["linux123"],
				defaultValues=["linux123"],
				editable=True,
				multiValue=False,
			)
		)
		for host_id, values in _get_legacy_append_values().items():
			for val in values:
				if val.startswith("pwh="):
					logger.info("Migrating legacy append value %r for host %r", val, host_id)
					val = val.removeprefix("pwh=").strip()
					if val:
						add_config_states.append(
							ConfigState(
								configId="netboot.linux-bootimage.cmdline.pwh",
								objectId=host_id,
								values=[val],
							)
						)
					break

	if "netboot.linux-bootimage.cmdline.noapic" not in config_ids:
		logger.info("Creating config 'netboot.linux-bootimage.cmdline.noapic'")
		add_configs.append(
			BoolConfig(
				id="netboot.linux-bootimage.cmdline.noapic",
				description="Disable the use of the I/O Advanced Programmable Interrupt Controller (I/O APIC)?",
				defaultValues=[False],
			)
		)
		for host_id, values in _get_legacy_append_values().items():
			if "noapic" in values:
				logger.info("Migrating legacy append value %r for host %r", val, host_id)
				add_config_states.append(
					ConfigState(
						configId="netboot.linux-bootimage.cmdline.noapic",
						objectId=host_id,
						values=[True],
					)
				)

	if "netboot.linux-bootimage.cmdline.irqpoll" not in config_ids:
		logger.info("Creating config 'netboot.linux-bootimage.cmdline.irqpoll'")
		add_configs.append(
			BoolConfig(
				id="netboot.linux-bootimage.cmdline.irqpoll",
				description="Enable IRQ polling to support buggy or non-compliant hardware?",
				defaultValues=[False],
			)
		)
		for host_id, values in _get_legacy_append_values().items():
			if "irqpoll" in values:
				logger.info("Migrating legacy append value %r for host %r", val, host_id)
				add_config_states.append(
					ConfigState(
						configId="netboot.linux-bootimage.cmdline.irqpoll",
						objectId=host_id,
						values=[True],
					)
				)

	if "netboot.linux-bootimage.cmdline.pci" not in config_ids:
		logger.info("Creating config 'netboot.linux-bootimage.cmdline.pci'")
		add_configs.append(
			UnicodeConfig(
				id="netboot.linux-bootimage.cmdline.pci",
				description="PCI subsystem options.\n`nomsi` disables PCI Message Signaled Interrupts and forces use of legacy IRQs.",
				possibleValues=["nomsi"],
				defaultValues=[],
				editable=True,
				multiValue=True,
			)
		)
		for host_id, values in _get_legacy_append_values().items():
			for val in values:
				if val.startswith("pci="):
					logger.info("Migrating legacy append value %r for host %r", val, host_id)
					add_config_states.append(
						ConfigState(
							configId="netboot.linux-bootimage.cmdline.pci",
							objectId=host_id,
							values=[v.strip() for v in val.removeprefix("pci=").split(",") if v.strip()],
						)
					)
					break

	if "netboot.linux-bootimage.cmdline.acpi" not in config_ids:
		logger.info("Creating config 'netboot.linux-bootimage.cmdline.acpi'")
		add_configs.append(
			UnicodeConfig(
				id="netboot.linux-bootimage.cmdline.acpi",
				description="Control the Advanced Configuration and Power Interface (ACPI) subsystem.\n`off` disables ACPI completely.",
				possibleValues=["off", "force", "strict", "noirq"],
				defaultValues=[],
				editable=True,
				multiValue=True,
			)
		)
		for host_id, values in _get_legacy_append_values().items():
			for val in values:
				if val.startswith("acpi="):
					logger.info("Migrating legacy append value %r for host %r", val, host_id)
					add_config_states.append(
						ConfigState(
							configId="netboot.linux-bootimage.cmdline.acpi",
							objectId=host_id,
							values=[v.strip() for v in val.removeprefix("acpi=").split(",") if v.strip()],
						)
					)
					break

	if "netboot.linux-bootimage.cmdline.reboot" not in config_ids:
		logger.info("Creating config 'netboot.linux-bootimage.cmdline.reboot'")
		add_configs.append(
			UnicodeConfig(
				id="netboot.linux-bootimage.cmdline.reboot",
				description=(
					"How should the system perform a reboot?\n"
					"`b`: Reboot using the BIOS reboot function (reliable on older hardware).\n"
					"`efi`: Use UEFI runtime services (works well with most modern machines)."
				),
				possibleValues=["b", "efi"],
				defaultValues=[],
				editable=True,
				multiValue=True,
			)
		)
		for host_id, values in _get_legacy_append_values().items():
			for val in values:
				if val.startswith("reboot="):
					logger.info("Migrating legacy append value %r for host %r", val, host_id)
					add_config_states.append(
						ConfigState(
							configId="netboot.linux-bootimage.cmdline.reboot",
							objectId=host_id,
							values=[v.strip() for v in val.removeprefix("reboot=").split(",") if v.strip()],
						)
					)
					break

	if add_configs:
		backend.config_createObjects(add_configs)
	if add_config_states:
		backend.configState_createObjects(add_config_states)

	# Delete obsolete configs
	for config_id in config_ids:
		if config_id.endswith(".product.cache.outdated") or config_id in ("product_sort_algorithm", "clientconfig.dhcpd.filename"):
			logger.info("Removing config %r", config_id)
			remove_configs.append({"id": config_id})
	if remove_configs:
		backend.config_deleteObjects(remove_configs)

	if "opsi.check.enabled" not in config_ids:
		logger.info("Creating config 'opsi.check.enabled'")
		backend.config_createObjects([BoolConfig(id="opsi.check.enabled", description="Enable check", defaultValues=[True])])

	if "opsi.check.downtime.start" not in config_ids:
		logger.info("Creating config 'opsi.check.downtime'")
		backend.config_createObjects(
			[
				UnicodeConfig(
					id="opsi.check.downtime.start",
					description="Check downtime start",
					possibleValues=[],
					defaultValues=[],
					editable=True,
					multiValue=False,
				)
			],
		)

	if "opsi.check.downtime.end" not in config_ids:
		logger.info("Creating config 'opsi.check.downtime'")
		backend.config_createObjects(
			[
				UnicodeConfig(
					id="opsi.check.downtime.end",
					description="Check downtime end",
					possibleValues=[],
					defaultValues=[],
					editable=True,
					multiValue=False,
				)
			],
		)

	if "opsi.check.ignore_products" not in config_ids:
		logger.info("Creating config 'opsi.check.ignore_products'")
		backend.config_createObjects(
			[
				UnicodeConfig(
					id="opsi.check.ignore_products",
					description="Ignore products",
					possibleValues=CHECK_DEFAULT_IGNORE_PRODUCTS,
					defaultValues=CHECK_DEFAULT_IGNORE_PRODUCTS,
					editable=True,
					multiValue=True,
				)
			],
		)
