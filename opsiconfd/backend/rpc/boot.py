# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.backend.rpc.boot
"""

from __future__ import annotations

import re
import secrets
import traceback
from abc import abstractmethod
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol, TypeVar

from jinja2 import Template
from jinja2.exceptions import UndefinedError
from opsicommon.exceptions import BackendMissingDataError
from opsicommon.objects import NetbootProduct, OpsiClient, OpsiDepotserver, ProductOnClient, ProductOnDepot
from opsicommon.types import Architecture, FirmwareType, forceHardwareAddress, forceHostId, forceIpAddress, forceUUIDString

from opsiconfd.config import DEFAULT_PRODUCT_GRUB_CFG_TEMPLATE, GRUB_CFG_TEMPLATE, get_configserver_id
from opsiconfd.logging import logger, secret_filter
from opsiconfd.utils import FileCache
from opsiconfd.utils.cryptography import HashingAlgorithm, PasswordHashFormat, create_password_hash

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol

SHADOW_HASH_RE = re.compile(r"^\$([a-z0-9]){1,2}\$(.+)\$(.+)$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", re.IGNORECASE)
MAC_RE = re.compile(r"^01-([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.IGNORECASE)


file_cache = FileCache()


def cmdline_param_to_string(name: str, values: list[str] | str | list[bool] | bool) -> str | None:
	values_ = [v for v in values] if isinstance(values, list) else [values]

	if values_ and isinstance(values_[0], bool):
		if values_[0]:
			return name
		return None

	vals = []
	for val in values_:
		if not val:
			continue
		val = str(val)
		if " " in val or "," in val or "$" in val:
			val = f'"{val}"'
		vals.append(val)
	if not vals:
		return None
	return f"{name}={','.join(vals)}"


@dataclass
class TemplateContextConfigState:
	id: str
	values: list[str | bool] = field(default_factory=list)
	_exists: bool = field(default=True, repr=False)

	@property
	def exists(self) -> bool:
		return self._exists

	@property
	def str_values(self) -> list[str]:
		return [str(v) for v in self.values]

	@property
	def bool_value(self) -> bool:
		return bool(self.value)

	@property
	def str_value(self) -> str:
		return str(self.value or "")

	@property
	def value(self) -> str | bool | None:
		if not self.values:
			return None
		if isinstance(self.values[0], bool):
			return self.values[0]
		return ",".join(str(v) for v in self.values)

	def __str__(self) -> str:
		if self.value is None:
			return ""
		return str(self.value)

	def __bool__(self) -> bool:
		if not self.exists:
			return False
		return bool(self.value)

	def password_hash(
		self, method: HashingAlgorithm | str = HashingAlgorithm.SHA512, format: PasswordHashFormat | str = PasswordHashFormat.SHADOW
	) -> str | None:
		value = self.value
		if not value or isinstance(value, bool):
			return None
		value = str(value)

		if not isinstance(method, HashingAlgorithm):
			method = HashingAlgorithm(method)
		assert isinstance(method, HashingAlgorithm)

		if not isinstance(format, PasswordHashFormat):
			format = PasswordHashFormat(format)
		assert isinstance(format, PasswordHashFormat)

		if format == PasswordHashFormat.GRUB:
			if value.startswith("grub."):
				# Already hashed
				return value
		elif format == PasswordHashFormat.SHADOW:
			match = SHADOW_HASH_RE.match(value)
			if match:
				if match.group(1) == HashingAlgorithm.SHA512.identifier() and method == HashingAlgorithm.SHA512:
					return value
				raise ValueError(f"Password is already hashed with method {match.group(1)}, but {method} is requested")

		return create_password_hash(password=value, algorithm=method, format=format)


class TemplateContextProductPropertyState(TemplateContextConfigState):
	pass


T = TypeVar("T", bound="TemplateContextStates")


class TemplateContextStates(dict[str, T]):
	@abstractmethod
	def __missing__(self, config_id: str) -> T:
		pass

	def get_by_prefix(self, prefix: str) -> dict[str, T]:
		return {key: value for key, value in self.items() if key.startswith(prefix)}

	def cmdline(self: T, pattern: list[str] | str | None = None, remove_prefix: list[str] | str | None = None) -> str:
		"""
		Generate Linux command line parameters from states.
		Optionally filter states by patterns (fnmatch).
		"""
		pattern = [pattern] if isinstance(pattern, str) else pattern or []
		remove_prefix = [remove_prefix] if isinstance(remove_prefix, str) else remove_prefix or []

		cmdline = []
		for name, state in self.items():
			if pattern and not any(fnmatch(name, p) for p in pattern or []):
				continue
			if remove_prefix:
				for prefix in remove_prefix:
					if name.startswith(prefix):
						name = name[len(prefix) :]
			string = cmdline_param_to_string(name, state.values)
			if string:
				cmdline.append(string)

		return " ".join(cmdline)


class TemplateContextConfigStates(TemplateContextStates):
	def __missing__(self, config_id: str) -> TemplateContextConfigState:
		return TemplateContextConfigState(id=config_id, _exists=False)


class TemplateContextProductPropertyStates(TemplateContextStates):
	def __missing__(self, config_id: str) -> TemplateContextProductPropertyState:
		return TemplateContextProductPropertyState(id=config_id, _exists=False)


@dataclass
class TemplateContextGRUB:
	_context: TemplateContext
	primary_menu_entries: list[str] = field(default_factory=list)

	def menu_entries(self, config_id: str | None = None) -> list[str]:
		entries = self.primary_menu_entries
		product_grub_cfg = file_cache.get_file_content(Path(DEFAULT_PRODUCT_GRUB_CFG_TEMPLATE))
		if product_grub_cfg:
			entries.append(product_grub_cfg)
		if config_id:
			entries.extend([str(entry) for entry in self._context.config_states[config_id].values if entry])
		return [Template(entry).render(self._context.context_args()) for entry in entries]


@dataclass
class TemplateContextOpsiLinuxBootimage:
	CMDLINE_PARAM_POSITION = {
		"quiet": 1,
		"splash": 2,
		"loglevel": 3,
	}
	_context: TemplateContext
	additional_cmdline_params: dict[str, list[str] | str | list[bool] | bool] = field(default_factory=dict)

	def cmdline(
		self,
		additional_params: dict[str, list[str] | str | list[bool] | bool] | None = None,
		config_id_prefix: str | None = "netboot.linux-bootimage.cmdline",
	) -> str:
		"""
		Generate a Linux command line from config states starting with the given prefix.
		Additional command line parameters can be set in `additional_cmdline_params` and will override
		any config state with the same name.
		"""
		params: dict[str, list[str] | str | list[bool] | bool] = {}

		service = self._context.config_states["clientconfig.configserver.url"].str_value
		if service:
			if not service.endswith("/rpc"):
				# TODO: Is this still needed?
				service = f"{service.rstrip('/')}/rpc"
			params["service"] = service

		if self._context.client:
			hostname, domain = self._context.client.id.split(".", 1)
			params["host_id"] = self._context.client.id
			params["hn"] = hostname
			params["dn"] = domain
			hwaddr = self._context.client.getHardwareAddress()
			if hwaddr:
				params["macaddress"] = hwaddr

		if self._context.product:
			params["product"] = self._context.product.id

		if config_id_prefix:
			config_id_prefix = f"{config_id_prefix.rstrip('.')}."
			self._context.config_states.cmdline
			for key, config_state in self._context.config_states.get_by_prefix(config_id_prefix).items():
				param_name = key.removeprefix(config_id_prefix).lstrip(".")
				if param_name == "pwh":
					pw_hash = config_state.password_hash("sha512", "shadow")
					if pw_hash:
						params[param_name] = pw_hash.replace("$", r"\$")
					continue
				params[param_name] = config_state.values

		if self.additional_cmdline_params:
			params.update(self.additional_cmdline_params)
		if additional_params:
			params.update(additional_params)

		if params.get("splash") and "loglevel" in params:
			del params["loglevel"]

		cmdline = []
		for name in sorted(params, key=lambda param: self.CMDLINE_PARAM_POSITION.get(param.split("=", 1)[0], 99)):
			string = cmdline_param_to_string(name, params[name])
			if string:
				cmdline.append(string)
		return " ".join(cmdline)


@dataclass
class TemplateContextProduct:
	_context: TemplateContext
	_product: NetbootProduct

	def __getattr__(self, name: str) -> Any:
		return getattr(self._product, name)

	@property
	def product(self) -> NetbootProduct:
		return self._product

	def grub_cfg(self) -> str:
		"""
		Render the product specific GRUB config snippet.
		"""
		logger.debug("Generating grub config for product '%s'", self._product.id)
		product_grub_cfg = (
			self._product.pxeConfigTemplate if self._product.pxeConfigTemplate not in (None, "", "install3264", "install-x64") else ""
		)
		logger.debug("PXE config template for product %r: %r", self._product.id, product_grub_cfg)

		if product_grub_cfg:
			logger.info("Using PXE config template directly from product %r", self._product.id)
			product_grub_cfg += "\n"
		else:
			logger.info("Using default product GRUB config template")
			default_template = Path(DEFAULT_PRODUCT_GRUB_CFG_TEMPLATE)
			product_grub_cfg = file_cache.get_file_content(default_template)
			if product_grub_cfg is None:
				raise FileNotFoundError(f"Default grub config file '{default_template}' not found")

		func_count = 0
		for frame in traceback.walk_stack(None):
			frame0 = frame[0]
			if frame0.f_code.co_name == "grub_cfg" and frame0.f_locals.get("self") is self:
				func_count += 1
				if func_count > 1:
					logger.error(
						"Recursion detected in product specific GRUB config template for product %r: %s", self._product.id, product_grub_cfg
					)
					raise RuntimeError("Recursion detected in product specific GRUB config template")

		try:
			context_args = self._context.context_args()
			product_grub_cfg = Template(product_grub_cfg).render(context_args)
		except UndefinedError as err:
			logger.error(
				"Error rendering grub config template for product '%s': %s\nTemplate:\n%s\nContext:\n%s",
				self._product.id,
				err,
				product_grub_cfg,
				context_args,
			)
			raise

		# Replace legacy placeholders
		if self._context.client:
			hostname, domain = self._context.client.id.split(".", 1)
			product_grub_cfg = product_grub_cfg.replace("%fqdn%", self._context.client.id)
			product_grub_cfg = product_grub_cfg.replace("%host_id%", self._context.client.id)
			product_grub_cfg = product_grub_cfg.replace("%hostname%", hostname)
			product_grub_cfg = product_grub_cfg.replace("%domain%", domain)
		for property_name, state in self._context.product_property_states.items():
			product_grub_cfg = product_grub_cfg.replace(f"%{property_name}%", state.str_value)

		return product_grub_cfg


class TemplateContext:
	depot: OpsiDepotserver
	client: OpsiClient | None
	product: TemplateContextProduct | None
	product_on_depot: ProductOnDepot | None
	product_on_client: ProductOnClient | None
	product_property_states: TemplateContextProductPropertyStates
	config_states: TemplateContextConfigStates
	grub: TemplateContextGRUB
	opsi_linux_bootimage: TemplateContextOpsiLinuxBootimage

	def __init__(
		self,
		depot: OpsiDepotserver,
		client: OpsiClient | None = None,
		product_on_depot: ProductOnDepot | None = None,
		product_on_client: ProductOnClient | None = None,
		product: NetbootProduct | None = None,
	) -> None:
		self.depot = depot
		self.client = client
		self.product = TemplateContextProduct(_context=self, _product=product) if product else None
		self.product_on_depot = product_on_depot
		self.product_on_client = product_on_client
		self.product_property_states = TemplateContextProductPropertyStates()
		self.config_states = TemplateContextConfigStates()
		self.grub = TemplateContextGRUB(_context=self)
		self.opsi_linux_bootimage = TemplateContextOpsiLinuxBootimage(_context=self)

	def context_args(self) -> dict:
		return {attr: val for attr, val in self.__dict__.items() if not attr.startswith("_")}


@dataclass(kw_only=True, slots=True)
class BootConfig:
	depot_id: str
	client_id: str | None = None
	product_id: str | None = None
	pxe_boot_server: str | None = None
	pxe_boot_filename: str | None = None
	grub_config: str | None = None


class RPCBootMixin(Protocol):
	def _get_boot_config_template_context(
		self: BackendProtocol,
		depot: OpsiDepotserver,
		client: OpsiClient | None = None,
		product_on_depot: ProductOnDepot | None = None,
		product_on_client: ProductOnClient | None = None,
		product: NetbootProduct | None = None,
	) -> TemplateContext:
		context = TemplateContext(
			depot=depot, client=client, product_on_depot=product_on_depot, product_on_client=product_on_client, product=product
		)
		host = client or depot
		context.config_states = TemplateContextConfigStates(
			{
				config_id: TemplateContextConfigState(id=config_id, values=values)
				for config_id, values in self.configState_getValues(
					config_ids=["clientconfig.configserver.url", "netboot.*"], object_ids=[host.id]
				)
				.get(host.id, {})
				.items()
			}
		)
		if product:
			context.product_property_states = TemplateContextProductPropertyStates(
				{
					product_property_id: TemplateContextProductPropertyState(id=product_property_id, values=values)
					for product_property_id, values in self.productPropertyState_getValues(product_ids=[product.id], object_ids=[host.id])
					.get(host.id, {})
					.get(product.id, {})
					.items()
				}
			)
		return context

	@rpc_method
	def boot_getConfig(
		self: BackendProtocol,
		architecture: Literal["x86", "x64", "arm", "arm64"] | None = None,
		firmware_type: Literal["UEFI", "BIOS"] | None = None,
		ip_version: int | None = None,
		protocol: Literal["TFTP", "HTTP"] | None = None,
		boot_server_address: str | None = None,
		depot_id: str | None = None,
		client_id: str | None = None,
		system_uuid: str | None = None,
		hardware_address: str | None = None,
		usage: Literal["DHCP", "FILE_LOAD"] | None = None,
	) -> BootConfig:
		"""
		Get the boot configuration for a client.
		"""
		self._check_role("admin")
		if ip_version and ip_version not in (4, 6):
			raise ValueError("ip_version must be 4, 6, or None")
		_architecture = Architecture(architecture) if architecture else None
		_firmware_type = FirmwareType(firmware_type) if firmware_type else None
		if protocol and protocol not in ("TFTP", "HTTP"):
			raise ValueError("protocol must be 'TFTP', 'HTTP', or None")
		boot_server_address = forceIpAddress(boot_server_address) if boot_server_address else None
		depot_id = forceHostId(depot_id) if depot_id else get_configserver_id()
		client_id = forceHostId(client_id) if client_id else None
		system_uuid = forceUUIDString(system_uuid) if system_uuid else None
		hardware_address = forceHardwareAddress(hardware_address) if hardware_address else None

		def get_host_identifiers(client: OpsiClient) -> list[str]:
			return self.configState_getValues(object_ids=[client.id], config_ids=["netboot.host_identifiers"]).get(client.id, {}).get(
				"netboot.host_identifiers"
			) or ["system_uuid", "mac_address"]

		client: OpsiClient | None = None
		if client_id:
			client_id = forceHostId(client_id)
			clients = self.host_getObjects(type="OpsiClient", id=client_id)
			if clients:
				client = clients[0]
				logger.debug("Found client by clientId: %r", client)
			else:
				logger.info("Client not found by clientId")

		if not client and system_uuid:
			system_uuid = forceUUIDString(system_uuid)
			clients = self.host_getObjects(type="OpsiClient", systemUUID=system_uuid)
			if clients and clients[0]:
				logger.debug("Found client by system_uuid: %r", clients[0])
				if "system_uuid" in get_host_identifiers(clients[0]):
					client = clients[0]
				else:
					logger.info("system_uuid is not in netboot.host_identifiers for client %r", clients[0].id)
			else:
				logger.info("Client not found by system_uuid")

		if not client and hardware_address:
			hardware_address = forceHardwareAddress(hardware_address)
			clients = self.host_getObjects(type="OpsiClient", hardwareAddress=hardware_address)
			if clients and clients[0]:
				logger.debug("Found client by hardware_address: %r", clients[0])
				if "mac_address" in get_host_identifiers(clients[0]):
					client = clients[0]
				else:
					logger.info("mac_address is not in netboot.host_identifiers for client %r", clients[0].id)
			else:
				logger.info("Client not found by hardware_address")

		product_on_client: ProductOnClient | None = None
		if client:
			depot_id = self.configState_getClientToDepotserver(clientIds=client_id)[0]["depotId"]
			try:
				product_on_client = self.productOnClient_getObjects(
					productType="NetbootProduct",
					clientId=client.id,
					actionRequest=["setup", "uninstall", "update", "always", "once", "custom"],
				)[0]
			except IndexError:
				logger.info("No NetbootProduct action found for client %r, returning default boot config", client.id)

		try:
			depot = self.host_getObjects(type="OpsiDepotserver", id=depot_id)[0]
		except IndexError:
			raise BackendMissingDataError(f"Depotserver with id '{depot_id}' not found")

		if not client:
			config_state_values = (
				self.configState_getValues(object_ids=[depot_id], config_ids=["netboot.pxe_boot_unknown_devices"])
				.get(depot_id, {})
				.get("netboot.pxe_boot_unknown_devices")
			)
			if not config_state_values or not config_state_values[0]:
				return BootConfig(depot_id=depot.id)

		product_on_depot: ProductOnDepot | None = None
		if product_on_client:
			try:
				product_on_depot = self.productOnDepot_getObjects(
					productType="NetbootProduct", productId=product_on_client.productId, depotId=depot_id
				)[0]
			except IndexError:
				logger.warning("Product %r not available on depot %r", product_on_client.productId, depot_id)

		product: NetbootProduct | None = None
		if product_on_depot:
			try:
				product = self.product_getObjects(
					type="NetbootProduct",
					id=product_on_depot.productId,
					productVersion=product_on_depot.productVersion,
					packageVersion=product_on_depot.packageVersion,
				)[0]
			except IndexError:
				logger.error(
					"Product %r version %r package version %r not found",
					product_on_depot.productId,
					product_on_depot.productVersion,
					product_on_depot.packageVersion,
				)

		context = self._get_boot_config_template_context(
			depot=depot,
			client=client,
			product_on_depot=product_on_depot,
			product_on_client=product_on_client,
			product=product,
		)

		if client:
			if context.config_states["netboot.use_host_onetime_password"].bool_value:
				logger.info("Using one time password for client %r", client.id)
				otp = secrets.token_hex(16)
				self.host_updateObjects([OpsiClient(id=client.id, oneTimePassword=otp)])
				context.opsi_linux_bootimage.additional_cmdline_params["otp"] = otp
			else:
				logger.info("Using OPSI host key for client %r", client.id)
				opsi_host_key = client.opsiHostKey
				if opsi_host_key:
					secret_filter.add_secrets(opsi_host_key)
					context.opsi_linux_bootimage.additional_cmdline_params["pckey"] = opsi_host_key
				else:
					logger.error("No OPSI host key set for client %r", client.id)

		grub_cfg_template = Path(GRUB_CFG_TEMPLATE)
		content = file_cache.get_file_content(grub_cfg_template)
		if not content:
			raise FileNotFoundError(f"GRUB config template file '{grub_cfg_template}' not found")

		pxe_boot_server = boot_server_address or depot.getIpAddress()
		pxe_boot_filename = None
		if _firmware_type and _architecture:
			loader = f"opsi-netboot.{_architecture.value.lower()}.{'bios' if _firmware_type == FirmwareType.BIOS else 'efi'}"

			if protocol == "HTTP":
				pxe_boot_filename = f"http://{pxe_boot_server}:4442/boot/opsi/loader/{loader}"
			else:
				pxe_boot_filename = f"opsi/loader/{loader}"

		grub_config = None
		if usage != "DHCP":
			grub_config = Template(content).render(context.context_args())
		if usage == "FILE_LOAD" and product_on_client and client:
			product_on_client.setActionProgress("pxe boot configuration read")
			if product_on_client.actionRequest != "always":
				product_on_client.setActionRequest("none")
			self.productOnClient_updateObjects([product_on_client])

		return BootConfig(
			depot_id=depot.id,
			client_id=client.id if client else None,
			product_id=product.id if product else None,
			pxe_boot_server=pxe_boot_server,
			pxe_boot_filename=pxe_boot_filename,
			grub_config=grub_config,
		)
