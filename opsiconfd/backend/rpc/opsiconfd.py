# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd backend interface
"""

from __future__ import annotations

from inspect import getmembers, ismethod
from types import MethodType
from typing import Any, Dict, List

from opsicommon.client.opsiservice import ServiceClient  # type: ignore[import]
from opsicommon.exceptions import (  # type: ignore[import]
	BackendModuleDisabledError,
	BackendPermissionDeniedError,
)
from opsicommon.objects import OpsiDepotserver  # type: ignore[import]
from opsicommon.types import forceHostId  # type: ignore[import]
from starlette.concurrency import run_in_threadpool

from opsiconfd import contextvar_client_session
from opsiconfd.application.utils import get_depot_server_id
from opsiconfd.backend.rpc import MethodInterface
from opsiconfd.config import config, opsi_config
from opsiconfd.logging import logger, secret_filter

from ..auth import RPCACE, RPCACE_ALLOW_ALL, read_acl_file
from ..mysql import MySQLConnection
from .depot import RPCDepotserverMixin
from .dhcpd_control import RPCDHCPDControlMixin
from .ext_admin_tasks import RPCExtAdminTasksMixin
from .ext_deprecated import RPCExtDeprecatedMixin
from .ext_dynamic_depot import RPCExtDynamicDepotMixin
from .ext_easy import RPCExtEasyMixin
from .ext_kiosk import RPCExtKioskMixin
from .ext_legacy import RPCExtLegacyMixin
from .ext_opsi import RPCExtOpsiMixin
from .ext_ssh_commands import RPCExtSSHCommandsMixin
from .ext_wan import RPCExtWANMixin
from .ext_wim import RPCExtWIMMixin
from .extender import RPCExtenderMixin
from .general import RPCGeneralMixin
from .host_control import RPCHostControlMixin
from .obj_audit_hardware import RPCAuditHardwareMixin
from .obj_audit_hardware_on_host import RPCAuditHardwareOnHostMixin
from .obj_audit_software import RPCAuditSoftwareMixin
from .obj_audit_software_on_client import RPCAuditSoftwareOnClientMixin
from .obj_audit_software_to_license_pool import RPCAuditSoftwareToLicensePoolMixin
from .obj_config import RPCConfigMixin
from .obj_config_state import RPCConfigStateMixin
from .obj_group import RPCGroupMixin
from .obj_host import RPCHostMixin
from .obj_license_contract import RPCLicenseContractMixin
from .obj_license_on_client import RPCLicenseOnClientMixin
from .obj_license_pool import RPCLicensePoolMixin
from .obj_object_to_group import RPCObjectToGroupMixin
from .obj_product import RPCProductMixin
from .obj_product_dependency import RPCProductDependencyMixin
from .obj_product_on_client import RPCProductOnClientMixin
from .obj_product_on_depot import RPCProductOnDepotMixin
from .obj_product_property import RPCProductPropertyMixin
from .obj_product_property_state import RPCProductPropertyStateMixin
from .obj_software_license import RPCSoftwareLicenseMixin
from .obj_software_license_to_license_pool import RPCSoftwareLicenseToLicensePoolMixin
from .opsipxeconfd import RPCOpsiPXEConfdMixin


def describe_interface(instance: Any) -> Dict[str, MethodInterface]:  # pylint: disable=too-many-locals
	"""
	Describes what public methods are available and the signatures they use.

	These methods are represented as a dict with the following keys: \
	*name*, *params*, *args*, *varargs*, *keywords*, *defaults*.

	:rtype: [{},]
	"""
	methods = {}
	for _, function in getmembers(instance, ismethod):
		rpc_interface: MethodInterface | None = getattr(function, "rpc_interface", None)  # pylint: disable=loop-invariant-statement
		if rpc_interface:  # pylint: disable=loop-invariant-statement
			methods[rpc_interface.name] = rpc_interface  # pylint: disable=loop-invariant-statement
	return methods


class Backend(  # pylint: disable=too-many-ancestors, too-many-instance-attributes
	RPCGeneralMixin,
	RPCHostMixin, RPCConfigMixin, RPCConfigStateMixin, RPCGroupMixin,
	RPCObjectToGroupMixin, RPCProductMixin, RPCProductDependencyMixin,
	RPCProductPropertyMixin, RPCProductPropertyStateMixin,
	RPCProductOnDepotMixin, RPCProductOnClientMixin,
	RPCLicenseContractMixin, RPCLicenseOnClientMixin, RPCLicensePoolMixin,
	RPCSoftwareLicenseToLicensePoolMixin, RPCSoftwareLicenseMixin,
	RPCAuditSoftwareToLicensePoolMixin,
	RPCAuditSoftwareMixin, RPCAuditSoftwareOnClientMixin,
	RPCAuditHardwareMixin, RPCAuditHardwareOnHostMixin,
	RPCExtLegacyMixin, RPCExtAdminTasksMixin, RPCExtDeprecatedMixin,
	RPCExtDynamicDepotMixin, RPCExtEasyMixin, RPCExtKioskMixin,
	RPCExtSSHCommandsMixin, RPCExtWIMMixin, RPCExtWANMixin, RPCExtOpsiMixin,
	RPCDepotserverMixin, RPCHostControlMixin, RPCDHCPDControlMixin, RPCOpsiPXEConfdMixin,
	RPCExtenderMixin
):
	__instance = None
	__initialized = False
	_depot_connections: dict[str, ServiceClient]
	_shutting_down: bool = False

	def __new__(cls, *args: Any, **kwargs: Any) -> Backend:
		if not cls.__instance:
			cls.__instance = super().__new__(cls, *args, **kwargs)
		return cls.__instance

	def __init__(self) -> None:
		if self.__initialized:
			return
		self.__initialized = True

		self._acl: Dict[str, List[RPCACE]] = {}
		self._depot_connections: dict[str, ServiceClient] = {}
		self._depot_id: str = get_depot_server_id()
		self._mysql = MySQLConnection()
		self._service_client: ServiceClient | None = None
		self._opsi_host_key: str | None = None
		self._interface: dict[str, MethodInterface] = {}
		self._interface_list: list[dict[str, Any]] = []
		self.available_modules: list[str] = []

		if opsi_config.get("host", "server-role") == "configserver":
			self._config_server_init()
		else:
			self._depot_server_init()

		for base in self.__class__.__bases__:
			base.__init__(self)  # type: ignore[misc]

	def __str__(self) -> str:
		return f"{self.__class__.__name__}({id(self)})"

	__repr__ = __str__

	def _config_server_init(self) -> None:
		self._mysql.connect()

		hosts = self._mysql.get_objects(
			table="HOST",
			object_type=OpsiDepotserver,
			ace=[],
			return_type="object",
			attributes=["id", "opsiHostKey"],
			filter={"type": "OpsiDepotserver", "id": self._depot_id}
		)
		if hosts:
			self._opsi_host_key = hosts[0].opsiHostKey
			secret_filter.add_secrets(self._opsi_host_key)
		else:
			logger.error("Depot %r not found in backend", self._depot_id)

		self._interface = describe_interface(self)
		self._interface_list = [self._interface[name].as_dict() for name in sorted(list(self._interface.keys()))]
		self.available_modules = self.get_licensing_info()["available_modules"]  # type: ignore[misc]

	def _create_jsonrpc_instance_methods(self) -> None:  # pylint: disable=too-many-locals
		if self._interface_list is None:
			raise ValueError("No interface specification present for _create_jsonrpc_instance_methods")

		for method in self._interface_list:
			try:  # pylint: disable=loop-try-except-usage
				method_name = method["name"]
				self._interface[method_name] = MethodInterface(**method)

				if method_name.startswith(("depot_", "dhcpd_", "opsipxeconfd_")) or method_name in (
					"backend_exit",
					"backend_getInterface",
					"jsonrpc_getSessionId",
				):
					continue

				logger.debug("Creating instance method: %s", method_name)  # pylint: disable=loop-global-usage

				args = method["args"]
				varargs = method["varargs"]
				keywords = method["keywords"]
				defaults = method["defaults"]

				arg_list = []
				call_list = []
				for i, argument in enumerate(args):
					if argument == "self":
						continue

					if isinstance(defaults, (tuple, list)) and len(defaults) + i >= len(args):  # pylint: disable=loop-invariant-statement
						default = defaults[len(defaults) - len(args) + i]  # pylint: disable=loop-invariant-statement
						if isinstance(default, str):
							default = "{0!r}".format(default).replace('"', "'")  # pylint: disable=consider-using-f-string
						arg_list.append(f"{argument}={default}")
					else:
						arg_list.append(argument)
					call_list.append(argument)

				if varargs:
					for vararg in varargs:
						arg_list.append(f"*{vararg}")
						call_list.append(vararg)

				if keywords:
					arg_list.append(f"**{keywords}")
					call_list.append(keywords)

				arg_string = ", ".join(arg_list)
				call_string = ", ".join(call_list)

				logger.trace("%s: arg string is: %s", method_name, arg_string)  # pylint: disable=loop-global-usage
				logger.trace("%s: call string is: %s", method_name, call_string)  # pylint: disable=loop-global-usage
				exec(  # pylint: disable=exec-used
					f'def {method_name}(self, {arg_string}): return self._service_client.jsonrpc(method="{method_name}", params=[{call_string}])'
				)
				func = eval(method_name)  # pylint: disable=eval-used
				setattr(func, "rpc_interface", self._interface[method_name])
				setattr(self, method_name, MethodType(func, self))  # pylint: disable=eval-used,dotted-import-in-loop

			except Exception as err:  # pylint: disable=broad-except
				logger.critical("Failed to create instance method '%s': %s", method, err, exc_info=True)  # pylint: disable=loop-global-usage

	def _depot_server_init(self) -> None:
		self._opsi_host_key = ""
		self._depot_id = ""
		address = ""
		self._service_client = ServiceClient(address=address, username=self._depot_id, password=self._opsi_host_key, verify="accept_all")
		self._service_client.connect()
		self._interface_list = self._service_client.jsonrpc(method="backend_getInterface")
		self._create_jsonrpc_instance_methods()

	def shutdown(self) -> None:
		self._shutting_down = True
		for jsonrpc_client in self._depot_connections.values():
			jsonrpc_client.disconnect()
		for base in self.__class__.__bases__:
			for method in base.__dict__.values():
				if callable(method) and hasattr(method, "backend_event_shutdown"):
					method(self)
		if self._service_client:
			self._service_client.disconnect()

	def reload_config(self) -> None:
		pass

	def _get_ace(self, method: str) -> List[RPCACE]:
		return []

	def _check_role(self, required_role: str) -> None:
		return None

	def _check_module(self, module: str) -> None:
		if module not in self.available_modules:
			raise BackendModuleDisabledError(f"Module {module!r} not available")

	def _get_depot_jsonrpc_connection(self, depot_id: str) -> ServiceClient:
		depot_id = forceHostId(depot_id)
		if depot_id == self._depot_id:
			raise ValueError("Is local depot")

		if depot_id not in self._depot_connections:
			try:
				self._depot_connections[depot_id] = ServiceClient(
					# TODO: verify
					address=f"https://{depot_id}:4447/rpc", username=self._depot_id, password=self._opsi_host_key, verify="accept_all"
				)
			except Exception as err:
				raise ConnectionError(f"Failed to connect to depot '{depot_id}': {err}") from err
		return self._depot_connections[depot_id]

	def _get_responsible_depot_id(self, client_id: str) -> str | None:
		"""This method returns the depot a client is assigned to."""
		try:
			return self.configState_getClientToDepotserver(clientIds=[client_id])[0]["depotId"]
		except (IndexError, KeyError):
			return None

	def get_method_interface(self, method: str) -> MethodInterface | None:
		return self._interface.get(method)

	def get_interface(self) -> list[Dict[str, Any]]:
		return self._interface_list

	async def async_call(self, method: str, **kwargs: Any) -> Any:
		return await run_in_threadpool(getattr(self, method), **kwargs)


class UnprotectedBackend(Backend):  # pylint: disable=too-many-ancestors
	def _get_ace(self, method: str) -> List[RPCACE]:
		return [RPCACE_ALLOW_ALL]

	def _check_role(self, required_role: str) -> None:
		return None


class ProtectedBackend(Backend):  # pylint: disable=too-many-ancestors
	def __init__(self) -> None:
		super().__init__()
		self._read_acl_file()

	def reload_config(self) -> None:
		super().reload_config()
		self._read_acl_file()

	def _read_acl_file(self) -> None:
		acl = read_acl_file(config.acl_file)
		for method_name in list(self._interface):
			self._acl[method_name] = [ace for ace in acl if ace.method_re.match(method_name)]

	def _get_ace(self, method: str) -> List[RPCACE]:  # pylint: disable=too-many-branches,too-many-statements,too-many-return-statements
		"""
		Get list of ACEs.
		"""
		session = contextvar_client_session.get()
		if not session:
			raise BackendPermissionDeniedError("Invalid session")

		user_type = "user"
		if session.host:
			user_type = "client"
			if session.host.getType() in ("OpsiConfigserver", "OpsiDepotserver"):
				user_type = "depot"

		ace_list = []
		for ace in self._acl.get(method, []):
			if ace.type == "all":
				ace_list.append(ace)
			elif user_type == "user":  # pylint: disable=loop-invariant-statement
				if ace.type == "sys_user":
					if not ace.id or ace.id == session.username:
						ace_list.append(ace)
				elif ace.type == "sys_group":
					if not ace.id or ace.id in session.user_groups:
						ace_list.append(ace)
			elif ace.type == "self" and user_type in ("client", "depot"):  # pylint: disable=loop-invariant-statement
				kwargs = ace.__dict__
				kwargs["id"] = session.username
				ace_list.append(RPCACE(**kwargs))
			elif user_type == "client" and ace.type == "opsi_client":  # pylint: disable=loop-invariant-statement
				if not ace.id or ace.id == session.username:
					ace_list.append(ace)
			elif user_type == "depot" and ace.type == "opsi_depotserver":  # pylint: disable=loop-invariant-statement
				if not ace.id or ace.id == session.username:
					ace_list.append(ace)

		if ace_list:
			return ace_list

		raise BackendPermissionDeniedError(f"No permission for method {method!r}")

	def _check_role(self, required_role: str) -> None:
		session = contextvar_client_session.get()
		if not session:
			raise BackendPermissionDeniedError("Invalid session")

		if required_role == "admin":
			if session.is_admin:
				return
			raise BackendPermissionDeniedError("Insufficient permissions")

		raise ValueError(f"Invalid role {required_role!r}")
