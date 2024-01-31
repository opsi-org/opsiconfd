# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd backend interface
"""

from __future__ import annotations

from contextlib import contextmanager
from inspect import getmembers, ismethod
from types import MethodType
from typing import Any, Generator

from opsicommon.client.opsiservice import ServiceClient  # type: ignore[import]
from opsicommon.exceptions import (  # type: ignore[import]
	BackendModuleDisabledError,
	BackendPermissionDeniedError,
)
from opsicommon.messagebus import (
	EventMessage,  # type: ignore[import]
	JSONRPCRequestMessage,
	timestamp,
)
from opsicommon.objects import OpsiDepotserver, serialize  # type: ignore[import]
from starlette.concurrency import run_in_threadpool

# server_timing needed for jsonrpc_forward
from opsiconfd import (  # pylint: disable=unused-import
	contextvar_client_session,
	server_timing,
)
from opsiconfd.application import app
from opsiconfd.backend import get_service_client, stop_service_clients
from opsiconfd.backend.rpc import MethodInterface
from opsiconfd.config import config, get_depotserver_id, get_server_role
from opsiconfd.logging import logger, secret_filter
from opsiconfd.messagebus import get_user_id_for_service_worker
from opsiconfd.messagebus.redis import sync_send_message
from opsiconfd.worker import Worker

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
from .obj_user import RPCUserMixin
from .opsipxeconfd import RPCOpsiPXEConfdControlMixin


def describe_interface(instance: Any) -> dict[str, MethodInterface]:  # pylint: disable=too-many-locals
	"""
	Describes what public methods are available and the signatures they use.

	These methods are represented as a dict with the following keys: \
	*name*, *params*, *args*, *varargs*, *keywords*, *defaults*.

	:rtype: [{},]
	"""
	methods = {}
	for _, function in getmembers(instance, ismethod):
		rpc_interface: MethodInterface | None = getattr(function, "rpc_interface", None)
		if rpc_interface and (not rpc_interface.deprecated or config.provide_deprecated_methods):
			methods[rpc_interface.name] = rpc_interface
	return methods


class Backend(  # pylint: disable=too-many-ancestors, too-many-instance-attributes
	RPCGeneralMixin,
	RPCUserMixin,
	RPCHostMixin,
	RPCConfigMixin,
	RPCConfigStateMixin,
	RPCGroupMixin,
	RPCObjectToGroupMixin,
	RPCProductMixin,
	RPCProductDependencyMixin,
	RPCProductPropertyMixin,
	RPCProductPropertyStateMixin,
	RPCProductOnDepotMixin,
	RPCProductOnClientMixin,
	RPCLicenseContractMixin,
	RPCLicenseOnClientMixin,
	RPCLicensePoolMixin,
	RPCSoftwareLicenseToLicensePoolMixin,
	RPCSoftwareLicenseMixin,
	RPCAuditSoftwareToLicensePoolMixin,
	RPCAuditSoftwareMixin,
	RPCAuditSoftwareOnClientMixin,
	RPCAuditHardwareMixin,
	RPCAuditHardwareOnHostMixin,
	RPCExtLegacyMixin,
	RPCExtAdminTasksMixin,
	RPCExtDeprecatedMixin,
	RPCExtDynamicDepotMixin,
	RPCExtEasyMixin,
	RPCExtKioskMixin,
	RPCExtSSHCommandsMixin,
	RPCExtWIMMixin,
	RPCExtWANMixin,
	RPCExtOpsiMixin,
	RPCDepotserverMixin,
	RPCHostControlMixin,
	RPCDHCPDControlMixin,
	RPCOpsiPXEConfdControlMixin,
	RPCExtenderMixin,
):
	__instance = None
	__initialized = False
	_shutting_down: bool = False

	def __new__(cls, *args: Any, **kwargs: Any) -> Backend:
		if not cls.__instance:
			cls.__instance = super().__new__(cls, *args, **kwargs)
		return cls.__instance

	@classmethod
	def reset_singleton(cls) -> None:
		cls.__instance = None

	def __init__(self) -> None:
		if self.__initialized:
			return
		self.__initialized = True
		self.events_enabled = True
		self._app = app
		self._acl: dict[str, list[RPCACE]] = {}
		self._server_role = get_server_role()
		self._depot_id: str = get_depotserver_id()
		self._mysql = MySQLConnection()
		self._service_client: ServiceClient | None = None
		self._opsi_host_key: str | None = None
		self._interface: dict[str, MethodInterface] = {}
		self._interface_list: list[dict[str, Any]] = []
		self.available_modules: list[str] = []
		self._messagebus_user_id = None
		try:
			self._messagebus_user_id = get_user_id_for_service_worker(Worker.get_instance().id)
		except RuntimeError:
			pass

		if self._server_role == "configserver":
			self._config_server_init()
		else:
			self._depot_server_init()
		self.available_modules = self.backend_getLicensingInfo()["available_modules"]  # type: ignore[misc]

		for base in Backend.__bases__:
			logger.debug("Init %s", base)
			base.__init__(self)  # type: ignore[misc]

		if self._server_role == "configserver":
			self._interface = describe_interface(self)
			self._interface_list = [self._interface[name].as_dict() for name in sorted(list(self._interface.keys()))]

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
			filter={"type": "OpsiDepotserver", "id": self._depot_id},
		)
		if hosts:
			self._opsi_host_key = hosts[0].opsiHostKey
			if self._opsi_host_key:
				secret_filter.add_secrets(self._opsi_host_key)
		else:
			logger.info("Configserver %r not found in backend", self._depot_id)

	def _create_jsonrpc_instance_methods(self) -> None:  # pylint: disable=too-many-locals,too-many-branches
		if self._interface_list is None:
			raise ValueError("No interface specification present for _create_jsonrpc_instance_methods")

		for method in self._interface_list:
			try:
				method_name = method["name"]
				method_interface = MethodInterface(**method)
				if method_interface.deprecated and not config.provide_deprecated_methods:
					continue

				self._interface[method_name] = method_interface

				if method_name.startswith(("depot_", "dhcpd_", "opsipxeconfd_", "network_", "workbench_")) or method_name in (
					"backend_exit",
					"backend_getInterface",
					"jsonrpc_getSessionId",
				):
					continue

				logger.debug("Creating instance method: %s", method_name)

				args = method["args"]
				varargs = method["varargs"]
				keywords = method["keywords"]
				defaults = method["defaults"]

				arg_list = []
				call_list = []
				for i, argument in enumerate(args):
					if argument == "self":
						continue

					if isinstance(defaults, (tuple, list)) and len(defaults) + i >= len(args):
						default = defaults[len(defaults) - len(args) + i]
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

				logger.trace("%s: arg string is: %s", method_name, arg_string)
				logger.trace("%s: call string is: %s", method_name, call_string)
				exec(  # pylint: disable=exec-used
					f"def {method_name}(self, {arg_string}):\n"
					'	with server_timing("jsonrpc_forward"):\n'
					f'		return self._service_client.jsonrpc(method="{method_name}", params=[{call_string}])\n'
				)
				func = eval(method_name)  # pylint: disable=eval-used
				setattr(func, "rpc_interface", self._interface[method_name])
				setattr(self, method_name, MethodType(func, self))  # pylint: disable=eval-used

			except Exception as err:  # pylint: disable=broad-except
				logger.critical("Failed to create instance method '%s': %s", method, err, exc_info=True)

	def _depot_server_init(self) -> None:
		self._service_client = get_service_client("backend")
		self._interface_list = self._service_client.jsonrpc(method="backend_getInterface")
		self._create_jsonrpc_instance_methods()

	@contextmanager
	def events_disabled(self) -> Generator[None, None, None]:
		events_enabled = self.events_enabled
		self.events_enabled = False
		try:
			yield
		finally:
			self.events_enabled = events_enabled

	def shutdown(self) -> None:
		self._shutting_down = True
		with self.events_disabled():
			for base in self.__class__.__bases__:
				for method in base.__dict__.values():
					if callable(method) and hasattr(method, "backend_event_shutdown"):
						method(self)
		if self._server_role == "depotserver":
			stop_service_clients()

	def reload_config(self) -> None:
		self._dhcpd_control_reload_config()  # pylint: disable=no-member
		self._read_host_control_config_file()  # pylint: disable=no-member
		self._read_opsipxeconfd_control_config_file()  # pylint: disable=no-member

	def _get_ace(self, method: str) -> list[RPCACE]:  # pylint: disable=unused-argument
		return []

	def _check_role(self, required_role: str) -> None:  # pylint: disable=unused-argument
		return None

	def _check_module(self, module: str) -> None:
		if app.app_state.type == "maintenance":
			# Do not check in maintenance mode (backup / restore)
			return
		if module not in self.available_modules:
			raise BackendModuleDisabledError(f"Module {module!r} not available")

	def _get_responsible_depot_id(self, client_id: str) -> str | None:
		"""This method returns the depot a client is assigned to."""
		try:
			return self.configState_getClientToDepotserver(clientIds=[client_id])[0]["depotId"]
		except (IndexError, KeyError):
			return None

	def _send_messagebus_event(self, event: str, data: dict[str, Any]) -> None:
		if not self.events_enabled or not self._messagebus_user_id:
			return
		sync_send_message(
			EventMessage(
				sender=self._messagebus_user_id,
				channel=f"event:{event}",
				event=event,
				data=data,
			)
		)

	def _execute_rpc_on_depot(self, depot_id: str, method: str, params: list[Any] | None = None) -> None:
		logger.info("Executing RPC method %r on depot %r", method, depot_id)
		worker = Worker.get_instance()
		jsonrpc_request = JSONRPCRequestMessage(
			sender=get_user_id_for_service_worker(worker.id),
			channel=f"service:depot:{depot_id}:jsonrpc",
			expires=timestamp() + int(30_000),
			method=method,
			params=tuple(serialize(params) or []),
		)
		sync_send_message(jsonrpc_request)

	def get_method_interface(self, method: str) -> MethodInterface | None:
		return self._interface.get(method)

	def get_interface(self) -> list[dict[str, Any]]:
		return self._interface_list

	async def async_call(self, method: str, **kwargs: Any) -> Any:
		return await run_in_threadpool(getattr(self, method), **kwargs)


class UnprotectedBackend(Backend):  # pylint: disable=too-many-ancestors
	def _get_ace(self, method: str) -> list[RPCACE]:
		return [RPCACE_ALLOW_ALL]

	def _check_role(self, required_role: str) -> None:
		return None


class ProtectedBackend(Backend):  # pylint: disable=too-many-ancestors
	def __init__(self) -> None:
		super().__init__()
		if not self._acl:
			self._read_acl_file()

	def reload_config(self) -> None:
		super().reload_config()
		self._read_acl_file()

	def _read_acl_file(self) -> None:
		acl = read_acl_file(config.acl_file)
		for method_name in list(self._interface):
			self._acl[method_name] = [ace for ace in acl if ace.method_re.match(method_name)]

	def _get_ace(self, method: str) -> list[RPCACE]:  # pylint: disable=too-many-branches,too-many-statements,too-many-return-statements
		"""
		Get list of ACEs.
		"""
		if not self._acl:
			return []

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
			elif user_type == "user":
				if ace.type == "sys_user":
					if not ace.id or ace.id == session.username:
						ace_list.append(ace)
				elif ace.type == "sys_group":
					if not ace.id or ace.id in session.user_groups:
						ace_list.append(ace)
			elif ace.type == "self" and user_type in ("client", "depot"):
				kwargs = ace.__dict__
				kwargs["id"] = session.username
				ace_list.append(RPCACE(**kwargs))
			elif user_type == "client" and ace.type == "opsi_client":
				if not ace.id or ace.id == session.username:
					ace_list.append(ace)
			elif user_type == "depot" and ace.type == "opsi_depotserver":
				if not ace.id or ace.id == session.username:
					ace_list.append(ace)

		if ace_list:
			return ace_list

		logger.info("No macthing ACEs for method %r (user=%r, acl-file=%r)", method, session.username, config.acl_file)
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
