# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd backend interface
"""

from __future__ import annotations

import re
from inspect import getfullargspec, getmembers, ismethod, signature
from textwrap import dedent
from typing import Any, Dict, List

from opsicommon.client.jsonrpc import JSONRPCClient  # type: ignore[import]
from opsicommon.exceptions import (  # type: ignore[import]
	BackendModuleDisabledError,
	BackendPermissionDeniedError,
)
from opsicommon.objects import OpsiDepotserver  # type: ignore[import]
from opsicommon.types import forceHostId  # type: ignore[import]
from starlette.concurrency import run_in_threadpool

from opsiconfd import contextvar_client_session
from opsiconfd.application.utils import get_depot_server_id
from opsiconfd.config import config
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


def describe_interface(instance: Any) -> Dict[str, Any]:  # pylint: disable=too-many-locals
	"""
	Describes what public methods are available and the signatures they use.

	These methods are represented as a dict with the following keys: \
	*name*, *params*, *args*, *varargs*, *keywords*, *defaults*.

	:rtype: [{},]
	"""
	methods = {}
	for _, function in getmembers(instance, ismethod):
		method_name = function.__name__
		if not getattr(function, "rpc_method", False):
			continue

		spec = getfullargspec(function)
		sig = signature(function)
		args = spec.args
		defaults = spec.defaults
		params = [arg for arg in args if arg != "self"]  # pylint: disable=loop-invariant-statement
		annotations = {}
		for param in params:
			str_param = str(sig.parameters[param])
			if ": " in str_param:
				annotations[param] = str_param.split(": ", 1)[1].split(" = ", 1)[0]

		if defaults is not None:
			offset = len(params) - len(defaults)
			for i in range(len(defaults)):
				index = offset + i
				params[index] = f"*{params[index]}"

		for index, element in enumerate((spec.varargs, spec.varkw), start=1):
			if element:
				stars = "*" * index
				params.extend([f"{stars}{arg}" for arg in (element if isinstance(element, list) else [element])])

		logger.trace("%s interface method: name %s, params %s", instance.__class__.__name__, method_name, params)
		doc = function.__doc__
		if doc:
			doc = dedent(doc).lstrip() or None

		methods[method_name] = {
			"name": method_name,
			"params": params,
			"args": args,
			"varargs": spec.varargs,
			"keywords": spec.varkw,
			"defaults": defaults,
			"deprecated": getattr(function, "deprecated", False),
			"alternative_method": getattr(function, "alternative_method", None),
			"doc": doc,
			"annotations": annotations,
		}

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
	_depot_connections: dict[str, JSONRPCClient]
	_shutting_down: bool = False

	def __new__(cls, *args: Any, **kwargs: Any) -> Backend:
		if not cls.__instance:
			cls.__instance = super().__new__(cls, *args, **kwargs)
		return cls.__instance

	def __init__(self) -> None:
		if self.__initialized:
			return
		self.__initialized = True

		self._depot_connections: dict[str, JSONRPCClient] = {}
		self._depot_id: str = get_depot_server_id()

		self._mysql = MySQLConnection()
		self._mysql.connect()
		self._acl: Dict[str, List[RPCACE]] = {}

		for base in self.__class__.__bases__:
			base.__init__(self)  # type: ignore[misc]

		self._interface = describe_interface(self)
		self._interface_list = [self._interface[name] for name in sorted(list(self._interface.keys()))]
		self.available_modules = self.backend_getLicensingInfo()["available_modules"]

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

		self.read_acl_file()

	def shutdown(self) -> None:
		self._shutting_down = True
		for jsonrpc_client in self._depot_connections.values():
			jsonrpc_client.disconnect()
		for base in self.__class__.__bases__:
			for method in base.__dict__.values():
				if callable(method) and hasattr(method, "backend_event_shutdown"):
					method(self)

	def reload_config(self) -> None:
		self.read_acl_file()

	def read_acl_file(self) -> None:
		acl = read_acl_file(config.acl_file)
		for method_name in list(self._interface):
			self._acl[method_name] = [ace for ace in acl if ace.method_re.match(method_name)]

	def _get_ace(self, method: str) -> List[RPCACE]:
		return []

	def _check_role(self, required_role: str) -> None:
		return None

	def _check_module(self, module: str) -> None:
		if module not in self.available_modules:
			raise BackendModuleDisabledError(f"Module {module!r} not available")

	def _get_depot_jsonrpc_connection(self, depot_id: str) -> JSONRPCClient:
		depot_id = forceHostId(depot_id)
		if depot_id == self._depot_id:
			raise ValueError("Is local depot")

		if depot_id not in self._depot_connections:
			try:
				self._depot_connections[depot_id] = JSONRPCClient(
					address=f"https://{depot_id}:4447/rpc", username=self._depot_id, password=self._opsi_host_key
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

	def get_method_interface(self, method: str) -> Dict[str, Any] | None:
		return self._interface.get(method)

	def get_interface(self) -> List[Dict[str, Any]]:
		return self._interface_list

	async def async_call(self, method: str, **kwargs: Any) -> Any:
		return await run_in_threadpool(getattr(self, method), **kwargs)


class UnprotectedBackend(Backend):  # pylint: disable=too-many-ancestors
	def _get_ace(self, method: str) -> List[RPCACE]:
		return [RPCACE_ALLOW_ALL]

	def _check_role(self, required_role: str) -> None:
		return None


class ProtectedBackend(Backend):  # pylint: disable=too-many-ancestors
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
