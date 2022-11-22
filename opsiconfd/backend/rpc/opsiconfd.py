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

from opsicommon.exceptions import BackendPermissionDeniedError  # type: ignore[import]

from opsiconfd import contextvar_client_address, contextvar_client_session
from opsiconfd.config import config
from opsiconfd.logging import logger

from .. import get_client_backend
from ..auth import RPCACE, read_acl_file
from ..mysql import MySQLConnection
from .depot import RPCDepotserverMixin
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
from .obj_audit_hardware import RPCAuditHardwareMixin
from .obj_audit_hardware_on_host import RPCAuditHardwareOnHostMixin
from .obj_audit_software import RPCAuditSoftwareMixin
from .obj_audit_software_on_client import RPCAuditSoftwareOnClientMixin
from .obj_config import RPCConfigMixin
from .obj_config_state import RPCConfigStateMixin
from .obj_group import RPCGroupMixin
from .obj_host import RPCHostMixin
from .obj_object_to_group import RPCObjectToGroupMixin
from .obj_product import RPCProductMixin
from .obj_product_dependency import RPCProductDependencyMixin
from .obj_product_on_client import RPCProductOnClientMixin
from .obj_product_on_depot import RPCProductOnDepotMixin
from .obj_product_property import RPCProductPropertyMixin
from .obj_product_property_state import RPCProductPropertyStateMixin

backend_interface = None  # pylint: disable=invalid-name


def get_backend_interface() -> List[Dict[str, Any]]:
	global backend_interface  # pylint: disable=invalid-name, global-statement
	if backend_interface is None:
		backend_interface = OpsiconfdBackend().get_interface()
	return backend_interface


def describe_interface(instance: Any) -> List[Dict[str, Any]]:  # pylint: disable=too-many-locals
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

	return [methods[name] for name in sorted(list(methods.keys()))]


class OpsiconfdBackend(  # pylint: disable=too-many-ancestors
	RPCGeneralMixin,
	RPCHostMixin, RPCConfigMixin, RPCConfigStateMixin, RPCGroupMixin,
	RPCObjectToGroupMixin, RPCProductMixin, RPCProductDependencyMixin,
	RPCProductPropertyMixin, RPCProductPropertyStateMixin,
	RPCProductOnDepotMixin, RPCProductOnClientMixin,
	RPCAuditSoftwareMixin, RPCAuditSoftwareOnClientMixin,
	RPCAuditHardwareMixin, RPCAuditHardwareOnHostMixin,
	RPCExtLegacyMixin, RPCExtAdminTasksMixin, RPCExtDeprecatedMixin,
	RPCExtDynamicDepotMixin, RPCExtEasyMixin, RPCExtKioskMixin,
	RPCExtSSHCommandsMixin, RPCExtWIMMixin, RPCExtWANMixin, RPCExtOpsiMixin,
	RPCDepotserverMixin, RPCExtenderMixin
):
	__instance = None
	__initialized = False

	def __new__(cls, *args: Any, **kwargs: Any) -> OpsiconfdBackend:
		if not cls.__instance:
			cls.__instance = super().__new__(cls, *args, **kwargs)
		return cls.__instance

	def __init__(self) -> None:
		if self.__initialized:
			return
		self.__initialized = True
		self._mysql = MySQLConnection()
		self._mysql.connect()
		self._acl: Dict[str, List[RPCACE]] = {}

		for base in self.__class__.__bases__:
			base.__init__(self)  # type: ignore[misc]

		self._interface = describe_interface(self)
		self._backend = get_client_backend()
		self.method_names = [meth["name"] for meth in self._interface]
		self.read_acl_file()

	def read_acl_file(self) -> None:
		acl = read_acl_file(config.acl_file)
		for method_name in self.method_names:
			self._acl[method_name] = [ace for ace in acl if ace.method_re.match(method_name)]

	def _get_ace(self, method: str) -> List[RPCACE]:  # pylint: disable=too-many-branches,too-many-statements,too-many-return-statements
		"""
		Get list of ACEs.
		"""
		if not contextvar_client_address.get():
			# Local call, no restrictions
			return [RPCACE(method_re=re.compile(".*"), type="all")]
		session = contextvar_client_session.get()
		if not session or not session.user_store:
			raise BackendPermissionDeniedError("Invalid session")

		user_type = "user"
		if session.user_store.host:
			user_type = "client"
			if session.user_store.host.getType() in ("OpsiConfigserver", "OpsiDepotserver"):
				user_type = "depot"

		ace_list = []
		for ace in self._acl.get(method, []):
			if ace.type == "all":
				ace_list.append(ace)
			elif user_type == "user":  # pylint: disable=loop-invariant-statement
				if ace.type == "sys_user":
					if not ace.id or ace.id == session.user_store.username:
						ace_list.append(ace)
				elif ace.type == "sys_group":
					if not ace.id or ace.id in session.user_store.userGroups:
						ace_list.append(ace)
			elif ace.type == "self" and user_type in ("client", "depot"):  # pylint: disable=loop-invariant-statement
				kwargs = ace.__dict__
				kwargs["id"] = session.user_store.username
				ace_list.append(RPCACE(**kwargs))
			elif user_type == "client" and ace.type == "opsi_client":  # pylint: disable=loop-invariant-statement
				if not ace.id or ace.id == session.user_store.username:
					ace_list.append(ace)
			elif user_type == "depot" and ace.type == "opsi_depotserver":  # pylint: disable=loop-invariant-statement
				if not ace.id or ace.id == session.user_store.username:
					ace_list.append(ace)

		if ace_list:
			return ace_list

		raise BackendPermissionDeniedError(f"No permission for method {method!r}")

	def _check_role(self, required_role: str) -> None:
		session = contextvar_client_session.get()
		if not session or not session.user_store:
			raise BackendPermissionDeniedError("Invalid session")

		if required_role == "admin":
			if session.user_store.isAdmin:
				return
			raise BackendPermissionDeniedError("Insufficient permissions")

		raise ValueError(f"Invalid role {required_role!r}")

	def get_interface(self) -> List[Dict[str, Any]]:
		return self._interface
