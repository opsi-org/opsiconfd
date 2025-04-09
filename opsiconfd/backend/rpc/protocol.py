# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd backend interface
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, Protocol

from opsiconfd.backend.rpc.boot import RPCBootMixin
from opsiconfd.backend.rpc.depot import RPCDepotserverMixin
from opsiconfd.backend.rpc.dhcpd_control import RPCDHCPDControlMixin
from opsiconfd.backend.rpc.driver import RPCDriverMixin
from opsiconfd.backend.rpc.ext_admin_tasks import RPCExtAdminTasksMixin
from opsiconfd.backend.rpc.ext_deprecated import RPCExtDeprecatedMixin
from opsiconfd.backend.rpc.ext_dynamic_depot import RPCExtDynamicDepotMixin
from opsiconfd.backend.rpc.ext_easy import RPCExtEasyMixin
from opsiconfd.backend.rpc.ext_group_actions import RPCExtGroupActionsMixin
from opsiconfd.backend.rpc.ext_kiosk import RPCExtKioskMixin
from opsiconfd.backend.rpc.ext_legacy import RPCExtLegacyMixin
from opsiconfd.backend.rpc.ext_opsi import RPCExtOpsiMixin
from opsiconfd.backend.rpc.ext_ssh_commands import RPCExtSSHCommandsMixin
from opsiconfd.backend.rpc.ext_wan import RPCExtWANMixin
from opsiconfd.backend.rpc.ext_wim import RPCExtWIMMixin
from opsiconfd.backend.rpc.extender import RPCExtenderMixin
from opsiconfd.backend.rpc.general import RPCGeneralMixin
from opsiconfd.backend.rpc.host_control import RPCHostControlMixin
from opsiconfd.backend.rpc.obj_audit_hardware import RPCAuditHardwareMixin
from opsiconfd.backend.rpc.obj_audit_hardware_on_host import RPCAuditHardwareOnHostMixin
from opsiconfd.backend.rpc.obj_audit_software import RPCAuditSoftwareMixin
from opsiconfd.backend.rpc.obj_audit_software_on_client import RPCAuditSoftwareOnClientMixin
from opsiconfd.backend.rpc.obj_audit_software_to_license_pool import RPCAuditSoftwareToLicensePoolMixin
from opsiconfd.backend.rpc.obj_config import RPCConfigMixin
from opsiconfd.backend.rpc.obj_config_state import RPCConfigStateMixin
from opsiconfd.backend.rpc.obj_group import RPCGroupMixin
from opsiconfd.backend.rpc.obj_host import RPCHostMixin
from opsiconfd.backend.rpc.obj_license_contract import RPCLicenseContractMixin
from opsiconfd.backend.rpc.obj_license_on_client import RPCLicenseOnClientMixin
from opsiconfd.backend.rpc.obj_license_pool import RPCLicensePoolMixin
from opsiconfd.backend.rpc.obj_object_to_group import RPCObjectToGroupMixin
from opsiconfd.backend.rpc.obj_product import RPCProductMixin
from opsiconfd.backend.rpc.obj_product_dependency import RPCProductDependencyMixin
from opsiconfd.backend.rpc.obj_product_on_client import RPCProductOnClientMixin
from opsiconfd.backend.rpc.obj_product_on_depot import RPCProductOnDepotMixin
from opsiconfd.backend.rpc.obj_product_property import RPCProductPropertyMixin
from opsiconfd.backend.rpc.obj_product_property_state import RPCProductPropertyStateMixin
from opsiconfd.backend.rpc.obj_software_license import RPCSoftwareLicenseMixin
from opsiconfd.backend.rpc.obj_software_license_to_license_pool import RPCSoftwareLicenseToLicensePoolMixin
from opsiconfd.backend.rpc.obj_user import RPCUserMixin
from opsiconfd.backend.rpc.opsipxeconfd import RPCOpsiPXEConfdControlMixin

if TYPE_CHECKING:
	from opsiconfd.application import OpsiconfdApp

	from ..auth import RPCACE
	from ..mysql import MySQLConnection

IdentType = Literal["unicode", "str", "dict", "hash", "list", "tuple"]


class BackendProtocol(
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
	RPCExtGroupActionsMixin,
	RPCExtEasyMixin,
	RPCExtWANMixin,
	RPCExtOpsiMixin,
	RPCExtWIMMixin,
	RPCExtKioskMixin,
	RPCExtSSHCommandsMixin,
	RPCDepotserverMixin,
	RPCHostControlMixin,
	RPCDriverMixin,
	RPCBootMixin,
	RPCDHCPDControlMixin,
	RPCOpsiPXEConfdControlMixin,
	RPCExtenderMixin,
	Protocol,
):
	@property
	def _app(self) -> OpsiconfdApp: ...

	@property
	def _mysql(self) -> MySQLConnection: ...

	@property
	def _server_role(self) -> str: ...

	@property
	def _depot_id(self) -> str: ...

	@property
	def _customer_id(self) -> str | None: ...

	@property
	def _opsi_host_key(self) -> str: ...

	@property
	def _shutting_down(self) -> bool: ...

	@property
	def events_enabled(self) -> bool: ...

	def _get_ace(self, method: str) -> list[RPCACE]: ...

	def _check_role(self, required_role: str) -> None: ...

	def _get_client_id(self) -> str | None: ...

	def _module_available(self, module: str) -> bool: ...

	def _assert_module(self, module: str) -> None: ...

	def _execute_rpc_on_depot(self, depot_id: str, method: str, params: list[Any] | None = None) -> None: ...

	def _get_responsible_depot_id(self, client_id: str) -> str | None: ...

	def get_interface(self) -> list[dict[str, Any]]: ...

	def _send_messagebus_event(self, event: str, data: dict[str, Any]) -> None: ...
