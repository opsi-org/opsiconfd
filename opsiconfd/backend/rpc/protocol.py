# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd backend interface
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Literal, Protocol

from .depot import RPCDepotserverMixin
from .ext_admin_tasks import RPCExtAdminTasksMixin
from .ext_deprecated import RPCExtDeprecatedMixin
from .ext_dynamic_depot import RPCExtDynamicDepotMixin
from .ext_easy import RPCExtEasyMixin
from .ext_group_actions import RPCExtGroupActionsMixin
from .ext_kiosk import RPCExtKioskMixin
from .ext_legacy import RPCExtLegacyMixin
from .ext_opsi import RPCExtOpsiMixin
from .ext_ssh_commands import RPCExtSSHCommandsMixin
from .ext_wan import RPCExtWANMixin
from .ext_wim import RPCExtWIMMixin
from .extender import RPCExtenderMixin
from .general import RPCGeneralMixin
from .obj_audit_hardware import RPCAuditHardwareMixin
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

if TYPE_CHECKING:
	from ..auth import RPCACE
	from ..mysql import MySQLConnection


IdentType = Literal["unicode", "str", "dict", "hash", "list", "tuple"]


class BackendProtocol(  # pylint: disable=too-many-ancestors
	RPCGeneralMixin,
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
	RPCAuditSoftwareMixin,
	RPCAuditSoftwareOnClientMixin,
	RPCAuditHardwareMixin,
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
	RPCExtenderMixin,
	Protocol,
):
	@property
	def _mysql(self) -> MySQLConnection:
		...

	def _get_ace(self, method: str) -> List[RPCACE]:
		...

	def _check_role(self, required_role: str) -> None:
		...

	def get_interface(self) -> List[Dict[str, Any]]:
		...
