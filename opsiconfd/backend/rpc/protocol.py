# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd backend interface
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Literal, Protocol

from .depot import RPCDepotserverMixin
from .ext_admin_tasks import RPCExtAdminTasksMixin
from .ext_deprecated import RPCExtDeprecatedMixin
from .ext_dynamic_depot import RPCExtDynamicDepotMixin
from .ext_easy import RPCExtEasyMixin
from .ext_group_actions import RPCExtGroupActionsMixin
from .ext_kiosk import RPCExtKioskMixin
from .ext_legacy import RPCExtLegacyMixin
from .ext_ssh_commands import RPCExtSSHCommandsMixin
from .ext_wan import RPCExtWANMixin
from .ext_wim import RPCExtWIMMixin
from .extender import RPCExtenderMixin
from .obj_config import RPCConfigMixin
from .obj_config_state import RPCConfigStateMixin
from .obj_host import RPCHostMixin

if TYPE_CHECKING:
	from ..auth import RPCACE
	from ..mysql import MySQLConnection


IdentType = Literal["unicode", "str", "dict", "hash", "list", "tuple"]


class BackendProtocol(  # pylint: disable=too-many-ancestors
	RPCHostMixin,
	RPCConfigMixin,
	RPCConfigStateMixin,
	RPCExtLegacyMixin,
	RPCExtAdminTasksMixin,
	RPCExtDeprecatedMixin,
	RPCExtDynamicDepotMixin,
	RPCExtGroupActionsMixin,
	RPCExtEasyMixin,
	RPCExtWANMixin,
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
