# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.extender
"""


from datetime import datetime

from opsiconfd.backend.rpc.extender import RPCExtenderMixin

from .utils import get_config  # pylint: disable=unused-import


class Backend(RPCExtenderMixin):  # pylint: disable=too-few-public-methods
	pass


def test_extender_loading() -> None:
	with get_config({"extension_config_dir": "tests/data/opsi-config/backendManager/extend.d"}):
		extender = Backend()
		count_rpc_methods = 0
		for val in extender.__dict__.values():
			if hasattr(val, "rpc_method"):
				count_rpc_methods += 1
		assert count_rpc_methods == 134

		val = extender.getServiceTime()  # type: ignore[attr-defined]  # pylint: disable=no-member
		assert str(datetime.now())[:16] == val[:16]
