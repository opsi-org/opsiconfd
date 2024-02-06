# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.extender
"""

from inspect import getmembers, ismethod
from pathlib import Path

from opsiconfd.backend.rpc.extender import RPCExtenderMixin
from tests.utils import get_config


class Backend(RPCExtenderMixin):
	def __init__(self) -> None:
		super().__init__()
		self.ace_called: list[str] = []

	def _get_ace(self, method: str) -> None:
		self.ace_called.append(method)


def test_extender_loading(tmp_path: Path) -> None:
	ext1 = tmp_path / "1.conf"
	ext1.write_text("def extend1(self):\n\treturn 1\n\ndef extend2(self, param2):\n\treturn None\n", encoding="utf-8")
	ext2 = tmp_path / "2.conf"
	ext2.write_text("def extend2(self, param2):\n\treturn 2\n\ndef extend3(self, param3):\n\treturn 3\n", encoding="utf-8")

	with get_config({"extension_config_dir": str(tmp_path)}):
		extender = Backend()
		count_rpc_methods = 0
		for _, function in getmembers(extender, ismethod):
			if hasattr(function, "rpc_interface"):
				count_rpc_methods += 1
		assert count_rpc_methods == 3

		assert extender.extend1() == 1  # type: ignore[attr-defined]
		assert extender.extend2("a") == 2  # type: ignore[attr-defined]
		assert extender.extend3("b") == 3  # type: ignore[attr-defined]

		assert extender.ace_called == ["extend1", "extend2", "extend3"]
