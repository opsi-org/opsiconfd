# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test backend.rpc
"""

from typing import Any

from opsiconfd.backend.rpc import DOC_INSERT_OBJECT, rpc_method
from opsiconfd.backend.rpc.opsiconfd import describe_interface


def test_rpc_method_decorator() -> None:
	class Test:
		def __init__(self) -> None:
			self.ace_called: list[str] = []

		def _get_ace(self, method: str) -> None:
			self.ace_called.append(method)

		@rpc_method
		def func1(self, arg1: str) -> str:  # pylint: disable=unused-argument
			return arg1

		@rpc_method(check_acl="func2_other")
		def func2(self, arg1: str = None) -> str | None:  # pylint: disable=unused-argument
			return arg1

		@rpc_method(check_acl=False)
		def func3(self, arg1: str = None) -> str | None:  # pylint: disable=unused-argument
			return arg1

		@rpc_method
		def test_insertObject(self, obj: Any) -> str:  # pylint: disable=unused-argument,invalid-name
			return obj

		@rpc_method(check_acl=True)
		def test2_insertObject(self, obj: Any) -> str:  # pylint: disable=unused-argument,invalid-name
			"""DOC"""
			return obj

	test = Test()
	assert getattr(test.func1, "rpc_interface")
	assert getattr(test.func2, "rpc_interface")
	assert getattr(test.func3, "rpc_interface")
	assert getattr(test.test_insertObject, "rpc_interface")
	assert getattr(test.test2_insertObject, "rpc_interface")
	assert test.test_insertObject.__doc__ == DOC_INSERT_OBJECT
	assert test.test2_insertObject.__doc__ == "DOC"

	assert test.func1("f1") == "f1"
	assert test.func2("f2") == "f2"
	assert test.func3("f3") == "f3"
	assert test.test_insertObject("test") == "test"
	assert test.test2_insertObject("test") == "test"

	assert test.ace_called == ["func1", "func2_other", "test_insertObject", "test2_insertObject"]
