# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test backend.rpc
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from opsiconfd.backend.rpc import DOC_INSERT_OBJECT, rpc_method


class SomeStrEnum(StrEnum):
	VAL1 = "val1"
	VAL2 = "val2"


@dataclass
class SomeDataclass:
	attr1: int
	attr2: str | None = None


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
		def func2(self, arg1: str | None = None) -> str | None:  # pylint: disable=unused-argument
			return arg1

		@rpc_method(check_acl=False)
		def func3(self, arg1: str | None = None) -> str | None:  # pylint: disable=unused-argument
			return arg1

		@rpc_method
		def test_insertObject(self, obj: Any) -> str:  # pylint: disable=unused-argument,invalid-name
			return obj

		@rpc_method(check_acl=True)
		def test2_insertObject(self, obj: Any) -> str:  # pylint: disable=unused-argument,invalid-name
			"""DOC"""
			return obj

		@rpc_method(deprecated=True)
		def test_deprecated(self) -> str:
			return ""

		@rpc_method(drop_version="5.0")
		def test_drop(self) -> str:
			return ""

		@rpc_method
		def test_annotation(
			self, param1: str | None = None, param2: SomeStrEnum | None = None, param3: SomeDataclass | None = None
		) -> bool:
			return param1 and param2 and param3

	test = Test()
	assert getattr(test.func1, "rpc_interface")
	assert getattr(test.func2, "rpc_interface")
	assert getattr(test.func3, "rpc_interface")
	assert getattr(test.test_insertObject, "rpc_interface")
	assert getattr(test.test2_insertObject, "rpc_interface")

	interface = getattr(test.test_annotation, "rpc_interface")
	assert interface.name == "test_annotation"
	assert interface.params == ["*param1", "*param2", "*param3"]
	assert interface.args == ["self", "param1", "param2", "param3"]
	assert not interface.varargs
	assert not interface.keywords
	assert interface.defaults == (None, None, None)
	assert interface.annotations == {"param1": "str | None", "param2": "Any | None", "param3": "Any | None"}

	assert test.test_insertObject.__doc__ == DOC_INSERT_OBJECT
	assert test.test2_insertObject.__doc__ == "DOC"
	assert test.test_deprecated.rpc_interface.deprecated  # pylint: disable=no-member
	assert test.test_drop.rpc_interface.deprecated  # pylint: disable=no-member
	assert test.test_drop.rpc_interface.drop_version == "5.0"  # pylint: disable=no-member

	assert test.func1("f1") == "f1"
	assert test.func2("f2") == "f2"
	assert test.func3("f3") == "f3"
	assert test.test_insertObject("test") == "test"
	assert test.test2_insertObject("test") == "test"

	assert test.ace_called == ["func1", "func2_other", "test_insertObject", "test2_insertObject"]
