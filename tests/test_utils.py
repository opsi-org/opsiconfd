# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test utils
"""

import pytest

from opsiconfd.utils import is_json_serializable


class TestClass:  # pylint: disable=too-few-public-methods
	member1: int
	member2: str

	def __init__(self, integer, string):
		self.member1 = integer
		self.member2 = string

	def print(self):
		print("m1:", self.member1, "m2", self.member2)


@pytest.mark.parametrize(
	"data, output",
	[
		(None, True),
		(["one", "two", "three"], True),
		("one", True),
		(1, True),
		({}, True),
		({"one": 1}, True),
		(TestClass(1, "one"), False),
		(Exception, False),
	],
)
def test_is_json_serializable(data, output):
	assert is_json_serializable(data) == output
