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

from .utils import TestClass


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
