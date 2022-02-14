# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application utils
"""

import pytest

from opsiconfd.application.utils import parse_list


@pytest.mark.parametrize(
	"data, output",
	[
		(None, None),
		(["one", "two", "three"], ["one", "two", "three"]),
		("one", "one"),
		(["[one,two,three]"], ["one", "two", "three"]),
		(['["one","two","three"]'], ["one", "two", "three"]),
		(["one"], ["one"]),
	],
)
def test_parse_list(data, output):

	print(data)
	print(output)
	assert parse_list(data) == output
