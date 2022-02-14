# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application utils
"""

import pytest

from opsiconfd.application.utils import parse_list, merge_dicts


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


@pytest.mark.parametrize(
	"dict_a, dict_b, path, output",
	[
		({"a": [1]}, {"a": [2, 3]}, None, {"a": [1, 2, 3]}),  # merge lists
		({"a": [1, 2, 4]}, {"a": [2, 3, 5]}, None, {"a": [1, 2, 3, 4, 5]}),  # merge lists no duplicats
		(
			{"a": {"test": 1}, "b": {"test": 2}},
			{"a": {"test": 1}, "b": {"test": 2}},
			None,
			{"a": {"test": 1}, "b": {"test": 2}},
		),  # identical
		(
			{"a": {"test": [1, 3, 5]}, "b": {"test": [1, 2, 4]}},
			{"a": {"test": [2, 4]}, "b": {"test": [3, 4, 5]}},
			None,
			{"a": {"test": [1, 2, 3, 4, 5]}, "b": {"test": [1, 2, 3, 4, 5]}},
		),  # dict in dict
		(
			{"a": {"test": {"end": "hallo"}}, "b": {"test": [1, 2, 4]}},
			{"a": {"test": {"end": "hallo"}}, "b": {"test": [3, 4, 5]}},
			None,
			{"a": {"test": {"end": "hallo"}}, "b": {"test": [1, 2, 3, 4, 5]}},
		),  # dict in dict with identical string and merged list
	],
)
def test_merge_dicts(dict_a, dict_b, path, output):

	assert merge_dicts(dict_a, dict_b, path) == output


@pytest.mark.parametrize(
	"dict_a, dict_b, path, output",
	[(None, None, None, None), ("", "", None, None)],
)
def test_merge_dicts_value_error(dict_a, dict_b, path, output):

	with pytest.raises(ValueError):
		assert merge_dicts(dict_a, dict_b, path) == output


@pytest.mark.parametrize(
	"dict_a, dict_b, path, output",
	[
		({"a": [1]}, {"a": {"test": 1}}, None, None),
		(
			{"a": {"test": {"end": "hallo"}}, "b": {"test": [1, 2, 4]}},
			{"a": {"test": {"end": "hallo"}}, "b": {"test": [3, 4, 5]}},
			None,
			{"a": {"test": {"end": "welt"}}, "b": {"test": [1, 2, 3, 4, 5]}},
		),  # confict in test dict
	],
)
def test_merge_dicts_conflict(dict_a, dict_b, path, output):

	with pytest.raises(Exception):
		assert merge_dicts(dict_a, dict_b, path) == output
