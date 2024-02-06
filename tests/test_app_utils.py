# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application utils
"""

from typing import Any

import pytest

from opsiconfd.application.utils import (
	bool_product_property,
	merge_dicts,
	parse_list,
	unicode_product_property,
)


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
def test_parse_list(data: Any, output: Any) -> None:
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
		({"a": [1, 2, 3], "b": [1]}, {"b": [2]}, None, {"a": [1, 2, 3], "b": [1, 2]}),  # key a not in dict b
		(
			{
				"a": [1, 2, 3],
			},
			{"a": [1, 2, 3], "b": [2]},
			None,
			{"a": [1, 2, 3], "b": [2]},
		),  # key b not in dict a
		(
			{
				"a": [1, 2, 3],
			},
			{"b": [2]},
			None,
			{"a": [1, 2, 3], "b": [2]},
		),  # key b not in dict a and key a not in dict b
	],
)
def test_merge_dicts(dict_a: dict, dict_b: dict, path: list[str] | None, output: dict) -> None:
	assert merge_dicts(dict_a, dict_b, path) == output


@pytest.mark.parametrize(
	"dict_a, dict_b, path, output",
	[(None, None, None, None), ("", "", None, None)],
)
def test_merge_dicts_value_error(dict_a: dict, dict_b: dict, path: list[str] | None, output: dict) -> None:
	with pytest.raises(ValueError):
		assert merge_dicts(dict_a, dict_b, path) == output


@pytest.mark.parametrize(
	"dict_a, dict_b, path, output",
	[
		({"a": [1]}, {"a": {"test": 1}}, None, None),
		(
			{"a": {"test": {"end": "hallo"}}, "b": {"test": [1, 2, 4]}},
			{"a": {"test": {"end": "welt"}}, "b": {"test": [3, 4, 5]}},
			None,
			None,
		),  # confict in test dict
	],
)
def test_merge_dicts_conflict(dict_a: dict, dict_b: dict, path: list[str] | None, output: dict) -> None:
	with pytest.raises(Exception):
		assert merge_dicts(dict_a, dict_b, path) == output


@pytest.mark.parametrize(
	"data, output",
	[
		(None, [""]),
		("", [""]),
		("Hello World", ["Hello World"]),
		("[]", [""]),
		('["test", "value", "Hello World"]', ["test", "value", "Hello World"]),
	],
)
def test_unicode_product_property(data: Any, output: Any) -> None:
	assert unicode_product_property(data) == output


@pytest.mark.parametrize(
	"data, output",
	[
		(None, False),
		("", False),
		("False", False),
		("[False]", False),
		("[FALSE]", False),
		("[false]", False),
		("Hello", False),
		("True", True),
		("true", True),
		("[true]", True),
		("[True]", True),
		("[TRUE]", True),
	],
)
def test_bool_product_property(data: Any, output: Any) -> None:
	assert bool_product_property(data) == output
