# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
Test opsiconfd.patch
"""

from opsiconfd.patch import apply_patches, assert_function_unchanged


def test_apply_patches() -> None:
	apply_patches()


def test_assert_function_unchanged() -> None:
	assert_function_unchanged(
		assert_function_unchanged,
		"bfab5c2cf7f18d01ce10b447c4f477e55a379a24a57eda3507d87691f52afbff0a392a9cfe3a0aa2011f15f69b238eeb6c694cd916e71322e62fe272826b8b1c",
	)
