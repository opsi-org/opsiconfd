# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.patch
"""

import inspect
from hashlib import sha512
from typing import Callable


def assert_function_unchanged(function_to_patch: Callable, function_hash: str) -> None:
	source = inspect.getsource(function_to_patch)
	source_hash = sha512(source.encode("utf-8")).hexdigest()
	if source_hash != function_hash:
		# logger.debug(source)
		raise ValueError(f"Function to patch '{function_to_patch}' has changed, expected '{function_hash}', got '{source_hash}'")


def apply_patches() -> None:
	pass
