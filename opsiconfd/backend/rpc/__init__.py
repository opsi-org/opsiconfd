# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
backend.rpc
"""

from __future__ import annotations

from functools import partial
from typing import Callable


def rpc_method(func: Callable) -> Callable:
	setattr(func, "rpc_method", True)
	return func


def deprecated_rpc_method(func: Callable = None, *, alternative_method: str = None) -> Callable:
	if func is None:
		return partial(deprecated, alternative_method=alternative_method)

	setattr(func, "rpc_method", True)
	setattr(func, "deprecated", True)
	setattr(func, "alternative_method", alternative_method)
	return func


deprecated = deprecated_rpc_method
