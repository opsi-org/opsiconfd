# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
backend.rpc
"""

from typing import Callable


def rpc_method(func: Callable) -> Callable:
	setattr(func, "rpc_method", True)
	return func
