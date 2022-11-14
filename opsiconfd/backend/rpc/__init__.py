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
from typing import TYPE_CHECKING, Callable, List, Literal, Protocol

if TYPE_CHECKING:
	from ..auth import RPCACE
	from ..mysql import MySQLConnection

IdentType = Literal["unicode", "str", "dict", "hash", "list", "tuple"]


class BackendProtocol(Protocol):  # pylint: disable=too-few-public-methods
	@property
	def _mysql(self) -> MySQLConnection:
		...

	def _get_ace(self, method: str) -> List[RPCACE]:
		...


def rpc_method(func: Callable) -> Callable:
	setattr(func, "rpc_method", True)
	return func


def deprecated(func: Callable = None, *, alternative_method: Callable = None) -> Callable:
	if func is None:
		return partial(deprecated, alternative_method=alternative_method)

	setattr(func, "deprecated", True)
	setattr(func, "alternative_method", alternative_method)
	return func
