# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
The opsi configuration service.
"""

from __future__ import annotations

__version__ = "4.3.17.7"


from contextlib import contextmanager
from contextvars import Context, ContextVar
from time import perf_counter
from typing import TYPE_CHECKING, Any, Dict, Generator, Optional

if TYPE_CHECKING:
	from opsiconfd.session import OPSISession

contextvar_request_id: ContextVar[Optional[int]] = ContextVar("request_id", default=None)
contextvar_client_session: ContextVar[Optional[OPSISession]] = ContextVar("client_session", default=None)
contextvar_client_address: ContextVar[Optional[str]] = ContextVar("client_address", default=None)
contextvar_server_timing: ContextVar[Dict[str, float]] = ContextVar("server_timing", default={})


def get_contextvars() -> Dict[str, Any]:
	return {
		var.name: var.get()  # type: ignore[attr-defined]
		for var in (
			contextvar_request_id,
			contextvar_client_session,
			contextvar_client_address,
			contextvar_server_timing,
		)
	}


def set_contextvars(values: Dict[str, Any]) -> None:
	for var, val in values.items():
		try:
			globals()[f"contextvar_{var}"].set(val)
		except KeyError:
			pass


def set_contextvars_from_contex(context: Context) -> None:
	set_contextvars({var.name: val for var, val in context.items()})


@contextmanager
def server_timing(timing_name: str) -> Generator[dict[str, float], None, None]:
	val = contextvar_server_timing.get() or {}
	val[timing_name] = 0.0
	start = perf_counter()
	yield val
	end = perf_counter()
	val[timing_name] += (end - start) * 1000
	contextvar_server_timing.set(val)
