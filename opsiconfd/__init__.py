# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
The opsi configuration service.
"""

__version__ = "4.3.0.1"

from contextvars import Context, ContextVar
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
	# Prevent circular import error
	from .session import OPSISession, UserStore

contextvar_request_id: ContextVar[Optional[int]] = ContextVar("request_id", default=None)
contextvar_client_session: ContextVar[Optional["OPSISession"]] = ContextVar("client_session", default=None)
contextvar_user_store: ContextVar[Optional["UserStore"]] = ContextVar("user_store", default=None)
contextvar_client_address: ContextVar[Optional[str]] = ContextVar("client_address", default=None)
contextvar_server_timing: ContextVar[Dict[str, float]] = ContextVar("server_timing", default={})


def get_contextvars() -> Dict[str, Any]:
	return {
		var.name: var.get()  # type: ignore[attr-defined]
		for var in (
			contextvar_request_id,
			contextvar_client_session,
			contextvar_user_store,
			contextvar_client_address,
			contextvar_server_timing,
		)
	}


def set_contextvars(values: Dict[str, Any]) -> None:
	for var, val in values.items():
		try:  # pylint: disable=loop-try-except-usage
			globals()[f"contextvar_{var}"].set(val)
		except KeyError:
			pass


def set_contextvars_from_contex(context: Context) -> None:
	set_contextvars({var.name: val for var, val in context.items()})
