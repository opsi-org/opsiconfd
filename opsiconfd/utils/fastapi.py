# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

from collections.abc import Iterator
from typing import Any

from fastapi import APIRouter, FastAPI
from starlette.routing import BaseRoute


def iter_routes(router: APIRouter | FastAPI, prefix: str = "") -> Iterator[tuple[str, BaseRoute]]:
	"""Iterate over routes in a FastAPI router tree with their effective paths."""
	for route in router.routes:
		original_router = getattr(route, "original_router", None)
		include_context = getattr(route, "include_context", None)
		if isinstance(original_router, APIRouter) and include_context is not None:
			yield from iter_routes(original_router, f"{prefix}{include_context.prefix}")
			continue
		route_path = getattr(route, "path", None)
		if route_path is not None:
			yield f"{prefix}{route_path}", route


def _mark_routes_changed(router: APIRouter | FastAPI) -> None:
	"""Invalidate FastAPI's effective-route cache after direct route removal."""
	mark_routes_changed = getattr(router, "_mark_routes_changed", None)
	if mark_routes_changed:
		mark_routes_changed()


def _remove_route_path(router: APIRouter | FastAPI, path: str, prefix: str = "") -> bool:
	"""Remove matching routes recursively from a FastAPI router tree."""
	changed = False
	path_lower = path.lower()
	for route in list(router.routes):
		original_router: Any = getattr(route, "original_router", None)
		include_context: Any = getattr(route, "include_context", None)
		if isinstance(original_router, APIRouter) and include_context is not None:
			effective_prefix = f"{prefix}{include_context.prefix}"
			if effective_prefix.lower().startswith(path_lower):
				router.routes.remove(route)
				changed = True
			elif _remove_route_path(original_router, path, effective_prefix):
				changed = True
			continue
		route_path = getattr(route, "path", None)
		if route_path is not None and f"{prefix}{route_path}".lower().startswith(path_lower):
			router.routes.remove(route)
			changed = True
	if changed:
		_mark_routes_changed(router)
	return changed


def remove_router(app: FastAPI, router: APIRouter, router_prefix: str) -> None:
	"""Remove an included router from an application."""
	for route in list(app.routes):
		include_context = getattr(route, "include_context", None)
		if getattr(route, "original_router", None) is router and getattr(include_context, "prefix", None) == router_prefix:
			app.routes.remove(route)
			_mark_routes_changed(app.router)
			return
	_remove_route_path(app.router, router_prefix)


def remove_route_path(app: FastAPI, path: str) -> None:
	"""Remove all application routes starting with the specified path."""
	_remove_route_path(app.router, path)
