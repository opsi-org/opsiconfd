# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
The opsi configuration service.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from ipaddress import ip_network
from typing import Any, Callable, Type, TypeVar

from fastapi import FastAPI
from msgspec import msgpack
from OPSI import __version__ as python_opsi_version  # type: ignore[import]
from starlette._utils import is_async_callable
from starlette.concurrency import run_in_threadpool

from .. import __version__
from ..config import config
from ..logging import logger
from ..rest import RestApiValidationError
from ..utils import async_redis_client, redis_client

AppStateT = TypeVar('AppStateT', bound='AppState')


@dataclass(slots=True, kw_only=True, repr=False)
class AppState:
	@property
	def type(self) -> str:
		return ""

	def to_dict(self) -> dict[str, Any]:
		_dict = asdict(self)
		_dict["type"] = self.type
		return _dict

	def __repr__(self) -> str:
		return f"AppState({self.type})"

	__str__ = __repr__

	@classmethod
	def from_dict(cls: Type[AppStateT], data: dict[str, Any]) -> AppStateT:
		_cls = cls
		_type = data.pop("type", None)
		if _cls is AppState:
			if _type == "normal":
				_cls = NormalState  # type: ignore[assignment]
			elif _type == "maintenance":
				_cls = MaintenanceState  # type: ignore[assignment]
		return _cls(**data)


@dataclass(slots=True, kw_only=True)
class NormalState(AppState):
	@property
	def type(self) -> str:
		return "normal"


@dataclass(slots=True, kw_only=True)
class MaintenanceState(AppState):
	retry_after: int = 500
	message: str = "Maintenance mode, please try again later"
	address_exceptions: list[str] = field(default_factory=lambda: ["::1/128", "127.0.0.1/32"])

	@property
	def type(self) -> str:
		return "maintenance"

	def __post_init__(self) -> None:
		self.address_exceptions = self.address_exceptions or []
		for idx, address_exception in enumerate(self.address_exceptions):
			self.address_exceptions[idx] = ip_network(address_exception).compressed
		self.address_exceptions = list(set(self.address_exceptions))


@dataclass(slots=True, kw_only=True)
class ShutdownState(AppState):
	@property
	def type(self) -> str:
		return "shutdown"


class OpsiconfdApp(FastAPI):
	def __init__(self) -> None:
		super().__init__(
			title="opsiconfd",
			description="",
			version=f"{__version__} [python-opsi={python_opsi_version}]",
			responses={422: {"model": RestApiValidationError, "description": "Validation Error"}},
		)
		self._app_state_handler: set[Callable] = set()
		self.app_state: AppState = NormalState()
		if config.maintenance is not False:
			self.app_state = MaintenanceState(address_exceptions=config.maintenance + ["127.0.0.1/32", "::1/128"])

	def register_app_state_handler(self, handler: Callable) -> None:
		self._app_state_handler.add(handler)

	async def load_app_state_from_redis(self) -> None:
		redis = await async_redis_client()
		msgpack_data = await redis.get(f"{config.redis_key('status')}:application:app_state")
		if not msgpack_data:
			return

		try:
			self.app_state = AppState.from_dict(msgpack.decode(msgpack_data))
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)

	async def store_app_state_in_redis(self) -> None:
		redis = await async_redis_client()
		await redis.set(f"{config.redis_key('status')}:application:app_state", msgpack.encode(self.app_state.to_dict()))

	async def app_state_manager_task(self) -> None:
		cur_state = AppState()
		while not self.app_state.type == "shutdown":
			if cur_state != self.app_state:
				await self.store_app_state_in_redis()
			else:
				await self.load_app_state_from_redis()

			changed = cur_state != self.app_state
			if changed:
				cur_state = self.app_state
				logger.info("App state is now: %r", self.app_state)
				for handler in self._app_state_handler:
					logger.debug("Calling app state handler: %s", handler)
					if is_async_callable(handler):
						await handler(self.app_state)
					else:
						await run_in_threadpool(handler, self.app_state)

			await asyncio.sleep(1)  # pylint: disable=dotted-import-in-loop


app = OpsiconfdApp()


@app.on_event("startup")
async def startup() -> None:
	asyncio.create_task(app.app_state_manager_task())
	from . import main  # pylint: disable=import-outside-toplevel,unused-import


@app.on_event("shutdown")
async def shutdown() -> None:
	app.app_state = ShutdownState()
