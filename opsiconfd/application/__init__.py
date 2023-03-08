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
import time
from contextlib import nullcontext
from dataclasses import asdict, dataclass, field
from ipaddress import ip_network
from threading import Event
from typing import Any, Callable, Type, TypeVar

from fastapi import FastAPI
from msgspec import msgpack
from opsicommon import __version__ as python_opsi_common_version  # type: ignore[import]
from opsicommon.messagebus import EventMessage
from starlette._utils import is_async_callable
from starlette.concurrency import run_in_threadpool

from opsiconfd import __version__
from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.redis import (
	async_redis_client,
	async_redis_lock,
	redis_client,
	redis_lock,
)
from opsiconfd.rest import RestApiValidationError
from opsiconfd.utils import asyncio_create_task

AppStateT = TypeVar("AppStateT", bound="AppState")


@dataclass(slots=True, kw_only=True, repr=False)
class AppState:
	accomplished: bool = False

	@property
	def type(self) -> str:
		return ""

	def to_dict(self) -> dict[str, Any]:
		_dict = asdict(self)
		_dict["type"] = self.type
		return _dict

	def __repr__(self) -> str:
		return f"AppState({self.type}/{'accomplished' if self.accomplished else 'pending'})"

	__str__ = __repr__

	@classmethod
	def from_dict(cls: Type[AppStateT], data: dict[str, Any]) -> AppStateT:
		_cls = cls
		_type = data.pop("type", None)
		if _cls is AppState:
			if _type == "startup":
				_cls = StartupState  # type: ignore[assignment]
			elif _type == "normal":
				_cls = NormalState  # type: ignore[assignment]
			elif _type == "maintenance":
				_cls = MaintenanceState  # type: ignore[assignment]
			elif _type == "shutdown":
				_cls = ShutdownState  # type: ignore[assignment]
			else:
				raise ValueError(f"Invalid AppState type {_type!r}")
		return _cls(**data)


@dataclass(slots=True, kw_only=True)
class StartupState(AppState):
	@property
	def type(self) -> str:
		return "startup"


@dataclass(slots=True, kw_only=True)
class NormalState(AppState):
	@property
	def type(self) -> str:
		return "normal"


@dataclass(slots=True, kw_only=True)
class ShutdownState(AppState):
	@property
	def type(self) -> str:
		return "shutdown"


@dataclass(slots=True, kw_only=True)
class MaintenanceState(AppState):
	retry_after: int = 600
	message: str = "Maintenance mode, please try again later"
	address_exceptions: list[str] = field(default_factory=lambda: ["::1/128", "127.0.0.1/32"])

	@property
	def type(self) -> str:
		return "maintenance"

	def __post_init__(self) -> None:
		self.retry_after = int(self.retry_after)
		self.address_exceptions = self.address_exceptions or []
		for idx, address_exception in enumerate(self.address_exceptions):
			self.address_exceptions[idx] = ip_network(address_exception).compressed
		self.address_exceptions = sorted(list(set(self.address_exceptions)))


class OpsiconfdApp(FastAPI):
	def __init__(self) -> None:
		super().__init__(
			title="opsiconfd",
			description="",
			version=f"{__version__} [python-opsi-common={python_opsi_common_version}]",
			responses={422: {"model": RestApiValidationError, "description": "Validation Error"}},
		)
		self._app_state_handler: set[Callable] = set()
		self._app_state: AppState = StartupState()
		self._manager_task_should_stop = False
		self.application_setup_done = False

	@property
	def app_state(self) -> AppState:
		return self._app_state

	def register_app_state_handler(self, handler: Callable) -> None:
		self._app_state_handler.add(handler)

	def wait_for_app_state(self, app_state: AppState, timeout: float = 0.0) -> None:
		start = time.time()
		while True:
			if self._app_state.type == app_state.type and self._app_state.accomplished:
				return
			wait_time = time.time() - start
			if wait_time >= timeout:
				raise TimeoutError(
					f"Timed out after {wait_time:0.2f} seconds while waiting for app state {app_state.type!r} to be accomplished"
				)
			time.sleep(1)

	def set_app_state(self, app_state: AppState, wait_accomplished: float | None = 30.0) -> None:
		app_state.accomplished = False
		with redis_lock("app-state", acquire_timeout=2.0, lock_timeout=10.0):
			self.store_app_state_in_redis(app_state)
		if wait_accomplished is not None and wait_accomplished > 0:
			self.wait_for_app_state(app_state, wait_accomplished)

	async def load_app_state_from_redis(self, update_accomplished: bool = False) -> AppState | None:
		redis = await async_redis_client()
		async with async_redis_lock("app-state", acquire_timeout=2.0, lock_timeout=10.0) if update_accomplished else nullcontext():
			msgpack_data = await redis.get(f"{config.redis_key('state')}:application:app_state")
			if not msgpack_data:
				return None

			try:
				app_state = AppState.from_dict(msgpack.decode(msgpack_data))
				if update_accomplished and not app_state.accomplished:
					accomplished = True
					async for redis_key_b in redis.scan_iter(f"{config.redis_key('state')}:workers:*"):
						if (await redis.hget(redis_key_b, "app_state")) != app_state.type.encode("utf-8"):
							accomplished = False
							break
					if accomplished:
						app_state.accomplished = accomplished
						await self.async_store_app_state_in_redis(app_state)
				return app_state
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
		return None

	async def async_store_app_state_in_redis(self, app_state: AppState) -> None:
		redis = await async_redis_client()
		state_dict = app_state.to_dict()
		logger.debug("Store app state: %s", state_dict)
		await redis.set(f"{config.redis_key('state')}:application:app_state", msgpack.encode(state_dict))

	def store_app_state_in_redis(self, app_state: AppState) -> None:
		state_dict = app_state.to_dict()
		logger.debug("Store app state: %s", state_dict)
		with redis_client() as redis:
			redis.set(f"{config.redis_key('state')}:application:app_state", msgpack.encode(state_dict))

	async def send_app_state_changed_event(self, prev_state: AppState, state: AppState) -> None:
		from opsiconfd.messagebus import (  # pylint: disable=import-outside-toplevel
			get_user_id_for_service_node,
		)
		from opsiconfd.messagebus.redis import (  # pylint: disable=import-outside-toplevel
			send_message,
		)

		event = EventMessage(
			sender=get_user_id_for_service_node(config.node_name),
			channel="event:app_state_changed",
			event="app_state_changed",
			data={"prev_state": prev_state.to_dict(), "state": state.to_dict()},
		)
		await send_message(event)

	def stop_app_state_manager_task(self) -> None:
		self._manager_task_should_stop = True

	async def app_state_manager_task(  # pylint: disable=too-many-branches
		self,
		manager_mode: bool = False,
		init_app_state: AppState | tuple[AppState, ...] | None = None,
		initalized_event: Event | None = None,
	) -> None:
		"""
		init_app_state: If the current app state is not in the list of init app states, the first init app state will be set.
		"""
		self._manager_task_should_stop = False

		if manager_mode and init_app_state:
			async with async_redis_lock("app-state", acquire_timeout=2.0, lock_timeout=10.0):
				app_state = await self.load_app_state_from_redis(update_accomplished=False)
				if not isinstance(init_app_state, tuple):
					init_app_state = (init_app_state,)
				if not app_state or app_state.type not in [a.type for a in init_app_state]:
					app_state = init_app_state[0]
					await self.async_store_app_state_in_redis(app_state)  # type: ignore[arg-type]
				if app_state:
					self._app_state = app_state

		interval = 1
		while not self._manager_task_should_stop:
			cur_state = self._app_state
			app_state = await self.load_app_state_from_redis(update_accomplished=manager_mode)
			if app_state:
				if initalized_event:
					initalized_event.set()
				self._app_state = app_state

			if cur_state != self._app_state:
				logger.info("App state is now: %r", self._app_state)

				if manager_mode:
					await self.send_app_state_changed_event(prev_state=cur_state, state=self._app_state)

				cur_state = self._app_state

				for handler in self._app_state_handler:
					logger.debug("Calling app state handler: %s", handler)
					if is_async_callable(handler):
						await handler(self._app_state)
					else:
						await run_in_threadpool(handler, self._app_state)

			if self._app_state == ShutdownState(accomplished=True):
				self._manager_task_should_stop = True

			await asyncio.sleep(interval)


app = OpsiconfdApp()


@app.on_event("startup")
async def startup() -> None:
	"""This will be run in worker processes"""
	asyncio_create_task(app.app_state_manager_task(manager_mode=False))
	from . import main  # pylint: disable=import-outside-toplevel,unused-import


@app.on_event("shutdown")
async def shutdown() -> None:
	app.set_app_state(ShutdownState(), wait_accomplished=None)
