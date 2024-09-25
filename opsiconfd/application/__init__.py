# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
The opsi configuration service.
"""

from __future__ import annotations

import asyncio
import threading
import time
from contextlib import asynccontextmanager, nullcontext
from dataclasses import asdict, dataclass, field
from ipaddress import ip_network
from threading import Event
from typing import Any, AsyncGenerator, Callable, Type, TypeVar

from fastapi import FastAPI
from msgspec import msgpack
from opsicommon import __version__ as python_opsi_common_version
from opsicommon.messagebus.message import EventMessage
from starlette._utils import is_async_callable
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp

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


@asynccontextmanager
async def lifespan(opsiconfd_app: OpsiconfdApp) -> AsyncGenerator[None, None]:
	from opsiconfd.application.main import (
		application_shutdown,
		application_startup,
		async_application_shutdown,
		async_application_startup,
	)

	try:
		asyncio_create_task(opsiconfd_app.app_state_manager_task(manager_mode=False))
		await run_in_threadpool(application_startup)
		await async_application_startup()
	except Exception as error:
		logger.critical("Error during application startup: %s", error, exc_info=True)
		raise error
	yield
	logger.info("Processing shutdown event")
	try:
		await run_in_threadpool(application_shutdown)
		await async_application_shutdown()
	except Exception as error:
		logger.critical("Error during application shutdown: %s", error, exc_info=True)
	opsiconfd_app.set_app_state(ShutdownState(), wait_accomplished=None)


class OpsiconfdApp(FastAPI):
	app_state_redis_key = f"{config.redis_key('state')}:application:app_state"

	def __init__(self) -> None:
		super().__init__(
			title="opsiconfd",
			description="",
			lifespan=lifespan,
			version=f"{__version__} [python-opsi-common={python_opsi_common_version}]",
			responses={422: {"model": RestApiValidationError, "description": "Validation Error"}},
		)
		self._app_state_handler: set[Callable] = set()
		self._app_state: AppState = StartupState()
		self._manager_task_should_stop = False
		self._manager_task_stopped = threading.Event()
		self.application_setup_done = False

	@property
	def app_state(self) -> AppState:
		return self._app_state

	def build_middleware_stack(self) -> ASGIApp:
		from opsiconfd.application.main import setup_app

		setup_app()

		stack = super().build_middleware_stack()
		return stack

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
			msgpack_data = await redis.get(self.app_state_redis_key)
			if not msgpack_data:
				return None

			try:
				app_state = AppState.from_dict(msgpack.decode(msgpack_data))
				if update_accomplished and not app_state.accomplished:
					accomplished = True
					async for redis_key_b in redis.scan_iter(f"{config.redis_key('state')}:workers:*", count=1000):
						if (await redis.hget(redis_key_b, "app_state")) != app_state.type.encode("utf-8"):
							accomplished = False
							break
					if accomplished:
						app_state.accomplished = accomplished
						await self.async_store_app_state_in_redis(app_state)
				return app_state
			except Exception as err:
				logger.error(err, exc_info=True)
		return None

	async def async_store_app_state_in_redis(self, app_state: AppState) -> None:
		redis = await async_redis_client()
		state_dict = app_state.to_dict()
		logger.debug("Store app state: %s", state_dict)
		await redis.set(self.app_state_redis_key, msgpack.encode(state_dict))

	def store_app_state_in_redis(self, app_state: AppState) -> None:
		state_dict = app_state.to_dict()
		logger.debug("Store app state: %s", state_dict)
		redis_client().set(self.app_state_redis_key, msgpack.encode(state_dict))

	async def send_app_state_changed_event(self, old_state: AppState, state: AppState) -> None:
		from opsiconfd.messagebus import (
			get_user_id_for_service_node,
		)
		from opsiconfd.messagebus.redis import (
			send_message,
		)

		event = EventMessage(
			sender=get_user_id_for_service_node(config.node_name),
			channel="event:app_state_changed",
			event="app_state_changed",
			data={"old_state": old_state.to_dict(), "state": state.to_dict()},
		)
		await send_message(event)

	def stop_app_state_manager_task(self, wait: bool = False) -> None:
		self._manager_task_should_stop = True
		if wait:
			self._manager_task_stopped.wait(5.0)

	async def app_state_manager_task(
		self,
		manager_mode: bool = False,
		init_app_state: AppState | tuple[AppState, ...] | None = None,
		initalized_event: Event | None = None,
	) -> None:
		"""
		init_app_state: If the current app state is not in the list of init app states, the first init app state will be set.
		"""
		self._manager_task_stopped.clear()
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

		interval = 3
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
					await self.send_app_state_changed_event(old_state=cur_state, state=self._app_state)

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

		self._manager_task_stopped.set()


app = OpsiconfdApp()
