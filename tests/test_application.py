# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application
"""

import asyncio
import time
from threading import Event, Thread
from typing import Generator

import pytest
from fastapi import status
from fastapi.websockets import WebSocketDisconnect
from msgspec import msgpack

from opsiconfd.application import (
	AppState,
	MaintenanceState,
	NormalState,
	ShutdownState,
	app,
)
from opsiconfd.redis import redis_client

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	clean_redis,
	config,
	test_client,
)


class AppStateReaderThread(Thread):
	def __init__(self, redis_key: str) -> None:
		super().__init__(daemon=True)
		self.redis_key = redis_key
		self.app_states: list[AppState] = []
		self.stop = False

	def run(self) -> None:
		redis = redis_client()
		while not self.stop:
			data = redis.get(self.redis_key)
			if data:
				app_state = AppState.from_dict(msgpack.decode(data))
				if not self.app_states or app_state != self.app_states[-1]:
					self.app_states.append(app_state)
					print("App state changed:", app_state)
			time.sleep(0.01)


@pytest.fixture
def app_state_reader(config: Config) -> Generator[AppStateReaderThread, None, None]:  # noqa: F811
	thread = AppStateReaderThread(f"{config.redis_key('state')}:application:app_state")
	thread.start()
	yield thread
	thread.stop = True
	thread.join()


def test_app_state_maintenance() -> None:
	state = MaintenanceState(retry_after=10, message="test", address_exceptions=["::1", "11.11.11.11", "10.10.0.0/16"])
	assert state.message == "test"
	assert state.retry_after == 10
	assert state.address_exceptions == ["10.10.0.0/16", "11.11.11.11/32", "::1/128"]

	state = MaintenanceState()
	assert state.address_exceptions == ["127.0.0.1/32", "::1/128"]

	state = MaintenanceState(address_exceptions=[])
	assert not state.address_exceptions


def test_app_state_from_dict() -> None:
	state: AppState
	state = ShutdownState()
	assert str(state) == "AppState(shutdown/pending)"
	state_dict = state.to_dict()
	state2 = AppState.from_dict(state_dict)
	assert type(state) is type(state2)

	state = NormalState()
	state_dict = state.to_dict()
	state2 = AppState.from_dict(state_dict)
	assert type(state) is type(state2)

	# type: ignore[assignment]
	state = MaintenanceState(retry_after=60, message="test", address_exceptions=["10.10.10.1/32", "10.10.10.2/32"])
	state_dict = state.to_dict()
	state2 = AppState.from_dict(state_dict)
	assert type(state) is type(state2)
	assert state.retry_after == state2.retry_after  # type: ignore[attr-defined]
	assert state.message == state2.message  # type: ignore[attr-defined]
	assert state.address_exceptions == state2.address_exceptions  # type: ignore[attr-defined]


def test_maintenance(
	test_client: OpsiconfdTestClient,  # noqa: F811
	app_state_reader: AppStateReaderThread,
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	initalized_event = Event()
	thread = Thread(
		target=asyncio.run,
		args=[app.app_state_manager_task(manager_mode=True, init_app_state=NormalState(), initalized_event=initalized_event)],
		daemon=True,
	)
	thread.start()
	try:
		initalized_event.wait(5)

		response = test_client.get("/session/authenticated")
		assert response.status_code == 200
		with test_client.websocket_connect("/messagebus/v1") as websocket:
			assert websocket
			data = websocket.receive()
			assert data["type"] == "websocket.send"
			assert b"channel_subscription_event" in data["bytes"]

		app.set_app_state(MaintenanceState(address_exceptions=[], retry_after=11, message="pytest"))
		time.sleep(1)
		response = test_client.get("/session/authenticated")
		assert response.status_code == 503
		assert response.headers["Retry-After"] == "11"
		assert response.text == "pytest"

		with pytest.raises(WebSocketDisconnect) as excinfo:
			with test_client.websocket_connect("/messagebus/v1") as websocket:
				pass
		assert excinfo.value.code == status.WS_1013_TRY_AGAIN_LATER
		assert excinfo.value.reason == "pytest\nRetry-After: 11"

		app.set_app_state(NormalState())
		time.sleep(1)
		response = test_client.get("/session/authenticated")
		assert response.status_code == 200

		app.set_app_state(MaintenanceState(address_exceptions=[]))
		time.sleep(1)
		response = test_client.get("/session/authenticated")
		assert response.status_code == 503

		app.set_app_state(NormalState())
		time.sleep(1)
		response = test_client.get("/session/authenticated")
		assert response.status_code == 200

		app.set_app_state(MaintenanceState(address_exceptions=["::1/128", "127.0.0.1/32"]))
		time.sleep(1)
		response = test_client.get("/session/authenticated")
		assert response.status_code == 200
	finally:
		app.set_app_state(ShutdownState())
		thread.join(5)
