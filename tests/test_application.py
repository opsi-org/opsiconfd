# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application
"""

import time

from opsiconfd.application import AppState, MaintenanceState, NormalState, app

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_redis,
	test_client,
)


def test_app_state_maintenance() -> None:
	state = MaintenanceState(retry_after=10, message="test", address_exceptions=["::1", "11.11.11.11", "10.10.0.0/16"])
	assert state.message == "test"
	assert state.retry_after == 10
	assert state.address_exceptions == ["::1/128", "11.11.11.11/32", "10.10.0.0/16"]

	state = MaintenanceState()
	assert state.address_exceptions == ["::1/128", "127.0.0.1/32"]

	state = MaintenanceState(address_exceptions=[])
	assert not state.address_exceptions


def test_app_state_from_dict() -> None:
	state = NormalState()
	state_dict = state.to_dict()
	state2 = AppState.from_dict(state_dict)
	assert type(state) is type(state2)

	state = MaintenanceState(retry_after=60, message="test", address_exceptions=["10.10.10.1/32", "10.10.10.2/32"])  # type: ignore[assignment]
	state_dict = state.to_dict()
	state2 = AppState.from_dict(state_dict)
	assert type(state) is type(state2)
	assert state.retry_after == state2.retry_after  # type: ignore[attr-defined]
	assert state.message == state2.message  # type: ignore[attr-defined]
	assert state.address_exceptions == state2.address_exceptions  # type: ignore[attr-defined]


def test_maintenance(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	with test_client as client:
		response = client.get("/session/authenticated")
		assert response.status_code == 200

		app.app_state = MaintenanceState(address_exceptions=[], retry_after=11, message="pytest")
		time.sleep(1)
		response = client.get("/session/authenticated")
		assert response.status_code == 503
		assert response.headers["Retry-After"] == "11"
		assert response.text == "pytest"

		app.app_state = NormalState()
		time.sleep(1)
		response = client.get("/session/authenticated")
		assert response.status_code == 200

		app.app_state = MaintenanceState(address_exceptions=[])
		time.sleep(1)
		response = client.get("/session/authenticated")
		assert response.status_code == 503

		app.app_state = NormalState()
		time.sleep(1)
		response = client.get("/session/authenticated")
		assert response.status_code == 200

		app.app_state = MaintenanceState(address_exceptions=["::1/128", "127.0.0.1/32"])
		time.sleep(1)
		response = client.get("/session/authenticated")
		assert response.status_code == 200
