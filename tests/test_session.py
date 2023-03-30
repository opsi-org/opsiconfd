# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
session tests
"""

import uuid
from asyncio import sleep

import pytest
from starlette.datastructures import Headers

from opsiconfd.session import OPSISession, SessionManager
from opsiconfd.utils import utc_time_timestamp

from .utils import (  # pylint: disable=unused-import
	async_redis_client,
	clean_redis,
	get_config,
)


def test_session_serialize() -> None:
	client_addr = "172.10.11.12"
	session = OPSISession(client_addr=client_addr)
	data = session.serialize()
	session2 = OPSISession.from_serialized(data)
	assert session.serialize() == session2.serialize()


@pytest.mark.asyncio
async def test_session_manager_max_age() -> None:
	with get_config({"session_lifetime": 10}):
		manager = SessionManager()
		headers = Headers()
		sess = await manager.get_session("172.10.11.12", headers=headers)
		assert sess.max_age == 10

		await sess.store()
		await sess.load()
		assert sess.max_age == 10

		headers = Headers({"x-opsi-session-lifetime": "5"})
		sess = await manager.get_session("172.10.11.12", headers=headers)
		assert sess.max_age == 5

		await sess.store()
		await sess.load()
		assert sess.max_age == 5

		await sess.update_messagebus_last_used()
		assert sess.max_age == 2147483648

		await sess.store()
		await sess.load()
		assert sess.max_age == 2147483648

		sess._messagebus_last_used = int(utc_time_timestamp()) - 60  # pylint: disable=protected-access
		assert sess.max_age == 5

		await manager.stop(wait=True)


@pytest.mark.asyncio
async def test_session_load_if_needed() -> None:
	async with async_redis_client() as redis_client:
		manager = SessionManager()
		sess = await manager.get_session("172.10.11.12")
		sess.username = "testuser"
		await sess.store()
		assert sess.version
		res = await redis_client.hgetall(sess.redis_key)
		assert res[b"version"] == sess.version.encode("utf-8")

		# Change an attribute to see if session is loaded
		await redis_client.hset(sess.redis_key, "username", "changed-in-redis")

		# Should return True, but session should not be loaded from redis (username unchanged)
		assert await sess.load_if_needed()
		assert sess.username == "testuser"

		await redis_client.hset(sess.redis_key, "version", str(uuid.uuid4()))
		# Should return True, and session should not be loaded from redis
		assert await sess.load_if_needed()
		assert sess.username == "changed-in-redis"

		# Change an attribute to see if session is loaded
		await redis_client.hset(sess.redis_key, "username", "changed-in-redis-again")
		# Should return True, but session should not be loaded from redis (username unchanged)
		assert await sess.load_if_needed()
		assert sess.username == "changed-in-redis"

		# Now delete session in redis
		await redis_client.delete(sess.redis_key)
		# Should return False, session not loaded
		assert not await sess.load_if_needed()

		await manager.stop(wait=True)


@pytest.mark.asyncio
async def test_session_manager_store_session() -> None:
	async with async_redis_client() as redis_client:
		manager = SessionManager()
		manager._session_store_interval = 60  # pylint: disable=protected-access
		sess1 = await manager.get_session("172.10.11.11")
		await sleep(2)
		res = await redis_client.hgetall(sess1.redis_key)
		sess1.authenticated = True
		await sleep(2)
		res = await redis_client.hgetall(sess1.redis_key)
		assert res

		manager._session_store_interval = 1  # pylint: disable=protected-access
		sess2 = await manager.get_session("172.10.11.12")
		res = await redis_client.hgetall(sess2.redis_key)
		assert not res
		await sleep(2)
		res = await redis_client.hgetall(sess2.redis_key)
		assert res

		await manager.stop(wait=True)


@pytest.mark.asyncio
async def test_session_manager_remove_expired_session() -> None:
	async with async_redis_client() as redis_client:
		manager = SessionManager()
		headers = Headers({"x-opsi-session-lifetime": "5"})
		sess = await manager.get_session("172.10.11.12", headers=headers)
		sess.authenticated = True
		await sleep(1)
		assert sess.session_id in manager.sessions
		res = await redis_client.hgetall(sess.redis_key)
		assert res
		await sleep(5)
		assert sess.session_id not in manager.sessions
		res = await redis_client.hgetall(sess.redis_key)
		assert not res
		await manager.stop(wait=True)


@pytest.mark.asyncio
async def test_session_manager_changed_client_addr() -> None:
	manager = SessionManager()
	sess1 = await manager.get_session("172.10.11.12")
	assert sess1
	sess2 = await manager.get_session("172.10.11.13", session_id=sess1.session_id)
	assert sess2
	assert sess1.session_id != sess2.session_id
	await manager.stop(wait=True)


@pytest.mark.asyncio
async def test_session_manager_concurrent() -> None:
	async with async_redis_client() as redis_client:
		manager1 = SessionManager()
		manager2 = SessionManager()
		headers = Headers({"x-opsi-session-lifetime": "5"})
		sess1 = await manager1.get_session("172.10.11.12", headers=headers)
		await sess1.store()

		res = await redis_client.hgetall(sess1.redis_key)
		assert res

		sess2 = await manager2.get_session("172.10.11.12", session_id=sess1.session_id)
		assert sess1.session_id == sess2.session_id
		assert sess1.created == sess2.created
		assert sess1.max_age == sess2.max_age

		sess2.max_age = 1
		await sleep(2)

		assert sess2.deleted

		res = await redis_client.hgetall(sess1.redis_key)
		assert not res

		sess1 = await manager1.get_session("172.10.11.12", session_id=sess1.session_id)
		assert sess1.session_id != sess2.session_id

		await manager1.stop(wait=True)
		await manager2.stop(wait=True)
