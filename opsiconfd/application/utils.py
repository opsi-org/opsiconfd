# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
application utils
"""

from asyncio import Task, create_task, sleep

import msgspec
from fastapi import HTTPException
from starlette.endpoints import WebSocketEndpoint
from starlette.status import (
	HTTP_401_UNAUTHORIZED,
	HTTP_403_FORBIDDEN,
	WS_1000_NORMAL_CLOSURE,
	WS_1011_INTERNAL_ERROR,
)
from starlette.types import Message, Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState

from opsiconfd import contextvar_client_session
from opsiconfd.logging import logger


def get_username() -> str:
	client_session = contextvar_client_session.get()
	if not client_session or not client_session.username:
		raise RuntimeError("Session invalid")
	return client_session.username


def parse_list(query_list: list[str] | None) -> list[str] | None:
	def remove_prefix(value: str, prefix: str) -> str:
		return value[value.startswith(prefix) and len(prefix) :]

	def remove_postfix(value: str, postfix: str) -> str:
		if value.endswith(postfix):
			value = value[: -len(postfix)]
		return value

	if query_list is None:
		return None

	# we already have a list, we can return
	if len(query_list) > 1:
		return query_list

	# if we don't start with a "[" and end with "]" it's just a normal entry
	flat_list = query_list[0]
	if not flat_list.startswith("[") and not flat_list.endswith("]"):
		return query_list

	flat_list = remove_prefix(flat_list, "[")
	flat_list = remove_postfix(flat_list, "]")

	result_list = flat_list.split(",")
	result_list = [remove_prefix(n.strip(), '"') for n in result_list]
	result_list = [remove_postfix(n.strip(), '"') for n in result_list]

	return list(filter(None, result_list))


# used in webgui backend
def bool_product_property(value: str | None) -> bool:
	if value:
		if value.lower() == "[true]" or str(value) == "1" or value.lower() == "true":
			return True
	return False


# used in webgui backend
def unicode_product_property(value: str | None) -> list[str]:
	if value and isinstance(value, str):
		if value.startswith('["'):
			return msgspec.json.decode(value.encode("utf-8"))
		if value == "[]":
			return [""]
		return value.replace('\\"', '"').split(",")
	return [""]


# used in webgui backend
def merge_dicts(dict_a: dict, dict_b: dict, path: list[str] | None = None) -> dict:
	if not dict_a or not dict_b:
		raise ValueError("Merge_dicts: At least one of the dicts (a and b) is not set.")
	if path is None:
		path = []
	for key in dict_b:
		if key in dict_a:
			if isinstance(dict_a[key], dict) and isinstance(dict_b[key], dict):
				merge_dicts(dict_a[key], dict_b[key], path + [str(key)])
			elif isinstance(dict_a[key], list) and isinstance(dict_b[key], list):
				dict_a[key] = list(set(dict_a[key] + dict_b[key]))
			elif dict_a[key] == dict_b[key]:
				pass
			else:
				raise RuntimeError(f"Conflict at { '.'.join(path + [str(key)])}")
		else:
			dict_a[key] = dict_b[key]
	return dict_a


class OpsiconfdWebSocket(WebSocket):
	async def receive(self) -> Message:
		await self.scope["session"].update_last_used()
		return await super().receive()

	async def send(self, message: Message) -> None:
		await self.scope["session"].update_last_used()
		return await super().send(message)


class OpsiconfdWebSocketEndpoint(WebSocketEndpoint):
	admin_only = False

	def __init__(self, scope: Scope, receive: Receive, send: Send) -> None:
		super().__init__(scope, receive, send)
		self._check_session_task: Task

	async def _check_authorization(self) -> None:
		if not self.scope.get("session"):
			raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail=f"Access to {self}, no valid session found")

		if self.admin_only and not self.scope["session"].is_admin:
			raise HTTPException(
				status_code=HTTP_403_FORBIDDEN,
				detail=f"Access to {self} denied for user {self.scope['session'].username!r}",
			)

	async def check_session_task(self, websocket: WebSocket) -> None:
		try:
			session = self.scope["session"]
			while True:
				await sleep(15)
				if websocket.client_state != WebSocketState.CONNECTED:
					break
				if session.expired:
					logger.info("Session expired")
					await websocket.close(code=WS_1000_NORMAL_CLOSURE)
		except WebSocketDisconnect as err:
			logger.debug("check_session_task: %s", err)

	async def dispatch(self) -> None:
		websocket = OpsiconfdWebSocket(self.scope, receive=self.receive, send=self.send)
		await self._check_authorization()

		await websocket.accept()

		self._check_session_task = create_task(self.check_session_task(websocket))

		await self.on_connect(websocket, **websocket.query_params)

		close_code = WS_1000_NORMAL_CLOSURE

		try:
			while True:
				message = await websocket.receive()
				if message["type"] == "websocket.receive":
					data = await self.decode(websocket, message)
					await self.on_receive(websocket, data)
				elif message["type"] == "websocket.disconnect":
					close_code = int(message.get("code", WS_1000_NORMAL_CLOSURE))
					break
		except Exception as exc:
			close_code = WS_1011_INTERNAL_ERROR
			raise exc
		finally:
			await self.on_disconnect(websocket, close_code)

	async def on_connect(self, websocket: WebSocket) -> None:
		pass
