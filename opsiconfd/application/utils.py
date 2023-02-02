# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
application utils
"""

from asyncio import Task, get_running_loop, sleep
from inspect import Parameter
from typing import List, Optional

from fastapi import HTTPException, params
from fastapi.dependencies.utils import (
	get_dependant,
	get_param_field,
	solve_dependencies,
)
from fastapi.exceptions import WebSocketRequestValidationError
from msgpack import dumps as msgpack_dumps  # type: ignore[import]
from orjson import loads  # pylint: disable=no-name-in-module
from starlette.endpoints import WebSocketEndpoint
from starlette.status import (
	HTTP_401_UNAUTHORIZED,
	HTTP_403_FORBIDDEN,
	WS_1000_NORMAL_CLOSURE,
	WS_1011_INTERNAL_ERROR,
)
from starlette.types import Message, Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState
from websockets.exceptions import ConnectionClosedOK

from .. import contextvar_client_session
from ..config import FQDN
from ..logging import logger


def get_configserver_id() -> str:
	return FQDN


def get_username() -> str:
	client_session = contextvar_client_session.get()
	if not client_session:
		raise RuntimeError("Session invalid")
	return client_session.user_store.username


def parse_list(query_list: List[str] | None) -> List[str] | None:
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
def unicode_product_property(value: str | None) -> List[str]:
	if value and isinstance(value, str):
		if value.startswith('["'):
			return loads(value)  # pylint: disable=no-member
		if value == "[]":
			return [""]
		return value.replace('\\"', '"').split(",")
	return [""]


# used in webgui backend
def merge_dicts(dict_a: dict, dict_b: dict, path: List[str] | None = None) -> dict:
	if not dict_a or not dict_b:
		raise ValueError("Merge_dicts: At least one of the dicts (a and b) is not set.")
	if path is None:
		path = []  # pylint: disable=use-tuple-over-list
	for key in dict_b:
		if key in dict_a:
			if isinstance(dict_a[key], dict) and isinstance(dict_b[key], dict):
				merge_dicts(dict_a[key], dict_b[key], path + [str(key)])
			elif isinstance(dict_a[key], list) and isinstance(dict_b[key], list):
				dict_a[key] = list(set(dict_a[key] + dict_b[key]))
			elif dict_a[key] == dict_b[key]:
				pass
			else:
				raise ValueError(f"Conflict at { '.'.join(path + [str(key)])}")
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
		self._set_cookie_task: Task
		self._check_session_task: Task

	async def _check_authorization(self) -> None:
		if not self.scope.get("session"):
			raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail=f"Access to {self}, no valid session found")

		if self.admin_only and not self.scope["session"].user_store.isAdmin:
			raise HTTPException(
				status_code=HTTP_403_FORBIDDEN,
				detail=f"Access to {self} denied for user {self.scope['session'].user_store.username!r}",
			)

	async def set_cookie_task(self, websocket: WebSocket, set_cookie_interval: int) -> None:
		try:
			session = self.scope["session"]
			while True:
				await sleep(set_cookie_interval)
				if websocket.client_state != WebSocketState.CONNECTED:
					break
				logger.debug("Send set-cookie")
				await websocket.send_bytes(msgpack_dumps({"type": "set-cookie", "payload": session.get_cookie()}))
		except (ConnectionClosedOK, WebSocketDisconnect) as err:
			logger.debug("set_cookie_task: %s", err)

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
		except (ConnectionClosedOK, WebSocketDisconnect) as err:
			logger.debug("check_session_task: %s", err)

	async def dispatch(self) -> None:
		websocket = OpsiconfdWebSocket(self.scope, receive=self.receive, send=self.send)
		await self._check_authorization()

		dependant = get_dependant(path="", call=self.on_connect)

		param = Parameter("set_cookie_interval", default=0, annotation=Optional[int], kind=Parameter.KEYWORD_ONLY)

		dependant.query_params.append(get_param_field(param=param, default_field_info=params.Query, param_name=param.name))
		solved_result = await solve_dependencies(request=websocket, dependant=dependant)
		values, errors, *_ = solved_result
		if errors:
			logger.info(errors)
			raise WebSocketRequestValidationError(errors)

		await websocket.accept()

		self._check_session_task = get_running_loop().create_task(self.check_session_task(websocket))

		set_cookie_interval = values.pop("set_cookie_interval")
		if set_cookie_interval > 0:
			logger.debug("set_cookie_interval is %d", set_cookie_interval)
			self._set_cookie_task = get_running_loop().create_task(self.set_cookie_task(websocket, set_cookie_interval))
		await self.on_connect(**values)

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
