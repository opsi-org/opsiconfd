# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
application utils
"""

from starlette import status
from starlette.types import Message
from starlette.endpoints import WebSocketEndpoint
from starlette.websockets import WebSocket
from fastapi import HTTPException
from fastapi.dependencies.utils import solve_dependencies, get_dependant
from fastapi.exceptions import WebSocketRequestValidationError

from ..logging import logger


def parse_list(query_list):
	def remove_prefix(value: str, prefix: str):
		return value[value.startswith(prefix) and len(prefix) :]

	def remove_postfix(value: str, postfix: str):
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


class OpsiconfdWebSocket(WebSocket):
	async def receive(self) -> Message:
		await self.scope["session"].update_last_used()
		return await super().receive()

	async def send(self, message: Message) -> None:
		await self.scope["session"].update_last_used()
		return await super().send(message)


class OpsiconfdWebSocketEndpoint(WebSocketEndpoint):
	admin_only = False

	async def _check_authorization(self) -> None:
		if not self.scope.get("session"):
			raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Access to {self}, no valid session found")

		if self.admin_only and not self.scope["session"].user_store.isAdmin:
			raise HTTPException(
				status_code=status.HTTP_403_FORBIDDEN,
				detail=f"Access to {self} denied for user {self.scope['session'].user_store.username!r}",
			)

	async def dispatch(self) -> None:
		websocket = OpsiconfdWebSocket(self.scope, receive=self.receive, send=self.send)
		try:
			await self._check_authorization()
		except HTTPException:
			await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
			raise

		dependant = get_dependant(path="", call=self.on_connect)
		solved_result = await solve_dependencies(request=websocket, dependant=dependant)
		values, errors, *_ = solved_result
		if errors:
			logger.info(errors)
			await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
			raise WebSocketRequestValidationError(errors)

		await websocket.accept()

		await self.on_connect(**values)

		close_code = status.WS_1000_NORMAL_CLOSURE

		try:
			while True:
				message = await websocket.receive()
				if message["type"] == "websocket.receive":
					data = await self.decode(websocket, message)
					await self.on_receive(websocket, data)
				elif message["type"] == "websocket.disconnect":
					close_code = int(message.get("code", status.WS_1000_NORMAL_CLOSURE))
					break
		except Exception as exc:
			close_code = status.WS_1011_INTERNAL_ERROR
			raise exc
		finally:
			await self.on_disconnect(websocket, close_code)
