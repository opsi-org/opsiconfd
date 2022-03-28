# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
application utils
"""

import asyncio
from inspect import Parameter
from typing import Optional

import msgpack  # type: ignore[import]
import orjson
from fastapi import HTTPException, params
from fastapi.dependencies.utils import (
	get_dependant,
	get_param_field,
	solve_dependencies,
)
from fastapi.exceptions import WebSocketRequestValidationError
from starlette import status
from starlette.endpoints import WebSocketEndpoint
from starlette.types import Message, Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState
from websockets.exceptions import ConnectionClosedOK

from .. import contextvar_client_session
from ..backend import get_mysql
from ..config import FQDN
from ..logging import logger


def get_configserver_id():
	return FQDN


def get_username():
	client_session = contextvar_client_session.get()
	if not client_session:
		raise RuntimeError("Session invalid")
	return client_session.user_store.username


def get_user_privileges():
	username = get_username()
	privileges = {}
	mysql = get_mysql()  # pylint: disable=invalid-name
	with mysql.session() as session:
		for row in session.execute(
			"""
			SELECT
				cs.configId,
				cs.values
			FROM
				CONFIG_STATE AS cs
			WHERE
				cs.configId LIKE :config_id_filter
			GROUP BY
				cs.configId
			ORDER BY
				cs.configId
			""",
			{"config_id_filter": f"user.{{{username}}}.privilege.%"},
		).fetchall():
			try:
				priv = ".".join(row["configId"].split(".")[3:])
				vals = [val for val in orjson.loads(row["values"]) if val != ""]  # pylint: disable=no-member
				privileges[priv] = vals
			except orjson.JSONDecodeError as err:  # pylint: disable=no-member
				logger.error("Failed to parse privilege %s: %s", row, err)

		return privileges


def get_allowed_objects():
	allowed = {"product_groups": ..., "host_groups": ...}
	privileges = get_user_privileges()
	if True in privileges.get("product.groupaccess.configured", [False]):
		allowed["product_groups"] = privileges.get("product.groupaccess.productgroups", [])
	if True in privileges.get("host.groupaccess.configured", [False]):
		allowed["host_groups"] = privileges.get("host.groupaccess.productgroups", [])
	return allowed


def build_tree(group, groups, allowed, processed=None):
	if not processed:
		processed = []
	processed.append(group["id"])

	is_root_group = group["parent"] == "#"  # or group["id"] == "clientdirectory"
	group["allowed"] = is_root_group or allowed == ... or group["id"] in allowed

	children = {}
	for grp in groups:
		if grp["id"] == group["id"]:
			continue
		if grp["parent"] == group["id"]:
			if grp["id"] in processed:
				logger.error("Loop: %s %s", grp["id"], processed)
			else:
				children[grp["id"]] = build_tree(grp, groups, allowed, processed)
	if children:
		if "children" not in group:
			group["children"] = {}
		group["children"].update(children)
	else:
		if group["type"] == "HostGroup":
			group["children"] = None

	if not is_root_group and group.get("children"):
		for child in group["children"].values():
			# Correct id for webgui
			child["id"] = f'{child["id"]};{group["id"]}'
			if child.get("allowed"):
				# Allow parent if child is allowed
				group["allowed"] = True

	return group


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


# used in webgui backend
def bool_product_property(value):
	if value:
		if value.lower() == "[true]" or str(value) == "1" or value.lower() == "true":
			return True
	return False


# used in webgui backend
def unicode_product_property(value):
	if value and isinstance(value, str):
		if value.startswith('["'):
			return orjson.loads(value)  # pylint: disable=no-member
		if value == "[]":
			return [""]
		return value.replace('\\"', '"').split(",")
	return [""]


# used in webgui backend
def merge_dicts(dict_a: dict, dict_b: dict, path=None) -> dict:
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
				raise Exception(f"Conflict at { '.'.join(path + [str(key)])}")
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
		self._set_cookie_task: asyncio.Task
		self._check_session_task: asyncio.Task

	async def _check_authorization(self) -> None:
		if not self.scope.get("session"):
			raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Access to {self}, no valid session found")

		if self.admin_only and not self.scope["session"].user_store.isAdmin:
			raise HTTPException(
				status_code=status.HTTP_403_FORBIDDEN,
				detail=f"Access to {self} denied for user {self.scope['session'].user_store.username!r}",
			)

	async def set_cookie_task(self, websocket: WebSocket, set_cookie_interval: int):
		try:
			while True:
				await asyncio.sleep(set_cookie_interval)
				if websocket.client_state != WebSocketState.CONNECTED:
					break
				logger.debug("Send set-cookie")
				await websocket.send_bytes(
					msgpack.dumps({"type": "set-cookie", "payload": self.scope["session"].get_headers()["Set-Cookie"]})
				)
		except (ConnectionClosedOK, WebSocketDisconnect) as err:
			logger.debug("set_cookie_task: %s", err)

	async def check_session_task(self, websocket: WebSocket):
		try:
			while True:
				await asyncio.sleep(15)
				if websocket.client_state != WebSocketState.CONNECTED:
					break
				if self.scope["session"].expired:
					logger.info("Session expired")
					await websocket.close(code=status.WS_1000_NORMAL_CLOSURE)
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

		self._check_session_task = asyncio.get_event_loop().create_task(self.check_session_task(websocket))

		set_cookie_interval = values.pop("set_cookie_interval")
		if set_cookie_interval > 0:
			logger.debug("set_cookie_interval is %d", set_cookie_interval)
			self._set_cookie_task = asyncio.get_event_loop().create_task(self.set_cookie_task(websocket, set_cookie_interval))
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

	async def on_connect(self, websocket: WebSocket) -> None:
		pass
