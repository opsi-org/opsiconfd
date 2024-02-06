# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
proxy
"""


from asyncio import gather
from typing import Callable
from urllib.parse import urljoin, urlparse

from aiohttp import ClientConnectorError, ClientSession
from fastapi import FastAPI, status
from fastapi.requests import Request
from fastapi.responses import Response, StreamingResponse
from opsicommon.logging.constants import TRACE
from starlette.background import BackgroundTask
from starlette.datastructures import Headers
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState

from opsiconfd.config import config
from opsiconfd.logging import get_logger
from opsiconfd.session import SESSION_COOKIE_NAME


def reverse_proxy_setup(_app: FastAPI) -> None:
	ReverseProxy(_app, "/grafana", config.grafana_internal_url, forward_cookies=["grafana_session"], preserve_host=True)


proxy_logger = get_logger("opsiconfd.reverse_proxy")


class ReverseProxy:
	def __init__(
		self,
		app: FastAPI,
		mount_path: str,
		base_url: str,
		methods: tuple = ("GET", "POST"),
		forward_authorization: bool = False,
		forward_cookies: list[str] | None = None,
		preserve_host: bool = False,
		forward_response_headers: list[str] | None = None,
	) -> None:
		self.mount_path = mount_path
		url = urlparse(base_url)
		self.base_url = f"{url.scheme}://{url.netloc.split('@', 1)[-1]}"
		self.base_path = (url.path or "").rstrip("/")
		self.forward_authorization = forward_authorization
		self.forward_cookies = forward_cookies
		self.preserve_host = preserve_host
		if forward_response_headers is None:
			forward_response_headers = ["Content-Type", "Content-Length", "Content-Encoding", "Last-Modified"]
		self.forward_response_headers = [h.lower() for h in forward_response_headers]
		app.add_route(f"{mount_path}{{path:path}}", self.handle_request, list(methods))  # type: ignore[attr-defined]
		app.add_websocket_route(f"{mount_path}{{path:path}}", self.handle_websocket_request)  # type: ignore[attr-defined]

	def _get_path(self, path: str) -> str | None:
		_path = self.base_path + "/" + path[len(self.mount_path) :].lstrip("/")
		full_url = urljoin(self.base_url, _path)
		if not full_url.startswith(self.base_url):
			proxy_logger.error("Invalid path: %s", path)
			return None
		return _path

	def _request_headers(self, request_headers: Headers, client_address: str) -> dict[str, str]:
		_request_headers = dict(request_headers)

		# TODO: https://tools.ietf.org/html/rfc7239
		_request_headers["x-forwarded-proto"] = "https"
		_request_headers["x-forwarded-host"] = _request_headers["host"].split(":")[0]
		_request_headers["x-forwarded-server"] = _request_headers["host"].split(":")[0]
		_request_headers["x-forwarded-for"] = client_address
		_request_headers["x-real-ip"] = client_address

		remove_headers = []
		if not self.preserve_host:
			remove_headers.append("host")
		if not self.forward_authorization:
			remove_headers.append("authorization")
		cookies = []
		if self.forward_cookies:
			send_all = "*" in self.forward_cookies
			for cookie in _request_headers.get("cookie", "").split(";"):
				cookie = cookie.strip()
				name = cookie.split("=", 1)[0]
				if name == SESSION_COOKIE_NAME:
					# Never send opsiconfd cookie
					continue
				if send_all or name in self.forward_cookies:
					cookies.append(cookie)
		if cookies:
			_request_headers["cookie"] = "; ".join(cookies)
		else:
			remove_headers.append("cookie")
		for header in remove_headers:
			if header in _request_headers:
				del _request_headers[header]

		return _request_headers

	async def handle_request(self, request: Request) -> Response:
		path = self._get_path(request.url.path)
		if not path:
			return Response(content="Not found", status_code=404)
		if request.url.query:
			path = f"{path}?{request.url.query}"
		client = ClientSession(self.base_url, auto_decompress=False)

		request_headers = self._request_headers(request.headers, request.scope["client"][0])
		if proxy_logger.isEnabledFor(TRACE):
			proxy_logger.trace(">>> %s %s", request.method, path)
			for header, value in request_headers.items():
				proxy_logger.trace(">>> %s: %s", header, value)

		try:
			resp = await client._request(
				method=request.method, headers=request_headers, str_or_url=path, data=request.stream(), allow_redirects=False
			)
		except ClientConnectorError as err:
			proxy_logger.error(err)
			await client.close()
			return Response(status_code=status.HTTP_502_BAD_GATEWAY, content=str(err))

		proxy_logger.debug("Got response: %s", resp)

		response_headers = {k: v for k, v in resp.headers.items() if k.lower() in self.forward_response_headers}

		if proxy_logger.isEnabledFor(TRACE):
			proxy_logger.trace("<<< %s", resp.status)
			for header, value in response_headers.items():
				proxy_logger.trace("<<< %s: %s", header, value)

		request.scope["reverse_proxy"] = True

		return StreamingResponse(
			status_code=resp.status,
			headers=response_headers,
			content=resp.content.iter_any(),
			background=BackgroundTask(client.close),
		)

	async def _websocket_reader(self, name: str, reader: Callable, writer: Callable, state: WebSocketState) -> None:
		trace_log = proxy_logger.isEnabledFor(TRACE)
		while state == WebSocketState.CONNECTED:
			data = await reader()
			if trace_log:
				proxy_logger.trace("%s: %s", name, data)
			await writer(data)

	async def handle_websocket_request(self, client_websocket: WebSocket) -> None:
		path = self._get_path(client_websocket.url.path)
		if not path:
			await client_websocket.close(status.WS_1008_POLICY_VIOLATION)
			return

		client = ClientSession(self.base_url, auto_decompress=False)
		try:
			request_headers = self._request_headers(client_websocket.headers, client_websocket.scope["client"][0])

			await client_websocket.accept()
			async with client.ws_connect(url=path, headers=request_headers) as server_websocket:
				server_websocket_reader = self._websocket_reader(
					"<<<", server_websocket.receive_str, client_websocket.send_text, client_websocket.client_state
				)
				client_websocket_reader = self._websocket_reader(
					">>>", client_websocket.receive_text, server_websocket.send_str, client_websocket.client_state
				)
				try:
					await gather(server_websocket_reader, client_websocket_reader)
				except WebSocketDisconnect:
					proxy_logger.info("Client disconnect: %s %s", client_websocket.scope["client"][0], client_websocket.url.path)
				except TypeError:
					proxy_logger.info("Server disconnect: %s %s", client_websocket.scope["client"][0], client_websocket.url.path)
				if client_websocket.client_state == WebSocketState.CONNECTED:
					await client_websocket.close()
				await server_websocket.close()
		except ClientConnectorError as err:
			proxy_logger.error(err)
			await client_websocket.close(status.WS_1014_BAD_GATEWAY)
		finally:
			await client.close()
