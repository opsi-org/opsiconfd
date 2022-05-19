# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
proxy
"""


from typing import List
from urllib.parse import urljoin, urlparse

import aiohttp
from fastapi.requests import Request
from fastapi.responses import Response, StreamingResponse
from starlette.background import BackgroundTask
from starlette.types import ASGIApp

from ..config import config
from ..logging import logger
from ..session import SESSION_COOKIE_NAME


def reverse_proxy_setup(_app):
	ReverseProxy(_app, "/grafana", config.grafana_internal_url, forward_cookies=["grafana_session"])


class ReverseProxy:  # pylint: disable=too-few-public-methods
	def __init__(  # pylint: disable=too-many-arguments
		self,
		app: ASGIApp,
		base_path: str,
		base_url: str,
		methods: tuple = ("GET", "POST"),
		forward_authorization: bool = False,
		forward_cookies: List[str] = None,
	) -> None:
		self.base_path = base_path
		url = urlparse(base_url)
		self.base_url = f"{url.scheme}://{url.netloc.split('@', 1)[-1]}"
		self.forward_authorization = forward_authorization
		self.forward_cookies = forward_cookies
		app.add_route(f"{base_path}/{{path:path}}", self.handle_request, methods)

	async def handle_request(self, request: Request):
		path = "/" + request.url.path[len(self.base_path) :].lstrip("/")
		full_url = urljoin(self.base_url, path)
		if not full_url.startswith(self.base_url):
			logger.error("Invalid path: %s", request.url.path)
			return Response(content="Not found", status_code=404)

		client = aiohttp.ClientSession(self.base_url, auto_decompress=False)
		request_headers = dict(request.headers)

		# TODO: https://tools.ietf.org/html/rfc7239
		request_headers["x-forwarded-proto"] = "https"
		request_headers["x-forwarded-host"] = request_headers["host"].split(":")[0]
		request_headers["x-forwarded-server"] = request_headers["host"].split(":")[0]
		request_headers["x-forwarded-for"] = request.client.host
		request_headers["x-real-ip"] = request.client.host

		remove_headers = ["host"]
		if not self.forward_authorization:
			remove_headers.append("authorization")
		if self.forward_cookies:
			cookies = []
			send_all = "*" in self.forward_cookies
			for cookie in request_headers.get("cookie", "").split(";"):
				cookie = cookie.strip()
				name = cookie.split("=", 1)[0]
				if name == SESSION_COOKIE_NAME:
					# Never send opsiconfd cookie
					continue
				if send_all or name in self.forward_cookies:
					cookies.append(cookie)
			if cookies:
				request_headers["cookie"] = "; ".join(cookies)
		else:
			remove_headers.append("cookie")
		for header in remove_headers:
			if header in request_headers:
				del request_headers[header]

		resp = await client._request(  # pylint: disable=protected-access
			method=request.method, headers=request_headers, str_or_url=path, data=request.stream(), allow_redirects=False
		)
		logger.debug("Got response: %s", resp)

		response_headers = dict(resp.headers)

		request.scope["reverse_proxy"] = True
		return StreamingResponse(
			content=resp.content.iter_any(),
			status_code=resp.status,
			headers=response_headers,
			background=BackgroundTask(client.close),
		)
