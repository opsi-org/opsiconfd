# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
application.middelware
"""

import warnings
from ctypes import c_long
from datetime import datetime, timezone
from time import time
from urllib.parse import urlparse

from fastapi import FastAPI
from opsicommon.logging.constants import TRACE  # type: ignore[import]
from starlette.datastructures import MutableHeaders
from starlette.types import Message, Receive, Scope, Send

from opsiconfd import contextvar_client_address, contextvar_request_id
from opsiconfd.config import config
from opsiconfd.logging import get_logger, logger
from opsiconfd.utils import normalize_ip_address
from opsiconfd.worker import Worker

PATH_MAPPINGS = {
	# Some WebDAV-Clients do not accept redirect on initial PROPFIND
	"/dav": "/dav/",
	"/boot": "/boot/",
	"/depot": "/depot/",
	"/public": "/public/",
	"/repository": "/repository/",
	"/workbench": "/workbench/",
}


header_logger = get_logger("opsiconfd.headers")


server_date = (0, b"", b"")


def get_server_date() -> tuple[bytes, bytes]:
	global server_date
	now = int(time())
	if server_date[0] != now:
		server_date = (
			now,
			str(now).encode("ascii"),
			datetime.fromtimestamp(now, timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %Z").encode("utf-8"),
		)
	return server_date[1], server_date[2]


class BaseMiddleware:
	def __init__(self, app: FastAPI) -> None:
		self.app = app
		self.worker_id = Worker.get_instance().id.encode("utf-8")

	@staticmethod
	def get_client_address(scope: Scope) -> tuple[str | None, int]:
		"""Get sanitized client address"""
		host, port = scope.get("client", (None, 0))
		if host:
			host = normalize_ip_address(host)
		return host, port

	@staticmethod
	def before_send(scope: Scope, receive: Receive, send: Send) -> None:
		pass

	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
		if scope["type"] not in ("http", "websocket"):
			return await self.app(scope, receive, send)

		# Generate request id and store in contextvar
		request_id = id(scope)

		# Longs on Windows are only 32 bits, but memory adresses on 64 bit python are 64 bits
		# Ensure it fits inside a long, truncating if necessary
		request_id = abs(c_long(request_id).value)
		scope["request_id"] = request_id
		contextvar_request_id.set(request_id)
		req_headers = dict(scope["headers"])

		# scope["path"] can change while processing, keep original value in scope["full_path"]
		# Wrong path will still appear in log: GET /boot/ HTTP/1.1" 200   (h11_impl.py:477)
		# Remove full_path and replace with path when the following issue is fixed:
		# https://github.com/encode/starlette/issues/1336
		scope["full_path"] = scope.get("path")
		if scope["full_path"]:
			new_path: str | None = None
			if scope["full_path"].startswith("/grafana/api/datasources/proxy"):
				# Redirect grafana proxy calls to simplify and avoid authentication grafana server => opsiconfd
				# Without redirect:
				#   browser => opsiconfd (reverse proxy) => grafana server (simple json) => opsiconfd (/metrics)
				# With redirect:
				#   browser => opsiconfd (/metrics)
				new_path = f"/metrics/grafana/{scope['full_path'].rsplit('/')[-1]}"
			else:
				new_path = PATH_MAPPINGS.get(scope["full_path"])
			if new_path:
				scope["full_path"] = scope["path"] = new_path
				scope["raw_path"] = new_path.encode("utf-8")

		client_host, client_port = self.get_client_address(scope)

		if scope.get("http_version") and scope["http_version"] != "1.1":
			warnings.warn(
				f"Client {client_host!r} ({req_headers.get('user-agent', '')!r}) is using http version {scope.get('http_version')}",
				RuntimeWarning,
			)

		if client_host in config.trusted_proxies:
			proxy_host = client_host
			# from uvicorn/middleware/proxy_headers.py

			if b"x-forwarded-for" in req_headers:
				# Determine the client address from the last trusted IP in the
				# X-Forwarded-For header. We've lost the connecting client's port
				# information by now, so only include the host.
				x_forwarded_for = req_headers[b"x-forwarded-for"].decode("ascii")
				client_host = x_forwarded_for.split(",")[-1].strip()
				client_port = 0
				logger.debug("Accepting x-forwarded-for header (host=%s) from trusted proxy %s", client_host, proxy_host)

		scope["client"] = (client_host, client_port)
		contextvar_client_address.set(client_host)

		async def send_wrapper(message: Message) -> None:
			if message["type"] == "http.response.start":
				host = req_headers.get(b"host", b"localhost:4447").decode().split(":")[0]
				origin_scheme = "https"
				origin_port = 4447
				try:
					origin = urlparse(req_headers[b"origin"].decode())
					origin_scheme = origin.scheme
					origin_port = int(origin.port)
				except Exception:
					pass

				headers = MutableHeaders(scope=message)
				headers.append("Access-Control-Allow-Origin", f"{origin_scheme}://{host}:{origin_port}")
				headers.append("Access-Control-Allow-Methods", "*")
				headers.append(
					"Access-Control-Allow-Headers",
					"Accept,Accept-Encoding,Authorization,Connection,Content-Type,Encoding,Host,Origin,X-opsi-session-lifetime,X-Requested-With",
				)
				headers.append("Access-Control-Allow-Credentials", "true")

				if header_logger.isEnabledFor(TRACE):
					header_logger.trace("<<< HTTP/%s %s %s", scope.get("http_version"), scope.get("method"), scope.get("path"))
					for header, value in req_headers.items():
						header_logger.trace("<<< %s: %s", header.decode("utf-8", "replace"), value.decode("utf-8", "replace"))
					header_logger.trace(">>> HTTP/%s %s", scope.get("http_version"), message.get("status"))
					for header, value in dict(headers).items():
						header_logger.trace(">>> %s: %s", header, value)

			self.before_send(scope, receive, send)

			if "headers" in message:
				if (
					scope["full_path"]
					and scope["full_path"].startswith("/public/boot")
					and req_headers.get("user-agent", "").startswith("UefiHttpBoot")
				):
					# Grub 2.06 needs titled headers (Content-Length instead of content-length)
					message["headers"] = [(k.title(), v) for k, v in message["headers"] if k not in (b"date", b"server")]

				dat = get_server_date()
				message["headers"].append((b"date", dat[1]))
				message["headers"].append((b"x-date-unix-timestamp", dat[0]))
				message["headers"].append((b"x-opsi-worker-id", self.worker_id))
			await send(message)

		return await self.app(scope, receive, send_wrapper)
