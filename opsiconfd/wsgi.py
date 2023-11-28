# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.wsgi
"""

import asyncio
import sys
from queue import Queue
from typing import Any, Callable

from starlette.concurrency import run_in_threadpool
from starlette.types import Receive, Scope, Send


class InputBuffer:
	"""Input buffer"""

	def __init__(self) -> None:
		self._queue: Queue[bytes] = Queue(5)
		self._buffer = b""
		self._read_pos = 0
		self._end_of_data = False

	def end_of_data(self) -> None:
		self._end_of_data = True

	def write(self, data: bytes) -> int:
		if len(data) > 0:
			self._queue.put(data)
		return len(data)

	def read(self, size: int) -> bytes:
		if self._read_pos == 0:
			if self._end_of_data and self._queue.empty():
				return b""
			self._buffer = self._queue.get()

		start = self._read_pos
		end = start + size
		if end >= len(self._buffer):
			end = len(self._buffer)
			self._read_pos = 0
		else:
			self._read_pos += size

		view = memoryview(self._buffer)[start:end]
		return view

	def readline(self) -> bytes:
		return self.read(16 * 1024)

	def close(self) -> None:
		pass


def build_environ(scope: Scope) -> dict:
	"""
	Builds a scope into a WSGI environ object.
	"""
	environ = {
		"REQUEST_METHOD": scope["method"],
		"SCRIPT_NAME": scope.get("root_path", ""),
		"PATH_INFO": scope["path"],
		"QUERY_STRING": scope["query_string"].decode("ascii"),
		"SERVER_PROTOCOL": f"HTTP/{scope['http_version']}",
		"wsgi.version": (1, 0),
		"wsgi.url_scheme": scope.get("scheme", "http"),
		"wsgi.input": None,
		"wsgi.errors": sys.stdout,
		"wsgi.multithread": True,
		"wsgi.multiprocess": True,
		"wsgi.run_once": False,
	}

	# Get server name and port - required in WSGI, not in ASGI
	server = scope.get("server") or ("localhost", 80)
	environ["SERVER_NAME"] = server[0]
	environ["SERVER_PORT"] = server[1]

	# Get client IP address
	if scope.get("client"):
		environ["REMOTE_ADDR"] = scope["client"][0]

	# Go through headers and make them into environ entries
	for name, value in scope.get("headers", []):
		name = name.decode("latin1")
		if name == "content-length":
			corrected_name = "CONTENT_LENGTH"
		elif name == "content-type":
			corrected_name = "CONTENT_TYPE"
		else:
			corrected_name = f"HTTP_{name}".upper().replace("-", "_")
		# HTTPbis say only ASCII chars are allowed in headers, but we latin1 just in case
		value = value.decode("latin1")
		if corrected_name in environ:
			value = environ[corrected_name] + "," + value
		environ[corrected_name] = value

	environ["wsgi.input"] = InputBuffer()

	return environ


class WSGIMiddleware:  # pylint: disable=too-few-public-methods
	def __init__(self, app: Callable) -> None:
		self.app = app

	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
		assert scope["type"] == "http"
		responder = WSGIResponder(self.app, scope)
		await responder(receive, send)


class WSGIResponder:  # pylint: disable=too-many-instance-attributes
	def __init__(self, app: Callable, scope: Scope) -> None:
		self.app = app
		self.scope = scope
		self.status = None
		self.response_headers = None
		self.send_event = asyncio.Event()
		# The reason for using a queue is that if the reader is faster than the sender,
		# which should be the case most of the time, the send queue will not fill up endlessly.
		# The original implementation from uvicorn uses a list, which eats up a lot of memory.
		self.send_queue: Queue = Queue(5)
		self.loop = asyncio.get_running_loop()
		self.response_started = False
		self.exc_info = None  # type: Any

	async def __call__(self, receive: Receive, send: Send) -> None:
		environ = build_environ(self.scope)
		receiver = self.loop.create_task(self.receiver(receive, environ["wsgi.input"]))
		sender = None
		try:
			sender = self.loop.create_task(self.sender(send))
			await run_in_threadpool(self.wsgi, environ, self.start_response)
			await asyncio.wait_for(receiver, None)
			await asyncio.wait_for(sender, None)
			if self.exc_info is not None:
				raise self.exc_info[0].with_traceback(self.exc_info[1], self.exc_info[2])
		finally:
			environ["wsgi.input"].close()
			if sender and not sender.done():
				sender.cancel()  # pragma: no cover

	async def receiver(self, receive: Receive, wsgi_input: InputBuffer) -> None:
		more_body = True
		while more_body:
			message = await receive()
			wsgi_input.write(message.get("body", b""))
			more_body = message.get("more_body", False)
		wsgi_input.end_of_data()

	async def sender(self, send: Send) -> None:
		while True:
			while not self.send_queue.empty():
				message = self.send_queue.get()
				if message is None:
					# Done
					return
				await send(message)
			await self.send_event.wait()
			self.send_event.clear()

	def start_response(
		self,
		status: str,
		response_headers: list[tuple[str, str]],
		exc_info: Any = None,
	) -> None:
		self.exc_info = exc_info
		if not self.response_started:
			self.response_started = True
			status_code_string, _ = status.split(" ", 1)
			status_code = int(status_code_string)
			headers = [(name.strip().encode("ascii").lower(), value.strip().encode("ascii")) for name, value in response_headers]
			self.send_queue.put(
				{
					"type": "http.response.start",
					"status": status_code,
					"headers": headers,
				}
			)
			self.loop.call_soon_threadsafe(self.send_event.set)

	def wsgi(self, environ: dict, start_response: Callable) -> None:
		for chunk in self.app(environ, start_response):
			self.send_queue.put({"type": "http.response.body", "body": chunk, "more_body": True})
			self.loop.call_soon_threadsafe(self.send_event.set)

		self.send_queue.put({"type": "http.response.body", "body": b""})
		self.send_queue.put(None)
		self.loop.call_soon_threadsafe(self.send_event.set)
