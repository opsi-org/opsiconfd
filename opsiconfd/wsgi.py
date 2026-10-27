# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.wsgi
"""

import asyncio
import os
import sys
import threading
from collections.abc import Callable
from queue import Empty, Full, Queue
from typing import Any

from starlette.concurrency import run_in_threadpool
from starlette.types import Receive, Scope, Send

# Marks the end of the request body in the input queue
_END_OF_DATA = object()


class _Stopped(ConnectionAbortedError):
	"""Raised in the WSGI thread if the response can no longer be delivered."""


class InputBuffer:
	"""
	Input buffer connecting the ASGI receiver (event loop) with the WSGI application (thread).

	The number of buffered chunks is limited to apply backpressure to the client.
	"""

	def __init__(self, allow_memory_view: bool = True) -> None:
		self._allow_memory_view = allow_memory_view
		self._queue: Queue[Any] = Queue(5)
		self._buffer = b""
		self._read_pos = 0
		self._eof = False
		self._aborted = threading.Event()
		self._closed = threading.Event()

	def _put(self, item: Any) -> None:
		"""Put an item into the queue (blocking). Discards the item if the buffer is closed."""
		while not self._closed.is_set():
			try:
				self._queue.put(item, timeout=0.5)
				return
			except Full:
				continue

	async def _aput(self, item: Any) -> None:
		"""Put an item into the queue without blocking the event loop."""
		if self._closed.is_set():
			return
		try:
			self._queue.put_nowait(item)
		except Full:
			await run_in_threadpool(self._put, item)

	async def write(self, data: bytes) -> int:
		"""Add a chunk of the request body."""
		if len(data) > 0:
			await self._aput(data)
		return len(data)

	async def end_of_data(self) -> None:
		"""Mark the end of the request body."""
		await self._aput(_END_OF_DATA)

	def abort(self) -> None:
		"""Abort the request body (e.g. client disconnected). Pending and future reads will fail."""
		self._aborted.set()

	def _get(self) -> Any:
		while True:
			if self._aborted.is_set():
				raise ConnectionAbortedError("Request body incomplete, client disconnected")
			try:
				return self._queue.get(timeout=0.5)
			except Empty:
				continue

	def read(self, size: int) -> bytes | memoryview:
		if self._read_pos == 0:
			if self._eof:
				return b""
			item = self._get()
			if item is _END_OF_DATA:
				self._eof = True
				return b""
			self._buffer = item

		start = self._read_pos
		end = start + size
		if end >= len(self._buffer):
			end = len(self._buffer)
			self._read_pos = 0
		else:
			self._read_pos += size

		if not self._allow_memory_view:
			return self._buffer[start:end]

		return memoryview(self._buffer)[start:end]

	def readline(self) -> bytes | memoryview:
		return self.read(16 * 1024)

	def close(self) -> None:
		"""Close the buffer. Data written afterwards is discarded."""
		self._closed.set()


ENC, ESC = sys.getfilesystemencoding(), "surrogateescape"


def unicode_to_wsgi(data: str) -> str:
	"""Convert an environment variable to a WSGI "bytes-as-unicode" string"""
	return data.encode(ENC, ESC).decode("iso-8859-1")


def build_environ(scope: Scope) -> dict:
	"""
	Builds a scope and request body into a WSGI environ object.
	"""
	script_name = scope.get("root_path", "").encode("utf8").decode("latin1")
	path_info = scope["path"].encode("utf8").decode("latin1")
	path_info = path_info.removeprefix(script_name)

	script_name_environ_var = os.environ.get("SCRIPT_NAME", "")
	if script_name_environ_var:
		script_name = unicode_to_wsgi(script_name_environ_var)

	environ = {
		"asgi.scope": scope,
		"REQUEST_METHOD": scope["method"],
		"SCRIPT_NAME": script_name,
		"PATH_INFO": path_info,
		"QUERY_STRING": scope["query_string"].decode("latin1"),
		"SERVER_PROTOCOL": f"HTTP/{scope['http_version']}",
		"wsgi.version": (1, 0),
		"wsgi.url_scheme": scope.get("scheme", "http"),
		"wsgi.errors": sys.stdout,
		"wsgi.multithread": True,
		"wsgi.multiprocess": True,
		"wsgi.run_once": False,
	}

	# Get server name and port - required in WSGI, not in ASGI
	server_addr, server_port = scope.get("server") or ("localhost", 80)
	environ["SERVER_NAME"] = server_addr
	environ["SERVER_PORT"] = str(server_port or 0)

	# Get client IP address
	client = scope.get("client")
	if client is not None:
		addr, port = client
		environ["REMOTE_ADDR"] = addr
		environ["REMOTE_PORT"] = str(port)

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
		if val := environ.get(corrected_name):
			if corrected_name == "CONTENT_LENGTH":
				# Never merge, conflicting values are a sign of request smuggling attempts
				if val != value.strip():
					raise ValueError("Conflicting Content-Length headers")
				continue
			value = f"{val},{value}"
		environ[corrected_name] = value

	# wsgidav.util.parse_xml_body() uses lxml.etree.fromstring() which does not support memoryview
	environ["wsgi.input"] = InputBuffer(allow_memory_view=scope["method"] in ("POST", "PUT"))

	return environ


class WSGIMiddleware:
	"""ASGI middleware running a WSGI application in a thread pool."""

	def __init__(self, app: Callable) -> None:
		self.app = app

	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
		assert scope["type"] == "http"
		responder = WSGIResponder(self.app, scope)
		await responder(receive, send)


class WSGIResponder:
	"""Handles a single request / response cycle of a WSGI application."""

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
		# Set if the response can no longer be delivered (client disconnected or sender stopped)
		self._stopped = threading.Event()
		self.loop = asyncio.get_running_loop()
		self.response_started = False
		self.exc_info = None  # type: Any

	async def __call__(self, receive: Receive, send: Send) -> None:
		environ = build_environ(self.scope)
		wsgi_input: InputBuffer = environ["wsgi.input"]
		receiver = self.loop.create_task(self.receiver(receive, wsgi_input))
		sender = self.loop.create_task(self.sender(send))
		# Unblock the WSGI thread if the sender terminates (normally or by an error)
		sender.add_done_callback(lambda _: self._stopped.set())
		try:
			await run_in_threadpool(self.wsgi, environ, self.start_response)
			if not self._stopped.is_set() or sender.done():
				await asyncio.wait_for(sender, None)
			if self.exc_info is not None:
				raise self.exc_info[0].with_traceback(self.exc_info[1], self.exc_info[2])
		finally:
			# The WSGI application may not have consumed the whole request body.
			# Further body data is discarded and the receiver is stopped.
			wsgi_input.close()
			tasks = [task for task in (receiver, sender) if not task.done()]
			for task in tasks:
				task.cancel()
			if tasks:
				await asyncio.gather(*tasks, return_exceptions=True)

	async def receiver(self, receive: Receive, wsgi_input: InputBuffer) -> None:
		"""Feed the request body into the input buffer and watch for client disconnects."""
		body_complete = False
		try:
			while True:
				message = await receive()
				if message["type"] == "http.disconnect":
					self._stopped.set()
					if not body_complete:
						wsgi_input.abort()
					return
				if body_complete:
					continue
				await wsgi_input.write(message.get("body", b""))
				if not message.get("more_body", False):
					body_complete = True
					await wsgi_input.end_of_data()
		except Exception:
			wsgi_input.abort()
			raise

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
			headers = [
				(name.strip().encode("ascii").lower(), value.strip().encode("latin1", "replace")) for name, value in response_headers
			]
			self._put(
				{
					"type": "http.response.start",
					"status": status_code,
					"headers": headers,
				}
			)

	def _put(self, message: dict | None) -> None:
		"""
		Put a message into the send queue (called from the WSGI thread).

		Raises:
			_Stopped: If the response can no longer be delivered.
		"""
		while True:
			if self._stopped.is_set():
				raise _Stopped("Response can not be delivered")
			try:
				self.send_queue.put(message, timeout=0.5)
				break
			except Full:
				continue
		self.loop.call_soon_threadsafe(self.send_event.set)

	def wsgi(self, environ: dict, start_response: Callable) -> None:
		"""Run the WSGI application in a thread and pass the response to the sender."""
		result = None
		try:
			result = self.app(environ, start_response)
			for chunk in result:
				self._put({"type": "http.response.body", "body": chunk, "more_body": True})

			self._put({"type": "http.response.body", "body": b""})
			self._put(None)
		except ConnectionError:
			# Client disconnected or response can no longer be delivered
			if not self._stopped.is_set():
				raise
		finally:
			# Required by the WSGI specification, releases resources (e.g. open files)
			if result is not None and hasattr(result, "close"):
				result.close()
