# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
wsgi tests
"""

import asyncio
from collections.abc import Callable, Iterable
from typing import Any

import pytest

from opsiconfd.wsgi import InputBuffer, WSGIMiddleware, build_environ


def get_scope(headers: list[tuple[bytes, bytes]] | None = None, method: str = "PUT") -> dict[str, Any]:
	return {
		"type": "http",
		"method": method,
		"path": "/test",
		"query_string": "a=ü".encode(),
		"http_version": "1.1",
		"headers": headers or [],
	}


def test_build_environ_query_string_not_ascii() -> None:
	assert build_environ(get_scope())["QUERY_STRING"] == "a=ü".encode().decode("latin1")


def test_build_environ_content_length() -> None:
	environ = build_environ(get_scope([(b"content-length", b"5"), (b"content-length", b"5")]))
	assert environ["CONTENT_LENGTH"] == "5"
	with pytest.raises(ValueError, match="Conflicting"):
		build_environ(get_scope([(b"content-length", b"5"), (b"content-length", b"6")]))


def test_input_buffer_empty_final_message() -> None:
	async def run() -> list[bytes]:
		buffer = InputBuffer(allow_memory_view=False)
		await buffer.write(b"abc")
		await buffer.write(b"")
		await buffer.end_of_data()

		def read_all() -> list[bytes]:
			chunks = []
			while data := buffer.read(2):
				chunks.append(bytes(data))
			return chunks

		return await asyncio.to_thread(read_all)

	assert asyncio.run(run()) == [b"ab", b"c"]


def test_input_buffer_abort() -> None:
	buffer = InputBuffer()
	buffer.abort()
	with pytest.raises(ConnectionAbortedError):
		buffer.read(10)


async def run_asgi(app: Callable, messages: list[dict[str, Any]], scope: dict[str, Any]) -> list[dict[str, Any]]:
	incoming = list(messages)
	sent: list[dict[str, Any]] = []
	response_complete = asyncio.Event()

	async def receive() -> dict[str, Any]:
		if incoming:
			return incoming.pop(0)
		await response_complete.wait()
		return {"type": "http.disconnect"}

	async def send(message: dict[str, Any]) -> None:
		sent.append(message)
		if message["type"] == "http.response.body" and not message.get("more_body"):
			response_complete.set()

	await asyncio.wait_for(WSGIMiddleware(app)(scope, receive, send), timeout=10)
	return sent


def test_wsgi_middleware_upload_without_reading_body() -> None:
	# The application does not read the body, but the client sends a lot of data
	def app(environ: dict, start_response: Callable) -> Iterable[bytes]:
		start_response("403 Forbidden", [("Content-Type", "text/plain")])
		return [b"denied"]

	messages = [{"type": "http.request", "body": b"x" * 1024, "more_body": True} for _ in range(50)]
	messages.append({"type": "http.request", "body": b"", "more_body": False})
	sent = asyncio.run(run_asgi(app, messages, get_scope()))
	assert sent[0]["status"] == 403
	assert sent[1]["body"] == b"denied"


def test_wsgi_middleware_upload_ending_with_empty_message() -> None:
	def app(environ: dict, start_response: Callable) -> Iterable[bytes]:
		body = b""
		while data := environ["wsgi.input"].read(10):
			body += bytes(data)
		start_response("200 OK", [("Content-Type", "text/plain")])
		return [body]

	messages = [
		{"type": "http.request", "body": b"12345", "more_body": True},
		{"type": "http.request", "body": b"67890", "more_body": True},
		{"type": "http.request", "body": b"", "more_body": False},
	]
	sent = asyncio.run(run_asgi(app, messages, get_scope()))
	assert sent[0]["status"] == 200
	assert sent[1]["body"] == b"1234567890"


def test_wsgi_middleware_closes_iterable() -> None:
	closed = []

	class Result:
		def __iter__(self) -> Any:
			yield b"data"

		def close(self) -> None:
			closed.append(True)

	def app(environ: dict, start_response: Callable) -> Iterable[bytes]:
		start_response("200 OK", [])
		return Result()

	messages = [{"type": "http.request", "body": b"", "more_body": False}]
	asyncio.run(run_asgi(app, messages, get_scope(method="GET")))
	assert closed == [True]


def test_wsgi_middleware_client_disconnect_during_upload() -> None:
	def app(environ: dict, start_response: Callable) -> Iterable[bytes]:
		while environ["wsgi.input"].read(10):
			pass
		start_response("200 OK", [])
		return [b""]

	async def run() -> None:
		messages = [{"type": "http.request", "body": b"12345", "more_body": True}, {"type": "http.disconnect"}]

		async def receive() -> dict[str, Any]:
			return messages.pop(0) if messages else {"type": "http.disconnect"}

		async def send(message: dict[str, Any]) -> None:
			pass

		# Must not hang and must not raise
		await asyncio.wait_for(WSGIMiddleware(app)(get_scope(), receive, send), timeout=10)

	asyncio.run(run())
