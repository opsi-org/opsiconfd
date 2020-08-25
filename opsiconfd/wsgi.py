import asyncio
import io
import sys
import typing
import tempfile

from starlette.concurrency import run_in_threadpool
from starlette.types import Message, Receive, Scope, Send

MAX_BODY_MEM_SIZE = 10 * 1000 * 1000

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
	
	if environ.get("CONTENT_LENGTH") is not None and int(environ["CONTENT_LENGTH"]) <= MAX_BODY_MEM_SIZE:
		# io.BytesIO is faster than tempfile.SpooledTemporaryFile
		environ["wsgi.input"] = io.BytesIO()
	else:
		#environ["wsgi.input"] = tempfile.SpooledTemporaryFile(max_size=MAX_BODY_MEM_SIZE)
		environ["wsgi.input"] = tempfile.TemporaryFile()
	
	return environ


class WSGIMiddleware:
	def __init__(self, app: typing.Callable, workers: int = 10) -> None:
		self.app = app

	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
		assert scope["type"] == "http"
		responder = WSGIResponder(self.app, scope)
		await responder(receive, send)


class WSGIResponder:
	def __init__(self, app: typing.Callable, scope: Scope) -> None:
		self.app = app
		self.scope = scope
		self.status = None
		self.response_headers = None
		self.send_event = asyncio.Event()
		self.send_queue = []  # type: typing.List[typing.Optional[Message]]
		self.loop = asyncio.get_event_loop()
		self.response_started = False
		self.exc_info = None  # type: typing.Any

	async def __call__(self, receive: Receive, send: Send) -> None:
		environ = build_environ(self.scope)
		receiver = self.loop.create_task(self.receiver(receive, environ["wsgi.input"]))
		sender = None
		try:
			await asyncio.wait_for(receiver, None)
			environ["wsgi.input"].seek(0)
			sender = self.loop.create_task(self.sender(send))
			await run_in_threadpool(self.wsgi, environ, self.start_response)
			self.send_queue.append(None)
			self.send_event.set()
			await asyncio.wait_for(sender, None)
			if self.exc_info is not None:
				raise self.exc_info[0].with_traceback(
					self.exc_info[1], self.exc_info[2]
				)
		finally:
			environ["wsgi.input"].close()
			if sender and not sender.done():
				sender.cancel()  # pragma: no cover

	async def receiver(self, receive: Receive, wsgi_input: io.BytesIO):
		more_body = True
		while more_body:
			message = await receive()
			wsgi_input.write(message.get("body", b""))
			more_body = message.get("more_body", False)
	
	async def sender(self, send: Send) -> None:
		while True:
			if self.send_queue:
				message = self.send_queue.pop(0)
				if message is None:
					return
				await send(message)
			else:
				await self.send_event.wait()
				self.send_event.clear()

	def start_response(
		self,
		status: str,
		response_headers: typing.List[typing.Tuple[str, str]],
		exc_info: typing.Any = None,
	) -> None:
		self.exc_info = exc_info
		if not self.response_started:
			self.response_started = True
			status_code_string, _ = status.split(" ", 1)
			status_code = int(status_code_string)
			headers = [
				(name.strip().encode("ascii").lower(), value.strip().encode("ascii"))
				for name, value in response_headers
			]
			self.send_queue.append(
				{
					"type": "http.response.start",
					"status": status_code,
					"headers": headers,
				}
			)
			self.loop.call_soon_threadsafe(self.send_event.set)

	def wsgi(self, environ: dict, start_response: typing.Callable) -> None:
		for chunk in self.app(environ, start_response):
			self.send_queue.append(
				{"type": "http.response.body", "body": chunk, "more_body": True}
			)
			self.loop.call_soon_threadsafe(self.send_event.set)

		self.send_queue.append({"type": "http.response.body", "body": b""})
		self.loop.call_soon_threadsafe(self.send_event.set)
