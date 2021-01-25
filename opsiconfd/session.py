# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
:copyright: uib GmbH <info@uib.de>
:author: Jan Schneider <j.schneider@uib.de>
:license: GNU Affero General Public License version 3
"""

import time
import typing
import asyncio
from typing import List
from collections import namedtuple
import uuid
import base64
import datetime
import orjson

from fastapi import HTTPException, status
from fastapi.responses import PlainTextResponse, JSONResponse, RedirectResponse
from starlette.datastructures import MutableHeaders, Headers
from starlette.requests import HTTPConnection, Request
#from starlette.sessions import CookieBackend, Session, SessionBackend
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from aredis.exceptions import ResponseError
from OPSI.Backend.Manager.AccessControl import UserStore
from OPSI.Util import serialize, deserialize, ipAddressInNetwork, timestamp
from OPSI.Exceptions import BackendAuthenticationError, BackendPermissionDeniedError

from .logging import logger, secret_filter, set_context # pylint: disable=no-name-in-module
from .worker import (
	sync_redis_client, get_redis_client, run_in_threadpool,
	contextvar_client_session, contextvar_server_timing
)
from .backend import get_client_backend
from .config import config
from .utils import get_fqdn

"""
https://github.com/tiangolo/fastapi/blob/master/docs/tutorial/middleware.md

You can add middleware to FastAPI applications.

A "middleware" is a function that works with every request before it is processed by any specific path operation.
And also with every response before returning it.

	It takes each request that comes to your application.
	It can then do something to that request or run any needed code.
	Then it passes the request to be processed by the rest of the application (by some path operation).
	It then takes the response generated by the application (by some path operation).
	It can do something to that response or run any needed code.
	Then it returns the response.
""" # pylint: disable=pointless-string-statement

BasicAuth = namedtuple("BasicAuth", ["username", "password"])
def get_basic_auth(headers: Headers):
	auth_header = headers.get("authorization")
	if not auth_header:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Authorization header missing",
			headers={"WWW-Authenticate": 'Basic realm="opsi", charset="UTF-8"'}
		)

	if not auth_header.startswith("Basic "):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Authorization method unsupported",
			headers={"WWW-Authenticate": 'Basic realm="opsi", charset="UTF-8"'}
		)

	encoded_auth = auth_header[6:] # Stripping "Basic "
	secret_filter.add_secrets(encoded_auth)
	auth = base64.decodebytes(encoded_auth.encode("ascii")).decode("utf-8")

	(username, password) = auth.split(':', 1)
	secret_filter.add_secrets(password)

	return BasicAuth(username, password)

def authenticate(connection: HTTPConnection) -> None:
	auth = get_basic_auth(connection.headers)
	auth_type = None
	if auth.username == "monitoring":
		auth_type = "opsi-passwd"
	get_client_backend().backendAccessControl.authenticate(auth.username, auth.password, auth_type=auth_type)

def get_session_from_context():
	try:
		return contextvar_client_session.get()
	except LookupError as exc:
		logger.debug("Failed to get session from context: %s", exc)


class SessionMiddleware:
	def __init__(self, app: ASGIApp, public_path: List[str] = []) -> None: # pylint: disable=dangerous-default-value
		self.app = app
		self.session_cookie_name = 'opsiconfd-session'
		self.max_age = 120  # in seconds
		#self.security_flags = "httponly; samesite=lax; secure"
		self.security_flags = ""
		self._public_path = public_path

	def get_set_cookie_string(self, session_id) -> dict:
		return f"{self.session_cookie_name}={session_id}; path=/; Max-Age={self.max_age}"

	def get_session_id_from_headers(self, headers: Headers) -> str: # pylint: disable=inconsistent-return-statements
		#connection.cookies.get(self.session_cookie_name, None) # pylint: disable=inconsistent-return-statements
		# Not working for opsi-script, which sometimes sends:
		# 'NULL; opsiconfd-session=7b9efe97a143438684267dfb71cbace2'
		# Workaround:
		cookies = headers.get("cookie")
		if cookies:
			for cookie in cookies.split(';'):
				cookie = cookie.strip().split('=', 1)
				if len(cookie) == 2:
					if cookie[0].strip().lower() == self.session_cookie_name:
						return cookie[1].strip().lower()

	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None: # pylint: disable=too-many-locals, too-many-branches, too-many-statements
		start = time.perf_counter()
		connection = HTTPConnection(scope)
		session = None
		client_address = connection.client.host
		set_context({"client_address": client_address})
		logger.trace("SessionMiddleware %s", scope)
		try:
			if config.networks:
				is_allowed_network = False
				for network in config.networks:
					if ipAddressInNetwork(client_address, network):
						is_allowed_network = True
						break

				if not is_allowed_network:
					raise ConnectionRefusedError(f"Host '{client_address}' is not allowed to connect")

			redis_client = await get_redis_client()
			if scope["type"] not in ("http", "websocket"):
				await self.app(scope, receive, send)
				return

			is_public = False
			for p in self._public_path: # pylint: disable=invalid-name
				if scope["path"].startswith(f"{p}"):
					is_public = True

			if scope["path"] == "/admin" or scope["path"] == "/":
				request = Request(scope, receive)
				fqdn = get_fqdn()
				hostname = request.base_url.hostname
				if ("localhost" in hostname or "127.0.0.1" in hostname) and request.base_url.hostname != fqdn:
					url = f"https://{fqdn}:{request.url.port}/admin"
					logger.info("Redirecting to %s ...", url)
					response = RedirectResponse(url, status_code=308)
					await response(scope, receive, send)
					return

			session_id = self.get_session_id_from_headers(connection.headers)
			if not is_public or session_id:
				session = OPSISession(self, session_id, connection)
				await session.init()
			contextvar_client_session.set(session)
			scope["session"] = session

			#sht = (time.perf_counter() - start) * 1000
			#if sht > 100:
			#	logger.warning("Session init took %0.2fms", sht)

			auth_done = False
			if not is_public:
				if not session.user_store.username or not session.user_store.authenticated:
					# Check if blocked
					is_blocked = bool(await redis_client.get(f"opsiconfd:stats:client:blocked:{connection.client.host}"))
					if not is_blocked:
						now = round(time.time())*1000
						cmd = f"ts.range opsiconfd:stats:client:failed_auth:{connection.client.host} {(now-(config.auth_failures_interval*1000))} {now} aggregation count {(config.auth_failures_interval*1000)}" # pylint: disable=line-too-long
						logger.debug(cmd)
						try:
							num_failed_auth = await redis_client.execute_command(cmd)
							num_failed_auth =  int(num_failed_auth[-1][1])
							logger.debug("num_failed_auth: %s", num_failed_auth)
						except ResponseError as err:
							num_failed_auth = 0
							if str(err).find("key does not exist") == -1:
								raise
						if num_failed_auth > config.max_auth_failures:
							is_blocked = True
							logger.warning("Blocking client '%s' for %0.2f minutes", connection.client.host, (config.client_block_time/60))
							await redis_client.setex(f"opsiconfd:stats:client:blocked:{connection.client.host}", config.client_block_time, True)
					if is_blocked:
						raise ConnectionRefusedError(f"Client '{connection.client.host}' is blocked")

					# Authenticate
					logger.info("Start authentication of client %s", connection.client.host)
					await run_in_threadpool(authenticate, connection)
					auth_done = True

					if session.user_store.host:
						logger.info("Host authenticated, updating host object")
						await run_in_threadpool(update_host_object, connection, session)

					if session.user_store.isAdmin and config.admin_networks:
						is_admin_network = False
						for network in config.admin_networks:
							if ipAddressInNetwork(connection.client.host, network):
								is_admin_network = True
								break

						if not is_admin_network:
							logger.warning("User '%s' from '%s' not in admin network '%s'",
								session.user_store.username,
								connection.client.host,
								config.admin_networks
							)
							session.user_store.isAdmin = False
							asyncio.get_event_loop().create_task(session.store())

				# Check authorization
				needs_admin = not (
					scope["path"].startswith(("/rpc", "/depot", "/monitoring")) and
					scope.get("method") in ("GET", "HEAD")
				)

				if needs_admin and not session.user_store.isAdmin:
					raise BackendPermissionDeniedError(f"Not an admin user '{session.user_store.username}'")

			server_timing = contextvar_server_timing.get()
			sht = (time.perf_counter() - start) * 1000
			if not auth_done and sht > 1000:
				logger.warning("Session handling took %0.2fms", sht)
			server_timing["session_handling"] = sht

			contextvar_server_timing.set(server_timing)

			async def send_wrapper(message: Message) -> None:
				if message["type"] == "http.response.start":
					if session:
						asyncio.get_event_loop().create_task(session.store())
						headers = MutableHeaders(scope=message)
						headers.append("Set-Cookie", self.get_set_cookie_string(session.session_id))
				await send(message)

			await self.app(scope, receive, send_wrapper)

		except Exception as err: # pylint: disable=broad-except
			status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
			headers = None
			error = None

			if isinstance(err, BackendAuthenticationError) or isinstance(err, BackendPermissionDeniedError): # pylint: disable=consider-merging-isinstance
				logger.debug(err, exc_info=True)
				logger.warning(err)

				status_code = status.HTTP_401_UNAUTHORIZED
				headers = {"WWW-Authenticate": 'Basic realm="opsi", charset="UTF-8"'}
				error = "Authentication error"
				if isinstance(err, BackendPermissionDeniedError):
					error = "Permission denied"
				cmd = f"ts.add opsiconfd:stats:client:failed_auth:{connection.client.host} * 1 RETENTION 86400000 LABELS client_addr {connection.client.host}" # pylint: disable=line-too-long
				logger.debug(cmd)
				asyncio.get_event_loop().create_task(redis_client.execute_command(cmd)) # type: ignore

			elif isinstance(err, ConnectionRefusedError):
				status_code = status.HTTP_403_FORBIDDEN
				error = str(err)

			elif isinstance(err, HTTPException):
				status_code = err.status_code # pylint: disable=no-member
				headers = err.headers # pylint: disable=no-member
				error = str(err)

			else:
				logger.error(err, exc_info=True)
				error = str(err)

			if scope["type"] == "websocket":
				await send({"type": "websocket.close", "code": status_code})
			else:
				response = None
				headers = headers or {}
				if session and session.session_id:
					headers.update({"Set-Cookie": self.get_set_cookie_string(session.session_id)})

				if scope["path"].startswith("/rpc"):
					logger.debug("Returning jsonrpc response because path startswith /rpc")
					response = JSONResponse(
						status_code=status_code,
						content={"jsonrpc": "2.0", "id": None, "result": None, "error": error},
						headers=headers
					)
				if not response:
					if connection.headers.get("accept") and "application/json" in connection.headers.get("accept"):
						logger.debug("Returning json response because of accept header")
						response = JSONResponse(
							status_code=status_code,
							content={"error": error},
							headers=headers
						)
				if not response:
					logger.debug("Returning plaintext response")
					response = PlainTextResponse(
						status_code=status_code,
						content=error,
						headers=headers
					)
				await response(scope, receive, send)

class OPSISession(): # pylint: disable=too-many-instance-attributes
	redis_key_prefix = "opsiconfd:sessions"

	def __init__(self, session_middelware: SessionMiddleware, session_id: str, connection: HTTPConnection) -> None:
		self._session_middelware = session_middelware
		self.session_id = session_id
		self.client_addr = connection.client.host
		self.user_agent = connection.headers.get("user-agent")
		self.created = 0
		self.last_used = 0
		self.user_store = UserStore()
		self.option_store = {}
		self._data: typing.Dict[str, typing.Any] = {}
		self.is_new_session = True

	def __repr__(self):
		return f"<{self.__class__.__name__} at {hex(id(self))} created={self.created} last_used={self.last_used}>"

	@classmethod
	def utc_time_timestamp(cls):
		dt = datetime.datetime.now() # pylint: disable=invalid-name
		utc_time = dt.replace(tzinfo=datetime.timezone.utc)
		return utc_time.timestamp()

	@property
	def max_age(self):
		return self._session_middelware.max_age

	@property
	def session_cookie_name(self):
		return self._session_middelware.session_cookie_name

	@property
	def redis_key(self) -> str:
		assert self.session_id
		return f"{self.redis_key_prefix}:{self.client_addr}:{self.session_id}"

	@property
	def expired(self) -> bool:
		return self.utc_time_timestamp() - self.last_used > self.max_age

	async def init(self) -> None:
		if self.session_id is None:
			logger.debug("Session id missing (%s / %s)", self.client_addr, self.user_agent)
			await self.init_new_session()
		else:
			if await self.load():
				if self.expired:
					logger.debug("Session expired: %s (%s / %s)", self, self.client_addr, self.user_agent)
					await self.init_new_session()
				else:
					logger.debug("Reusing session: %s (%s / %s)", self, self.client_addr, self.user_agent)
			else:
				logger.debug("Session not found: %s (%s / %s)", self, self.client_addr, self.user_agent)
				await self.init_new_session()

		if not self.created:
			self.created = self.utc_time_timestamp()
		self._update_last_used()
		await self.store()

	def _init_new_session(self) -> None:
		"""Generate a new session id if number of client sessions is less than max client sessions."""
		redis_session_keys = []
		try:
			with sync_redis_client() as redis:
				for key in redis.scan_iter(f"{self.redis_key_prefix}:{self.client_addr}:*"):
					redis_session_keys.append(key.decode("utf8"))
			#redis_client = await get_redis_client()
			#async for key in redis_client.scan_iter(f"{self.redis_key_prefix}:{self.client_addr}:*"):
			#	redis_session_keys.append(key.decode("utf8"))
			if config.max_session_per_ip > 0 and len(redis_session_keys) > config.max_session_per_ip:
				error = f"Too many sessions from {self.client_addr} / {self.user_agent}, configured maximum is: {config.max_session_per_ip}"
				logger.warning(error)
				raise ConnectionRefusedError(error)
		except ConnectionRefusedError as err:
			raise HTTPException(
				status_code=status.HTTP_403_FORBIDDEN,
				detail=str(err)
			) from err

		self.session_id = str(uuid.uuid4()).replace("-", "")
		logger.confidential("Generated a new session id %s for %s / %s", self.session_id, self.client_addr, self.user_agent)

	async def init_new_session(self) -> None:
		await run_in_threadpool(self._init_new_session)

	def _load(self) -> bool:
		self._data = {}
		"""
		# This is to slow!
		redis_session_keys = []
		async for redis_key in redis_client.scan_iter(f"{self.redis_key_prefix}:*:{self.session_id}"):
			redis_session_keys.append(redis_key.decode("utf8"))
		if len(redis_session_keys) == 0:
			return False
		# There sould only be one key with self.session_id in redis.
		# Logging if there is a problem in the future.
		if len(redis_session_keys) > 1:
			logger.warning("More than one redis key with same session id!")
		if redis_session_keys[0] != self.redis_key:
			await redis_client.rename(redis_session_keys[0], self.redis_key)
		""" # pylint: disable=pointless-string-statement
		with sync_redis_client() as redis:
			#start = time.perf_counter()
			data = redis.get(self.redis_key)
			#ms = (time.perf_counter() - start) * 1000
			#if ms > 100:
			#	logger.warning("Session loading from redis took %0.2fms", ms)
		if not data:
			return False
		data = orjson.loads(data) # pylint: disable=c-extension-no-member
		self.created = data.get("created", self.created)
		self.last_used = data.get("last_used", self.last_used)
		for k, v in data.get("user_store", {}).items(): # pylint: disable=invalid-name
			setattr(self.user_store, k, deserialize(v))
		self.option_store = data.get("option_store", self.option_store)
		self._data = data.get("data", self._data)
		self.is_new_session = False
		return True

	async def load(self) -> bool:
		# aredis is sometimes slow ~300ms load, using redis for now
		return await run_in_threadpool(self._load)

	def _store(self) -> None:
		data = {
			"created": self.created,
			"last_used": self.last_used,
			"user_store": serialize(self.user_store.__dict__),
			"option_store": self.option_store,
			"data": self._data
		}
		# Set is not serializable
		if "userGroups" in data["user_store"]:
			data["user_store"]["userGroups"] = list(data["user_store"]["userGroups"])
		# Do not store password
		if "password" in data["user_store"]:
			del data["user_store"]["password"]
		with sync_redis_client() as redis:
			#start = time.perf_counter()
			redis.set(self.redis_key, orjson.dumps(data), ex=self.max_age) # pylint: disable=c-extension-no-member
			#ms = (time.perf_counter() - start) * 1000
			#if ms > 100:
			#	logger.warning("Session storing to redis took %0.2fms", ms)
		#redis_client = await get_redis_client()
		#await redis_client.set(self.redis_key, orjson.dumps(data), ex=self.max_age)

	async def store(self) -> None:
		# aredis is sometimes slow ~300ms load, using redis for now
		await run_in_threadpool(self._store)

	def _update_last_used(self):
		self.last_used = self.utc_time_timestamp()

	def get(self, name: str, default: typing.Any = None) -> typing.Any:
		return self._data.get(name, default)

	def set(self, key: str, value: typing.Any) -> None:
		self._data[key] = value


def update_host_object(connection: HTTPConnection, session: OPSISession) -> None:
	hosts = get_client_backend().host_getObjects(['ipAddress', 'lastSeen'], id=session.user_store.host.id) # pylint: disable=no-member
	if not hosts:
		logger.error("Host %s not found in backend while trying to update ip address and lastseen", session.user_store.host.id)
		return
	host = hosts[0]
	if host.getType() != 'OpsiClient':
		return
	host.setLastSeen(timestamp())
	if config.update_ip and connection.client.host not in (None, "127.0.0.1", "::1", host.ipAddress):
		host.setIpAddress(connection.client.host)
	else:
		# Value None on update means no change!
		host.ipAddress = None
	get_client_backend().host_updateObjects(host) # pylint: disable=no-member
