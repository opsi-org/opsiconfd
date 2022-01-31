# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
admininterface
"""

from urllib.parse import urlparse
from operator import itemgetter
import os
import signal
import datetime
import collections
import shutil
import tempfile
import msgpack  # type: ignore[import]
import requests
import orjson

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.routing import APIRoute, Mount
from starlette.concurrency import run_in_threadpool

from OPSI import __version__ as python_opsi_version  # type: ignore[import]
from OPSI.Exceptions import BackendPermissionDeniedError  # type: ignore[import]

from .. import __version__, contextvar_client_session
from ..session import OPSISession
from ..logging import logger
from ..config import config, FQDN, VAR_ADDON_DIR
from ..backend import get_backend_interface, get_backend
from ..utils import (
	utc_time_timestamp,
	get_random_string,
	get_manager_pid,
	async_redis_client,
	ip_address_to_redis_key,
	ip_address_from_redis_key,
)
from ..ssl import get_ca_cert_info, get_server_cert_info
from ..addon import AddonManager

from .memoryprofiler import memory_profiler_router


admin_interface_router = APIRouter()


def admin_interface_setup(app):
	app.include_router(router=admin_interface_router, prefix="/admin")
	app.include_router(router=memory_profiler_router, prefix="/admin/memory")


@admin_interface_router.get("/")
async def admin_interface_index(request: Request):
	backend = get_backend()
	username = ""
	session = contextvar_client_session.get()
	if session and session.user_store:
		username = session.user_store.username
	context = {
		"request": request,
		"opsi_version": f"{__version__} [python-opsi={python_opsi_version}]",
		"node_name": config.node_name,
		"username": username,
		"interface": get_backend_interface(),
		"ca_info": get_ca_cert_info(),
		"cert_info": get_server_cert_info(),
		"num_servers": get_num_servers(backend),
		"num_clients": get_num_clients(backend),
	}
	return config.jinja_templates.TemplateResponse("admininterface.html", context)


@admin_interface_router.post("/logout")
async def logout(request: Request):
	return_401 = False
	try:
		request_body = await request.json()
		return_401 = request_body["return_401"]
	except Exception:  # pylint: disable=broad-except
		pass
	client_session = contextvar_client_session.get()
	if client_session:
		await client_session.delete()
	if return_401:
		raise BackendPermissionDeniedError("Session deleted")
	return JSONResponse({"status": 200, "error": None, "data": "session deleted"})


@admin_interface_router.post("/reload")
async def reload():
	os.kill(get_manager_pid(), signal.SIGHUP)
	return JSONResponse({"status": 200, "error": None, "data": "reload sent"})


@admin_interface_router.post("/unblock-all")
async def unblock_all_clients(response: Response):
	redis = await async_redis_client()

	try:
		clients = set()
		deleted_keys = set()
		async with redis.pipeline(transaction=False) as pipe:
			for base_key in ("opsiconfd:stats:client:failed_auth", "opsiconfd:stats:client:blocked"):

				async for key in redis.scan_iter(f"{base_key}:*"):
					key_str = key.decode("utf8")
					deleted_keys.add(key_str)
					client = ip_address_from_redis_key(key_str.split(":")[-1])
					clients.add(client)
					logger.debug("redis key to delete: %s", key_str)
					await pipe.delete(key)
			await pipe.execute()
		response = JSONResponse({"status": 200, "error": None, "data": {"clients": list(clients), "redis-keys": list(deleted_keys)}})
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Error while removing redis client keys: %s", err)
		response = JSONResponse({"status": 500, "error": {"message": "Error while removing redis client keys", "detail": str(err)}})
	return response


@admin_interface_router.post("/unblock-client")
async def unblock_client(request: Request):
	try:
		request_body = await request.json()
		client_addr = request_body.get("client_addr")

		logger.debug("unblock client addr: %s ", client_addr)
		client_addr_redis = ip_address_to_redis_key(client_addr)
		redis = await async_redis_client()
		deleted_keys = []
		redis_code = await redis.delete(f"opsiconfd:stats:client:failed_auth:{client_addr_redis}")
		if redis_code == 1:
			deleted_keys.append(f"opsiconfd:stats:client:failed_auth:{client_addr_redis}")
		redis_code = await redis.delete(f"opsiconfd:stats:client:blocked:{client_addr_redis}")
		if redis_code == 1:
			deleted_keys.append(f"opsiconfd:stats:client:blocked:{client_addr_redis}")

		response = JSONResponse({"status": 200, "error": None, "data": {"client": client_addr, "redis-keys": deleted_keys}})
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Error while removing redis client keys: %s", err)
		response = JSONResponse({"status": 500, "error": {"message": "Error while removing redis client keys", "detail": str(err)}})
	return response


@admin_interface_router.post("/delete-client-sessions")
async def delete_client_sessions(request: Request):
	try:
		request_body = await request.json() or {}
		client_addr = request_body.get("client_addr")
		if not request_body:
			raise ValueError("client_addr missing")
		redis = await async_redis_client()
		sessions = []
		deleted_keys = []
		keys = redis.scan_iter(f"{OPSISession.redis_key_prefix}:{ip_address_to_redis_key(client_addr)}:*")
		if keys:
			async with redis.pipeline(transaction=False) as pipe:
				async for key in keys:
					sessions.append(key.decode("utf8").split(":")[-1])
					deleted_keys.append(key.decode("utf8"))
					await pipe.delete(key)
				await pipe.execute()

		response = JSONResponse(
			{"status": 200, "error": None, "data": {"client": client_addr, "sessions": sessions, "redis-keys": deleted_keys}}
		)
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Error while removing redis session keys: %s", err)
		response = JSONResponse({"status": 500, "error": {"message": "Error while removing redis client keys", "detail": str(err)}})
	return response


@admin_interface_router.get("/addons")
async def get_addon_list() -> list:
	addon_list = []
	for addon in AddonManager().addons:
		addon_list.append(
			{"id": addon.id, "name": addon.name, "version": addon.version, "install_path": addon.path, "path": addon.router_prefix}
		)
	return sorted(addon_list, key=itemgetter("id"))


def _install_addon(data: bytes):
	addon_installed = None
	with tempfile.TemporaryDirectory() as tmp_dir:
		addon_file = os.path.join(tmp_dir, "addon.zip")
		with open(addon_file, "wb") as file:
			file.write(data)
		content_dir = os.path.join(tmp_dir, "content")
		shutil.unpack_archive(filename=addon_file, extract_dir=content_dir)
		for addon_id in os.listdir(content_dir):
			addon_dir = os.path.join(content_dir, addon_id)
			if (
				os.path.isdir(addon_dir)
				and os.path.isdir(os.path.join(addon_dir, "python"))
				and os.path.isfile(os.path.join(addon_dir, "python", "__init__.py"))
			):
				target = os.path.join(VAR_ADDON_DIR, addon_id)
				if os.path.exists(target):
					shutil.rmtree(target)
				shutil.move(addon_dir, target)
				addon_installed = addon_id

	if not addon_installed:
		raise RuntimeError("Invalid addon")

	manager_pid = get_manager_pid()
	if manager_pid:
		os.kill(manager_pid, signal.SIGHUP)


@admin_interface_router.post("/addons/install")
async def install_addon(request: Request) -> list:
	form = await request.form()
	if isinstance(form["addonfile"], str):
		raise RuntimeError("Invalid addon")
	data = await form["addonfile"].read()
	await run_in_threadpool(_install_addon, data)


@admin_interface_router.get("/rpc-list")
async def get_rpc_list() -> list:

	redis = await async_redis_client()
	redis_result = await redis.lrange("opsiconfd:stats:rpcs", 0, -1)

	rpc_list = []
	for value in redis_result:
		try:
			value = msgpack.loads(value)
		except msgpack.exceptions.ExtraData:
			# Was json encoded before, can be removed in the future
			value = orjson.loads(value)  # pylint: disable=no-member
		rpc = {
			"rpc_num": value.get("rpc_num"),
			"method": value.get("method"),
			"params": value.get("num_params"),
			"results": value.get("num_results"),
			"date": value.get("date", datetime.date(2020, 1, 1).strftime("%Y-%m-%dT%H:%M:%SZ")),
			"client": value.get("client", "0.0.0.0"),
			"error": value.get("error"),
			"duration": value.get("duration"),
		}
		rpc_list.append(rpc)

	rpc_list = sorted(rpc_list, key=itemgetter("rpc_num"))
	return rpc_list


@admin_interface_router.get("/rpc-count")
async def get_rpc_count():
	redis = await async_redis_client()
	count = await redis.llen("opsiconfd:stats:rpcs")

	response = JSONResponse({"rpc_count": count})
	return response


@admin_interface_router.get("/session-list")
async def get_session_list() -> list:
	redis = await async_redis_client()
	session_list = []
	async for redis_key in redis.scan_iter("opsiconfd:sessions:*"):
		data = await redis.get(redis_key)
		session = msgpack.loads(data)
		tmp = redis_key.decode().split(":")
		session_list.append(
			{
				"created": session["created"],
				"last_used": session["last_used"],
				"validity": session["max_age"] - (utc_time_timestamp() - session["last_used"]),
				"max_age": session["max_age"],
				"user_agent": session["user_agent"],
				"authenticated": session["user_store"].get("authenticated"),
				"username": session["user_store"].get("username"),
				"address": ip_address_from_redis_key(tmp[-2]),
				"session_id": tmp[-1][:6] + "...",
			}
		)
	session_list = sorted(session_list, key=itemgetter("address", "validity"))
	return session_list


@admin_interface_router.get("/locked-products-list")
async def get_locked_products_list() -> list:
	backend = get_backend()
	products = backend.getProductLocks_hash()  # pylint: disable=no-member
	return products


@admin_interface_router.post("/products/{product}/unlock")
def unlock_product(product):
	backend = get_backend()
	try:
		backend.unlockProduct(product)  # pylint: disable=no-member
		response = JSONResponse({"status": 200, "error": None, "data": {"product": product, "action": "unlock"}})
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Error while removing redis session keys: %s", err)
		response = JSONResponse({"status": 500, "error": {"message": "Error while unlocking product", "detail": str(err)}})
	return response


@admin_interface_router.post("/products/unlock")
def unlock_all_product():
	backend = get_backend()
	products = []
	for pod in backend.productOnDepot_getObjects(depotId=[], locked=True):  # pylint: disable=no-member
		if pod.productId not in products:
			products.append(pod.productId)
	try:
		for product in products:
			backend.unlockProduct(product)  # pylint: disable=no-member
		response = JSONResponse({"status": 200, "error": None, "data": None})
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Error while removing redis session keys: %s", err)
		response = JSONResponse({"status": 500, "error": {"message": "Error while unlocking products", "detail": str(err)}})
	return response


@admin_interface_router.get("/blocked-clients")
async def get_blocked_clients() -> list:
	redis = await async_redis_client()
	redis_keys = redis.scan_iter("opsiconfd:stats:client:blocked:*")

	blocked_clients = []
	async for key in redis_keys:
		logger.debug("redis key to delete: %s", key)
		blocked_clients.append(ip_address_from_redis_key(key.decode("utf8").split(":")[-1]))
	return blocked_clients


@admin_interface_router.get("/grafana")
def open_grafana(request: Request):

	if request.base_url.hostname != FQDN:
		return RedirectResponse(f"https://{FQDN}:{request.url.port}/admin/grafana")

	auth = None
	headers = None
	url = urlparse(config.grafana_internal_url)
	if url.username is not None:
		if url.password is None:
			# Username only, assuming this is an api key
			logger.debug("Using api key for grafana authorization")
			headers = {"Authorization": f"Bearer {url.username}"}
		else:
			logger.debug("Using username %s and password grafana authorization", url.username)
			auth = (url.username, url.password)

	session = requests.Session()
	session.verify = config.ssl_trusted_certs
	if not config.grafana_verify_cert:
		session.verify = False

	response = session.get(
		f"{url.scheme}://{url.hostname}:{url.port}/api/users/lookup?loginOrEmail=opsidashboard", headers=headers, auth=auth
	)

	password = get_random_string(8)
	if response.status_code == 404:
		logger.debug("Create new user opsidashboard")

		data = {"name": "opsidashboard", "email": "opsidashboard@admin", "login": "opsidashboard", "password": password, "OrgId": 1}
		response = session.post(f"{url.scheme}://{url.hostname}:{url.port}/api/admin/users", headers=headers, auth=auth, data=data)
		if response.status_code != 200:
			logger.error("Failed to create user opsidashboard: %s - %s", response.status_code, response.text)
	else:
		logger.debug("change opsidashboard password")
		data = {"password": password}
		user_id = response.json().get("id")
		response = session.put(f"{config.grafana_internal_url}/api/admin/users/{user_id}/password", headers=headers, auth=auth, data=data)
		if response.status_code != 200:
			logger.error("Failed to update password for user opsidashboard: %s - %s", response.status_code, response.text)

	redirect_response = RedirectResponse("/metrics/grafana/dashboard")
	data = {"password": password, "user": "opsidashboard"}
	response = session.post(f"{url.scheme}://{url.hostname}:{url.port}/login", json=data)
	if response.status_code != 200:
		logger.error("Grafana login failed: %s - %s", response.status_code, response.text)
	else:
		redirect_response.set_cookie(key="grafana_session", value=session.cookies.get_dict().get("grafana_session"))
	return redirect_response


@admin_interface_router.get("/config")
def get_confd_conf(all: bool = False) -> JSONResponse:  # pylint: disable=redefined-builtin

	KEYS_TO_REMOVE = [  # pylint: disable=invalid-name
		"version",
		"setup",
		"action",
		"ex_help",
		"log_max_msg_len",
		"debug",
		"profiler",
		"server_type",
		"node_name",
		"executor_workers",
		"log_slow_async_callbacks",
		"ssl_ca_key_passphrase",
		"ssl_server_key_passphrase",
	]

	current_config = config.items().copy()
	if not all:
		for key in KEYS_TO_REMOVE:
			if key in current_config:
				del current_config[key]
	current_config = {key.replace("_", "-"): value for key, value in sorted(current_config.items())}

	return JSONResponse({"status": 200, "error": None, "data": {"config": current_config}})


@admin_interface_router.get("/routes")
def get_routes(request: Request) -> JSONResponse:  # pylint: disable=redefined-builtin
	app = request.app
	routes = {}
	for route in app.routes:
		if isinstance(route, Mount):
			routes[route.path] = str(route.app.__module__)
		elif isinstance(route, APIRoute):
			module = route.endpoint.__module__
			if module.startswith("opsiconfd.addon_"):
				module = f"opsiconfd.addon.{module.split('/')[-1]}"
			routes[route.path] = f"{module}.{route.endpoint.__qualname__}"
		else:
			routes[route.path] = route.__class__.__name__

	return JSONResponse({"status": 200, "error": None, "data": collections.OrderedDict(sorted(routes.items()))})


def get_num_servers(backend):
	servers = len(backend.host_getIdents(type="OpsiDepotserver"))
	return servers


def get_num_clients(backend):
	clients = len(backend.host_getIdents(type="OpsiClient"))
	return clients
