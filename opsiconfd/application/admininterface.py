# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
admininterface
"""

import collections
import datetime
import json
import os
import re
import signal
import tempfile
from operator import itemgetter
from shutil import move, rmtree, unpack_archive
from typing import Dict, List

import msgpack  # type: ignore[import]
from fastapi import APIRouter, Request, Response, UploadFile, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.routing import APIRoute, Mount
from OPSI import __version__ as python_opsi_version  # type: ignore[import]
from opsicommon.license import OpsiLicenseFile  # type: ignore[import]
from starlette.concurrency import run_in_threadpool

from .. import __version__, contextvar_client_session
from ..addon import AddonManager
from ..backend import get_backend, get_backend_interface
from ..config import FQDN, VAR_ADDON_DIR, config
from ..grafana import async_grafana_session, create_dashboard_user
from ..logging import logger
from ..session import OPSISession
from ..ssl import get_ca_cert_info, get_server_cert_info
from ..statistics import GRAFANA_DASHBOARD_UID
from ..utils import (
	async_redis_client,
	get_manager_pid,
	ip_address_from_redis_key,
	ip_address_to_redis_key,
	utc_time_timestamp,
)
from .memoryprofiler import memory_profiler_router
from .metrics import create_grafana_datasource

admin_interface_router = APIRouter()
welcome_interface_router = APIRouter()


def admin_interface_setup(app):
	app.include_router(router=admin_interface_router, prefix="/admin")
	app.include_router(router=memory_profiler_router, prefix="/admin/memory")
	app.include_router(router=welcome_interface_router, prefix="/welcome")


@welcome_interface_router.get("/")
async def welcome_interface_index(request: Request):

	ucs_server = False
	try:
		with open("/etc/lsb-release", encoding="utf8") as lsb_relase:
			logger.debug("Checking if we are on UCS.")
			if "univention" in lsb_relase.read():
				ucs_server = True
	except FileNotFoundError:
		logger.debug("No /etc/lsb-release found.")

	welcome_page = config.welcome_page

	client_lang = "en"
	if request.headers.get("accept-language", "").startswith("de"):
		client_lang = "de"
	context = {
		"request": request,
		"client_lang": client_lang,
		"opsi_version": f"{__version__} [python-opsi={python_opsi_version}]",
		"ucs_server": ucs_server,
		"welcome_page": welcome_page,
	}
	return config.jinja_templates.TemplateResponse("welcome.html", context)


@welcome_interface_router.post("/deactivate")
async def welcome_interface_deactivate():
	config.welcome_page = False
	config.set_config_in_config_file("welcome-page", "false")


@admin_interface_router.get("/")
async def admin_interface_index(request: Request):
	backend = get_backend()
	username = ""
	session = contextvar_client_session.get()
	if session and session.user_store:
		username = session.user_store.username
	interface = get_backend_interface()
	for method in interface:
		if method["doc"]:
			method["doc"] = re.sub(r"(\s*\n\s*)+\n+", "\n\n", method["doc"])  # pylint: disable=dotted-import-in-loop
			method["doc"] = method["doc"].replace("\n", "<br />").replace("\t", "&nbsp;&nbsp;&nbsp;").replace('"', "\\u0022")
	context = {
		"request": request,
		"opsi_version": f"{__version__} [python-opsi={python_opsi_version}]",
		"node_name": config.node_name,
		"username": username,
		"interface": interface,
		"ca_info": get_ca_cert_info(),
		"cert_info": get_server_cert_info(),
		"num_servers": get_num_servers(backend),
		"num_clients": get_num_clients(backend),
		"disabled_features": config.admin_interface_disabled_features,
		"addons": [
			{"id": addon.id, "name": addon.name, "version": addon.version, "install_path": addon.path, "path": addon.router_prefix}
			for addon in AddonManager().addons
		],
	}
	return config.jinja_templates.TemplateResponse("admininterface.html", context)


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
		response = JSONResponse(
			{"status": 500, "error": {"message": "Error while removing redis client keys", "detail": str(err)}}, status_code=500
		)
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
		response = JSONResponse(
			{"status": 500, "error": {"message": "Error while removing redis client keys", "detail": str(err)}}, status_code=500
		)
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
	addon_list = [
		{"id": addon.id, "name": addon.name, "version": addon.version, "install_path": addon.path, "path": addon.router_prefix}
		for addon in AddonManager().addons
	]
	return sorted(addon_list, key=itemgetter("id"))


def _install_addon(data: bytes):
	addon_installed = None
	join = os.path.join
	exists = os.path.exists
	isdir = os.path.isdir
	isfile = os.path.isfile
	listdir = os.listdir
	with tempfile.TemporaryDirectory() as tmp_dir:
		addon_file = join(tmp_dir, "addon.zip")
		with open(addon_file, "wb") as file:
			file.write(data)
		content_dir = join(tmp_dir, "content")
		unpack_archive(filename=addon_file, extract_dir=content_dir)
		for addon_id in listdir(content_dir):
			addon_dir = join(content_dir, addon_id)
			if isdir(addon_dir) and isdir(join(addon_dir, "python")) and isfile(join(addon_dir, "python", "__init__.py")):
				target = join(VAR_ADDON_DIR, addon_id)
				if exists(target):
					rmtree(target)
				move(addon_dir, target)
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
		value = msgpack.loads(value)  # pylint: disable=dotted-import-in-loop
		rpc = {
			"rpc_num": value.get("rpc_num"),
			"method": value.get("method"),
			"params": value.get("num_params"),
			"results": value.get("num_results"),
			"date": value.get("date", datetime.date(2020, 1, 1).strftime("%Y-%m-%dT%H:%M:%SZ")),  # pylint: disable=dotted-import-in-loop
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
		validity = session["max_age"] - (utc_time_timestamp() - session["last_used"])
		if validity <= 0:
			continue
		session_list.append(
			{
				"created": session["created"],
				"last_used": session["last_used"],
				"validity": validity,
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
async def unlock_product(request: Request, product: str) -> JSONResponse:
	backend = get_backend()
	depots = None
	try:
		request_body = await request.json()
		depots = request_body.get("depots", None)
	except json.decoder.JSONDecodeError:
		pass
	try:
		backend.unlockProduct(productId=product, depotIds=depots)  # pylint: disable=no-member
		response = JSONResponse({"status": 200, "error": None, "data": {"product": product, "action": "unlock"}})
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Error while removing redis session keys: %s", err)
		response = JSONResponse({"status": 500, "error": {"message": "Error while unlocking product", "detail": str(err)}}, status_code=500)
	return response


@admin_interface_router.post("/products/unlock")
def unlock_all_product():
	backend = get_backend()
	try:
		for product in set(
			pod.productId for pod in backend.productOnDepot_getObjects(depotId=[], locked=True)  # pylint: disable=no-member
		):
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
async def open_grafana(request: Request):
	if not config.grafana_external_url.startswith("/") and request.base_url.hostname not in (
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"localhost",
		FQDN,
	):
		url = f"{request.base_url.scheme}://{FQDN}:{request.base_url.port}{request.scope['path']}"
		logger.info("Redirecting %s to %s (%s)", request.base_url.hostname, FQDN, url)
		return RedirectResponse(url)

	redirect_response = RedirectResponse(url=f"{config.grafana_external_url}/d/{GRAFANA_DASHBOARD_UID}/opsiconfd-main-dashboard?kiosk=tv")
	try:
		await create_grafana_datasource()
		username, password = await create_dashboard_user()
		async with async_grafana_session(username, password) as (base_url, session):
			data = {"password": password, "user": "opsidashboard"}
			response = await session.post(f"{base_url}/login", json=data)
			if response.status != 200:
				logger.error("Grafana login failed: %s - %s", response.status, await response.text())
			else:
				match = re.search(r"grafana_session=([0-9a-f]+)", response.headers.get("Set-Cookie", ""))
				if match:
					redirect_response.set_cookie(key="grafana_session", value=match.group(1))
				else:
					logger.error("Failed to get grafana_session cookie")

	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)

	return redirect_response


@admin_interface_router.get("/config")
def get_confd_conf(all: bool = False) -> JSONResponse:  # pylint: disable=redefined-builtin

	keys_to_remove = (
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
	)

	current_config = config.items().copy()
	if not all:
		for key in keys_to_remove:
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


@admin_interface_router.get("/licensing_info")
def get_licensing_info() -> JSONResponse:
	info = get_backend().backend_getLicensingInfo(True, False, True, allow_cache=False)  # pylint: disable=no-member
	active_date = None
	modules: Dict[str, dict] = {}
	previous: Dict[str, dict] = {}
	for at_date, date_info in info.get("dates", {}).items():
		at_date = datetime.date.fromisoformat(at_date)  # pylint: disable=dotted-import-in-loop
		if (at_date <= datetime.date.today()) and (  # pylint: disable=dotted-import-in-loop,loop-invariant-statement
			not active_date or at_date > active_date
		):
			active_date = at_date

		for module_id, module in date_info["modules"].items():
			if module_id not in modules:
				modules[module_id] = {}
			modules[module_id][at_date.strftime("%Y-%m-%d")] = module
			module["changed"] = True
			if module_id in previous:
				module["changed"] = (
					module["state"] != previous[module_id]["state"]
					or module["license_ids"] != previous[module_id]["license_ids"]
					or module["client_number"] != previous[module_id]["client_number"]
				)
			previous[module_id] = module

	lic = (info.get("licenses") or [{}])[0]
	return JSONResponse(
		{
			"status": 200,
			"error": None,
			"data": {
				"info": {
					"customer_name": lic.get("customer_name", ""),
					"customer_address": lic.get("customer_address", ""),
					"customer_unit": lic.get("customer_unit", ""),
					"checksum": info["licenses_checksum"],
					"macos_clients": info["client_numbers"]["macos"],
					"linux_clients": info["client_numbers"]["linux"],
					"windows_clients": info["client_numbers"]["windows"],
					"all_clients": info["client_numbers"]["all"],
				},
				"module_dates": modules,
				"active_date": str(active_date) if active_date else None,
			},
		}
	)


@admin_interface_router.post("/license_upload")
async def license_upload(files: List[UploadFile]):
	try:
		for file in files:
			if not re.match(r"^\w[\w -]*\.opsilic$", file.filename):  # pylint: disable=dotted-import-in-loop
				raise ValueError(f"Invalid filename {file.filename!r}")
			olf = OpsiLicenseFile(os.path.join("/etc/opsi/licenses", file.filename))  # pylint: disable=dotted-import-in-loop
			olf.read_string((await file.read()).decode("utf-8"))  # type: ignore[union-attr]
			if not olf.licenses:
				raise ValueError(f"No license found in {file.filename!r}")
			logger.notice("Writing opsi license file %r", olf.filename)
			olf.write()
			os.chmod(olf.filename, 0o660)  # pylint: disable=dotted-import-in-loop
		return JSONResponse({"status": 201, "error": None, "data": f"{len(files)} opsi license files imported"}, status.HTTP_201_CREATED)
	except Exception as err:  # pylint: disable=broad-except
		logger.warning(err, exc_info=True)
		return JSONResponse({"status": 422, "error": f"Invalid license file: {err}", "data": None}, status.HTTP_422_UNPROCESSABLE_ENTITY)


def get_num_servers(backend):
	servers = len(backend.host_getIdents(type="OpsiDepotserver"))
	return servers


def get_num_clients(backend):
	clients = len(backend.host_getIdents(type="OpsiClient"))
	return clients
