# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
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
from typing import Any
from urllib.parse import urlparse

import msgspec
from fastapi import APIRouter, FastAPI, Request, Response, UploadFile, status
from fastapi.responses import RedirectResponse
from fastapi.routing import APIRoute, Mount
from opsicommon import __version__ as python_opsi_common_version
from opsicommon.license import OpsiLicenseFile
from opsicommon.objects import OpsiDepotserver
from opsicommon.system.info import linux_distro_id_like_contains
from redis import ResponseError
from starlette.concurrency import run_in_threadpool

from opsiconfd import __version__, contextvar_client_session
from opsiconfd.addon import AddonManager
from opsiconfd.application import AppState
from opsiconfd.application.memoryprofiler import memory_profiler_router
from opsiconfd.application.metrics import create_grafana_datasource
from opsiconfd.backend import get_protected_backend, get_unprotected_backend
from opsiconfd.backend.rpc.depot import TransferSlotType
from opsiconfd.backend.rpc.obj_host import auto_fill_depotserver_urls
from opsiconfd.config import FQDN, VAR_ADDON_DIR, config, jinja_templates
from opsiconfd.grafana import (
	GRAFANA_DASHBOARD_UID,
	async_grafana_session,
	create_dashboard_user,
)
from opsiconfd.logging import logger
from opsiconfd.messagebus.redis import CHANNEL_INFO_SUFFIX, get_websocket_connected_users
from opsiconfd.redis import (
	async_redis_client,
	decode_redis_result,
	ip_address_from_redis_key,
	ip_address_to_redis_key,
	redis_client,
)
from opsiconfd.rest import RESTErrorResponse, RESTResponse, rest_api
from opsiconfd.session import OPSISession
from opsiconfd.ssl import get_ca_certs_info, get_server_cert_info
from opsiconfd.utils import get_manager_pid

admin_interface_router = APIRouter()
welcome_interface_router = APIRouter()


def admin_interface_setup(app: FastAPI) -> None:
	app.include_router(router=admin_interface_router, prefix="/admin")
	app.include_router(router=memory_profiler_router, prefix="/admin/memory")
	app.include_router(router=welcome_interface_router, prefix="/welcome")


@welcome_interface_router.get("/")
async def welcome_interface_index(request: Request) -> Response:
	welcome_page = config.welcome_page

	webgui = False
	for addon in AddonManager().addons:
		if addon.id == "webgui":
			webgui = True

	client_lang = "en"
	if request.headers.get("accept-language", "").startswith("de"):
		client_lang = "de"
	context = {
		"request": request,
		"client_lang": client_lang,
		"opsi_version": f"{__version__} [python-opsi-common={python_opsi_common_version}]",
		"ucs_server": linux_distro_id_like_contains("univention"),
		"webgui": webgui,
		"welcome_page": welcome_page,
	}
	return jinja_templates().TemplateResponse(request=request, name="welcome.html", context=context)


@welcome_interface_router.post("/deactivate")
async def welcome_interface_deactivate() -> None:
	config.welcome_page = False
	config.set_config_in_config_file("welcome-page", "false")


@admin_interface_router.get("/")
async def admin_interface_index(request: Request) -> Response:
	backend = get_protected_backend()
	username = ""
	session = contextvar_client_session.get()
	if session and session.username:
		username = session.username
	interface = backend.get_interface()
	for method in interface:
		if method["doc"]:
			method["doc"] = re.sub(r"(\s*\n\s*)+\n+", "\n\n", method["doc"])
			method["doc"] = method["doc"].replace("\n", "<br />").replace("\t", "&nbsp;&nbsp;&nbsp;").replace('"', "\\u0022")

	ca_infos = get_ca_certs_info()
	for ca_info in ca_infos:
		ca_info["issuer_txt"] = ", ".join(f"{k} = {v}" for k, v in ca_info["issuer"].items() if v)
		ca_info["subject_txt"] = ", ".join(f"{k} = {v}" for k, v in ca_info["subject"].items() if v)

	cert_info = get_server_cert_info()
	cert_info["issuer_txt"] = ", ".join(f"{k} = {v}" for k, v in cert_info["issuer"].items() if v)
	cert_info["subject_txt"] = ", ".join(f"{k} = {v}" for k, v in cert_info["subject"].items() if v)
	context = {
		"request": request,
		"opsi_version": f"{__version__} [python-opsi-common={python_opsi_common_version}]",
		"node_name": config.node_name,
		"username": username,
		"interface": interface,
		"available_modules": backend.available_modules,
		"ca_infos": ca_infos,
		"cert_info": cert_info,
		"num_servers": get_num_servers(),
		"num_clients": get_num_clients(),
		"disabled_features": config.disabled_features,
		"addons": [
			{"id": addon.id, "name": addon.name, "version": addon.version, "install_path": addon.path, "path": addon.router_prefix}
			for addon in AddonManager().addons
		],
		"multi_factor_auth": config.multi_factor_auth,
	}

	return jinja_templates().TemplateResponse(request=request, name="admininterface.html", context=context)


@admin_interface_router.get("/app-state")
@rest_api
async def get_app_state(request: Request) -> RESTResponse:
	return RESTResponse(data=request.app.app_state.to_dict())


@admin_interface_router.post("/app-state")
@rest_api
async def set_app_state(request: Request) -> RESTResponse:
	params = await request.json()
	if params.pop("auto_add_to_address_exceptions", False) and params["type"] == "maintenance":
		params["address_exceptions"] = params.get("address_exceptions", []) + ["127.0.0.1/32", "::1/128"]
		if request.client:
			params["address_exceptions"].append(request.client.host)
		if "retry_after" in params:
			params["retry_after"] = int(params["retry_after"])
	await run_in_threadpool(request.app.set_app_state, AppState.from_dict(params))
	return RESTResponse(data=request.app.app_state.to_dict())


@admin_interface_router.get("/messagebus-connected-clients")
@rest_api
async def get_messagebus_connected_clients() -> RESTResponse:
	depot_ids = [u async for u in get_websocket_connected_users(user_type="depot")]
	client_ids = [u async for u in get_websocket_connected_users(user_type="client")]
	user_ids = [u async for u in get_websocket_connected_users(user_type="user")]
	return RESTResponse(data={"depot_ids": depot_ids, "client_ids": client_ids, "user_ids": user_ids})


@admin_interface_router.post("/messagebus-channel-info")
@rest_api
async def get_messagebus_channel_info(request: Request) -> RESTResponse:
	request_body = await request.json()
	raw_filter = {attribute: value for attribute, value in request_body.get("filter", {}).items() if value}
	filter = {attribute: re.compile(value) for attribute, value in raw_filter.items()}

	redis = await async_redis_client()
	channel_prefix = f"{config.redis_key('messagebus')}:channels:"
	channel_prefix_len = len(channel_prefix)
	channel_info_suffix = CHANNEL_INFO_SUFFIX.decode("utf-8")
	channel_info: dict[str, dict[str, Any]] = {}
	channel_filter = filter.get("channel")
	info_filter = {k: v for k, v in filter.items() if k != "channel"}
	async for key_b in redis.scan_iter(f"{channel_prefix}*", count=1000):
		key = str(key_b.decode("utf-8"))
		if key.endswith(channel_info_suffix):
			continue
		if channel_filter and not channel_filter.search(key):
			continue
		info_key = f"{key}{channel_info_suffix}"
		info = await redis.hgetall(info_key)
		info = {k.decode("utf-8"): v.decode("utf-8") for k, v in info.items()} if info else {}
		skip = False
		for attribute, attr_filter in info_filter.items():
			value = info.get(attribute)
			if not value or not attr_filter.search(value):
				skip = True
				break
		if skip:
			continue
		name = key[channel_prefix_len:]
		channel_type, name = name.split(":", 1)
		if channel_type not in channel_info:
			channel_info[channel_type] = {}
		channel_info[channel_type][name] = info

	return RESTResponse(
		data={
			"filter": raw_filter,
			"number_of_channels": {k: len(v) for k, v in channel_info.items()},
			"channels": dict(sorted(channel_info.items())),
		}
	)


@admin_interface_router.post("/reload")
@rest_api
async def reload() -> RESTResponse:
	manager_pid = get_manager_pid()
	if not manager_pid:
		raise RuntimeError("Manager pid not found")
	os.kill(manager_pid, signal.SIGHUP)
	return RESTResponse("reload sent")


async def _unblock_all_clients() -> dict:
	redis = await async_redis_client()
	clients = set()
	deleted_keys = set()
	async with redis.pipeline(transaction=False) as pipe:
		for base_key in (f"{config.redis_key('stats')}:client:failed_auth", f"{config.redis_key('stats')}:client:blocked"):
			async for key in redis.scan_iter(f"{base_key}:*", count=1000):
				key_str = key.decode("utf8")
				deleted_keys.add(key_str)
				client = ip_address_from_redis_key(key_str.split(":")[-1])
				clients.add(client)
				logger.debug("redis key to delete: %s", key_str)
				await pipe.delete(key)  # type: ignore[attr-defined]
		await pipe.execute()  # type: ignore[attr-defined]
	return {"clients": list(clients), "redis-keys": list(deleted_keys)}


@admin_interface_router.post("/unblock-all")
@rest_api
async def unblock_all_clients() -> RESTResponse:
	try:
		result = await _unblock_all_clients()
		return RESTResponse(result)
	except Exception as err:
		logger.error("Error while removing redis client keys: %s", err)
		return RESTErrorResponse(message="Error while removing redis client keys", details=err)


async def _unblock_client(client_addr: str) -> dict:
	logger.debug("unblock client addr: %s ", client_addr)
	client_addr_redis = ip_address_to_redis_key(client_addr)
	redis = await async_redis_client()
	deleted_keys = []
	redis_code = await redis.delete(f"{config.redis_key('stats')}:client:failed_auth:{client_addr_redis}")
	if redis_code == 1:
		deleted_keys.append(f"{config.redis_key('stats')}:client:failed_auth:{client_addr_redis}")
	redis_code = await redis.delete(f"{config.redis_key('stats')}:client:blocked:{client_addr_redis}")
	if redis_code == 1:
		deleted_keys.append(f"{config.redis_key('stats')}:client:blocked:{client_addr_redis}")

	return {"client": client_addr, "redis-keys": deleted_keys}


@admin_interface_router.post("/unblock-client")
@rest_api
async def unblock_client(request: Request) -> RESTResponse:
	try:
		request_body = await request.json()
		client_addr = request_body.get("client_addr")
		result = await _unblock_client(client_addr)
		return RESTResponse(result)
	except Exception as err:
		logger.error("Error while removing redis client keys: %s", err)
		return RESTErrorResponse(message="Error while removing redis client keys.", details=err)


@admin_interface_router.post("/delete-client-sessions")
@rest_api
async def delete_client_sessions(request: Request) -> RESTResponse:
	request_body = await request.json() or {}
	if not request_body:
		raise ValueError("client_addr missing")
	client_addr = request_body.get("client_addr")
	if not client_addr:
		raise ValueError("client_addr missing")

	redis = await async_redis_client()
	ip_key = f"{config.redis_key('address_to_session')}:{ip_address_to_redis_key(client_addr)}"
	session_ids = [sid.decode("utf-8") for sid in await redis.smembers(ip_key)]
	deleted_keys = []
	if session_ids:
		async with redis.pipeline(transaction=True) as pipe:
			for session_id in session_ids:
				key = f"{config.redis_key('session')}:{session_id}"
				await pipe.delete(key)
				deleted_keys.append(key)
			await pipe.delete(ip_key)
			await pipe.execute()

	return RESTResponse({"client": client_addr, "sessions": session_ids, "redis-keys": deleted_keys})


@admin_interface_router.get("/depots")
@rest_api
async def get_depot_list() -> RESTResponse:
	redis = redis_client()
	backend = get_unprotected_backend()
	depots = backend.host_getObjects(type="OpsiDepotserver")
	max_slots = backend.get_max_transfer_slots(TransferSlotType.OPSICLIENTD_PRODUCT_SYNC, [d.id for d in depots])
	slot_key = config.redis_key("slot")
	depot_infos = sorted(
		[
			{
				"id": depot.id,
				"configserver": depot.getType() == "OpsiConfigserver",
				"description": depot.description,
				"opsiHostKey": depot.opsiHostKey,
				"max_product_sync_transfer_slots": max_slots.get(depot.id, 0),
				"used_product_sync_transfer_slots": len(list(redis.scan_iter(f"{slot_key}:{depot.id}:*", count=1000))),
			}
			for depot in depots
			# if d.getType() != "OpsiConfigserver"
		],
		key=itemgetter("id"),
	)
	return RESTResponse(depot_infos)


@admin_interface_router.post("/depot-create")
@rest_api
async def create_depot(request: Request) -> RESTResponse:
	request_body = await request.json() or {}
	depot_id = request_body.get("id")
	if not depot_id:
		return RESTErrorResponse(http_status=status.HTTP_422_UNPROCESSABLE_ENTITY, message="Depot ID missing")
	backend = get_unprotected_backend()
	if backend.host_getIdents(id=depot_id):
		return RESTErrorResponse(http_status=status.HTTP_422_UNPROCESSABLE_ENTITY, message="Depot already exists")

	depot = OpsiDepotserver(id=depot_id, description=request_body.get("description"))
	auto_fill_depotserver_urls(depot)
	backend.host_createObjects(depot)
	return RESTResponse("ok")


@admin_interface_router.get("/addons")
@rest_api
async def get_addon_list() -> RESTResponse:
	addon_list = [
		{"id": addon.id, "name": addon.name, "version": addon.version, "install_path": addon.path, "path": addon.router_prefix}
		for addon in AddonManager().addons
	]
	return RESTResponse(sorted(addon_list, key=itemgetter("id")))


@admin_interface_router.get("/addons/failed")
@rest_api
async def get_failed_addons() -> RESTResponse:
	return RESTResponse(_get_failed_addons())


def _get_failed_addons() -> list:
	redis = redis_client()
	failed_addons = decode_redis_result(redis.lrange(f"{config.redis_key('state')}:application:addons:errors", 0, -1))
	errors = []
	for failed_addon in failed_addons:
		error = {"name": failed_addon}
		error.update(decode_redis_result(redis.hgetall(f"{config.redis_key('state')}:application:addons:errors:{failed_addon}")))
		errors.append(error)
	return errors


def _install_addon(data: bytes) -> None:
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
@rest_api
async def install_addon(request: Request) -> RESTResponse:
	form = await request.form()
	if isinstance(form["addonfile"], str):
		raise RuntimeError("Invalid addon")
	data = await form["addonfile"].read()
	await run_in_threadpool(_install_addon, data)
	return RESTResponse("Addon installed")


@admin_interface_router.get("/rpc-list")
@rest_api
async def get_rpc_list() -> RESTResponse:
	redis = await async_redis_client()
	redis_result = await redis.lrange(f"{config.redis_key('stats')}:rpcs", 0, -1)

	rpc_list = []
	for value in redis_result:
		value = msgspec.msgpack.decode(value)
		rpc = {
			"rpc_num": value.get("rpc_num"),
			"method": value.get("method"),
			"params": value.get("num_params"),
			"results": value.get("num_results"),
			"date": value.get("date", datetime.date(2020, 1, 1).strftime("%Y-%m-%dT%H:%M:%SZ")),
			"client": value.get("client", "0.0.0.0"),
			"deprecated": value.get("deprecated", False),
			"error": value.get("error", False),
			"duration": value.get("duration"),
		}
		rpc_list.append(rpc)

	rpc_list = sorted(rpc_list, key=itemgetter("rpc_num"), reverse=True)
	return RESTResponse(rpc_list)


@admin_interface_router.get("/rpc-count")
@rest_api
async def get_rpc_count() -> RESTResponse:
	redis = await async_redis_client()
	count = await redis.llen(f"{config.redis_key('stats')}:rpcs")
	return RESTResponse({"rpc_count": count})


@admin_interface_router.get("/session-list")
@rest_api
async def get_session_list() -> RESTResponse:
	redis = await async_redis_client()
	session_list = []
	async for redis_key in redis.scan_iter(f"{config.redis_key('session')}:*", count=1000):
		try:
			session_data = await redis.hgetall(redis_key)
		except ResponseError as err:
			logger.warning(err)
			continue

		if not session_data:
			continue

		client_addr = session_data[b"client_addr"].decode("utf-8")
		session_id = redis_key.decode("utf-8").rsplit(":", 1)[-1]
		session = OPSISession(client_addr=client_addr, session_id=session_id)
		await session.load()
		if session.expired:
			continue
		session_list.append(
			{
				"created": session.created,
				"last_used": session.last_used,
				"messagebus_last_used": session.messagebus_last_used,
				"validity": session.validity,
				"max_age": session.max_age,
				"user_agent": session.user_agent,
				"authenticated": session.authenticated,
				"username": session.username,
				"auth_methods": list(session.auth_methods or []),
				"address": client_addr,
				"session_id": session_id[:6] + "...",
			}
		)
	session_list = sorted(session_list, key=itemgetter("address", "validity"))
	return RESTResponse(session_list)


@admin_interface_router.get("/user-list")
@rest_api
async def get_user_list() -> RESTResponse:
	backend = get_unprotected_backend()
	user_list = []
	for user in await run_in_threadpool(backend.user_getObjects):
		user_dict = {k: v for k, v in user.to_hash().items() if k != "otpSecret"}
		user_list.append(user_dict)
	return RESTResponse(user_list)


@admin_interface_router.post("/update-multi-factor-auth")
@rest_api
async def update_multi_factor_auth(request: Request) -> RESTResponse:
	params = await request.json()
	backend = get_unprotected_backend()
	res = await run_in_threadpool(backend.user_updateMultiFactorAuth, params.get("user_id"), params.get("type"), "qrcode")
	return RESTResponse(res)


@admin_interface_router.get("/locked-products-list", response_model=list[str])
@rest_api
async def get_locked_products_list() -> RESTResponse:
	backend = get_unprotected_backend()
	products = await run_in_threadpool(backend.getProductLocks_hash)
	return RESTResponse(products)


async def _unlock_products(product_ids: list[str] | None = None, depot_ids: list[str] | None = None) -> None:
	product_ids = product_ids or []
	depot_ids = depot_ids or []
	backend = get_unprotected_backend()
	product_on_depots = await backend.async_call("productOnDepot_getObjects", productId=product_ids, depotId=depot_ids, locked=True)
	if not product_on_depots:
		return
	for product_on_depot in product_on_depots:
		product_on_depot.locked = False
	await backend.async_call("productOnDepot_updateObjects", productOnDepots=product_on_depots)


@admin_interface_router.post("/products/{product}/unlock")
@rest_api
async def unlock_product(request: Request, product: str) -> RESTResponse:
	try:
		request_body = await request.json()
		depot_ids = request_body.get("depots") or []
	except json.decoder.JSONDecodeError:
		pass

	try:
		await _unlock_products([product], depot_ids)
		return RESTResponse({"product": product, "action": "unlock"})
	except Exception as err:
		logger.error("Error while unlocking product: %s", err)
		return RESTErrorResponse(
			message="Error while unlocking product",
			http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
			details=err,
		)


@admin_interface_router.post("/products/unlock")
@rest_api
async def unlock_all_products() -> RESTResponse:
	try:
		await _unlock_products()
		return RESTResponse()
	except Exception as err:
		logger.error("Error while removing redis session keys: %s", err)
		return RESTErrorResponse(message="Error while unlocking products", details=err)


@admin_interface_router.get("/blocked-clients", response_model=list[str])
@rest_api
async def get_blocked_clients() -> RESTResponse:
	redis = await async_redis_client()
	redis_keys = redis.scan_iter(f"{config.redis_key('stats')}:client:blocked:*", count=1000)

	blocked_clients = []
	async for key in redis_keys:
		blocked_clients.append(ip_address_from_redis_key(key.decode("utf8").split(":")[-1]))
	return RESTResponse(data=blocked_clients, total=len(blocked_clients))


@admin_interface_router.get("/grafana")
async def open_grafana(request: Request) -> RedirectResponse:
	url = urlparse(config.grafana_external_url)
	local_addreses = (
		"127.0.0.1",
		"::1",
		"localhost",
		FQDN,
	)
	if (
		url.scheme
		and url.hostname
		and request.base_url.hostname
		and url.hostname.lower() in local_addreses
		and url.hostname.lower() != request.base_url.hostname.lower()
	):
		redirect_url = f"{request.base_url.scheme}://{url.hostname}:{request.base_url.port}{request.scope['path']}"
		logger.info("Redirecting %s to %s (%s)", request.base_url.hostname, url.hostname, redirect_url)
		return RedirectResponse(redirect_url)

	redirect_response = RedirectResponse(
		url=f"{config.grafana_external_url.rstrip('/')}/d/{GRAFANA_DASHBOARD_UID}/opsiconfd-main-dashboard?kiosk=tv"
	)
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
					redirect_response.set_cookie(key="grafana_session", path="/grafana", value=match.group(1))
				else:
					logger.error("Failed to get grafana_session cookie")

	except Exception as err:
		logger.error(err, exc_info=True)

	return redirect_response


@admin_interface_router.get("/config")
@rest_api
def get_confd_conf(all: bool = False) -> RESTResponse:
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

	return RESTResponse({"config": current_config})


@admin_interface_router.get("/routes")
@rest_api
def get_routes(request: Request) -> RESTResponse:
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

	return RESTResponse(collections.OrderedDict(sorted(routes.items())))


@admin_interface_router.get("/licensing_info")
@rest_api
def get_licensing_info() -> RESTResponse:
	info = get_unprotected_backend().backend_getLicensingInfo(True, False, True, allow_cache=False)
	active_date = None
	modules: dict[str, dict] = {}
	previous: dict[str, dict] = {}
	obsolete_modules = info.get("obsolete_modules", [])
	for at_date, date_info in info.get("dates", {}).items():
		at_date = datetime.date.fromisoformat(at_date)
		if (at_date <= datetime.date.today()) and (not active_date or at_date > active_date):
			active_date = at_date

		for module_id, module in date_info["modules"].items():
			if module_id in obsolete_modules:
				continue
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
	return RESTResponse(
		{
			"info": {
				"customer_name": lic.get("customer_name", ""),
				"customer_address": lic.get("customer_address", ""),
				"customer_unit": lic.get("customer_unit", ""),
				"checksum": info["licenses_checksum"],
				"macos_clients": info["client_numbers"]["macos"],
				"linux_clients": info["client_numbers"]["linux"],
				"windows_clients": info["client_numbers"]["windows"],
				"all_clients": info["client_numbers"]["all"],
				"inactive_clients": info["client_numbers"]["inactive"],
			},
			"module_dates": modules,
			"active_date": str(active_date) if active_date else None,
		}
	)


@admin_interface_router.post("/license_upload")
@rest_api
async def license_upload(files: list[UploadFile]) -> RESTResponse:
	try:
		for file in files:
			if not file.filename:
				raise ValueError(f"No filename in {file!r}")
			if not re.match(r"^\w[\w -]*\.opsilic$", file.filename):
				raise ValueError(f"Invalid filename {file.filename!r}")
			olf = OpsiLicenseFile(os.path.join("/etc/opsi/licenses", file.filename))
			assert olf.filename
			olf.read_string((await file.read()).decode("utf-8"))  # type: ignore[union-attr]
			if not olf.licenses:
				raise ValueError(f"No license found in {file.filename!r}")
			logger.notice("Writing opsi license file %r", olf.filename)
			olf.write()
			os.chmod(olf.filename, 0o660)
		return RESTResponse(data=f"{len(files)} opsi license files imported", http_status=status.HTTP_201_CREATED)
	except Exception as err:
		logger.warning(err, exc_info=True)
		return RESTErrorResponse(http_status=status.HTTP_422_UNPROCESSABLE_ENTITY, message="Invalid license file.", details=err)


def get_num_servers() -> int:
	servers = len(get_unprotected_backend().host_getIdents(type="OpsiDepotserver"))
	return servers


def get_num_clients() -> int:
	clients = len(get_unprotected_backend().host_getIdents(type="OpsiClient"))
	return clients
