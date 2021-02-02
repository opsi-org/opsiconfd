"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""

import sys
import time
from urllib.parse import urlparse
from operator import itemgetter
import os
import datetime
import orjson
import requests

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from pympler import tracker, classtracker

from OPSI import __version__ as python_opsi_version
from .. import __version__

from ..session import OPSISession
from ..logging import logger
from ..config import config
from ..backend import get_backend_interface
from ..worker import get_redis_client
from ..utils import get_random_string, get_fqdn, get_node_name, decode_redis_result

admin_interface_router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(config.static_dir, "templates"))

MEMORY_TRACKER = None
CLASS_TRACKER = None

def admin_interface_setup(app):
	app.include_router(admin_interface_router, prefix="/admin")


@admin_interface_router.get("/?")
async def admin_interface_index(request: Request):

	context = {
		"request": request,
		"opsi_version": f"{__version__} [python-opsi={python_opsi_version}]",
		"interface": get_backend_interface(),
	}
	return templates.TemplateResponse("admininterface.html", context)


@admin_interface_router.post("/unblock-all")
async def unblock_all_clients(response: Response):
	redis_client = await get_redis_client()

	try:
		clients = []
		deleted_keys = []
		keys = redis_client.scan_iter("opsiconfd:stats:client:failed_auth:*")
		async with await redis_client.pipeline(transaction=False) as pipe:
			async for key in keys:
				deleted_keys.append(key.decode("utf8"))
				if key.decode("utf8").split(":")[-1] not in clients:
					clients.append(key.decode("utf8").split(":")[-1])
				logger.debug("redis key to delete: %s", key)
				await pipe.delete(key)

			keys = redis_client.scan_iter("opsiconfd:stats:client:blocked:*")
			async for key in keys:
				logger.debug("redis key to delete: %s", key)
				deleted_keys.append(key.decode("utf8"))
				if key.decode("utf8").split(":")[-1] not in clients:
					clients.append(key.decode("utf8").split(":")[-1])
				await pipe.delete(key)
			await pipe.execute()

		response = JSONResponse({"status": 200, "error": None, "data": {"clients": clients, "redis-keys": deleted_keys}})
	except Exception as err: # pylint: disable=broad-except
		logger.error("Error while removing redis client keys: %s", err)
		response = JSONResponse({"status": 500, "error": { "message": "Error while removing redis client keys", "detail": str(err)}})
	return response


@admin_interface_router.post("/unblock-client")
async def unblock_client(request: Request):
	try:
		request_body = await request.json()
		client_addr = request_body.get("client_addr")

		logger.debug("unblock client addr: %s ", client_addr)
		redis_client = await get_redis_client()
		deleted_keys = []
		redis_code = await redis_client.delete(f"opsiconfd:stats:client:failed_auth:{client_addr}")
		if redis_code == 1:
			deleted_keys.append(f"opsiconfd:stats:client:failed_auth:{client_addr}")
		redis_code = await redis_client.delete(f"opsiconfd:stats:client:blocked:{client_addr}")
		if redis_code == 1:
			deleted_keys.append(f"opsiconfd:stats:client:blocked:{client_addr}")

		response = JSONResponse({"status": 200, "error": None, "data": {"client": client_addr, "redis-keys": deleted_keys}})
	except Exception as err: # pylint: disable=broad-except
		logger.error("Error while removing redis client keys: %s", err)
		response = JSONResponse({"status": 500, "error": { "message": "Error while removing redis client keys", "detail": str(err)}})
	return response


@admin_interface_router.post("/delete-client-sessions")
async def delete_client_sessions(request: Request):
	try:
		request_body = await request.json()
		client_addr = request_body.get("client_addr")
		redis_client = await get_redis_client()
		keys = redis_client.scan_iter(f"{OPSISession.redis_key_prefix}:{client_addr}:*")
		sessions = []
		deleted_keys = []
		async with await redis_client.pipeline(transaction=False) as pipe:
			async for key in keys:
				sessions.append(key.decode("utf8").split(":")[-1])
				deleted_keys.append(key.decode("utf8"))
				await pipe.delete(key)
			await pipe.execute()

		response = JSONResponse({"status": 200, "error": None, "data": {"client": client_addr, "sessions": sessions, "redis-keys": deleted_keys}})
	except Exception as err: # pylint: disable=broad-except
		logger.error("Error while removing redis session keys: %s", err)
		response = JSONResponse({"status": 500, "error": { "message": "Error while removing redis client keys", "detail": str(err)}})
	return response


@admin_interface_router.get("/rpc-list")
async def get_rpc_list() -> list:

	redis_client = await get_redis_client()
	redis_result = await redis_client.lrange("opsiconfd:stats:rpcs", 0, -1)

	rpc_list = []
	for value in redis_result:
		value = orjson.loads(value)  # pylint: disable=c-extension-no-member
		rpc = {
			"rpc_num": value.get("rpc_num"),
			"method": value.get("method"),
			"params": value.get("num_params"),
			"results": value.get("num_results"),
			"date": value.get("date", datetime.date(2020,1,1).strftime('%Y-%m-%dT%H:%M:%SZ')),
			"client": value.get("client",  "0.0.0.0"),
			"error": value.get("error"),
			"duration": value.get("duration")
		}
		rpc_list.append(rpc)

	rpc_list = sorted(rpc_list, key=itemgetter('rpc_num'))
	return rpc_list


@admin_interface_router.get("/rpc-count")
async def get_rpc_count():
	redis_client = await get_redis_client()
	count = await redis_client.llen("opsiconfd:stats:rpcs")

	response = JSONResponse({"rpc_count": count})
	return response


@admin_interface_router.get("/blocked-clients")
async def get_blocked_clients() -> list:
	redis_client = await get_redis_client()
	redis_keys = redis_client.scan_iter("opsiconfd:stats:client:blocked:*")

	blocked_clients = []
	async for key in redis_keys:
		logger.debug("redis key to delete: %s", key)
		blocked_clients.append(key.decode("utf8").split(":")[-1])
	return blocked_clients


@admin_interface_router.get("/grafana")
def open_grafana(request: Request):

	fqdn = get_fqdn()
	if request.base_url.hostname != fqdn:
		url = f"https://{fqdn}:{request.url.port}/admin/grafana"
		response = RedirectResponse(url=url)
		return response

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
	response = session.get(f"{url.scheme}://{url.hostname}:{url.port}/api/users/lookup?loginOrEmail=opsidashboard", headers=headers, auth=auth)

	password = get_random_string(8)
	if response.status_code == 404:
		logger.debug("create new user opsidashboard")

		data = {
			"name":"opsidashboard",
			"email":"opsidashboard@admin",
			"login":"opsidashboard",
			"password":password,
			"OrgId": 1
		}
		response = session.post(f"{url.scheme}://{url.hostname}:{url.port}/api/admin/users", headers=headers, auth=auth, data=data)
	else:
		logger.debug("change opsidashboard password")
		data = {
			"password": password
		}
		user_id = response.json().get("id")
		response = session.put(f"{config.grafana_internal_url}/api/admin/users/{user_id}/password", headers=headers, auth=auth, data=data)

	data = {
		"password": password,
		"user": "opsidashboard"
	}
	response = session.post(f"{url.scheme}://{url.hostname}:{url.port}/login", data=data)

	url = "/metrics/grafana/dashboard"
	response = RedirectResponse(url=url)
	response.set_cookie(key="grafana_session",value=session.cookies.get_dict().get("grafana_session"))
	return response

@admin_interface_router.get("/config")
def get_confd_conf(all: bool = False) -> JSONResponse: # pylint: disable=redefined-builtin

	KEYS_TO_REMOVE = [ # pylint: disable=invalid-name
		"version",
		"setup",
		"action",
		"ex_help",
		"log_max_msg_len",
		"debug",
		"profiler",
		"server_type",
		"node_name",
		"executor_type",
		"executor_workers",
		"log_slow_async_callbacks"
	]

	current_config = config.items().copy()
	if not all:
		for key in KEYS_TO_REMOVE:
			del current_config[key]
	current_config = dict(sorted(current_config.items()))

	response = JSONResponse({"status": 200, "error": None, "data": {"config": current_config}})
	return response


@admin_interface_router.get("/memory-summary")
def pympler_info() -> JSONResponse:

	global MEMORY_TRACKER # pylint: disable=global-statement
	if not MEMORY_TRACKER:
		MEMORY_TRACKER = tracker.SummaryTracker()

	memory_summary = MEMORY_TRACKER.create_summary()
	memory_summary = sorted(memory_summary, key=lambda x: x[2], reverse=True)

	response = JSONResponse({"status": 200, "error": None, "data": {"memory_summary": memory_summary}})
	return response

@admin_interface_router.post("/memory/snapshot")
async def memory_info() -> JSONResponse:

	global MEMORY_TRACKER # pylint: disable=global-statement
	if not MEMORY_TRACKER:
		MEMORY_TRACKER = tracker.SummaryTracker()

	memory_summary = MEMORY_TRACKER.create_summary()
	memory_summary = sorted(memory_summary, key=lambda x: x[2], reverse=True)

	redis_client = await get_redis_client()
	timestamp = int(time.time() * 1000)
	node = get_node_name()

	# TODO: redis pipeline
	value = orjson.dumps({"memory_summary": memory_summary, "timestamp": timestamp}) # pylint: disable=c-extension-no-member
	redis_result = await redis_client.lpush(f"opsiconfd:stats:memory:summary:{node}", value)
	logger.debug("redis lpush memory summary: %s", redis_result)
	redis_result = await redis_client.ltrim(f"opsiconfd:stats:memory:summary:{node}", 0, 9)
	logger.debug("redis ltrim memory summary: %s", redis_result)

	logger.devel("MEMORY_TRACKER.summaries: %s", MEMORY_TRACKER.summaries)
	logger.devel("MEMORY_TRACKER: %s", len(MEMORY_TRACKER.summaries))

	for idx in range(0, len(memory_summary)-1):
		memory_summary[idx][2] = convert_bytes(memory_summary[idx][2])

	response = JSONResponse({"status": 200, "error": None, "data": {"memory_summary": memory_summary}})
	return response

@admin_interface_router.delete("/memory/snapshot")
async def delte_memory_snapshot() -> JSONResponse:

	redis_client = await get_redis_client()
	node = get_node_name()

	await redis_client.delete(f"opsiconfd:stats:memory:summary:{node}")

	global MEMORY_TRACKER # pylint: disable=global-statement
	MEMORY_TRACKER = None

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Deleted all memory snapshots."}})
	return response

@admin_interface_router.get("/memory/diff")
async def get_memory_diff(snapshot1: int = 1, snapshot2: int = -1) -> JSONResponse:

	logger.devel("snapshot1 %s", snapshot1)
	logger.devel("snapshot2 %s", snapshot2)

	global MEMORY_TRACKER # pylint: disable=global-statement
	if not MEMORY_TRACKER:
		MEMORY_TRACKER = tracker.SummaryTracker()

	redis_client = await get_redis_client()
	node = get_node_name()
	# cmd = f"TS.ADD opsiconfd:stats:memory:summary:{node} {timestamp} "

	snapshot_count = await redis_client.llen(f"opsiconfd:stats:memory:summary:{node}")

	logger.devel("snapshot1 %s", type(snapshot1))
	logger.devel("snapshot2 %s", type(snapshot2))

	logger.devel("snapshot_count %s", snapshot_count)

	if snapshot1 < 0:
		start = abs(snapshot1) - 1
	else:
		start = snapshot_count - snapshot1

	if snapshot2 < 0:
		end = abs(snapshot2) - 1
	else:
		end = snapshot_count - snapshot2

	logger.devel("start: %s", start)
	logger.devel("end: %s", end)


	redis_result = await redis_client.lindex(f"opsiconfd:stats:memory:summary:{node}", start)
	snapshot1 = orjson.loads(decode_redis_result(redis_result)).get("memory_summary") # pylint: disable=c-extension-no-member
	redis_result = await redis_client.lindex(f"opsiconfd:stats:memory:summary:{node}", end)
	logger.devel(orjson.loads(decode_redis_result(redis_result)).get("timestamp")) # pylint: disable=c-extension-no-member
	snapshot2 = orjson.loads(decode_redis_result(redis_result)).get("memory_summary") # pylint: disable=c-extension-no-member
	logger.devel(orjson.loads(decode_redis_result(redis_result)).get("timestamp")) # pylint: disable=c-extension-no-member

	memory_summary = sorted(MEMORY_TRACKER.diff(summary1=snapshot1, summary2=snapshot2), key=lambda x: x[2], reverse=True)

	for idx in range(0, len(memory_summary)-1):
		memory_summary[idx][2] = convert_bytes(memory_summary[idx][2])

	response = JSONResponse({"status": 200, "error": None, "data": {"memory_diff": memory_summary}})
	return response

@admin_interface_router.post("/memory/classtracker")
async def classtracker_snapshot(request: Request) -> JSONResponse:

	request_body = await request.json()
	class_name = request_body.get("class")
	module_name = request_body.get("module")
	description = request_body.get("description")

	def get_class(modulename,classname):
		return getattr(sys.modules.get(modulename), classname)

	global CLASS_TRACKER # pylint: disable=global-statement
	if not CLASS_TRACKER:
		CLASS_TRACKER = classtracker.ClassTracker()

	logger.debug("class name: %s", class_name)
	logger.debug("module_name: %s", module_name)
	logger.debug("description: %s", description)

	logger.debug("get class: %s", get_class(module_name, class_name))
	CLASS_TRACKER.track_class(get_class(module_name, class_name), name=class_name)
	CLASS_TRACKER.create_snapshot(description)

	response = JSONResponse({
		"status": 200,
		"error": None,
		"data": {
			"msg": "class snapshot created.",
			"class": class_name,
			"description": description,
			"module": module_name
			}
		})
	return response

@admin_interface_router.get("/memory/classtracker/summary")
async def classtracker_summary() -> JSONResponse:

	global CLASS_TRACKER # pylint: disable=global-statement

	if not CLASS_TRACKER:
		CLASS_TRACKER = classtracker.ClassTracker()

	class_tracker_summary = []
	logger.essential("---- SUMMARY ------------------------------------------------------------------")
	for snapshot in CLASS_TRACKER.snapshots:
		classes = []
		logger.essential(snapshot.desc)
		for cls in snapshot.classes:
			cls_values = snapshot.classes.get(cls)
			logger.essential("  %s", cls)

			active = cls_values.get("active")
			mem_sum = convert_bytes(cls_values.get("sum"))
			mem_avg = convert_bytes(cls_values.get("avg"))

			logger.essential("    %5s %15s %15s", "active", "sum", "average")
			logger.essential("    %5s %15s %15s",  active, mem_sum, mem_avg)

			cls_dict = {
				"class": cls,
				"active": active,
				"sum": mem_sum,
				"avg": mem_avg
			}
			classes.append(cls_dict)
		snapshot_dict = {
			"description": snapshot.desc,
			"classes": classes
		}
		class_tracker_summary.append(snapshot_dict)
	logger.essential("-------------------------------------------------------------------------------")

	# CLASS_TRACKER.close() # TODO close class Tracker

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Class Tracker Summary.", "summary": class_tracker_summary}})
	return response

# TODO: maybe do this in JS
def convert_bytes(bytes): # pylint: disable=redefined-builtin
	unit = "B"
	for unit in ["B", "KB", "MB", "GB"]:
		if bytes < 1024.0 or unit == "GB":
			break
		bytes = bytes/1024.0
	return f"{bytes:.2f} {unit}"

