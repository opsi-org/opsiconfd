# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
memoryprofiler
"""

import gc
import io
import os
import sys
import time
import tempfile
import tracemalloc
from typing import Any, Optional, Dict

import psutil
import msgpack  # type: ignore[import]

from fastapi import Request, APIRouter
from fastapi.responses import JSONResponse

import objgraph  # type: ignore[import]
from pympler import tracker, classtracker  # type: ignore[import]
from guppy import hpy  # type: ignore[import]
from starlette.responses import Response

from ..logging import logger
from ..config import config
from ..utils import async_redis_client

memory_profiler_router = APIRouter()

MEMORY_TRACKER: Optional[tracker.SummaryTracker] = None
CLASS_TRACKER: Optional[classtracker.ClassTracker] = None
HEAP = None

TRACEMALLOC_PREV_SNAPSHOT: Optional[tracemalloc.Snapshot] = None
TRACEMALLOC_RSS_START = 0
TRACEMALLOC_RSS_PREV = 0


@memory_profiler_router.get("/tracemalloc-snapshot-new")
def memory_tracemalloc_snapshot_new(limit: int = 25) -> JSONResponse:
	global TRACEMALLOC_PREV_SNAPSHOT, TRACEMALLOC_RSS_PREV, TRACEMALLOC_RSS_START  # pylint: disable=global-statement
	gc.collect()
	mem_info = psutil.Process().memory_info()

	if not TRACEMALLOC_PREV_SNAPSHOT or not tracemalloc.is_tracing():
		tracemalloc.start(25)
		TRACEMALLOC_PREV_SNAPSHOT = tracemalloc.take_snapshot()
		TRACEMALLOC_RSS_START = mem_info.rss

	current = tracemalloc.take_snapshot()
	data = {
		"time": time.time(),
		"memory_info_rss": mem_info.rss,
		"memory_info_rss_diff_prev": mem_info.rss - TRACEMALLOC_RSS_PREV,
		"memory_info_rss_diff_start": mem_info.rss - TRACEMALLOC_RSS_START,
		"start": {"size": 0, "stats": []},
		"prev": {"size": 0, "stats": []},
	}
	for num, stat in enumerate(current.statistics("filename"), 1):
		data["start"]["size"] += stat.size
		if num <= limit:
			data["start"]["stats"].append(str(stat))

	for num, stat_diff in enumerate(current.compare_to(TRACEMALLOC_PREV_SNAPSHOT, "filename"), 1):
		data["prev"]["size"] += stat_diff.size_diff
		if num <= limit:
			data["prev"]["stats"].append(str(stat_diff))

	TRACEMALLOC_PREV_SNAPSHOT = current
	TRACEMALLOC_RSS_PREV = mem_info.rss

	return JSONResponse({"status": 200, "error": None, "data": data})


LAST_OBJGRAPH_SNAPSHOT: Dict[str, Any] = {}


@memory_profiler_router.get("/objgraph-snapshot-new")
def memory_objgraph_snapshot_new(max_obj_types: int = 25, max_obj: int = 50) -> JSONResponse:
	global LAST_OBJGRAPH_SNAPSHOT  # pylint: disable=global-statement
	gc.collect()
	mem_info = psutil.Process().memory_info()
	data = {
		"time": time.time(),
		"memory_info_rss": mem_info.rss,
		"memory_info_rss_diff": mem_info.rss - LAST_OBJGRAPH_SNAPSHOT.get("memory_info_rss", 0),
		"new_ids": {},
	}
	if LAST_OBJGRAPH_SNAPSHOT:
		new_ids = objgraph.get_new_ids(limit=max_obj_types)
		obj_types = sorted(new_ids.items(), key=lambda item: len(item[1]), reverse=True)

		for obj_type, ids in obj_types:
			if len(data["new_ids"]) >= max_obj_types:
				break
			if len(ids) == 0:
				continue
			logger.debug("obj_type: %s", obj_type)
			data["new_ids"][obj_type] = {"count": len(ids), "objects": {}}
			for num, addr in enumerate(ids):
				if num >= max_obj:
					break
				obj = objgraph.at(addr)
				repr_obj = repr(obj)
				if len(repr_obj) > 250:
					repr_obj = repr_obj[:249] + "…"
				data["new_ids"][obj_type]["objects"][addr] = {"size": sys.getsizeof(obj), "repr": repr_obj}

	LAST_OBJGRAPH_SNAPSHOT = data

	return JSONResponse({"status": 200, "error": None, "data": data})


@memory_profiler_router.get("/objgraph-snapshot-update")
def memory_objgraph_snapshot_update() -> JSONResponse:
	if not LAST_OBJGRAPH_SNAPSHOT:
		return memory_objgraph_snapshot_new()
	gc.collect()

	data = LAST_OBJGRAPH_SNAPSHOT

	for obj_type in data["new_ids"]:
		for addr in list(data["new_ids"][obj_type]["objects"]):
			if objgraph.at(addr) is None:
				logger.info("Removing id: %s", addr)
				del data["new_ids"][obj_type]["objects"][addr]
				data["new_ids"][obj_type]["count"] -= 1

	return JSONResponse({"status": 200, "error": None, "data": data})


@memory_profiler_router.get("/objgraph-show-backrefs")
def memory_objgraph_show_backrefs(obj_id: int, output_format: str = "png") -> Response:
	assert output_format in ("png", "dot")
	obj_id = int(obj_id)
	obj = objgraph.at(obj_id)
	if obj is None:
		msg = f"Object at address {obj_id} not found"
		return Response(status_code=404, media_type="text/plain", headers={"Content-Length": str(len(msg))}, content=msg)

	file = tempfile.NamedTemporaryFile(delete=False, suffix=f".{output_format}")  # pylint: disable=consider-using-with
	objgraph.show_backrefs([obj], filename=file.name, shortnames=False)
	data = file.read()
	file.close()
	os.remove(file.name)
	return Response(status_code=200, media_type=f"image/{output_format}", headers={"Content-Length": str(len(data))}, content=data)


@memory_profiler_router.post("/snapshot")
async def memory_info() -> JSONResponse:

	global MEMORY_TRACKER  # pylint: disable=global-statement
	if not MEMORY_TRACKER:
		MEMORY_TRACKER = tracker.SummaryTracker()

	memory_summary = MEMORY_TRACKER.create_summary()
	memory_summary = sorted(memory_summary, key=lambda x: x[2], reverse=True)

	redis = await async_redis_client()
	timestamp = int(time.time() * 1000)
	node = config.node_name

	async with redis.pipeline() as pipe:
		value = msgpack.dumps({"memory_summary": memory_summary, "timestamp": timestamp})  # pylint: disable=c-extension-no-member
		await pipe.lpush(f"opsiconfd:stats:memory:summary:{node}", value)
		await pipe.ltrim(f"opsiconfd:stats:memory:summary:{node}", 0, 9)
		redis_result = await pipe.execute()
	logger.debug("redis lpush memory summary: %s", redis_result)

	total_size = 0
	count = 0
	for idx in range(0, len(memory_summary) - 1):
		count += memory_summary[idx][1]
		total_size += memory_summary[idx][2]
		memory_summary[idx][2] = convert_bytes(memory_summary[idx][2])

	objs_size = convert_bytes(sys.getsizeof(gc.get_objects()))

	response = JSONResponse(
		{
			"status": 200,
			"error": None,
			"data": {"objs_size": objs_size, "count": count, "total_size": convert_bytes(total_size), "memory_summary": memory_summary},
		}
	)
	return response


@memory_profiler_router.delete("/snapshot")
async def delte_memory_snapshot() -> JSONResponse:

	redis = await async_redis_client()
	node = config.node_name

	await redis.delete(f"opsiconfd:stats:memory:summary:{node}")

	global MEMORY_TRACKER  # pylint: disable=global-statement
	MEMORY_TRACKER = None

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Deleted all memory snapshots."}})
	return response


@memory_profiler_router.get("/diff")
async def get_memory_diff(snapshot1: int = 1, snapshot2: int = -1) -> JSONResponse:

	global MEMORY_TRACKER  # pylint: disable=global-statement
	if not MEMORY_TRACKER:
		MEMORY_TRACKER = tracker.SummaryTracker()

	redis = await async_redis_client()
	node = config.node_name
	snapshot_count = await redis.llen(f"opsiconfd:stats:memory:summary:{node}")

	if snapshot1 < 0:
		start = abs(snapshot1) - 1
	else:
		start = snapshot_count - snapshot1

	if snapshot2 < 0:
		end = abs(snapshot2) - 1
	else:
		end = snapshot_count - snapshot2

	redis_result = await redis.lindex(f"opsiconfd:stats:memory:summary:{node}", start)
	snapshot1 = msgpack.loads(redis_result).get("memory_summary")  # pylint: disable=c-extension-no-member
	redis_result = await redis.lindex(f"opsiconfd:stats:memory:summary:{node}", end)
	snapshot2 = msgpack.loads(redis_result).get("memory_summary")  # pylint: disable=c-extension-no-member
	memory_summary = sorted(MEMORY_TRACKER.diff(summary1=snapshot1, summary2=snapshot2), key=lambda x: x[2], reverse=True)

	count = 0
	total_size = 0
	for idx in range(0, len(memory_summary) - 1):
		count += memory_summary[idx][1]
		total_size += memory_summary[idx][2]
		memory_summary[idx][2] = convert_bytes(memory_summary[idx][2])

	response = JSONResponse(
		{"status": 200, "error": None, "data": {"count": count, "total_size": convert_bytes(total_size), "memory_diff": memory_summary}}
	)
	return response


@memory_profiler_router.post("/classtracker")
async def classtracker_snapshot(request: Request) -> JSONResponse:

	request_body = await request.json()
	class_name = request_body.get("class")
	module_name = request_body.get("module")
	description = request_body.get("description")

	def get_class(modulename, classname):
		return getattr(sys.modules.get(modulename), classname)

	global CLASS_TRACKER  # pylint: disable=global-statement
	if not CLASS_TRACKER:
		CLASS_TRACKER = classtracker.ClassTracker()

	logger.debug("class name: %s", class_name)
	logger.debug("module_name: %s", module_name)
	logger.debug("description: %s", description)

	logger.debug("get class: %s", get_class(module_name, class_name))
	CLASS_TRACKER.track_class(get_class(module_name, class_name), name=class_name)
	CLASS_TRACKER.create_snapshot(description)

	response = JSONResponse(
		{
			"status": 200,
			"error": None,
			"data": {"msg": "class snapshot created.", "class": class_name, "description": description, "module": module_name},
		}
	)
	return response


@memory_profiler_router.get("/classtracker/summary")
async def classtracker_summary() -> JSONResponse:

	global CLASS_TRACKER  # pylint: disable=global-statement

	if not CLASS_TRACKER:
		CLASS_TRACKER = classtracker.ClassTracker()

	class_summary = []

	annotate_snapshots(CLASS_TRACKER.stats)

	for snapshot in CLASS_TRACKER.snapshots:
		classes = []
		for cls in snapshot.classes:
			cls_values = snapshot.classes.get(cls)
			active = cls_values.get("active")
			mem_sum = convert_bytes(cls_values.get("sum"))
			mem_avg = convert_bytes(cls_values.get("avg"))
			cls_dict = {"class": cls, "active": active, "sum": mem_sum, "avg": mem_avg}
			classes.append(cls_dict)
		class_summary.append({"description": snapshot.desc, "classes": classes})

	print_class_summary(class_summary)

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Class Tracker Summary.", "summary": class_summary}})
	return response


@memory_profiler_router.delete("/classtracker")
async def delte_class_tracker() -> JSONResponse:

	global CLASS_TRACKER  # pylint: disable=global-statement
	if CLASS_TRACKER:
		CLASS_TRACKER.close()
	CLASS_TRACKER = None

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Deleted class tracker."}})
	return response


@memory_profiler_router.post("/guppy")
async def guppy_snapshot() -> JSONResponse:

	global HEAP  # pylint: disable=global-statement
	if not HEAP:
		HEAP = hpy()

	heap_status = HEAP.heap()
	fn = io.StringIO()  # pylint: disable=invalid-name
	heap_status.dump(fn)

	redis = await async_redis_client()
	node = config.node_name

	async with redis.pipeline() as pipe:
		await pipe.lpush(f"opsiconfd:stats:memory:heap:{node}", msgpack.dumps(fn.getvalue()))
		await pipe.ltrim(f"opsiconfd:stats:memory:heap:{node}", 0, 9)
		redis_result = await pipe.execute()
	logger.debug("redis lpush memory summary: %s", redis_result)

	heap_objects = []
	for obj in heap_status.stat.get_rows():
		heap_objects.append(
			{
				"index": obj.index,
				"name": obj.name,
				"count": obj.count,
				"size": convert_bytes(obj.size),
				"cumulsize": convert_bytes(obj.cumulsize),
			}
		)

	response = JSONResponse(
		{
			"status": 200,
			"error": None,
			"data": {"objects": heap_status.stat.count, "total_size": convert_bytes(heap_status.stat.size), "heap_status": heap_objects},
		}
	)
	return response


@memory_profiler_router.delete("/guppy")
async def delte_guppy_snapshot() -> JSONResponse:

	redis = await async_redis_client()
	node = config.node_name

	await redis.delete(f"opsiconfd:stats:memory:heap:{node}")

	global HEAP  # pylint: disable=global-statement
	HEAP = None

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Deleted all guppy heap snapshots."}})
	return response


@memory_profiler_router.get("/guppy/setref")
async def guppy_set_ref() -> JSONResponse:

	global HEAP  # pylint: disable=global-statement
	if not HEAP:
		HEAP = hpy()
	HEAP.setref()

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Set new ref point"}})
	return response


@memory_profiler_router.get("/guppy/diff")
async def guppy_diff(snapshot1: int = 1, snapshot2: int = -1) -> JSONResponse:  # pylint: disable=too-many-locals

	global HEAP  # pylint: disable=global-statement
	if not HEAP:
		HEAP = hpy()

	redis = await async_redis_client()
	node = config.node_name
	snapshot_count = await redis.llen(f"opsiconfd:stats:memory:heap:{node}")

	if snapshot1 < 0:
		start = abs(snapshot1) - 1
	else:
		start = snapshot_count - snapshot1

	if snapshot2 < 0:
		end = abs(snapshot2) - 1
	else:
		end = snapshot_count - snapshot2

	redis_result = await redis.lindex(f"opsiconfd:stats:memory:heap:{node}", start)
	fn1 = io.StringIO(msgpack.loads(redis_result))
	snapshot1_heap = HEAP.load(fn1)
	redis_result = await redis.lindex(f"opsiconfd:stats:memory:heap:{node}", end)
	fn2 = io.StringIO(msgpack.loads(redis_result))
	snapshot2_heap = HEAP.load(fn2)

	heap_diff = snapshot2_heap - snapshot1_heap

	logger.debug("Total Objects : %s", heap_diff.count)
	logger.debug("Total Size : %s Bytes", heap_diff.size)
	logger.debug("Number of Entries : %s", heap_diff.numrows)

	heap_objects = []
	for obj in heap_diff.get_rows():
		heap_objects.append(
			{
				"index": obj.index,
				"name": obj.name,
				"count": obj.count,
				"size": convert_bytes(obj.size),
				"cumulsize": convert_bytes(obj.cumulsize),
			}
		)

	response = JSONResponse(
		{
			"status": 200,
			"error": None,
			"data": {"objects": heap_diff.count, "total_size": convert_bytes(heap_diff.size), "heap_diff": heap_objects},
		}
	)
	return response


def print_class_summary(cls_summary: list) -> None:

	logger.essential("---- SUMMARY " + "-" * 66)
	for snapshot in cls_summary:
		logger.essential("%-35s %11s %12s %12s", snapshot.get("description"), "active", "sum", "average")
		for cls in snapshot.get("classes"):
			name = cls.get("class")
			active = cls.get("active")
			mem_sum = cls.get("sum")
			mem_avg = cls.get("avg")
			logger.essential("  %-33s %11d %12s %12s", name, active, mem_sum, mem_avg)
	logger.essential("-" * 79)


def annotate_snapshots(stats):
	"""
	Annotate all snapshots with class-based summaries.
	"""
	for snapshot in stats.snapshots:
		annotate_snapshot(stats, snapshot)


def annotate_snapshot(stats, snapshot):
	"""
	Store additional statistical data in snapshot.
	"""

	snapshot.classes = {}

	for classname in list(stats.index.keys()):
		total = 0
		active = 0

		for tobj in stats.index[classname]:
			total += tobj.get_size_at_time(snapshot.timestamp)
			if tobj.birth < snapshot.timestamp and (tobj.death is None or tobj.death > snapshot.timestamp):
				active += 1
		try:
			avg = total / active
		except ZeroDivisionError:
			avg = 0

		snapshot.classes[classname] = dict(sum=total, avg=avg, active=active)


def convert_bytes(bytes):  # pylint: disable=redefined-builtin
	unit = "B"
	for unit in ["B", "KB", "MB", "GB"]:
		if abs(bytes) < 1024.0 or unit == "GB":
			break
		bytes = bytes / 1024.0
	return f"{bytes:.2f} {unit}"
