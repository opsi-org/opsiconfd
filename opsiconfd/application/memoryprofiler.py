# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
memoryprofiler
"""

import gc
import os
import sys
import tempfile
import time
import tracemalloc
from typing import Any, Dict, Optional

import msgspec
import objgraph  # type: ignore[import]
import psutil
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pympler import classtracker, tracker  # type: ignore[import]
from pympler.classtracker import Snapshot  # type: ignore[import]
from pympler.classtracker_stats import ConsoleStats  # type: ignore[import]
from starlette.responses import Response

from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.redis import async_redis_client

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
				data["new_ids"][obj_type]["objects"][addr] = {
					"size": sys.getsizeof(obj),
					"repr": repr_obj,
				}

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

	redis_prefix_stats = config.redis_key("stats")
	async with redis.pipeline() as pipe:
		value = msgspec.msgpack.encode({"memory_summary": memory_summary, "timestamp": timestamp})  # pylint: disable=c-extension-no-member
		await pipe.lpush(f"{redis_prefix_stats}:memory:summary:{node}", value)  # type: ignore[attr-defined]
		await pipe.ltrim(f"{redis_prefix_stats}:memory:summary:{node}", 0, 9)  # type: ignore[attr-defined]
		redis_result = await pipe.execute()  # type: ignore[attr-defined]
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

	await redis.delete(f"{config.redis_key('stats')}:memory:summary:{node}")

	global MEMORY_TRACKER  # pylint: disable=global-statement
	MEMORY_TRACKER = None

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Deleted all memory snapshots."}})
	return response


@memory_profiler_router.get("/diff")
async def get_memory_diff(snapshot1: int = 1, snapshot2: int = -1) -> JSONResponse:
	global MEMORY_TRACKER  # pylint: disable=global-statement
	if not MEMORY_TRACKER:
		MEMORY_TRACKER = tracker.SummaryTracker()

	redis_prefix_stats = config.redis_key("stats")

	redis = await async_redis_client()
	node = config.node_name
	snapshot_count = await redis.llen(f"{redis_prefix_stats}:memory:summary:{node}")

	if snapshot1 < 0:
		start = abs(snapshot1) - 1
	else:
		start = snapshot_count - snapshot1

	if snapshot2 < 0:
		end = abs(snapshot2) - 1
	else:
		end = snapshot_count - snapshot2

	redis_result = await redis.lindex(f"{redis_prefix_stats}:memory:summary:{node}", start)
	snapshot1 = msgspec.msgpack.decode(redis_result or b"").get("memory_summary")  # pylint: disable=c-extension-no-member
	redis_result = await redis.lindex(f"{redis_prefix_stats}:memory:summary:{node}", end)
	snapshot2 = msgspec.msgpack.decode(redis_result or b"").get("memory_summary")  # pylint: disable=c-extension-no-member
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

	def get_class(modulename: str, classname: str) -> type:
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


def annotate_snapshots(stats: ConsoleStats) -> None:
	"""
	Annotate all snapshots with class-based summaries.
	"""
	for snapshot in stats.snapshots:
		annotate_snapshot(stats, snapshot)


def annotate_snapshot(stats: ConsoleStats, snapshot: Snapshot) -> None:
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
		avg = 0 if active == 0 else total / active
		snapshot.classes[classname] = {"sum": total, "avg": avg, "active": active}


def convert_bytes(bytes: float) -> str:  # pylint: disable=redefined-builtin
	unit = "B"
	for unit in ["B", "KB", "MB", "GB"]:
		if abs(bytes) < 1024.0 or unit == "GB":
			break
		bytes = bytes / 1024.0
	return f"{bytes:.2f} {unit}"
