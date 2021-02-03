"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""

import sys
import time
import orjson

from fastapi import Request, APIRouter
from fastapi.responses import JSONResponse

from pympler import tracker, classtracker

from ..logging import logger
from ..worker import get_redis_client
from ..utils import get_node_name, decode_redis_result

memory_profiler_router = APIRouter()

MEMORY_TRACKER = None
CLASS_TRACKER = None


@memory_profiler_router.get("/memory-summary")
def pympler_info() -> JSONResponse:

	global MEMORY_TRACKER # pylint: disable=global-statement
	if not MEMORY_TRACKER:
		MEMORY_TRACKER = tracker.SummaryTracker()

	memory_summary = MEMORY_TRACKER.create_summary()
	memory_summary = sorted(memory_summary, key=lambda x: x[2], reverse=True)

	response = JSONResponse({"status": 200, "error": None, "data": {"memory_summary": memory_summary}})
	return response

@memory_profiler_router.post("/memory/snapshot")
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

@memory_profiler_router.delete("/memory/snapshot")
async def delte_memory_snapshot() -> JSONResponse:

	redis_client = await get_redis_client()
	node = get_node_name()

	await redis_client.delete(f"opsiconfd:stats:memory:summary:{node}")

	global MEMORY_TRACKER # pylint: disable=global-statement
	MEMORY_TRACKER = None

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Deleted all memory snapshots."}})
	return response

@memory_profiler_router.get("/memory/diff")
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

@memory_profiler_router.post("/memory/classtracker")
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

@memory_profiler_router.get("/memory/classtracker/summary")
async def classtracker_summary() -> JSONResponse:

	global CLASS_TRACKER # pylint: disable=global-statement

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
			cls_dict = {
				"class": cls,
				"active": active,
				"sum": mem_sum,
				"avg": mem_avg
			}
			classes.append(cls_dict)
		class_summary.append({"description": snapshot.desc, "classes": classes})

	# CLASS_TRACKER.close() # TODO close class Tracker

	print_class_summary(class_summary)

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Class Tracker Summary.", "summary": class_summary}})
	return response

# TODO: maybe do this in JS
def convert_bytes(bytes): # pylint: disable=redefined-builtin
	unit = "B"
	for unit in ["B", "KB", "MB", "GB"]:
		if bytes < 1024.0 or unit == "GB":
			break
		bytes = bytes/1024.0
	return f"{bytes:.2f} {unit}"

@memory_profiler_router.delete("/memory/classtracker")
async def delte_class_tracker() -> JSONResponse:

	logger.devel("delte_class_tracker")

	global CLASS_TRACKER # pylint: disable=global-statement
	CLASS_TRACKER.close()
	CLASS_TRACKER = None
	logger.devel(CLASS_TRACKER)

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Deleted class tracker."}})
	return response


def print_class_summary(summary: list) -> None:

	logger.essential("---- SUMMARY " + "-" * 66)
	for snapshot in summary:
		logger.essential("%-35s %11s %12s %12s", snapshot.get("description"), "active", "sum", 'average')
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
			if (tobj.birth < snapshot.timestamp and
					(tobj.death is None or
						tobj.death > snapshot.timestamp)):
				active += 1
		try:
			avg = total / active
		except ZeroDivisionError:
			avg = 0

		snapshot.classes[classname] = dict(sum=total, avg=avg, active=active)
