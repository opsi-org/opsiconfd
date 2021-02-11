"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""

import gc
import io
import sys
import time
import orjson

from fastapi import Request, APIRouter
from fastapi.responses import JSONResponse

from pympler import tracker, classtracker
from guppy import hpy

from ..logging import logger
from ..worker import get_redis_client
from ..utils import get_node_name, decode_redis_result

memory_profiler_router = APIRouter()

MEMORY_TRACKER = None
CLASS_TRACKER = None
HEAP = None


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

	async with await redis_client.pipeline() as pipe:
		value = orjson.dumps({"memory_summary": memory_summary, "timestamp": timestamp}) # pylint: disable=c-extension-no-member
		await pipe.lpush(f"opsiconfd:stats:memory:summary:{node}", value)
		await pipe.ltrim(f"opsiconfd:stats:memory:summary:{node}", 0, 9)
		redis_result = await pipe.execute()

	logger.devel("redis lpush memory summary: %s", redis_result)

	logger.devel("MEMORY_TRACKER.summaries: %s", MEMORY_TRACKER.summaries)
	logger.devel("MEMORY_TRACKER: %s", len(MEMORY_TRACKER.summaries))

	total_size = 0
	count = 0
	for idx in range(0, len(memory_summary)-1):
		count += memory_summary[idx][1]
		total_size += memory_summary[idx][2]
		memory_summary[idx][2] = convert_bytes(memory_summary[idx][2])

	objs_size = convert_bytes(sys.getsizeof(gc.get_objects()))

	response = JSONResponse({
		"status": 200,
		"error": None,
		"data": {
			"objs_size": objs_size,
			"count": count,
			"total_size": convert_bytes(total_size),
			"memory_summary": memory_summary
		}
	})
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

	count = 0
	total_size = 0
	for idx in range(0, len(memory_summary)-1):
		count += memory_summary[idx][1]
		total_size += memory_summary[idx][2]
		memory_summary[idx][2] = convert_bytes(memory_summary[idx][2])

	response = JSONResponse({
		"status": 200,
		"error": None,
		"data": {
			"count": count,
			"total_size": convert_bytes(total_size),
			"memory_diff": memory_summary
		}
	})
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

	print_class_summary(class_summary)

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Class Tracker Summary.", "summary": class_summary}})
	return response


@memory_profiler_router.delete("/memory/classtracker")
async def delte_class_tracker() -> JSONResponse:

	logger.devel("delte_class_tracker")

	global CLASS_TRACKER # pylint: disable=global-statement
	CLASS_TRACKER.close()
	CLASS_TRACKER = None
	logger.devel(CLASS_TRACKER)

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Deleted class tracker."}})
	return response


@memory_profiler_router.post("/memory/guppy")
async def guppy_snapshot() -> JSONResponse:

	global HEAP # pylint: disable=global-statement
	if not HEAP:
		HEAP = hpy()


	heap_status = HEAP.heap()
	logger.devel(dir(heap_status))
	logger.devel("SIZE: %s", convert_bytes(heap_status.size))
	fn = io.StringIO() # pylint: disable=invalid-name
	heap_status.dump(fn)

	redis_client = await get_redis_client()
	node = get_node_name()

	async with await redis_client.pipeline() as pipe:
		await pipe.lpush(f"opsiconfd:stats:memory:heap:{node}", fn.getvalue())
		await pipe.ltrim(f"opsiconfd:stats:memory:heap:{node}", 0, 9)
		redis_result = await pipe.execute()

	logger.devel("redis lpush memory summary: %s", redis_result)

	logger.devel(heap_status)
	logger.devel(heap_status.byclodo.stat)

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

	response = JSONResponse({
		"status": 200,
		"error": None,
		"data": {
			"objects": heap_status.stat.count,
			"total_size": convert_bytes(heap_status.stat.size),
			"heap_status": heap_objects
		}
	})
	return response


@memory_profiler_router.delete("/memory/guppy")
async def delte_guppy_snapshot() -> JSONResponse:

	redis_client = await get_redis_client()
	node = get_node_name()

	await redis_client.delete(f"opsiconfd:stats:memory:heap:{node}")

	global HEAP # pylint: disable=global-statement
	HEAP = None

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Deleted all guppy heap snapshots."}})
	return response


@memory_profiler_router.get("/memory/guppy/setref")
async def guppy_set_ref() -> JSONResponse:

	global HEAP # pylint: disable=global-statement
	if not HEAP:
		HEAP = hpy()
	HEAP.setref()

	response = JSONResponse({"status": 200, "error": None, "data": {"msg": "Set new ref point"}})
	return response

@memory_profiler_router.get("/memory/guppy/diff")
async def guppy_diff(snapshot1: int = 1, snapshot2: int = -1) -> JSONResponse:

	global HEAP # pylint: disable=global-statement
	if not HEAP:
		HEAP = hpy()

	redis_client = await get_redis_client()
	node = get_node_name()

	snapshot_count = await redis_client.llen(f"opsiconfd:stats:memory:heap:{node}")

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


	redis_result = await redis_client.lindex(f"opsiconfd:stats:memory:heap:{node}", start)

	logger.devel(decode_redis_result(redis_result))
	fn1 = io.StringIO(decode_redis_result(redis_result))
	logger.devel(fn1.getvalue())
	snapshot1 = HEAP.load(fn1)

	redis_result = await redis_client.lindex(f"opsiconfd:stats:memory:heap:{node}", end)
	fn2 = io.StringIO(decode_redis_result(redis_result))
	snapshot2 = HEAP.load(fn2)

	logger.devel(snapshot2)
	logger.devel(dir(snapshot2))
	heap_diff = snapshot2 - snapshot1

	logger.devel("Total Objects : %s", heap_diff.count)
	logger.devel("Total Size : %s Bytes", heap_diff.size)
	logger.devel("Number of Entries : %s", heap_diff.numrows)

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

	response = JSONResponse({
		"status": 200,
		"error": None,
		"data": {
			"objects": heap_diff.count,
			"total_size": convert_bytes(heap_diff.size),
			"heap_diff": heap_objects
		}
	})
	return response



def print_class_summary(cls_summary: list) -> None:

	logger.essential("---- SUMMARY " + "-" * 66)
	for snapshot in cls_summary:
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


def convert_bytes(bytes): # pylint: disable=redefined-builtin
	unit = "B"
	for unit in ["B", "KB", "MB", "GB"]:
		if abs(bytes) < 1024.0 or unit == "GB":
			break
		bytes = bytes/1024.0
	return f"{bytes:.2f} {unit}"
