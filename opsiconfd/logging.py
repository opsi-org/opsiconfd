# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd - logging
"""

import asyncio
import glob
import logging as pylogging
import os
import re
import shutil
import socket
import sys
import threading
import time
from asyncio import get_running_loop
from concurrent.futures import ThreadPoolExecutor
from logging import Formatter, LogRecord, PlaceHolder, StreamHandler
from queue import Empty, Queue
from typing import Any, Callable, Dict

import aioredis
import colorlog
import msgpack  # type: ignore[import]
from aiologger.handlers.files import AsyncFileHandler  # type: ignore[import]
from aiologger.handlers.streams import AsyncStreamHandler  # type: ignore[import]
from OPSI.Config import OPSI_ADMIN_GROUP  # type: ignore[import]
from opsicommon.logging import (  # type: ignore[import]
	DATETIME_FORMAT,
	LOG_COLORS,
	OPSI_LEVEL_TO_LEVEL,
	SECRET_REPLACEMENT_STRING,
	ContextSecretFormatter,
	context_filter,
	get_logger,
	handle_log_exception,
	secret_filter,
	set_filter_from_string,
	set_format,
)
from opsicommon.logging.constants import NONE  # type: ignore[import]
from opsicommon.logging.logging import (  # type: ignore[import]
	add_context_filter_to_loggers,
)

from .config import config
from .utils import get_async_redis_connection, get_redis_connection, retry_redis_call

# 1 log record ~= 550 bytes
LOG_STREAM_MAX_RECORDS = 50000

redis_log_handler = None  # pylint: disable=invalid-name
redis_log_adapter_thread = None  # pylint: disable=invalid-name

# Set default log level to ERROR early
root_logger = get_logger()
root_logger.setLevel(pylogging.ERROR)
logger = get_logger("opsiconfd.general")


class AsyncRotatingFileHandler(AsyncFileHandler):  # pylint: disable=too-many-instance-attributes
	rollover_check_interval = 60

	def __init__(  # pylint: disable=too-many-arguments
		self,
		filename: str,
		formatter: Formatter,
		active_lifetime: int = 0,
		mode: str = "a",
		encoding: str = "utf-8",
		max_bytes: int = 0,
		keep_rotated: int = 0,
		error_handler: Callable = None,
	) -> None:
		super().__init__(filename, mode, encoding)
		self.active_lifetime = active_lifetime
		self._max_bytes = max_bytes
		self._keep_rotated = keep_rotated
		self.formatter = formatter
		self._rollover_lock = asyncio.Lock()
		self._rollover_error = None
		self._error_handler = error_handler
		self.last_used = time.time()
		self.should_stop = False

		self._periodically_test_rollover_task = get_running_loop().create_task(self._periodically_test_rollover())

	async def _close_stream(self):
		try:
			await self.stream.flush()
			await self.stream.close()
		except Exception:  # pylint: disable=broad-except
			pass
		self.stream = None

	async def close(self):
		"""
		flush / close blocks sometimes, processing as task
		"""
		if not self.initialized:
			return
		self.should_stop = True
		loop = get_running_loop()
		loop.create_task(self._close_stream())
		self._initialization_lock = None

	async def _periodically_test_rollover(self):
		while True:
			try:  # pylint: disable=loop-try-except-usage
				if await get_running_loop().run_in_executor(None, self.should_rollover):
					async with self._rollover_lock:
						await self.do_rollover()
						self._rollover_error = None
			except Exception as err:  # pylint: disable=broad-except
				self._rollover_error = err
				logger.error(err, exc_info=True)  # pylint: disable=loop-global-usage
			check_interval = 300 if self._rollover_error else self.rollover_check_interval
			for _sec in range(check_interval):
				if self.should_stop:
					return
				await asyncio.sleep(1)  # pylint: disable=dotted-import-in-loop

	def should_rollover(self, record: LogRecord = None) -> bool:  # pylint: disable=unused-argument
		if not os.path.exists(self.absolute_file_path):
			# This will recreate a deleted log file
			return True
		return os.path.getsize(self.absolute_file_path) >= self._max_bytes

	async def do_rollover(self):
		loop = get_running_loop()
		if self.stream:
			await self.stream.close()
		if self._keep_rotated > 0:
			for num in range(self._keep_rotated, 0, -1):
				src_file_path = self.absolute_file_path
				if num > 1:
					src_file_path = f"{self.absolute_file_path}.{num-1}"
				if not await loop.run_in_executor(None, os.path.exists, src_file_path):  # pylint: disable=dotted-import-in-loop
					continue
				dst_file_path = f"{self.absolute_file_path}.{num}"
				await loop.run_in_executor(None, os.rename, src_file_path, dst_file_path)  # pylint: disable=dotted-import-in-loop
				await loop.run_in_executor(
					None, shutil.chown, dst_file_path, config.run_as_user, OPSI_ADMIN_GROUP  # pylint: disable=dotted-import-in-loop
				)
				await loop.run_in_executor(None, os.chmod, dst_file_path, 0o644)  # pylint: disable=dotted-import-in-loop

		for filename in await loop.run_in_executor(
			None, glob.glob, f"{self.absolute_file_path}.*"  # pylint: disable=dotted-import-in-loop, loop-invariant-statement
		):
			try:  # pylint: disable=loop-try-except-usage
				if int(filename.split(".")[-1]) > self._keep_rotated:
					await loop.run_in_executor(None, os.remove, filename)  # pylint: disable=dotted-import-in-loop
			except ValueError:
				await loop.run_in_executor(None, os.remove, filename)  # pylint: disable=dotted-import-in-loop

		self.stream = None
		await self._init_writer()
		await loop.run_in_executor(None, shutil.chown, self.absolute_file_path, config.run_as_user, OPSI_ADMIN_GROUP)
		await loop.run_in_executor(None, os.chmod, self.absolute_file_path, 0o644)

	async def emit(self, record: LogRecord):
		async with self._rollover_lock:
			self.last_used = time.time()
			return await super().emit(record)

	async def handle_error(self, record: LogRecord, exception: Exception):
		if self._error_handler:
			await self._error_handler(self, record, exception)


class AsyncRedisLogAdapter:  # pylint: disable=too-many-instance-attributes
	def __init__(self, running_event=None, stderr_file=None):
		self._stderr_file = stderr_file
		if not self._stderr_file:
			self._stderr_file = sys.stderr
		self._running_event = running_event
		self._read_config()
		self._loop = get_running_loop()
		self._redis = None
		self._file_logs: Dict[str, AsyncFileHandler] = {}
		self._file_log_active_lifetime = 30
		self._file_log_lock = threading.Lock()
		self._stderr_handler = None
		self._should_stop = False
		self._set_log_format_stderr()

		if self._log_level_file != NONE:
			if self._log_file_template:
				self.get_file_handler()

		self._loop.create_task(self._start())

	async def stop(self):
		self._should_stop = True
		for file_log in self._file_logs.values():
			await file_log.close()

	def reload(self):
		self._read_config()
		self._set_log_format_stderr()

		for file_handler in self._file_logs.values():
			file_handler.formatter = ContextSecretFormatter(
				Formatter(self._log_format_no_color(self._log_format_file), datefmt=DATETIME_FORMAT)
			)
			file_handler.max_bytes = self._max_log_file_size
			file_handler.keep_rotated = self._keep_rotated_log_files

	def _read_config(self):
		self._log_file_template = config.log_file
		self._max_log_file_size = round(config.max_log_size * 1000 * 1000)
		self._keep_rotated_log_files = config.keep_rotated_logs
		self._symlink_client_log_files = config.symlink_logs
		self._log_level_stderr = OPSI_LEVEL_TO_LEVEL[config.log_level_stderr]
		self._log_level_file = OPSI_LEVEL_TO_LEVEL[config.log_level_file]
		self._log_format_stderr = config.log_format_stderr
		self._log_format_file = config.log_format_file

	def _set_log_format_stderr(self):
		if self._log_level_stderr == NONE:
			self._stderr_handler = None
			return
		if sys.stderr.isatty():
			# colorize
			console_formatter = colorlog.ColoredFormatter(self._log_format_stderr, log_colors=LOG_COLORS, datefmt=DATETIME_FORMAT)
		else:
			console_formatter = Formatter(self._log_format_no_color(self._log_format_stderr), datefmt=DATETIME_FORMAT)
		if self._stderr_handler:
			self._stderr_handler.formatter = ContextSecretFormatter(console_formatter)
		else:
			self._stderr_handler = AsyncStreamHandler(stream=self._stderr_file, formatter=ContextSecretFormatter(console_formatter))
		self._stderr_handler.add_filter(context_filter.filter)

	def _log_format_no_color(self, log_format):  # pylint: disable=no-self-use
		return log_format.replace("%(log_color)s", "").replace("%(reset)s", "")

	async def _create_client_log_file_symlink(self, ip_address):
		try:
			fqdn = await self._loop.run_in_executor(None, socket.getfqdn, ip_address)
			if fqdn != ip_address:
				src = self._log_file_template.replace("%m", ip_address)
				src = os.path.basename(src)
				dst = self._log_file_template.replace("%m", fqdn)
				if not os.path.exists(dst):
					await self._loop.run_in_executor(None, os.symlink, src, dst)
		except Exception as exc:  # pylint: disable=broad-except
			logger.error(exc, exc_info=True)

	async def handle_file_handler_error(self, file_handler: AsyncFileHandler, record: LogRecord, exception: Exception):
		if not isinstance(exception, RuntimeError):
			handle_log_exception(exception, record, stderr=True, temp_file=True)
		if file_handler.absolute_file_path in self._file_logs:
			await self._file_logs[file_handler.absolute_file_path].close()
			del self._file_logs[file_handler.absolute_file_path]

	def get_file_handler(self, client=None):
		filename = None
		if not self._log_file_template:
			return None
		try:
			name = client or "opsiconfd"
			filename = os.path.abspath(self._log_file_template.replace("%m", name))
			with self._file_log_lock:
				if not self._file_logs.get(filename):
					logger.info("Creating new file log '%s'", filename)
					log_dir = os.path.dirname(filename)
					if not os.path.isdir(log_dir):
						logger.info("Creating log dir '%s'", log_dir)
						os.makedirs(log_dir)
					# Do not close main opsiconfd log file
					active_lifetime = 0 if name == "opsiconfd" else self._file_log_active_lifetime
					self._file_logs[filename] = AsyncRotatingFileHandler(
						filename=filename,
						formatter=ContextSecretFormatter(
							Formatter(self._log_format_no_color(self._log_format_file), datefmt=DATETIME_FORMAT)
						),
						active_lifetime=active_lifetime,
						mode="a",
						encoding="utf-8",
						max_bytes=self._max_log_file_size,
						keep_rotated=self._keep_rotated_log_files,
						error_handler=self.handle_file_handler_error,
					)
					if client and self._symlink_client_log_files:
						self._loop.create_task(self._create_client_log_file_symlink(client))
				self._file_logs[filename].add_filter(context_filter.filter)
				return self._file_logs[filename]
		except Exception as exc:  # pylint: disable=broad-except
			if filename in self._file_logs:
				del self._file_logs[filename]
			handle_log_exception(exc, stderr=True, temp_file=True)
		return None

	async def _watch_log_files(self):
		if not self._log_file_template:
			return
		while True:
			try:  # pylint: disable=loop-try-except-usage
				for filename in list(self._file_logs):
					if not self._file_logs[filename] or self._file_logs[filename].active_lifetime == 0:
						continue
					time_diff = time.time() - self._file_logs[filename].last_used  # pylint: disable=dotted-import-in-loop
					if time_diff > self._file_logs[filename].active_lifetime:
						with self._file_log_lock:
							logger.info(  # pylint: disable=loop-global-usage
								"Closing inactive file log '%s', file logs remaining active: %d",
								filename,
								len(self._file_logs) - 1,  # pylint: disable=loop-invariant-statement
							)
							await self._file_logs[filename].close()
							del self._file_logs[filename]
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)  # pylint: disable=loop-global-usage
			for _ in range(60):
				if self._should_stop:
					return
				await asyncio.sleep(1)  # pylint: disable=dotted-import-in-loop,loop-invariant-statement

	async def _start(self):
		try:
			self._redis = await get_async_redis_connection(config.redis_internal_url, timeout=30, test_connection=True)
			stream_name = f"opsiconfd:log:{config.node_name}"
			await self._redis.xtrim(name=stream_name, maxlen=10000, approximate=True)
			self._loop.create_task(self._reader(stream_name=stream_name))
			self._loop.create_task(self._watch_log_files())

		except Exception as err:  # pylint: disable=broad-except
			handle_log_exception(err, stderr=True, temp_file=True)
			if self._running_event:
				self._running_event.set()

	async def _reader(self, stream_name):  # pylint: disable=too-many-branches
		if self._running_event:
			self._running_event.set()

		last_id = "$"
		while True:  # pylint: disable=too-many-nested-blocks
			try:  # pylint: disable=loop-try-except-usage
				if not self._redis:
					self._redis = await get_async_redis_connection(config.redis_internal_url)
				# It is also possible to specify multiple streams
				data = await self._redis.xread(streams={stream_name: last_id}, block=1000)  # pylint: disable=loop-invariant-statement
				if not data:
					continue
				if self._should_stop:
					return
				for stream in data:
					for entry in stream[1]:
						last_id = entry[0]
						client = entry[1].get(b"client_address", b"").decode("utf-8")
						record_dict = msgpack.unpackb(entry[1][b"record"])  # pylint: disable=dotted-import-in-loop
						record_dict.update({"scope": None, "exc_info": None, "args": None})
						record = pylogging.makeLogRecord(record_dict)  # pylint: disable=dotted-import-in-loop
						# workaround for problem in aiologger.formatters.base.Formatter.format
						record.get_message = record.getMessage
						if self._stderr_handler and record.levelno >= self._log_level_stderr:
							await self._stderr_handler.handle(record)

						if record.levelno >= self._log_level_file:
							file_handler = self.get_file_handler(client)
							if file_handler:
								await file_handler.handle(record)

			except (KeyboardInterrupt, SystemExit):  # pylint: disable=try-except-raise
				raise
			except EOFError:
				break
			except (aioredis.ConnectionError, aioredis.BusyLoadingError):  # pylint: disable=dotted-import-in-loop, loop-invariant-statement
				self._redis = None
			except Exception as err:  # pylint: disable=broad-except
				handle_log_exception(err, stderr=True, temp_file=True)


class RedisLogHandler(pylogging.Handler, threading.Thread):
	"""
	Will collect log messages in pipeline and send collected
	log messages at once to redis in regular intervals.
	"""

	def __init__(self, max_msg_len: int = 0, max_delay: float = 0.1):
		pylogging.Handler.__init__(self)
		threading.Thread.__init__(self)
		self._name = "RedisLogHandlerThread"
		self.daemon = True
		self._max_msg_len = max_msg_len
		self._max_delay = max_delay
		self._redis = get_redis_connection(config.redis_internal_url)
		self._queue: Queue = Queue()
		self._should_stop = False
		self.start()

	@property
	def name(self):
		return self._name

	def run(self):
		try:
			# Trim legacy stream to zero
			self._redis.xtrim("opsiconfd:log", maxlen=0, approximate=False)
			# Trim redis log stream to max size
			self._redis.xtrim(f"opsiconfd:log:{config.node_name}", maxlen=LOG_STREAM_MAX_RECORDS, approximate=True)
			self._process_queue()
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)

	@retry_redis_call
	def _process_queue(self):
		name = f"opsiconfd:log:{config.node_name}"
		while not self._should_stop:
			time.sleep(self._max_delay)  # pylint: disable=dotted-import-in-loop
			if self._queue.qsize() > 0:  # pylint: disable=loop-invariant-statement
				pipeline = self._redis.pipeline()
				try:  # pylint: disable=loop-try-except-usage
					while True:
						pipeline.xadd(
							name,
							self._queue.get_nowait(),
							maxlen=LOG_STREAM_MAX_RECORDS,  # pylint: disable=loop-global-usage
							approximate=True,
						)
				except Empty:  # pylint: disable=loop-invariant-statement
					pass  # pylint: disable=loop-invariant-statement
				pipeline.execute()

	def stop(self):
		self._should_stop = True

	def log_record_to_dict(self, record: LogRecord) -> Dict[str, Any]:
		try:
			msg = record.getMessage()
		except TypeError:
			msg = record.msg
		for secret in secret_filter.secrets:
			msg = msg.replace(secret, SECRET_REPLACEMENT_STRING)
		if self._max_msg_len and len(msg) > self._max_msg_len:
			msg = msg[: self._max_msg_len - 1] + "…"

		if hasattr(record, "exc_info") and record.exc_info:
			# by calling format the formatted exception information is cached in attribute exc_text
			self.format(record)
			record.exc_info = None

		rec_dict = record.__dict__.copy()
		rec_dict["msg"] = msg
		for attr in ("scope", "exc_info", "args", "contextstring", "websocket"):
			if attr in rec_dict:
				del rec_dict[attr]
		return rec_dict

	def emit(self, record):
		try:
			entry = {}
			if hasattr(record, "context"):
				entry = dict(record.context)
			entry["record"] = msgpack.packb(self.log_record_to_dict(record))
			self._queue.put(entry)
		except (KeyboardInterrupt, SystemExit):  # pylint: disable=try-except-raise
			raise
		except Exception as exc:  # pylint: disable=broad-except
			handle_log_exception(exc, record, stderr=True, temp_file=True)


def enable_slow_callback_logging(slow_callback_duration=None):
	_run_orig = asyncio.events.Handle._run  # pylint: disable=protected-access
	if slow_callback_duration is None:
		slow_callback_duration = get_running_loop().slow_callback_duration

	def _run(self):
		start = time.perf_counter()
		retval = _run_orig(self)
		time_diff = time.perf_counter() - start
		if time_diff >= slow_callback_duration:
			logger.warning(
				"Slow asyncio callback: %s took %.3f seconds",
				asyncio.base_events._format_handle(self),  # pylint: disable=protected-access
				time_diff,
			)
		return retval

	asyncio.events.Handle._run = _run  # pylint: disable=protected-access


def init_logging(
	log_mode: str = "redis", is_worker: bool = False
):  # pylint: disable=too-many-branches,too-many-statements,too-many-nested-blocks
	redis_error = None
	try:
		if log_mode not in ("redis", "local"):
			raise ValueError(f"Invalid log mode '{log_mode}'")

		log_level = max(config.log_level, config.log_level_stderr, config.log_level_file)
		if log_mode == "local":
			log_level = config.log_level_stderr
		log_level = OPSI_LEVEL_TO_LEVEL[log_level]
		log_handler: pylogging.Handler

		if log_mode == "redis":
			try:
				global redis_log_handler  # pylint: disable=global-statement,invalid-name
				if not redis_log_handler:
					redis_log_handler = RedisLogHandler(max_msg_len=int(config.log_max_msg_len))
				log_handler = redis_log_handler
			except Exception as err:  # pylint: disable=broad-except
				redis_error = err
				log_mode = "local"

		if log_mode == "local":
			log_handler = StreamHandler(stream=sys.stderr)

		log_handler.setLevel(log_level)
		root_logger.handlers = [log_handler]
		root_logger.setLevel(log_level)
		set_format(stderr_format=config.log_format_stderr, file_format=config.log_format_file)

		if config.log_filter:
			set_filter_from_string(config.log_filter)

		for logger_name in ("asyncio", "uvicorn.error", "uvicorn.access", "wsgidav"):
			logger_ = pylogging.getLogger(logger_name)  # pylint: disable=dotted-import-in-loop
			logger_.handlers = [log_handler]  # pylint: disable=loop-invariant-statement
			logger_.propagate = False

		if config.log_levels:
			loggers = {
				getattr(logger_, "name"): logger_
				for logger_ in list(pylogging.Logger.manager.loggerDict.values())
				if hasattr(logger_, "name")
			}
			logger_level_configs = {}
			for entry in [
				entry.strip() for entry in config.log_levels.split(",") if entry.strip()  # pylint: disable=loop-invariant-statement
			]:
				logger_re, level = entry.rsplit(":", 1)
				logger_level_configs[logger_re.strip()] = int(level.strip())

			# Sort by regex length so the closest match will be applied at last
			for logger_re in sorted(logger_level_configs, key=len):
				level = logger_level_configs[logger_re]
				logger_re = re.compile(logger_re)  # pylint: disable=dotted-import-in-loop
				for logger_name, logger_obj in loggers.items():
					if isinstance(logger_obj, PlaceHolder):
						continue
					if logger_re.match(logger_name):
						if level < 10:
							level = OPSI_LEVEL_TO_LEVEL[level]
						logger_obj.setLevel(level)

		add_context_filter_to_loggers()

		if config.log_slow_async_callbacks > 0:
			enable_slow_callback_logging(config.log_slow_async_callbacks)

		if not is_worker:
			if log_mode == "redis" and (config.log_level_stderr != NONE or config.log_level_file != NONE):
				start_redis_log_adapter_thread()
			else:
				stop_redis_log_adapter_thread()

		if redis_error:
			logger.critical("Failed to initalize redis logging: %s", redis_error, exc_info=True)

	except Exception as exc:  # pylint: disable=broad-except
		handle_log_exception(exc, stderr=True, temp_file=True)


def shutdown_logging():
	stop_redis_log_adapter_thread()
	if redis_log_handler:
		redis_log_handler.stop()


class RedisLogAdapterThread(threading.Thread):
	def __init__(self, running_event=None):
		threading.Thread.__init__(self)
		self.name = "RedisLogAdapterThread"
		self._running_event = running_event
		self._redis_log_adapter = None
		self._loop = None

	def stop(self):
		if self._redis_log_adapter:
			self._loop.create_task(self._redis_log_adapter.stop())

	def reload(self):
		self._redis_log_adapter.reload()

	def run(self):
		try:
			self._loop = asyncio.new_event_loop()
			self._loop.set_default_executor(
				ThreadPoolExecutor(max_workers=5, thread_name_prefix="RedisLogAdapterThread-ThreadPoolExecutor")
			)
			self._loop.set_debug(config.debug)
			asyncio.set_event_loop(self._loop)

			def handle_asyncio_exception(loop: asyncio.AbstractEventLoop, context: dict):
				if loop.is_running():
					msg = context.get("exception", context["message"])
					print(f"Unhandled exception in RedisLogAdapterThread asyncio loop: {msg}", file=sys.stderr)

			self._loop.set_exception_handler(handle_asyncio_exception)
			self._loop.create_task(self.create_redis_log_adapter())
			self._loop.run_forever()
		except Exception as exc:  # pylint: disable=broad-except
			logger.error(exc, exc_info=True)

	async def create_redis_log_adapter(self):
		self._redis_log_adapter = AsyncRedisLogAdapter(running_event=self._running_event)


def start_redis_log_adapter_thread():
	global redis_log_adapter_thread  # pylint: disable=global-statement, invalid-name
	if redis_log_adapter_thread:
		redis_log_adapter_thread.reload()
		return
	running_event = threading.Event()
	redis_log_adapter_thread = RedisLogAdapterThread(running_event)
	redis_log_adapter_thread.daemon = True
	redis_log_adapter_thread.start()
	running_event.wait()


def stop_redis_log_adapter_thread():
	if not redis_log_adapter_thread:
		return
	redis_log_adapter_thread.stop()
