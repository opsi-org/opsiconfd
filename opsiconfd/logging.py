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
from asyncio import Event, get_running_loop
from concurrent.futures import ThreadPoolExecutor
from logging import Formatter, LogRecord, PlaceHolder, StreamHandler
from queue import Empty, Queue
from typing import Any, Callable, Dict, TextIO

import colorlog
import msgspec
from aiofiles.threadpool import AsyncTextIOWrapper  # type: ignore[import]
from aiologger.handlers.files import AsyncFileHandler  # type: ignore[import]
from aiologger.handlers.streams import AsyncStreamHandler  # type: ignore[import]
from opsicommon.logging import (  # type: ignore[import]
	DATETIME_FORMAT,
	LOG_COLORS,
	OPSI_LEVEL_TO_LEVEL,
	SECRET_REPLACEMENT_STRING,
	ContextSecretFormatter,
	RichConsoleHandler,
	context_filter,
	get_logger,
	handle_log_exception,
	secret_filter,
	set_filter_from_string,
	set_format,
)
from opsicommon.logging.constants import NONE, SECRET  # type: ignore[import]
from opsicommon.logging.logging import (  # type: ignore[import]
	add_context_filter_to_loggers,
)
from redis import BusyLoadingError as RedisBusyLoadingError
from redis import ConnectionError as RedisConnectionError
from rich.console import Console

from opsiconfd.redis import (
	get_async_redis_connection,
	get_redis_connection,
	retry_redis_call,
)
from opsiconfd.utils import asyncio_create_task

from .config import config, opsi_config

# 1 log record ~= 550 bytes
LOG_STREAM_MAX_RECORDS = 50000

redis_log_handler = None  # pylint: disable=invalid-name
redis_log_adapter_thread = None  # pylint: disable=invalid-name

# Set default log level to ERROR early
root_logger = get_logger()
root_logger.setLevel(pylogging.ERROR)
logger = get_logger("opsiconfd.general")


async def event_wait(event: Event, timeout: float) -> bool:
	try:
		await asyncio.wait_for(event.wait(), timeout)
	except asyncio.TimeoutError:
		pass
	return event.is_set()


class AsyncRotatingFileHandler(AsyncFileHandler):  # pylint: disable=too-many-instance-attributes
	rollover_check_interval: int = 60
	stream: AsyncTextIOWrapper

	def __init__(  # pylint: disable=too-many-arguments
		self,
		filename: str,
		formatter: Formatter,
		active_lifetime: int = 0,
		mode: str = "a",
		encoding: str = "utf-8",
		max_bytes: int = 0,
		keep_rotated: int = 0,
		error_handler: Callable | None = None,
	) -> None:
		super().__init__(filename, mode, encoding)
		self.active_lifetime = active_lifetime
		self._max_bytes = max_bytes
		self._keep_rotated = keep_rotated
		self.formatter = formatter
		self._rollover_lock = asyncio.Lock()
		self._rollover_error: Exception | None = None
		self._error_handler = error_handler
		self._should_stop = Event()
		self._periodically_test_rollover_task = asyncio.create_task(self._periodically_test_rollover())
		self.last_used = time.time()

	async def _close_stream(self) -> None:
		try:
			await self.stream.flush()
			await self.stream.close()
		except Exception:  # pylint: disable=broad-except
			pass
		self.stream = None

	async def close(self) -> None:
		"""
		flush / close blocks sometimes, processing as task
		"""
		self._should_stop.set()
		if not self.initialized:
			return
		asyncio_create_task(self._close_stream())
		self._initialization_lock = None

	async def _periodically_test_rollover(self) -> None:
		while True:
			try:
				if await get_running_loop().run_in_executor(None, self.should_rollover):
					async with self._rollover_lock:
						await self.do_rollover()
						self._rollover_error = None
			except Exception as err:  # pylint: disable=broad-except
				self._rollover_error = err
				logger.error(err, exc_info=True)
			check_interval = 300 if self._rollover_error else self.rollover_check_interval
			if await event_wait(self._should_stop, check_interval):
				break

	def should_rollover(self, record: LogRecord | None = None) -> bool:  # pylint: disable=unused-argument
		if not os.path.exists(self.absolute_file_path):
			# This will recreate a deleted log file
			return True
		return os.path.getsize(self.absolute_file_path) >= self._max_bytes

	async def do_rollover(self) -> None:
		loop = get_running_loop()
		if self.stream:
			await self.stream.close()
		if self._keep_rotated > 0:
			for num in range(self._keep_rotated, 0, -1):
				src_file_path = self.absolute_file_path
				if num > 1:
					src_file_path = f"{self.absolute_file_path}.{num-1}"
				if not await loop.run_in_executor(None, os.path.exists, src_file_path):
					continue
				dst_file_path = f"{self.absolute_file_path}.{num}"
				await loop.run_in_executor(None, os.rename, src_file_path, dst_file_path)
				try:
					await loop.run_in_executor(
						None,
						shutil.chown,
						dst_file_path,
						config.run_as_user,
						opsi_config.get("groups", "admingroup"),
					)
				except Exception:  # pylint: disable=broad-except
					pass
				try:
					await loop.run_in_executor(None, os.chmod, dst_file_path, 0o644)
				except Exception:  # pylint: disable=broad-except
					pass
		for filename in await loop.run_in_executor(None, glob.glob, f"{self.absolute_file_path}.*"):
			if isinstance(filename, str):
				try:
					if int(filename.split(".")[-1]) > self._keep_rotated:
						await loop.run_in_executor(None, os.remove, filename)
				except ValueError:
					await loop.run_in_executor(None, os.remove, filename)

		self.stream = None
		await self._init_writer()
		try:
			await loop.run_in_executor(None, os.chmod, self.absolute_file_path, 0o644)
			await loop.run_in_executor(
				None, shutil.chown, self.absolute_file_path, config.run_as_user, opsi_config.get("groups", "admingroup")
			)
		except Exception as err:  # pylint: disable=broad-except
			logger.warning(err)

	async def emit(self, record: LogRecord) -> None:
		async with self._rollover_lock:
			self.last_used = time.time()
			return await super().emit(record)

	async def handle_error(self, record: LogRecord, exception: Exception) -> None:
		if self._error_handler:
			await self._error_handler(self, record, exception)


class AsyncRedisLogAdapter:  # pylint: disable=too-many-instance-attributes
	def __init__(self, running_event: threading.Event | None = None, stderr_file: TextIO | None = None) -> None:
		self._stderr_file = stderr_file
		if not self._stderr_file:
			self._stderr_file = sys.stderr
		self._running_event = running_event
		self._read_config()
		self._loop = get_running_loop()
		self._redis = None
		self._redis_log_stream = f"{config.redis_key('log')}:{config.node_name}"
		self._file_logs: Dict[str, AsyncFileHandler] = {}
		self._file_log_active_lifetime = 30
		self._file_log_lock = threading.Lock()
		self._stderr_handler = None
		self._should_stop = Event()
		self._reader_stopped = asyncio.Event()
		self._set_log_format_stderr()

		if self._log_level_file != NONE:
			if self._log_file_template:
				self.get_file_handler()

		asyncio_create_task(self._start(), self._loop)

	async def stop(self) -> None:
		self._should_stop.set()
		for file_log in self._file_logs.values():
			await file_log.close()
		await event_wait(self._reader_stopped, 5.0)

	def reload(self) -> None:
		self._read_config()
		self._set_log_format_stderr()

		for file_handler in self._file_logs.values():
			file_handler.formatter = ContextSecretFormatter(
				Formatter(self._log_format_no_color(self._log_format_file), datefmt=DATETIME_FORMAT)
			)
			file_handler.max_bytes = self._max_log_file_size
			file_handler.keep_rotated = self._keep_rotated_log_files

	def _read_config(self) -> None:
		self._log_file_template = config.log_file
		self._max_log_file_size = round(config.max_log_size * 1000 * 1000)
		self._keep_rotated_log_files = config.keep_rotated_logs
		self._symlink_client_log_files = config.symlink_logs
		self._log_level_stderr = OPSI_LEVEL_TO_LEVEL[config.log_level_stderr]
		self._log_level_file = OPSI_LEVEL_TO_LEVEL[config.log_level_file]
		self._log_format_stderr = config.log_format_stderr
		self._log_format_file = config.log_format_file

	def _set_log_format_stderr(self) -> None:
		if self._log_level_stderr == NONE:
			self._stderr_handler = None
			return
		console_formatter: Formatter
		if sys.stderr.isatty():
			# colorize
			console_formatter = colorlog.ColoredFormatter(self._log_format_stderr, log_colors=LOG_COLORS, datefmt=DATETIME_FORMAT)
		else:
			console_formatter = Formatter(self._log_format_no_color(self._log_format_stderr), datefmt=DATETIME_FORMAT)
		if not self._stderr_handler:
			self._stderr_handler = AsyncStreamHandler(stream=self._stderr_file)
		self._stderr_handler.formatter = ContextSecretFormatter(console_formatter)
		self._stderr_handler.formatter.secret_filter_enabled = False  # Secrets are filtered before records are written to redis
		self._stderr_handler.add_filter(context_filter.filter)

	def _log_format_no_color(self, log_format: str) -> str:
		return log_format.replace("%(log_color)s", "").replace("%(reset)s", "")

	async def _create_client_log_file_symlink(self, ip_address: str) -> None:
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

	async def handle_file_handler_error(self, file_handler: AsyncFileHandler, record: LogRecord, exception: Exception) -> None:
		if not isinstance(exception, RuntimeError):
			handle_log_exception(exception, record, stderr=True, temp_file=True)
		if file_handler.absolute_file_path in self._file_logs:
			await self._file_logs[file_handler.absolute_file_path].close()
			del self._file_logs[file_handler.absolute_file_path]

	def get_file_handler(self, client: str | None = None) -> AsyncRotatingFileHandler | None:
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
					formatter = ContextSecretFormatter(Formatter(self._log_format_no_color(self._log_format_file), datefmt=DATETIME_FORMAT))
					formatter.secret_filter_enabled = False  # Secrets are filtered before records are written to redis
					self._file_logs[filename] = AsyncRotatingFileHandler(
						filename=filename,
						formatter=formatter,
						active_lifetime=active_lifetime,
						mode="a",
						encoding="utf-8",
						max_bytes=self._max_log_file_size,
						keep_rotated=self._keep_rotated_log_files,
						error_handler=self.handle_file_handler_error,
					)
					if client and self._symlink_client_log_files:
						asyncio_create_task(self._create_client_log_file_symlink(client), self._loop)
				self._file_logs[filename].add_filter(context_filter.filter)
				return self._file_logs[filename]
		except Exception as exc:  # pylint: disable=broad-except
			if filename in self._file_logs:
				del self._file_logs[filename]
			handle_log_exception(exc, stderr=True, temp_file=True)
		return None

	async def _watch_log_files(self) -> None:
		if not self._log_file_template:
			return
		while True:
			try:
				for filename in list(self._file_logs):
					if not self._file_logs[filename] or self._file_logs[filename].active_lifetime == 0:
						continue
					time_diff = time.time() - self._file_logs[filename].last_used
					if time_diff > self._file_logs[filename].active_lifetime:
						with self._file_log_lock:
							logger.info(
								"Closing inactive file log '%s', file logs remaining active: %d",
								filename,
								len(self._file_logs) - 1,
							)
							await self._file_logs[filename].close()
							del self._file_logs[filename]
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)

			if await event_wait(self._should_stop, 60.0):
				return

	async def _start(self) -> None:
		try:
			self._redis = await get_async_redis_connection(config.redis_internal_url, timeout=30, test_connection=True)
			await self._redis.xtrim(name=self._redis_log_stream, maxlen=10000, approximate=True)
			asyncio_create_task(self._reader(), self._loop)
			asyncio_create_task(self._watch_log_files(), self._loop)

		except Exception as err:  # pylint: disable=broad-except
			handle_log_exception(err, stderr=True, temp_file=True)
			if self._running_event:
				self._running_event.set()

	async def _reader(self) -> None:  # pylint: disable=too-many-branches
		if self._running_event:
			self._running_event.set()

		msgpack_decoder = msgspec.msgpack.Decoder()
		last_id = "$"
		while True:  # pylint: disable=too-many-nested-blocks
			try:
				if not self._redis:
					self._redis = await get_async_redis_connection(config.redis_internal_url)
				# It is also possible to specify multiple streams
				data = await self._redis.xread(streams={self._redis_log_stream: last_id}, block=1000)
				if self._should_stop.is_set():
					break
				if not data:
					continue
				for stream in data:
					for entry in stream[1]:
						last_id = entry[0]
						client = entry[1].get(b"client_address", b"").decode("utf-8")
						record_dict = msgpack_decoder.decode(entry[1][b"record"])
						record_dict.update({"scope": None, "exc_info": None, "args": None})
						record = pylogging.makeLogRecord(record_dict)

						if record.levelno >= self._log_level_file:
							file_handler = self.get_file_handler(client)
							if file_handler:
								await file_handler.handle(record)

						if self._stderr_handler and record.levelno >= self._log_level_stderr:
							await self._stderr_handler.handle(record)

			except (KeyboardInterrupt, SystemExit):  # pylint: disable=try-except-raise
				raise
			except EOFError:
				break
			except (RedisConnectionError, RedisBusyLoadingError):
				self._redis = None
			except Exception as err:  # pylint: disable=broad-except
				handle_log_exception(err, stderr=True, temp_file=True)

		self._reader_stopped.set()


class RedisLogHandler(pylogging.Handler, threading.Thread):  # pylint: disable=too-many-instance-attributes
	"""
	Will collect log messages in pipeline and send collected
	log messages at once to redis in regular intervals.
	"""

	def __init__(self, max_msg_len: int = 0, max_delay: float = 0.1) -> None:
		pylogging.Handler.__init__(self)
		threading.Thread.__init__(self)
		self._name = "RedisLogHandlerThread"
		self._max_msg_len = max_msg_len
		self._max_delay = max_delay
		self._redis = get_redis_connection(config.redis_internal_url)
		self._redis_log_stream = f"{config.redis_key('log')}:{config.node_name}"
		self._queue: Queue = Queue()
		self._should_stop = threading.Event()
		self._stopped = threading.Event()
		self._msgpack_encoder = msgspec.msgpack.Encoder()
		self.start()

	@property
	def name(self) -> str:  # type: ignore[override]
		return self._name

	def run(self) -> None:
		try:
			# Trim redis log stream to max size
			self._redis.xtrim(f"{self._redis_log_stream}", maxlen=LOG_STREAM_MAX_RECORDS, approximate=True)
			self._process_queue()
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)

	@retry_redis_call
	def _process_queue(self) -> None:
		while True:
			self._should_stop.wait(self._max_delay)
			if self._queue.qsize() > 0:
				pipeline = self._redis.pipeline()
				try:
					while True:
						pipeline.xadd(
							self._redis_log_stream,
							self._queue.get_nowait(),
							maxlen=LOG_STREAM_MAX_RECORDS,
							approximate=True,
						)
				except Empty:
					pass
				pipeline.execute()
			if self._should_stop.is_set():
				break

	def stop(self) -> None:
		self._should_stop.set()
		self._stopped.wait(3.0)

	def log_record_to_dict(self, record: LogRecord) -> Dict[str, Any]:
		try:
			msg = record.getMessage()
		except TypeError:
			msg = record.msg
		if self.level != SECRET:
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

	def emit(self, record: LogRecord) -> None:
		try:
			entry = {}
			context = getattr(record, "context", None)
			if context:
				entry = dict(context)
			entry["record"] = self._msgpack_encoder.encode(self.log_record_to_dict(record))
			self._queue.put(entry)
		except (KeyboardInterrupt, SystemExit):  # pylint: disable=try-except-raise
			raise
		except Exception as exc:  # pylint: disable=broad-except
			handle_log_exception(exc, record, stderr=True, temp_file=True)


def enable_slow_callback_logging(slow_callback_duration: float | None = None) -> None:
	_run_orig = asyncio.events.Handle._run  # pylint: disable=protected-access
	if slow_callback_duration is None:
		slow_callback_duration = get_running_loop().slow_callback_duration

	def _run(self: asyncio.events.Handle) -> int | None:
		start = time.perf_counter()
		retval = _run_orig(self)
		time_diff = time.perf_counter() - start
		if slow_callback_duration and time_diff >= slow_callback_duration:
			logger.warning(
				"Slow asyncio callback: %s took %.3f seconds",
				asyncio.base_events._format_handle(self),  # type: ignore[attr-defined]  # pylint: disable=protected-access
				time_diff,
			)
		return retval

	asyncio.events.Handle._run = _run  # type: ignore[assignment]  # pylint: disable=protected-access


def init_logging(  # pylint: disable=too-many-branches,too-many-statements,too-many-nested-blocks,too-many-locals
	log_mode: str = "redis", is_worker: bool = False, console: Console | None = None
) -> None:
	redis_error = None
	try:
		if log_mode not in ("redis", "local", "rich"):
			raise ValueError(f"Invalid log mode '{log_mode}'")

		log_level = max(config.log_level, config.log_level_stderr, config.log_level_file)
		if log_mode in ("local", "rich"):
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
		elif log_mode == "rich":
			if not console:
				console = Console()
			log_handler = RichConsoleHandler(console=console)

		log_handler.setLevel(log_level)
		root_logger.handlers = [log_handler]
		root_logger.setLevel(log_level)
		set_format(stderr_format=config.log_format_stderr, file_format=config.log_format_file)

		if config.log_filter:
			set_filter_from_string(config.log_filter)

		for logger_name in ("asyncio", "uvicorn.error", "uvicorn.access", "wsgidav"):
			logger_ = pylogging.getLogger(logger_name)
			logger_.handlers = [log_handler]
			logger_.propagate = False

		if config.log_levels:
			loggers = {
				getattr(logger_, "name"): logger_
				for logger_ in list(pylogging.Logger.manager.loggerDict.values())
				if hasattr(logger_, "name")
			}
			logger_level_configs = {}
			for entry in [entry.strip() for entry in config.log_levels.split(",") if entry.strip()]:
				logger_re, level = entry.rsplit(":", 1)
				logger_level_configs[logger_re.strip()] = int(level.strip())

			# Sort by regex length so the closest match will be applied at last
			for logger_re in sorted(logger_level_configs, key=len):
				level = logger_level_configs[logger_re]
				logger_re = re.compile(logger_re)
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


def shutdown_logging() -> None:
	if redis_log_handler:
		redis_log_handler.stop()
	stop_redis_log_adapter_thread()


class RedisLogAdapterThread(threading.Thread):
	def __init__(self, running_event: threading.Event | None = None) -> None:
		threading.Thread.__init__(self)
		self.name = "RedisLogAdapterThread"
		self._running_event = running_event
		self._redis_log_adapter: AsyncRedisLogAdapter | None = None
		self._loop: asyncio.AbstractEventLoop | None = None

	def stop(self) -> None:
		if self._redis_log_adapter and self._loop:
			asyncio_create_task(self._redis_log_adapter.stop(), self._loop)

	def reload(self) -> None:
		if self._redis_log_adapter:
			self._redis_log_adapter.reload()

	def run(self) -> None:
		try:
			self._loop = asyncio.new_event_loop()
			self._loop.set_default_executor(
				ThreadPoolExecutor(max_workers=5, thread_name_prefix="RedisLogAdapterThread-ThreadPoolExecutor")
			)
			self._loop.set_debug("asyncio" in config.debug_options)
			asyncio.set_event_loop(self._loop)

			def handle_asyncio_exception(loop: asyncio.AbstractEventLoop, context: dict) -> None:
				if loop.is_running():
					msg = context.get("exception", context["message"])
					print(f"Unhandled exception in RedisLogAdapterThread asyncio loop: {msg}", file=sys.stderr)

			self._loop.set_exception_handler(handle_asyncio_exception)
			asyncio_create_task(self.create_redis_log_adapter(), self._loop)
			self._loop.run_forever()
		except Exception as exc:  # pylint: disable=broad-except
			logger.error(exc, exc_info=True)

	async def create_redis_log_adapter(self) -> None:
		self._redis_log_adapter = AsyncRedisLogAdapter(running_event=self._running_event)


def start_redis_log_adapter_thread() -> None:
	global redis_log_adapter_thread  # pylint: disable=global-statement, invalid-name
	if redis_log_adapter_thread:
		redis_log_adapter_thread.reload()
		return
	running_event = threading.Event()
	redis_log_adapter_thread = RedisLogAdapterThread(running_event)
	redis_log_adapter_thread.daemon = True
	redis_log_adapter_thread.start()
	running_event.wait()


def stop_redis_log_adapter_thread() -> None:
	if not redis_log_adapter_thread:
		return
	redis_log_adapter_thread.stop()
