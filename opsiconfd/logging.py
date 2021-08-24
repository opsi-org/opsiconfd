# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd - logging
"""

import shutil
import time
import sys
import os
import socket
import threading
import asyncio
from queue import Queue, Empty
import logging as pylogging
from logging import LogRecord, Formatter, StreamHandler
from concurrent.futures import ThreadPoolExecutor

import aredis
import msgpack
import colorlog

from aiologger.handlers.streams import AsyncStreamHandler
from aiologger.handlers.files import AsyncFileHandler

from OPSI.Config import OPSI_ADMIN_GROUP

from opsicommon.logging import (
	logger, secret_filter, handle_log_exception, set_format,
	set_filter_from_string, context_filter, ContextSecretFormatter,
	SECRET_REPLACEMENT_STRING, LOG_COLORS, DATETIME_FORMAT,
	DEFAULT_COLORED_FORMAT, OPSI_LEVEL_TO_LEVEL
)
from opsicommon.logging.logging import add_context_filter_to_loggers

from .utils import retry_redis_call, get_aredis_connection, get_redis_connection
from .config import config

# 1 log record ~= 550 bytes
LOG_STREAM_MAX_RECORDS = 50000

# Set default log level to ERROR early
logger.setLevel(pylogging.ERROR)

class AsyncRotatingFileHandler(AsyncFileHandler):  # pylint: disable=too-many-instance-attributes
	rollover_check_interval = 60

	def __init__(  # pylint: disable=too-many-arguments
		self, filename: str,
		formatter: Formatter,
		active_lifetime: int = 0,
		mode: str = "a",
		encoding: str = 'utf-8',
		max_bytes: int = 0,
		keep_rotated: int = 0
	) -> None:
		super().__init__(filename, mode, encoding)
		self.active_lifetime = active_lifetime
		self._max_bytes = max_bytes
		self._keep_rotated = keep_rotated
		self.formatter = formatter
		self._rollover_lock = asyncio.Lock()
		self._rollover_error = None
		self.last_used = time.time()
		asyncio.get_event_loop().create_task(self._periodically_test_rollover())

	async def close(self):
		if not self.initialized:
			return
		loop = asyncio.get_event_loop()
		loop.create_task(self.stream.flush())
		loop.create_task(self.stream.close())
		self.stream = None
		self._initialization_lock = None


	async def _periodically_test_rollover(self):
		while True:
			try:
				if await asyncio.get_event_loop().run_in_executor(None, self.should_rollover):
					async with self._rollover_lock:
						await self.do_rollover()
						self._rollover_error = None
			except Exception as err: # pylint: disable=broad-except
				self._rollover_error = err
				logger.error(err)
			check_interval = 300 if self._rollover_error else self.rollover_check_interval
			for _sec in range(check_interval):
				await asyncio.sleep(1)

	def should_rollover(self, record: LogRecord = None) -> bool: # pylint: disable=unused-argument
		if not os.path.exists(self.absolute_file_path):
			# This will recreate a deleted log file
			return True
		return os.path.getsize(self.absolute_file_path) >= self._max_bytes

	async def do_rollover(self):
		if self.stream:
			await self.stream.close()
		if self._keep_rotated > 0:
			for num in range(self._keep_rotated, 0, -1):
				src_file_path = self.absolute_file_path
				if num > 1:
					src_file_path = f"{self.absolute_file_path}.{num-1}"
				dst_file_path = f"{self.absolute_file_path}.{num}"
				loop = asyncio.get_event_loop()
				if await loop.run_in_executor(None, os.path.exists, src_file_path):
					await loop.run_in_executor(None, os.rename, src_file_path, dst_file_path)
					shutil.chown(path=dst_file_path, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
					os.chmod(path=dst_file_path, mode=0o644)
		self.stream = None
		await self._init_writer()
		shutil.chown(path=self.absolute_file_path, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
		os.chmod(path=self.absolute_file_path, mode=0o644)

	async def emit(self, record: LogRecord):
		async with self._rollover_lock:
			self.last_used = time.time()
			return await super().emit(record)

	async def handle_error(self, record, exception):
		if not isinstance(exception, RuntimeError):
			handle_log_exception(exception, record, stderr=True, temp_file=True)

class AsyncRedisLogAdapter: # pylint: disable=too-many-instance-attributes
	def __init__( # pylint: disable=too-many-arguments
		self, running_event=None, log_file_template=None,
			max_log_file_size=0, keep_rotated_log_files=0, symlink_client_log_files=False,
			log_format_stderr=DEFAULT_COLORED_FORMAT, log_format_file=DEFAULT_COLORED_FORMAT,
			log_level_stderr=pylogging.NOTSET, log_level_file=pylogging.NOTSET
		):
		self._running_event = running_event
		self._log_file_template = log_file_template
		self._max_log_file_size = max_log_file_size
		self._keep_rotated_log_files = keep_rotated_log_files
		self._symlink_client_log_files = symlink_client_log_files
		self._log_level_stderr = log_level_stderr
		self._log_level_file = log_level_file
		self._log_format_stderr = log_format_stderr
		self._log_format_file = log_format_file
		self._loop = asyncio.get_event_loop()
		self._redis = None
		self._file_logs = {}
		self._file_log_active_lifetime = 30
		self._file_log_lock = threading.Lock()
		self._stderr_handler = None
		if self._log_level_stderr != pylogging.NONE:
			if sys.stderr.isatty():
				# colorize
				console_formatter = colorlog.ColoredFormatter(self._log_format_stderr, log_colors=LOG_COLORS, datefmt=DATETIME_FORMAT)
			else:
				console_formatter = Formatter(self._log_format_no_color(self._log_format_stderr), datefmt=DATETIME_FORMAT)
			self._stderr_handler = AsyncStreamHandler(stream=sys.stderr, formatter=ContextSecretFormatter(console_formatter))
			self._stderr_handler.add_filter(context_filter.filter)

		if self._log_level_file != pylogging.NONE:
			if self._log_file_template:
				self.get_file_handler()

		self._loop.create_task(self._start())

	async def stop(self):
		self._loop.stop()

	def _log_format_no_color(self, log_format): # pylint: disable=no-self-use
		return log_format.replace('%(log_color)s', '').replace('%(reset)s', '')

	async def _create_client_log_file_symlink(self, ip_address):
		try:
			fqdn = await self._loop.run_in_executor(None, socket.getfqdn, ip_address)
			if fqdn != ip_address:
				src = self._log_file_template.replace('%m', ip_address)
				src = os.path.basename(src)
				dst = self._log_file_template.replace('%m', fqdn)
				if not os.path.exists(dst):
					await self._loop.run_in_executor(None, os.symlink, src, dst)
		except Exception as exc: # pylint: disable=broad-except
			logger.error(exc, exc_info=True)

	def get_file_handler(self, client=None):
		filename = None
		if not self._log_file_template:
			return None
		try:
			name = client or 'opsiconfd'
			filename = self._log_file_template.replace('%m', name)
			with self._file_log_lock:
				if not filename in self._file_logs:
					logger.info("Creating new file log '%s'", filename)
					log_dir = os.path.dirname(filename)
					if not os.path.isdir(log_dir):
						logger.info("Creating log dir '%s'", log_dir)
						os.makedirs(log_dir)
					# Do not close main opsiconfd log file
					active_lifetime = 0 if name == 'opsiconfd' else self._file_log_active_lifetime
					self._file_logs[filename] = AsyncRotatingFileHandler(
						filename=filename,
						formatter=ContextSecretFormatter(Formatter(self._log_format_no_color(self._log_format_file), datefmt=DATETIME_FORMAT)),
						active_lifetime=active_lifetime,
						mode='a',
						encoding='utf-8',
						max_bytes=self._max_log_file_size,
						keep_rotated=self._keep_rotated_log_files
					)
					if client and self._symlink_client_log_files:
						self._loop.create_task(self._create_client_log_file_symlink(client))
				self._file_logs[filename].add_filter(context_filter.filter)
				return self._file_logs[filename]
		except Exception as exc:  # pylint: disable=broad-except
			self._file_logs[filename] = None
			handle_log_exception(exc, stderr=True, temp_file=True)
		return None

	async def _watch_log_files(self):
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
								filename, len(self._file_logs) - 1
							)
							await self._file_logs[filename].close()
							del self._file_logs[filename]
			except Exception as err: # pylint: disable=broad-except
				logger.error(err, exc_info=True)
			for _i in range(60):
				await asyncio.sleep(1)

	async def _start(self):
		try:
			self._redis = await get_aredis_connection(config.redis_internal_url)
			stream_name = f"opsiconfd:log:{config.node_name}"
			await self._redis.xtrim(name=stream_name, max_len=10000, approximate=True)
			self._loop.create_task(self._reader(stream_name=stream_name))
			self._loop.create_task(self._watch_log_files())

		except Exception as err: # pylint: disable=broad-except
			handle_log_exception(err, stderr=True, temp_file=True)

	async def _reader(self, stream_name):
		if self._running_event:
			self._running_event.set()

		b_stream_name = stream_name.encode("utf-8")
		last_id = '$'
		while True:
			try:
				if not self._redis:
					self._redis = await get_aredis_connection(config.redis_internal_url)
				# It is also possible to specify multiple streams
				data = await self._redis.xread(block=1000, **{stream_name: last_id})
				if not data:
					continue
				for entry in data[b_stream_name]:
					last_id = entry[0]
					client = entry[1].get(b"client_address", b"").decode("utf-8")
					record_dict = msgpack.unpackb(entry[1][b"record"])
					record_dict.update({
						"scope": None,
						"exc_info": None,
						"args": None
					})
					record = pylogging.makeLogRecord(record_dict)
					# workaround for problem in aiologger.formatters.base.Formatter.format
					record.get_message = record.getMessage
					if self._stderr_handler and record.levelno >= self._log_level_stderr:
						await self._stderr_handler.handle(record)

					if record.levelno >= self._log_level_file:
						file_handler = self.get_file_handler(client)
						if file_handler:
							await file_handler.handle(record)

					del record
					del record_dict
					del entry
				del data

			except (KeyboardInterrupt, SystemExit): # pylint: disable=try-except-raise
				raise
			except EOFError:
				break
			except (aredis.exceptions.ConnectionError, aredis.BusyLoadingError):
				self._redis = None
			except Exception as err: # pylint: disable=broad-except
				handle_log_exception(err, stderr=True, temp_file=True)

class RedisLogHandler(threading.Thread, pylogging.Handler):
	"""
	Will collect log messages in pipeline and send collected
	log messages at once to redis in regular intervals.
	"""
	def __init__(self, max_msg_len: int = 0, max_delay: float = 0.1):
		pylogging.Handler.__init__(self)
		threading.Thread.__init__(self)
		self.name = "RedisLogHandlerThread"
		self.daemon = True
		self._max_msg_len = max_msg_len
		self._max_delay = max_delay
		self._redis = get_redis_connection(config.redis_internal_url)
		self._queue = Queue()
		self._should_stop = False
		self.start()

	def run(self):
		try:
			# Trim legacy stream to zero
			self._redis.xtrim(
				"opsiconfd:log",
				maxlen=0,
				approximate=False
			)
			# Trim redis log stream to max size
			self._redis.xtrim(
				f"opsiconfd:log:{config.node_name}",
				maxlen=LOG_STREAM_MAX_RECORDS,
				approximate=True
			)
			self._process_queue()
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)

	@retry_redis_call
	def _process_queue(self):
		while not self._should_stop:
			time.sleep(self._max_delay)
			if self._queue.qsize() > 0:
				pipeline = self._redis.pipeline()
				while True:
					try:
						pipeline.xadd(
							f"opsiconfd:log:{config.node_name}",
							self._queue.get_nowait(),
							maxlen=LOG_STREAM_MAX_RECORDS,
							approximate=True
						)
					except Empty:
						break
				pipeline.execute()

	def stop(self):
		self._should_stop = True

	def log_record_to_dict(self, record):
		msg = record.getMessage()
		for secret in secret_filter.secrets:
			msg = msg.replace(secret, SECRET_REPLACEMENT_STRING)
		if self._max_msg_len and len(msg) > self._max_msg_len:
			msg = msg[:self._max_msg_len - 1] + '…'

		if hasattr(record, 'exc_info') and record.exc_info:
			# by calling format the formatted exception information is cached in attribute exc_text
			self.format(record)
			record.exc_info = None

		rec_dict = record.__dict__.copy()
		rec_dict["msg"] = msg
		for attr in ('scope', 'exc_info', 'args', 'contextstring'):
			if attr in rec_dict:
				del rec_dict[attr]
		return rec_dict

	def emit(self, record):
		try:
			str_record = msgpack.packb(self.log_record_to_dict(record))
			entry = dict(record.context or {})
			entry["record"] = str_record
			self._queue.put(entry)
		except (KeyboardInterrupt, SystemExit): # pylint: disable=try-except-raise
			raise
		except Exception as exc: # pylint: disable=broad-except
			handle_log_exception(exc, record, stderr=True, temp_file=True)


def enable_slow_callback_logging(slow_callback_duration = None):
	_run_orig = asyncio.events.Handle._run # pylint: disable=protected-access
	if slow_callback_duration is None:
		slow_callback_duration = asyncio.get_event_loop().slow_callback_duration

	def _run(self):
		start = time.perf_counter()
		retval = _run_orig(self)
		time_diff = time.perf_counter() - start
		if time_diff >= slow_callback_duration:
			logger.warning(
				"Slow asyncio callback: %s took %.3f seconds",
				asyncio.base_events._format_handle(self), time_diff # pylint: disable=protected-access
			)
		return retval

	asyncio.events.Handle._run = _run  # pylint: disable=protected-access


redis_log_handler = None  # pylint: disable=invalid-name

def init_logging(log_mode: str = "redis", is_worker: bool = False): # pylint: disable=too-many-branches
	redis_error = None
	try:
		if log_mode not in ("redis", "local"):
			raise ValueError(f"Invalid log mode '{log_mode}'")

		log_level = max(config.log_level, config.log_level_stderr, config.log_level_file)
		if log_mode == "local":
			log_level = config.log_level_stderr
		log_level = OPSI_LEVEL_TO_LEVEL[log_level]
		log_handler = None

		if log_mode == "redis":
			try:
				global redis_log_handler  # pylint: disable=global-statement,invalid-name
				if not redis_log_handler:
					redis_log_handler = RedisLogHandler(max_msg_len=int(config.log_max_msg_len))
				log_handler = redis_log_handler
			except Exception as err: # pylint: disable=broad-except
				redis_error = err
				log_mode = "local"

		if log_mode == "local":
			log_handler = StreamHandler(stream=sys.stderr)

		log_handler.setLevel(log_level)
		logger.handlers = [log_handler]
		logger.setLevel(log_level)
		set_format(stderr_format=config.log_format_stderr, file_format=config.log_format_file)

		if config.log_filter:
			set_filter_from_string(config.log_filter)

		for logger_name in ("asyncio", "uvicorn.error", "uvicorn.access", "wsgidav"):
			_logger = pylogging.getLogger(logger_name)
			_logger.setLevel(log_level)
			_logger.handlers = [log_handler]
			_logger.propagate = False

		add_context_filter_to_loggers()

		if config.log_slow_async_callbacks > 0:
			enable_slow_callback_logging(config.log_slow_async_callbacks)

		if not is_worker:
			if log_mode == "redis" and (config.log_level_stderr != pylogging.NONE or config.log_level_file != pylogging.NONE):
				start_redis_log_adapter_thread()
			else:
				stop_redis_log_adapter_thread()

		if redis_error:
			logger.critical("Failed to initalize redis logging: %s", redis_error, exc_info=True)

	except Exception as exc: # pylint: disable=broad-except
		handle_log_exception(exc, stderr=True, temp_file=True)


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

	def run(self):
		try:
			self._loop = asyncio.new_event_loop()
			self._loop.set_default_executor(
				ThreadPoolExecutor(
					max_workers=5,
					thread_name_prefix="RedisLogAdapterThread-ThreadPoolExecutor"
				)
			)
			self._loop.set_debug(config.debug)
			asyncio.set_event_loop(self._loop)
			def handle_asyncio_exception(loop, context):
				if loop.is_running():
					msg = context.get("exception", context["message"])
					print("Unhandled exception in RedisLogAdapterThread asyncio loop: %s" % msg, file=sys.stderr)
			self._loop.set_exception_handler(handle_asyncio_exception)
			self._redis_log_adapter = AsyncRedisLogAdapter(
				running_event=self._running_event,
				log_file_template=config.log_file,
				log_format_stderr=config.log_format_stderr,
				log_format_file=config.log_format_file,
				max_log_file_size=round(config.max_log_size * 1000 * 1000),
				keep_rotated_log_files=config.keep_rotated_logs,
				symlink_client_log_files=config.symlink_logs,
				log_level_stderr=OPSI_LEVEL_TO_LEVEL[config.log_level_stderr],
				log_level_file=OPSI_LEVEL_TO_LEVEL[config.log_level_file]
			)
			self._loop.run_forever()
		except Exception as exc: # pylint: disable=broad-except
			logger.error(exc, exc_info=True)

redis_log_adapter_thread = None # pylint: disable=invalid-name
def start_redis_log_adapter_thread():
	global redis_log_adapter_thread # pylint: disable=global-statement, invalid-name
	if redis_log_adapter_thread:
		return
	running_event = threading.Event()
	redis_log_adapter_thread = RedisLogAdapterThread(running_event)
	redis_log_adapter_thread.daemon = True
	redis_log_adapter_thread.start()
	running_event.wait()

def stop_redis_log_adapter_thread():
	global redis_log_adapter_thread # pylint: disable=global-statement, invalid-name
	if not redis_log_adapter_thread:
		return
	redis_log_adapter_thread.stop()
