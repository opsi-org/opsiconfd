# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Logging helpers

:copyright: uib GmbH <info@uib.de>
:author: Niko Wenselowski <n.wenselowski@uib.de>
:author: Jan Schneider <j.schneider@uib.de>
:license: GNU Affero General Public License version 3
"""

import traceback
import time
import sys
import os
import queue
import socket
import logging
import inspect
from logging import LogRecord, Formatter, StreamHandler, Filter
import threading
import asyncio
import aredis
import redis
import msgpack
import colorlog
from collections import namedtuple
from gunicorn import glogging
from logging.handlers import WatchedFileHandler, RotatingFileHandler
from aiologger.handlers.streams import AsyncStreamHandler
from aiologger.handlers.files import AsyncFileHandler

import OPSI.Logger

from .utils import Singleton
from .config import config

DEFAULT_FORMAT = "%(log_color)s[%(opsilevel)d] [%(asctime)s.%(msecs)03d]%(reset)s %(message)s   (%(filename)s:%(lineno)d)"
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
SECRET_REPLACEMENT_STRING = '***secret***'

#logger = logging.getLogger('opsiconfd')
logger = logging.getLogger()
#redis_log_handler = None

logging.NONE = 0
logging.NOTSET = logging.NONE
logging.SECRET = 10
logging.CONFIDENTIAL = logging.SECRET
logging.TRACE = 20
logging.DEBUG2 = logging.TRACE
logging.DEBUG = 30
logging.INFO = 40
logging.NOTICE = 50
logging.WARNING = 60
logging.WARN = logging.WARNING
logging.ERROR = 70
logging.CRITICAL = 80
logging.ESSENTIAL = 90
logging.COMMENT = logging.ESSENTIAL

logging._levelToName = {
	logging.SECRET: 'SECRET',
	logging.TRACE: 'TRACE',
	logging.DEBUG: 'DEBUG',
	logging.INFO: 'INFO',
	logging.NOTICE: 'NOTICE',
	logging.WARNING: 'WARNING',
	logging.ERROR: 'ERROR',
	logging.CRITICAL: 'CRITICAL',
	logging.ESSENTIAL: 'ESSENTIAL',
	logging.NONE: 'NONE'
}

logging._nameToLevel = {
	'SECRET': logging.SECRET,
	'TRACE': logging.TRACE,
	'DEBUG': logging.DEBUG,
	'INFO': logging.INFO,
	'NOTICE': logging.NOTICE,
	'WARNING': logging.WARNING,
	'ERROR': logging.ERROR,
	'CRITICAL': logging.CRITICAL,
	'ESSENTIAL': logging.ESSENTIAL,
	'NONE': logging.NONE
}

logging._levelToOpsiLevel = {
	logging.SECRET: 9,
	logging.TRACE: 8,
	logging.DEBUG: 7,
	logging.INFO: 6,
	logging.NOTICE: 5,
	logging.WARNING: 4,
	logging.ERROR: 3,
	logging.CRITICAL: 2,
	logging.ESSENTIAL: 1,
	logging.NONE: 0
}

logging._opsiLevelToLevel = {
	9: logging.SECRET,
	8: logging.TRACE,
	7: logging.DEBUG,
	6: logging.INFO,
	5: logging.NOTICE,
	4: logging.WARNING,
	3: logging.ERROR,
	2: logging.CRITICAL,
	1: logging.ESSENTIAL,
	0: logging.NONE
}

LOG_COLORS = {
	'SECRET': 'thin_yellow',
	'TRACE': 'thin_white',
	'DEBUG': 'white',
	'INFO': 'bold_white',
	'NOTICE': 'bold_green',
	'WARNING': 'bold_yellow',
	'ERROR': 'red',
	'CRITICAL': 'bold_red',
	'ESSENTIAL': 'bold_cyan'
}

def secret(self, msg, *args, **kwargs):
	if self.isEnabledFor(logging.SECRET):
		self._log(logging.SECRET, msg, args, **kwargs)
logging.Logger.secret = secret
logging.Logger.confidential = secret

def trace(self, msg, *args, **kwargs):
	if self.isEnabledFor(logging.TRACE):
		self._log(logging.TRACE, msg, args, **kwargs)
logging.Logger.trace = trace
logging.Logger.debug2 = trace

def notice(self, msg, *args, **kwargs):
	if self.isEnabledFor(logging.NOTICE):
		self._log(logging.NOTICE, msg, args, **kwargs)
logging.Logger.notice = notice

def essential(self, msg, *args, **kwargs):
	if self.isEnabledFor(logging.ESSENTIAL):
		self._log(logging.ESSENTIAL, msg, args, **kwargs)
logging.Logger.essential = essential
logging.Logger.comment = essential

def logrecord_init(self, name, level, pathname, lineno, msg, args, exc_info, func=None, sinfo=None, **kwargs):
	self.__init_orig__(name, level, pathname, lineno, msg, args, exc_info, func=func, sinfo=sinfo, **kwargs)
	self.opsilevel = logging._levelToOpsiLevel.get(level, level)

LogRecord.__init_orig__ = LogRecord.__init__
LogRecord.__init__ = logrecord_init

# Set default log level to ERROR early
logger.setLevel(logging.ERROR)

# Replace OPSI Logger
def opsi_logger_factory():
	return logger
OPSI.Logger.Logger = opsi_logger_factory

def setLogFile(logFile, currentThread=False, object=None):
	pass
logger.setLogFile = setLogFile

def setConfidentialStrings(strings):
	secret_filter.clear_secrets()
	secret_filter.add_secrets(*strings)
logger.setConfidentialStrings = setConfidentialStrings

def addConfidentialString(string):
	secret_filter.add_secrets(string)
logger.addConfidentialString = addConfidentialString

def logException(e, logLevel=logging.CRITICAL):
	logger.log(level=logLevel, msg=e, exc_info=True)
logger.logException = logException
# /Replace OPSI Logger

def handle_log_exception(exc, record=None, log=True):
	print("Logging error:", file=sys.stderr)
	traceback.print_exc(file=sys.stderr)
	if not log:
		return
	try:
		logger.error(f"Logging error: {exc}", exc_info=True)
		if record:
			logger.error(record.__dict__)
			#logger.error(f"{record.msg} - {record.args}")
	except:
		pass


class SecretFilter(metaclass=Singleton):
	def __init__(self, min_length=6):
		self._min_length = min_length
		self.secrets = []
	
	def clear_secrets(self):
		self.secrets = []
	
	def add_secrets(self, *secrets):
		for secret in secrets:
			if secret and len(secret) >= self._min_length and not secret in self.secrets:
				self.secrets.append(secret)
	
	def remove_secrets(self, *secrets):
		for secret in secrets:
			if secret in self.secrets:
				self.secrets.remove(secret)

secret_filter = SecretFilter()


class SecretFormatter(object):
	def __init__(self, orig_formatter):
		self.orig_formatter = orig_formatter
	
	def format(self, record):
		msg = self.orig_formatter.format(record)
		for secret in secret_filter.secrets:
			msg = msg.replace(secret, SECRET_REPLACEMENT_STRING)
		return msg
	
	def __getattr__(self, attr):
		return getattr(self.orig_formatter, attr)


class AdditionalFieldsFilter(Filter):
	def __init__(self):
		from .worker import contextvar_client_address, contextvar_server_address
		self._contextvar_client_address = contextvar_client_address
		self._contextvar_server_address = contextvar_server_address

	def filter(self, record):
		if not hasattr(record, "client_address"):
			record.client_address = self._contextvar_client_address.get() or ''
		if not hasattr(record, "server_address"):
			record.server_address = self._contextvar_server_address.get() or ''
		return True


class AsyncRotatingFileHandler(AsyncFileHandler):
	rollover_check_interval = 10

	def __init__(self, filename: str, formatter: Formatter,
				active_lifetime: int = 0, mode: str = "a", encoding: str = 'utf-8', max_bytes: int = 0, keep_rotated: int = 0) -> None:
		super().__init__(filename, mode, encoding)
		self.active_lifetime = active_lifetime
		self._max_bytes = max_bytes
		self._keep_rotated = keep_rotated
		self.formatter = formatter
		self._rollover_lock = asyncio.Lock(loop=self.loop)
		self.last_used = time.time()
		self.loop.create_task(self._periodically_test_rollover())
	
	async def _periodically_test_rollover(self):
		while True:
			try:
				if await self.loop.run_in_executor(None, self.should_rollover):
					async with self._rollover_lock:
						await self.do_rollover()
			except Exception as exc:
				handle_log_exception(exc)
			for i in range(self.rollover_check_interval):
				await asyncio.sleep(1)

	def should_rollover(self, record: LogRecord = None) -> bool:
		if not os.path.exists(self.absolute_file_path):
			# This will recreate a deleted log file
			return True
		return os.path.getsize(self.absolute_file_path) >= self._max_bytes
	
	async def do_rollover(self):
		if self.stream:
			await self.stream.close()
		if self._keep_rotated > 0:
			for n in range(self._keep_rotated, 0, -1):
				src_file_path = self.absolute_file_path
				if (n > 1):
					src_file_path = f"{self.absolute_file_path}.{n-1}"
				dst_file_path = f"{self.absolute_file_path}.{n}"
				if await self.loop.run_in_executor(None, lambda: os.path.exists(src_file_path)):
					await self.loop.run_in_executor(None, lambda: os.rename(src_file_path, dst_file_path))
		self.stream = None
		await self._init_writer()

	async def emit(self, record: LogRecord):
		async with self._rollover_lock:
			self.last_used = time.time()
			return await super().emit(record)

	async def handle_error(self, record, exception):
		if not isinstance(exception, RuntimeError):
			handle_log_exception(exception, record)

class AsyncRedisLogAdapter:
	def __init__(self, running_event=None, log_file_template=None,
				max_log_file_size=0, keep_rotated_log_files=0, symlink_client_log_files=False,
				log_format_stderr=DEFAULT_FORMAT, log_format_file=DEFAULT_FORMAT,
				log_level_stderr=logging.NOTSET, log_level_file=logging.NOTSET):
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
		if self._log_level_stderr != logging.NONE:
			if sys.stderr.isatty():
				# colorize
				console_formatter = colorlog.ColoredFormatter(self._log_format_stderr, log_colors=LOG_COLORS, datefmt=DATETIME_FORMAT)
			else:
				console_formatter = Formatter(self._log_format_no_color(self._log_format_stderr), datefmt=DATETIME_FORMAT)
			self._stderr_handler = AsyncStreamHandler(stream=sys.stderr, formatter=console_formatter)
		
		if self._log_level_file != logging.NONE:
			if self._log_file_template:
				self.get_file_handler()

		self._loop.create_task(self._start())

	async def stop(self):
		self._loop.stop()
	
	def _log_format_no_color(self, log_format):
		return log_format.replace('%(log_color)s', '').replace('%(reset)s', '')
	
	async def _create_client_log_file_symlink(self, ip_address):
		try:
			fqdn = await self._loop.run_in_executor(None, lambda: socket.getfqdn(ip_address))
			if fqdn != ip_address:
				src = self._log_file_template.replace('%m', ip_address)
				src = os.path.basename(src)
				dst = self._log_file_template.replace('%m', fqdn)
				await self._loop.run_in_executor(None, lambda: os.symlink(src, dst))
		except Exception as exc:
			handle_log_exception(exc)
	
	def get_file_handler(self, client=None):
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
						formatter=Formatter(self._log_format_no_color(self._log_format_file), datefmt=DATETIME_FORMAT),
						active_lifetime=active_lifetime,
						mode='a',
						encoding='utf-8',
						max_bytes=self._max_log_file_size,
						keep_rotated=self._keep_rotated_log_files
					)
					if client and self._symlink_client_log_files:
						self._loop.create_task(self._create_client_log_file_symlink(client))
				return self._file_logs[filename]
		except Exception as exc:
			self._file_logs[filename] = None
			handle_log_exception(exc)

	async def _watch_log_files(self):
		if not self._log_file_template:
			return
		while True:
			for filename in list(self._file_logs):
				if not self._file_logs[filename] or self._file_logs[filename].active_lifetime == 0:
					continue
				dt = time.time() - self._file_logs[filename].last_used
				if (dt > self._file_logs[filename].active_lifetime):
					with self._file_log_lock:
						logger.info("Closing inactive file log '%s', file logs remaining active: %d", filename, len(self._file_logs) - 1)
						del self._file_logs[filename]
			for i in range(60):
				await asyncio.sleep(1)
	
	async def _start(self):
		try:
			self._redis = aredis.StrictRedis.from_url(config.redis_internal_url)
			stream_name = "opsiconfd:log"
			await self._redis.xtrim(name=stream_name, max_len=10000, approximate=True)
			await asyncio.gather(self._reader(stream_name=stream_name), self._watch_log_files())
		except Exception as exc:
			handle_log_exception(exc)

	async def _reader(self, stream_name):
		if self._running_event:
			self._running_event.set()
		
		b_stream_name = stream_name.encode("utf-8")
		last_id = '$'
		while True:
			try:
				# It is also possible to specify multiple streams
				data = await self._redis.xread(block=1000, **{stream_name: last_id})
				if not data:
					continue
				for entry in data[b_stream_name]:
					last_id = entry[0] 
					client = entry[1][b"client"].decode("utf-8")
					record_dict = msgpack.unpackb(entry[1][b"record"])
					record_dict.update({
						"scope": None,
						"exc_info": None,
						"args": None,
						"client_address" : record_dict.get("client_address") or ""
					})
					record = logging.makeLogRecord(record_dict)

					if self._stderr_handler and record.levelno >= self._log_level_stderr:
						await self._stderr_handler.emit(record)
					
					if record.levelno >= self._log_level_file:
						file_handler = self.get_file_handler(client)
						if file_handler:
							await file_handler.emit(record)
			except (KeyboardInterrupt, SystemExit):
				raise
			except EOFError:
				break
			except Exception as exc:
				handle_log_exception(exc, log=False)

class RedisLogHandler(logging.Handler):
	def __init__(self, max_msg_len: int = 0):
		super().__init__()
		self._max_msg_len = max_msg_len
		self._redis = redis.Redis.from_url(config.redis_internal_url)
		self._redis_lock = threading.Lock()

	def log_record_to_dict(self, record):
		if hasattr(record, 'args'):
			if record.args:
				errors = []
				try:
					record.msg = record.msg.format(*record.args)
				except (TypeError, ValueError) as e:
					errors.append(e)
				try:
					record.msg = record.msg % record.args
				except (TypeError, ValueError) as e:
					errors.append(e)
				if len(errors) == 2:
					handle_log_exception(errors[0], log=False)
			else:
				record.msg = record.getMessage()
		for secret in secret_filter.secrets:
			record.msg = record.msg.replace(secret, SECRET_REPLACEMENT_STRING)
		if self._max_msg_len and len(record.msg) > self._max_msg_len:
			record.msg = record.msg[:self._max_msg_len - 1] + '…'
		if hasattr(record, 'exc_info') and record.exc_info:
			# by calling format the formatted exception information is cached in attribute exc_text
			self.format(record)
			record.exc_info = None
		d = record.__dict__
		for attr in ('scope', 'exc_info', 'args'):
			if attr in d:
				del d[attr]
		return d

	def emit(self, record):
		try:
			str_record = msgpack.packb(self.log_record_to_dict(record))
			client = ""
			if hasattr(record, "client_address") and record.client_address:
				client = record.client_address
			with self._redis_lock:
				stream_id = self._redis.xadd("opsiconfd:log", {"client": client, "record": str_record})
				#self._redis.publish(channel, message)
		except (KeyboardInterrupt, SystemExit):
			raise
		except Exception as exc:
			handle_log_exception(exc, record, log=False)

class GunicornLoggerSetup(glogging.Logger):
	def setup(self, cfg):
		self.error_log.handlers = logger.handlers
		self.access_log.handlers = []
		self.access_log.setLevel(0)

def enable_slow_callback_logging(slow_callback_duration = None):
	_run_orig = asyncio.events.Handle._run
	if slow_callback_duration is None:
		slow_callback_duration = asyncio.get_event_loop().slow_callback_duration

	def _run(self):
		start = time.perf_counter()
		retval = _run_orig(self)
		dt = time.perf_counter() - start
		if dt >= slow_callback_duration:
			logger.warning("Executing %s took %.3f seconds", asyncio.base_events._format_handle(self), dt)
		return retval

	asyncio.events.Handle._run = _run

def init_logging(log_mode="redis"):
	try:
		logger.addFilter(AdditionalFieldsFilter())
		log_level = max(config.log_level, config.log_level_stderr, config.log_level_file)
		log_level = logging._opsiLevelToLevel[log_level]
		log_handler = None
		if log_mode == "redis":
			log_handler = RedisLogHandler(max_msg_len=int(config.log_max_msg_len))
			log_handler.setLevel(log_level)
		elif log_mode == "local":
			console_formatter = colorlog.ColoredFormatter(config.log_format_stderr, datefmt=DATETIME_FORMAT, log_colors=LOG_COLORS)
			log_handler = StreamHandler(stream=sys.stderr)
			log_handler.setFormatter(console_formatter)
		else:
			raise ValueError(f"Invalid log mode '{log_mode}'")
		
		logger.handlers = [log_handler]
		logger.setLevel(log_level)

		for ln in ("asyncio", "uvicorn.error"):
			al = logging.getLogger(ln)
			al.setLevel(log_level)
			al.handlers = [log_handler]
			al.propagate = False
		
		if config.log_slow_async_callbacks > 0:
			enable_slow_callback_logging(config.log_slow_async_callbacks)
		
		logging.captureWarnings(True)
	
	except Exception as exc:
		handle_log_exception(exc)


class RedisLogAdapterThread(threading.Thread):
	def __init__(self, running_event=None):
		threading.Thread.__init__(self)
		self._running_event = running_event
		self._redis_log_adapter = None
	
	def stop(self):
		if self._redis_log_adapter:
			self._loop.create_task(self._redis_log_adapter.stop())
	
	def run(self):
		try:
			self._loop = asyncio.new_event_loop()
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
				log_level_stderr=logging._opsiLevelToLevel[config.log_level_stderr],
				log_level_file=logging._opsiLevelToLevel[config.log_level_file]
			)
			self._loop.run_forever()
		except Exception as exc:
			logger.error(exc, exc_info=True)

def start_redis_log_adapter_thread(running_event):
	thread = RedisLogAdapterThread(running_event)
	thread.daemon = True
	thread.start()
	return thread
