# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd main
"""

import asyncio
import gc
import getpass
import os
import pwd
import signal
import sys
import threading
import time
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Generator

import uvloop
from msgspec import json, msgpack
from opsicommon import __version__ as python_opsi_common_version  # type: ignore[import]
from opsicommon.logging import set_filter_from_string  # type: ignore[import]
from opsicommon.types import forceHostId  # type: ignore[import]
from opsicommon.utils import monkeypatch_subprocess_for_frozen  # type: ignore[import]
from rich.console import Console
from rich.progress import Progress

from . import __version__
from .application import MaintenanceState, app
from .backup import create_backup, restore_backup
from .check import console_health_check
from .config import GC_THRESHOLDS, config, configure_warnings, opsi_config
from .logging import AsyncRedisLogAdapter, init_logging, logger, shutdown_logging
from .manager import Manager
from .patch import apply_patches
from .setup import setup
from .utils import (
	compress_data,
	decompress_data,
	get_manager_pid,
	log_config,
	redis_client,
)

REDIS_CONECTION_TIMEOUT = 30


async def log_viewer() -> None:
	set_filter_from_string(config.log_filter)
	AsyncRedisLogAdapter(stderr_file=sys.stdout)
	while True:
		await asyncio.sleep(1)  # pylint: disable=dotted-import-in-loop


def setup_main() -> None:
	init_logging(log_mode="local")
	log_config()
	setup(full=True)


def log_viewer_main() -> None:
	try:
		asyncio.run(log_viewer())
	except KeyboardInterrupt:
		pass


def health_check_main() -> None:
	init_logging(log_mode="local")
	sys.exit(console_health_check())


@contextmanager
def maintenance_mode(progress: Progress, message: str, wait_accomplished: float) -> Generator[None, None, None]:
	logger.notice("Entering maintenance mode")
	maint_task = progress.add_task("Entering maintenance mode", total=None)
	threading.Thread(target=asyncio.run, args=[app.app_state_manager_task()], daemon=True).start()
	# Wait for app state to be read from redis
	time.sleep(3)
	orig_state = app.app_state
	if not isinstance(orig_state, MaintenanceState):
		# Not already in maintenance state
		app.set_app_state(
			MaintenanceState(retry_after=300, message=message, address_exceptions=[]),
			wait_accomplished=wait_accomplished,
		)
		progress.update(maint_task, total=1, completed=True)
	try:
		yield
	finally:
		if not isinstance(orig_state, MaintenanceState):
			logger.notice("Reentering %s mode", orig_state.type)
			progress.console.print(f"Reentering {orig_state.type} mode")
			orig_state.accomplished = False
			app.app_state = orig_state
			time.sleep(3)


def backup_main() -> None:
	console = Console(quiet=config.quiet)
	try:
		with Progress(console=console, redirect_stdout=False, redirect_stderr=False) as progress:
			init_logging(log_mode="rich", console=progress.console)
			backup_file = Path(config.backup_file)
			if not config.overwrite and backup_file.exists():
				raise FileExistsError(f"Backup file '{str(backup_file)}' already exists, use --overwrite to replace.")

			ctm = (
				nullcontext()
				if config.no_maintenance
				else maintenance_mode(
					progress=progress, message="Maintenance mode, backup in progress, please try again later", wait_accomplished=60
				)
			)
			with ctm:
				suffixes = [s.strip(".") for s in backup_file.suffixes[-2:]]
				encoding = suffixes[0]
				compression = None
				if len(suffixes) == 2:
					compression = suffixes[1]

				if encoding not in ("msgpack", "json"):
					raise ValueError(f"Invalid encoding {encoding!r}, valid encodings are 'msgpack' and 'json'")

				if compression:
					if compression not in ("lz4", "gz"):
						raise ValueError(f"Invalid compression {compression!r}, valid compressions are 'lz4' and 'gz'")

				progress.console.print(f"Creating backup [bold]{backup_file.name}[/bold]")

				data = create_backup(config_files=not config.no_config_files, progress=progress)

				file_task = progress.add_task("Creating backup file", total=None)

				logger.notice("Encoding data to %s", encoding)
				progress.console.print(f"Encoding data to {encoding}")
				encode = json.encode if encoding == "json" else msgpack.encode
				bdata = encode(data)

				if compression:
					logger.notice("Compressing data with %s", compression)
					progress.console.print(f"Compressing data with {compression}")
					bdata = compress_data(bdata, compression=compression)

				logger.notice("Writing data to file %s", backup_file)
				progress.console.print("Writing data to file")
				with open(config.backup_file, "wb") as file:
					file.write(bdata)

				progress.update(file_task, total=1, completed=True)

			progress.console.print(f"Backup file '{str(backup_file)}' succesfully created.")
	except KeyboardInterrupt:
		logger.error("Backup interrupted")
		console.quiet = False
		console.print("[bold red]Backup interrupted[/bold red]")
		sys.exit(2)
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)
		console.quiet = False
		console.print(f"[bold red]Failed to create backup file '{str(backup_file)}': {err}[/bold red]")
		sys.exit(1)
	sys.exit(0)


def restore_main() -> None:
	console = Console(quiet=config.quiet)
	try:
		with Progress(console=console, redirect_stdout=False, redirect_stderr=False) as progress:
			init_logging(log_mode="rich", console=progress.console)
			backup_file = Path(config.backup_file)
			if not backup_file.exists():
				raise FileExistsError(f"Backup file '{str(backup_file)}' not found")

			with maintenance_mode(
				progress=progress, message="Maintenance mode, restore in progress, please try again later", wait_accomplished=60
			):
				progress.console.print(f"Restoring from [bold]{backup_file.name}[/bold]")
				server_id = config.server_id
				if server_id not in ("local", "backup"):
					server_id = forceHostId(server_id)

				logger.notice("Reading data from file %s", backup_file)
				progress.console.print("Reading data from file")
				file_task = progress.add_task("Processing backup file", total=None)
				with open(config.backup_file, "rb") as file:
					bdata = file.read()

				head = bdata[0:4].hex()
				compression = None
				if head == "04224d18":
					compression = "lz4"
				elif head.startswith("1f8b"):
					compression = "gz"
				if compression:
					logger.notice("Decomressing %s data", compression)
					progress.console.print(f"Decomressing {compression} data")
					bdata = decompress_data(bdata, compression=compression)

				encoding = "json" if bdata.startswith(b"{") else "msgpack"
				logger.notice("Decoding %s data", encoding)
				progress.console.print(f"Decoding {encoding} data")
				decode = json.decode if encoding == "json" else msgpack.decode
				data = decode(bdata)  # type: ignore[operator]
				progress.update(file_task, total=1, completed=True)

				restore_backup(data, config_files=config.config_files, server_id=server_id, progress=progress)

			progress.console.print(f"Backup file '{str(backup_file)}' succesfully restored.")
	except KeyboardInterrupt:
		logger.error("Restore interrupted")
		console.quiet = False
		console.print("[bold red]Restore interrupted[/bold red]")
		sys.exit(2)
	except Exception as err:  # pylint: disable=broad-except
		logger.error(err, exc_info=True)
		console.quiet = False
		console.print(f"[bold red]Failed to restore backup from '{str(backup_file)}': {err}[/bold red]")
		sys.exit(1)
	sys.exit(0)


def opsiconfd_main() -> None:  # pylint: disable=too-many-statements, too-many-branches
	manager_pid = get_manager_pid(ignore_self=True)
	if config.action == "start" and manager_pid:
		raise RuntimeError(f"Opsiconfd manager process already running (pid {manager_pid})")

	if config.action in ("restart", "status"):
		os.execvp("systemctl", ["systemctl", "--no-pager", "--lines", "0", config.action, "opsiconfd"])

	if config.action in ("reload", "stop", "force-stop"):
		if manager_pid:
			# Send signal to manager process only, not to workers!
			send_signal = signal.SIGINT if config.action in ("stop", "force-stop") else signal.SIGHUP

			os.kill(manager_pid, send_signal)
			if config.action == "force-stop":
				# Wait 5 seconds for processes to terminate or resend signal to force stop
				for _num in range(5):
					time.sleep(1)  # pylint: disable=dotted-import-in-loop
					if not get_manager_pid():
						return
				try:
					os.kill(manager_pid, send_signal)
				except ProcessLookupError:
					return
		else:
			print("No running opsiconfd manager process found", file=sys.stderr)
			sys.exit(1)
		return

	apply_patches()

	logger.info("Setting garbage collector thresholds: %s", GC_THRESHOLDS)
	gc.set_threshold(*GC_THRESHOLDS)

	stdin = None
	try:  # pylint: disable=too-many-nested-blocks
		# Test if redis connection available
		logger.info("Testing redis connection (timeout: %d)", REDIS_CONECTION_TIMEOUT)
		with redis_client(timeout=REDIS_CONECTION_TIMEOUT, test_connection=True):
			logger.info("Redis connection is working")

		init_logging(log_mode=config.log_mode)
		logger.info("Using trusted certificates database: %s", config.ssl_trusted_certs)

		logger.essential("Opsiconfd version %s starting as %s", __version__, opsi_config.get("host", "server-role"))
		log_config()

		setup(full=bool(config.setup))

		if config.run_as_user and getpass.getuser() != config.run_as_user:
			logger.essential("Switching to user %s", config.run_as_user)
			try:
				user = pwd.getpwnam(config.run_as_user)
				gids = os.getgrouplist(user.pw_name, user.pw_gid)
				logger.debug("Set uid=%s, gid=%s, groups=%s", user.pw_uid, user.pw_gid, gids)
				os.setgid(user.pw_gid)
				os.setgroups(gids)
				os.setuid(user.pw_uid)
				os.environ["HOME"] = user.pw_dir
			except Exception as err:
				raise Exception(f"Failed to run as user '{config.run_as_user}': {err}") from err

		# Subprocesses will inherit file descriptors
		# Redirectring sys.stdin to prevent S_ISFIFO(stdin) to return true
		# This is important for subprocesses like opsi-package postinst scripts
		stdin = open(os.devnull, "rb")  # pylint: disable=consider-using-with
		os.dup2(stdin.fileno(), sys.stdin.fileno())

		# Do not use uvloop in redis logger thread because aiologger is currently incompatible with uvloop!
		# https://github.com/b2wdigital/aiologger/issues/38
		uvloop.install()

		manager = Manager()
		manager.run()
		shutdown_logging()

	finally:
		if stdin:
			stdin.close()
		for thread in threading.enumerate():  # pylint: disable=dotted-import-in-loop
			stop = getattr(thread, "stop", None)
			if stop:
				stop()
				thread.join(1)


def main() -> None:  # pylint: disable=too-many-return-statements
	monkeypatch_subprocess_for_frozen()
	configure_warnings()

	if config.version:
		print(f"{__version__} [python-opsi-common={python_opsi_common_version}]")
		return None

	if config.action == "setup":
		return setup_main()

	if config.action == "log-viewer":
		return log_viewer_main()

	if config.action == "health-check":
		return health_check_main()

	if config.action == "backup":
		return backup_main()

	if config.action == "restore":
		return restore_main()

	return opsiconfd_main()
