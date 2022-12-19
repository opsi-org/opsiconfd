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
from pathlib import Path

import uvloop
from opsicommon import __version__ as python_opsi_common_version  # type: ignore[import]
from opsicommon.logging import set_filter_from_string  # type: ignore[import]
from opsicommon.types import forceHostId  # type: ignore[import]
from opsicommon.utils import monkeypatch_subprocess_for_frozen  # type: ignore[import]
from rich.console import Console
from rich.progress import Progress

from opsiconfd import __version__
from opsiconfd.application import MaintenanceState, NormalState, app
from opsiconfd.backup import create_backup, restore_backup
from opsiconfd.check import health_check
from opsiconfd.config import GC_THRESHOLDS, config, configure_warnings, opsi_config
from opsiconfd.logging import (
	AsyncRedisLogAdapter,
	init_logging,
	logger,
	shutdown_logging,
)
from opsiconfd.manager import Manager
from opsiconfd.patch import apply_patches
from opsiconfd.redis import redis_client
from opsiconfd.setup import setup
from opsiconfd.utils import get_manager_pid, log_config

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
	result = health_check(print_messages=True)
	if result.get("status") == "ok":
		sys.exit(0)
	if result.get("status") == "warn":
		sys.exit(2)
	sys.exit(1)


def backup_main() -> None:
	console = Console(quiet=config.quiet)
	try:
		with Progress(console=console, redirect_stdout=False, redirect_stderr=False) as progress:
			init_logging(log_mode="rich", console=progress.console)
			backup_file = Path(config.backup_file)
			if not config.overwrite and backup_file.exists():
				raise FileExistsError(f"Backup file '{str(backup_file)}' already exists, use --overwrite to replace.")

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

			if not config.no_maintenance:
				threading.Thread(
					target=asyncio.run,
					args=[app.app_state_manager_task(manager_mode=True, init_app_state=(MaintenanceState(), NormalState()))],
					daemon=True,
				).start()
				app.app_state_initialized.wait(5)

			create_backup(config_files=not config.no_config_files, backup_file=backup_file, progress=progress)

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

			server_id = config.server_id
			if server_id not in ("backup", "local"):
				server_id = forceHostId(server_id)

			progress.console.print(f"Restoring from [bold]{backup_file.name}[/bold]")

			threading.Thread(
				target=asyncio.run,
				args=[app.app_state_manager_task(manager_mode=True, init_app_state=(MaintenanceState(), NormalState()))],
				daemon=True,
			).start()
			app.app_state_initialized.wait(5)

			restore_backup(backup_file, config_files=config.config_files, server_id=server_id, progress=progress)

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
