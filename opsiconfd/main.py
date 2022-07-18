# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd main
"""

import asyncio
import getpass
import os
import pprint
import pwd
import signal
import sys
import threading
import time

import uvloop
from OPSI import __version__ as python_opsi_version  # type: ignore[import]
from opsicommon.logging import set_filter_from_string  # type: ignore[import]

from . import __version__
from .config import config
from .logging import (
	AsyncRedisLogAdapter,
	init_logging,
	logger,
	secret_filter,
	shutdown_logging,
)
from .manager import Manager
from .patch import apply_patches
from .setup import setup
from .utils import get_manager_pid, redis_client

REDIS_CONECTION_TIMEOUT = 30


async def log_viewer() -> None:
	set_filter_from_string(config.log_filter)
	AsyncRedisLogAdapter(stderr_file=sys.stdout)
	while True:
		await asyncio.sleep(1)  # pylint: disable=dotted-import-in-loop


def main() -> None:  # pylint: disable=too-many-statements, too-many-branches too-many-locals
	secret_filter.add_secrets(config.ssl_ca_key_passphrase, config.ssl_server_key_passphrase)

	if config.version:
		print(f"{__version__} [python-opsi={python_opsi_version}]")
		return

	if config.action == "setup":
		init_logging(log_mode="local")
		logger.info("opsiconfd config:\n%s", pprint.pformat(config.items(), width=100, indent=4))
		setup(full=True)
		return

	if config.action == "log-viewer":
		try:
			asyncio.run(log_viewer())
		except KeyboardInterrupt:
			pass
		return

	manager_pid = get_manager_pid(ignore_self=True)

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

	try:  # pylint: disable=too-many-nested-blocks
		# Test if redis connection available
		logger.info("Testing redis connection (timeout: %d)", REDIS_CONECTION_TIMEOUT)
		with redis_client(timeout=REDIS_CONECTION_TIMEOUT, test_connection=True):
			logger.info("Redis connection is working")

		init_logging(log_mode=config.log_mode)
		logger.info("Using trusted certificates database: %s", config.ssl_trusted_certs)

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
		for thread in threading.enumerate():  # pylint: disable=dotted-import-in-loop
			stop = getattr(thread, "stop", None)
			if stop:
				stop()
				thread.join(1)
