# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd main
"""

import gc
import getpass
import os
import pwd
import signal
import sys
import threading
import time
from io import UnsupportedOperation

import uvloop
from opsicommon.utils import patch_popen

from opsiconfd import __version__
from opsiconfd.config import GC_THRESHOLDS, REDIS_CONECTION_TIMEOUT, config, configure_warnings, get_depotserver_id, get_server_role
from opsiconfd.logging import init_logging, logger, shutdown_logging
from opsiconfd.manager import Manager
from opsiconfd.patch import apply_patches
from opsiconfd.redis import delete_locks, redis_client
from opsiconfd.setup import setup
from opsiconfd.utils import get_manager_pid, log_config

patch_popen()
configure_warnings()


def opsiconfd_main() -> None:
	manager_pid = get_manager_pid(ignore_self=True)
	if config.action == "start" and manager_pid and config.check_running:
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
					time.sleep(1)
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
	try:
		# Test if redis connection available
		logger.info("Testing redis connection (timeout: %d)", REDIS_CONECTION_TIMEOUT)
		redis_client(timeout=REDIS_CONECTION_TIMEOUT, test_connection=True)
		logger.info("Redis connection is working")

		init_logging(log_mode=config.log_mode)

		if config.delete_locks:
			delete_locks()

		logger.info("Using trusted certificates database: %s", config.ssl_trusted_certs)

		logger.essential("Opsiconfd version %r starting on %r as %r", __version__, get_depotserver_id(), get_server_role())
		log_config()

		setup(explicit=bool(config.setup))

		# os.chdir("/tmp")
		if config.run_as_user and getpass.getuser() != config.run_as_user:
			logger.essential("Switching to user %s", config.run_as_user)
			try:
				user = pwd.getpwnam(config.run_as_user)
				gids = os.getgrouplist(user.pw_name, user.pw_gid)
				logger.debug("Set uid=%s, gid=%s, groups=%s", user.pw_uid, user.pw_gid, gids)
				# os.chdir(user.pw_dir)
				os.setgid(user.pw_gid)
				os.setgroups(gids)
				os.setuid(user.pw_uid)
				os.environ["HOME"] = user.pw_dir
			except Exception as err:
				raise RuntimeError(f"Failed to run as user '{config.run_as_user}': {err}") from err

		# Subprocesses will inherit file descriptors
		# Redirectring sys.stdin to prevent S_ISFIFO(stdin) to return true
		# This is important for subprocesses like opsi-package postinst scripts
		stdin = open(os.devnull, "rb")
		try:
			os.dup2(stdin.fileno(), sys.stdin.fileno())
		except UnsupportedOperation as err:
			logger.warning("Failed to redirect stdin: %s", err)

		# Do not use uvloop in redis logger thread because aiologger is currently incompatible with uvloop!
		# https://github.com/b2wdigital/aiologger/issues/38
		uvloop.install()

		manager = Manager()
		manager.run()
		shutdown_logging()

	finally:
		if stdin:
			stdin.close()
		for thread in threading.enumerate():
			stop = getattr(thread, "stop", None)
			if stop:
				stop()
				thread.join(1)
