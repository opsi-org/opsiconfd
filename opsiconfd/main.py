# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd main
"""

import os
import re
import sys
import pwd
import time
import asyncio
import threading
import signal
import pprint
import subprocess
import getpass
from concurrent.futures import ThreadPoolExecutor
import uvloop

from OPSI import __version__ as python_opsi_version

from opsicommon.logging import set_filter_from_string

from . import __version__
from .logging import logger, init_logging, secret_filter, AsyncRedisLogAdapter
from .config import config
from .setup import setup
from .patch import apply_patches
from .utils import get_manager_pid
from .manager import Manager


def run_with_jemlalloc():
	try:
		if "libjemalloc" in os.getenv("LD_PRELOAD", ""):
			return

		out = subprocess.check_output(["ldconfig", "-p"]).decode("utf-8", "replace")
		match = re.search(r".*=>\s*(.*libjemalloc.*)\s*", out)
		if not match:
			raise RuntimeError("libjemalloc not found")

		new_env = os.environ.copy()
		new_env["LD_PRELOAD"] = match.group(1)
		# print(f"Restarting with LD_PRELOAD={new_env['LD_PRELOAD']}")

		os.execve(sys.argv[0], sys.argv, new_env)
	except Exception as err:  # pylint: disable=broad-except
		print(err, file=sys.stderr)


def main():  # pylint: disable=too-many-statements, too-many-branches too-many-locals
	secret_filter.add_secrets(
		config.ssl_ca_key_passphrase,
		config.ssl_server_key_passphrase
	)

	if config.version:
		print(f"{__version__} [python-opsi={python_opsi_version}]")
		return

	if config.action == "setup":
		init_logging(log_mode="local")
		setup(full=True)
		return

	if config.action == "log-viewer":
		try:
			set_filter_from_string(config.log_filter)
			AsyncRedisLogAdapter(stderr_file=sys.stdout)
			loop = asyncio.get_event_loop()
			loop.run_forever()
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
					time.sleep(1)
					if not get_manager_pid():
						return
				os.kill(manager_pid, send_signal)
		else:
			print("No running opsiconfd manager process found", file=sys.stderr)
			sys.exit(1)
		return

	if manager_pid:
		print(f"Another opsiconfd manager process is already running (pid {manager_pid})", file=sys.stderr)
		sys.exit(1)

	if config.use_jemalloc and getattr(sys, 'frozen', False):
		try:
			run_with_jemlalloc()
		except Exception:  # pylint: disable=broad-except
			pass

	apply_patches()

	try:  # pylint: disable=too-many-nested-blocks
		asyncio.get_event_loop().set_default_executor(
			ThreadPoolExecutor(
				max_workers=5,
				thread_name_prefix="main-ThreadPoolExecutor"
			)
		)

		init_logging(log_mode=config.log_mode)
		logger.info("Using trusted certificates database: %s", config.ssl_trusted_certs)

		if "libjemalloc" in os.getenv("LD_PRELOAD", ""):
			logger.notice("Running with %s", os.getenv("LD_PRELOAD"))
		elif config.use_jemalloc:
			if getattr(sys, 'frozen', False):
				logger.error("Failed to use jemalloc, please make sure it is installed")
			else:
				logger.warning("Not running from binary, not using jemalloc, use LD_PRELOAD if needed")

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

		# Do not use uvloop in redis logger thread because aiologger is currently incompatible with uvloop!
		# https://github.com/b2wdigital/aiologger/issues/38
		uvloop.install()

		logger.essential("opsiconfd is starting")
		logger.info("opsiconfd config:\n%s", pprint.pformat(config.items(), width=100, indent=4))

		manager = Manager()
		manager.run()

	finally:
		time.sleep(1)
		for thread in threading.enumerate():
			if hasattr(thread, "stop"):
				thread.stop()
				thread.join()
