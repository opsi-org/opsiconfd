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
:copyright: uib GmbH <info@uib.de>
:license: GNU Affero General Public License version 3
"""

import os
import pwd
import grp
import shutil
import psutil
import getpass
import resource
import tempfile
import subprocess

from OPSI.Config import OPSI_ADMIN_GROUP, FILE_ADMIN_GROUP, DEFAULT_DEPOT_USER
from OPSI.setup import setup as python_opsi_setup, get_users, get_groups, add_user_to_group
from OPSI.Util import getfqdn

from .logging import logger
from .config import config

def setup_limits():
	logger.info("Setup system limits")
	# The hard limit is the maximum value that is allowed for the soft limit. Any changes to the hard limit require root access.
	# The soft limit is the value that Linux uses to limit the system resources for running processes. The soft limit cannot be greater than the hard limit.
	(soft_limit, hard_limit) = resource.getrlimit(resource.RLIMIT_NOFILE)
	if (soft_limit > 0 and soft_limit < 10000):
		try:
			# ulimit -n 10000
			resource.setrlimit(resource.RLIMIT_NOFILE, (10000, hard_limit))
			(soft_limit, hard_limit) = resource.getrlimit(resource.RLIMIT_NOFILE)
		except Exception as exc:
			logger.warning("Failed to set RLIMIT_NOFILE: %s", exc)
	logger.info("Maximum number of open file descriptors: %s", soft_limit)

def setup_users_and_groups():
	logger.info("Setup users and groups")
	groups = get_groups()
	users = get_users()
	
	if config.run_as_user != "root":
		if config.run_as_user not in users:
			create_user(
				username=config.run_as_user,
				primary_groupname=FILE_ADMIN_GROUP,
				home="/var/lib/opsi",
				shell="/bin/bash",
				system=True
			)
			users = get_users()
		if "shadow" in groups and config.run_as_user not in groups["shadow"].gr_mem:
			add_user_to_group(config.run_as_user, "shadow")
		if OPSI_ADMIN_GROUP in groups and config.run_as_user not in groups[OPSI_ADMIN_GROUP].gr_mem:
			add_user_to_group(config.run_as_user, OPSI_ADMIN_GROUP)

def setup_ssl():
	logger.info("Setup ssl")
	if os.path.exists(config.ssl_server_key) and os.path.exists(config.ssl_server_cert):
		return
	
	fqdn = getfqdn()
	tmp_dir = tempfile.mkdtemp()
	try:
		ca_key = os.path.join(tmp_dir, "ca.key")
		ca_crt = os.path.join(tmp_dir, "ca.crt")
		srv_key = os.path.join(tmp_dir, "srv.key")
		srv_crt = os.path.join(tmp_dir, "srv.crt")
		srv_csr = os.path.join(tmp_dir, "srv.csr")

		subject = f"/C=DE/ST=RP/L=Mainz/O=uib/OU=root/CN={fqdn}/emailAddress=root@{fqdn}"
		cmd = ["openssl", "req", "-nodes", "-x509", "-newkey", "rsa:2048", "-keyout", ca_key, "-out", ca_crt, "-subj", subject]
		subprocess.check_call(cmd)

		subject = f"/C=DE/ST=RP/L=Mainz/O=uib/OU=opsiconfd/CN={fqdn}/emailAddress=root@{fqdn}"
		cmd = ["openssl", "req", "-nodes", "-newkey", "rsa:2048", "-keyout", srv_key, "-out", srv_csr, "-subj", subject]
		subprocess.check_call(cmd)

		cmd = ["openssl", "x509", "-req", "-in", srv_csr, "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial", "-out", srv_crt]
		subprocess.check_call(cmd)

		if os.path.exists(config.ssl_server_key):
			os.unlink(config.ssl_server_key)
		if os.path.exists(config.ssl_server_cert):
			os.unlink(config.ssl_server_cert)
		
		with open(srv_key, "r") as _in:
			with open(config.ssl_server_key, "a") as out:
				out.write(_in.read())

		with open(srv_crt, "r") as _in:
			with open(config.ssl_server_cert, "a") as out:
				out.write(_in.read())
	finally:
		shutil.rmtree(tmp_dir)

def setup_file_permissions():
	logger.info("Setup file permissions")
	for fn in (config.ssl_server_key, config.ssl_server_cert):
		if os.path.exists(fn):
			shutil.chown(path=fn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
			os.chmod(path=fn, mode=0o600)

	log_dir = os.path.dirname(os.path.abspath(config.log_file))
	if log_dir.count(os.sep) > 0:
		for root, dirs, files in os.walk(log_dir):
			shutil.chown(root, config.run_as_user, OPSI_ADMIN_GROUP)
			os.chmod(path=root, mode=0o770)
			for item in dirs:
				shutil.chown(path=os.path.join(root, item), user=config.run_as_user, group=OPSI_ADMIN_GROUP)
				os.chmod(path=root, mode=0o770)
			for item in files:
				shutil.chown(path=os.path.join(root, item), user=config.run_as_user, group=OPSI_ADMIN_GROUP)
				os.chmod(path=root, mode=0o660)
	
def setup_systemd():
	systemd_running = False
	for proc in psutil.process_iter():
		if proc.name() == "systemd":
			systemd_running = True
			break
	if not systemd_running:
		logger.debug("Systemd not running")
		return
	
	logger.info("Setup systemd")
	subprocess.call(["systemctl", "daemon-reload"])
	subprocess.call(["systemctl", "enable", "opsiconfd.service"])

def setup(full: bool = True):
	logger.notice("Running opsiconfd setup")
	if not config.run_as_user:
		config.run_as_user = getpass.getuser()
	setup_limits()
	if full:
		python_opsi_setup()
		setup_users_and_groups()
		setup_file_permissions()
		setup_systemd()
