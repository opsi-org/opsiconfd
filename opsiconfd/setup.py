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
import datetime

from OPSI.Config import OPSI_ADMIN_GROUP, FILE_ADMIN_GROUP, DEFAULT_DEPOT_USER
from OPSI.setup import (
	setup_users_and_groups as po_setup_users_and_groups,
	setup_file_permissions as po_setup_file_permissions,
	get_users, get_groups, add_user_to_group, create_user, set_primary_group
)
from OPSI.Util import getfqdn
from OPSI.System.Posix import getLocalFqdn
from OPSI.Util.Task.InitializeBackend import initializeBackends
from OPSI.System import get_subprocess_environment

from .logging import logger
from .config import config
from .backend import get_backend
from .grafana import setup_grafana
from .statistics import setup_metric_downsampling
from .application.jsonrpc import metrics_registry

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
	
	if config.run_as_user == "root":
		return
	
	user = None
	try:
		user = pwd.getpwnam(config.run_as_user)
	except KeyError as e:
		# User not found
		create_user(
			username=config.run_as_user,
			primary_groupname=FILE_ADMIN_GROUP,
			home="/var/lib/opsi",
			shell="/bin/bash",
			system=True
		)
		user = pwd.getpwnam(config.run_as_user)
	
	gids = os.getgrouplist(user.pw_name, user.pw_gid)
	for groupname in ("shadow", OPSI_ADMIN_GROUP, FILE_ADMIN_GROUP):
		logger.debug("Processing group %s", groupname)
		try:
			group = grp.getgrnam(groupname)
			if group.gr_gid not in gids:
				add_user_to_group(config.run_as_user, groupname)
			if groupname == FILE_ADMIN_GROUP and user.pw_gid != group.gr_gid:
				try:
					set_primary_group(user.pw_name, FILE_ADMIN_GROUP)
				except Exception as e2:
					# Could be a user in active directory / ldap 
					logger.debug("Failed to set primary group of %s to %s: %s", user.pw_name, FILE_ADMIN_GROUP, e2)
		except KeyError as e:
			logger.debug("Group not found: %s", groupname)
			pass

def check_ssl_expiry():
	for cert in (config.ssl_ca_cert, config.ssl_server_cert):
		if os.path.exists(cert):
			logger.info("Checking expiry of certificate: %s", cert)
			cmd = ["openssl", "x509", "-enddate", "-noout", "-in", cert]
			out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, env=get_subprocess_environment())
			enddate = out.decode().split('=')[1].strip()
			enddate = datetime.datetime.strptime(enddate, "%b %d %H:%M:%S %Y %Z")
			diff = (enddate - datetime.datetime.now()).days
			if (diff <= 0):
				logger.error("Certificate '%s' expired on %s", cert, enddate)
			elif (diff < 30):
				logger.warning("Certificate '%s' will expire in %d days", cert, diff)
			
def setup_ssl():
	logger.info("Setup ssl")
	if (
		os.path.exists(config.ssl_ca_key) and os.path.exists(config.ssl_ca_cert) and
		os.path.exists(config.ssl_server_key) and os.path.exists(config.ssl_server_cert)
	):
		return
	
	ca_days = 730
	cert_days = 365
	fqdn = getfqdn()
	domain = '.'.join(fqdn.split('.')[1:])
	tmp_dir = tempfile.mkdtemp()
	try:
		ca_key = os.path.join(tmp_dir, "ca.key")
		ca_crt = os.path.join(tmp_dir, "ca.crt")
		srv_key = os.path.join(tmp_dir, "srv.key")
		srv_crt = os.path.join(tmp_dir, "srv.crt")
		srv_csr = os.path.join(tmp_dir, "srv.csr")

		new_ca = False
		if not os.path.exists(config.ssl_ca_key) or not os.path.exists(config.ssl_ca_cert):
			logger.info("Creating opsi CA")
			cmd = [
				"openssl", "req", "-nodes", "-x509", "-newkey", "rsa:4096", "-days", str(ca_days),
				"-keyout", ca_key, "-out", ca_crt,
				"-subj", f"/C=DE/ST=RP/L=Mainz/O=uib/OU=opsi@{domain}/CN=opsi CA/emailAddress=opsi@{domain}"
			]
			subprocess.check_output(cmd, stderr=subprocess.STDOUT, env=get_subprocess_environment())
			
			if os.path.exists(config.ssl_ca_key):
				os.unlink(config.ssl_ca_key)
			if not os.path.exists(os.path.dirname(config.ssl_ca_key)):
				os.makedirs(os.path.dirname(config.ssl_ca_key))
				os.chmod(path=os.path.dirname(config.ssl_ca_key), mode=0o700)
			with open(ca_key, "r") as _in:
				with open(config.ssl_ca_key, "a") as out:
					out.write(_in.read())
			
			if os.path.exists(config.ssl_ca_cert):
				os.unlink(config.ssl_ca_cert)
			if not os.path.exists(os.path.dirname(config.ssl_ca_cert)):
				os.makedirs(os.path.dirname(config.ssl_ca_cert))
				os.chmod(path=os.path.dirname(config.ssl_ca_cert), mode=0o700)
			with open(ca_crt, "r") as _in:
				with open(config.ssl_ca_cert, "a") as out:
					out.write(_in.read())
			
			setup_ssl_file_permissions()
			new_ca = True
		
		if new_ca or not os.path.exists(config.ssl_server_key) or not os.path.exists(config.ssl_server_cert):
			logger.info("Creating opsiconfd cert")
			cmd = [
				"openssl", "req", "-nodes", "-newkey", "rsa:4096",
				"-keyout", srv_key, "-out", srv_csr,
				"-subj", f"/C=DE/ST=RP/L=Mainz/O=uib/OU=opsi@{domain}/CN={fqdn}/emailAddress=opsi@{domain}"
			]
			subprocess.check_output(cmd, stderr=subprocess.STDOUT, env=get_subprocess_environment())

			cmd = [
				"openssl", "x509", "-req",
				"-CA", config.ssl_ca_cert, "-CAkey", config.ssl_ca_key, "-CAcreateserial",
				"-in", srv_csr, "-out", srv_crt, "-days", str(cert_days)
			]
			subprocess.check_output(cmd, stderr=subprocess.STDOUT, env=get_subprocess_environment())

			if os.path.exists(config.ssl_server_key):
				os.unlink(config.ssl_server_key)
			if os.path.exists(config.ssl_server_cert):
				os.unlink(config.ssl_server_cert)
			
			if not os.path.exists(os.path.dirname(config.ssl_server_key)):
				os.makedirs(os.path.dirname(config.ssl_server_key))
				os.chmod(path=os.path.dirname(config.ssl_server_key), mode=0o700)
			with open(srv_key, "r") as _in:
				with open(config.ssl_server_key, "a") as out:
					out.write(_in.read())
			if not os.path.exists(os.path.dirname(config.ssl_server_cert)):
				os.makedirs(os.path.dirname(config.ssl_server_cert))
				os.chmod(path=os.path.dirname(config.ssl_server_cert), mode=0o700)
			with open(srv_crt, "r") as _in:
				with open(config.ssl_server_cert, "a") as out:
					out.write(_in.read())
			
			setup_ssl_file_permissions()
	finally:
		shutil.rmtree(tmp_dir)

def setup_files():
	log_dir = os.path.dirname(config.log_file)
	if not os.path.isdir(log_dir):
		os.makedirs(log_dir)

def setup_ssl_file_permissions():
	for fn in (config.ssl_ca_key, config.ssl_ca_cert):
		if os.path.exists(fn):
			shutil.chown(path=fn, user='root', group=OPSI_ADMIN_GROUP)
			os.chmod(path=fn, mode=0o600)
	
	for fn in (config.ssl_server_key, config.ssl_server_cert):
		if os.path.exists(fn):
			shutil.chown(path=fn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
			os.chmod(path=fn, mode=0o600)

def setup_file_permissions():
	logger.info("Setup file permissions")
	
	setup_ssl_file_permissions()

	for fn in ("/var/log/opsi/opsiconfd/opsiconfd.log", ):
		if os.path.exists(fn):
			shutil.chown(path=fn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
			os.chmod(path=fn, mode=0o644)
	
	for d in (
		"/var/log/opsi/bootimage", "/var/log/opsi/clientconnect", "/var/log/opsi/instlog",
		"/var/log/opsi/opsiconfd", "/var/log/opsi/userlogin", "/var/lib/opsi/depot",
		"/var/lib/opsi/ntfs-images", "/var/lib/opsi/repository", "/var/lib/opsi/workbench"
	):
		if os.path.isdir(d) and not os.access(d, os.R_OK | os.W_OK | os.X_OK):
			po_setup_file_permissions(d)

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
	subprocess.run(["systemctl", "daemon-reload"], env=get_subprocess_environment(), capture_output=True)
	subprocess.run(["systemctl", "enable", "opsiconfd.service"], env=get_subprocess_environment(), capture_output=True)

def setup_backend():
	fqdn = getLocalFqdn()
	try:
		backend = get_backend()
		depot = backend.host_getObjects(type='OpsiDepotserver', id=fqdn)
	except Exception as e:
		logger.debug(e)
	
	logger.info("Setup backend")
	initializeBackends()

def setup(full: bool = True):
	logger.notice("Running opsiconfd setup")
	
	skip_setup = config.skip_setup or []
	if skip_setup:
		logger.notice("Skipping setup tasks: %s", ", ".join(skip_setup))
	
	if "all" in skip_setup:
		return
	
	if not config.run_as_user:
		config.run_as_user = getpass.getuser()
	if not "limits" in skip_setup:
		setup_limits()
	if full:
		if not "users" in skip_setup and not "groups" in skip_setup:
			po_setup_users_and_groups()
			setup_users_and_groups()
		if not "backend" in skip_setup:
			try:
				setup_backend()
			except Exception as e:
				# This can happen during package installation
				# where backend config files are missing
				logger.warning("Failed to setup backend: %s", e)
		if not "files" in skip_setup:
			setup_files()
		#po_setup_file_permissions() # takes very long with many files in /var/lib/opsi
		if not "ssl" in skip_setup:
			try:
				setup_ssl()
			except Exception as e:
				# This can fail if fqdn is not valid
				logger.error("Failed to setup ssl: %s", e)
		if not "systemd" in skip_setup:
			setup_systemd()
	else:
		if not "users" in skip_setup and not "groups" in skip_setup:
			setup_users_and_groups()
	if not "file_permissions" in skip_setup:
		# Always correct file permissions (run_as_user could be changed)
		setup_file_permissions()
	if not "grafana" in skip_setup:
		try:
			setup_grafana()
		except Exception as e:
			logger.warning("Failed to setup grafana: %s", e)

	if not "metric_downsampling" in skip_setup:
		try:
			setup_metric_downsampling()
		except Exception as e:
			logger.warning("Faild to setup redis downsampling: %s", e)
	
	check_ssl_expiry()

