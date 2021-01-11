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
import socket
import shutil
import psutil
import codecs
import getpass
import resource
import tempfile
import subprocess
import datetime
import random
from OpenSSL import crypto
from typing import Tuple

from OPSI.Config import OPSI_ADMIN_GROUP, FILE_ADMIN_GROUP, DEFAULT_DEPOT_USER
from OPSI.setup import (
	setup_users_and_groups as po_setup_users_and_groups,
	setup_file_permissions as po_setup_file_permissions,
	get_users, get_groups, add_user_to_group, create_user, set_primary_group
)
from OPSI.Util import getfqdn
from OPSI.System.Posix import getLocalFqdn, locateDHCPDConfig
from OPSI.Util.Task.InitializeBackend import initializeBackends
from OPSI.System import get_subprocess_environment

from .logging import logger
from .config import config
from .utils import get_ip_addresses
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

			with open(cert, "r") as file:
				cert = crypto.load_certificate(crypto.FILETYPE_PEM,  file.read())

			enddate = datetime.datetime.strptime(cert.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%SZ")
			diff = (enddate - datetime.datetime.now()).days

			if (diff <= 0):
				logger.error("Certificate '%s' expired on %s", cert, enddate)
			elif (diff < 30):
				logger.warning("Certificate '%s' will expire in %d days", cert, diff)

def renew_ca() -> None:

	ca_key = None
	if os.path.exists(config.ssl_ca_key):
		logger.info("Using existing key to create new ca.")
		with open(config.ssl_ca_key, "r") as file:
			ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM,  file.read())
	else:
		logger.info("Key not found. Create new ca with new key.")
		ca_key = crypto.PKey()
		ca_key.generate_key(crypto.TYPE_RSA, 4096)

	return create_ca(ca_key)

def create_ca(ca_key: crypto.PKey = None, ca_subject: crypto.X509Name = None) -> Tuple[crypto.X509, crypto.PKey]:
	ca_days = 730
	fqdn = getfqdn()
	domain = '.'.join(fqdn.split('.')[1:])

	logger.info("Creating opsi CA")

	if not ca_key:
		ca_key = crypto.PKey()
		ca_key.generate_key(crypto.TYPE_RSA, 4096)

	ca_crt = crypto.X509()
	random_number = random.getrandbits(32)
	ca_serial_number = int.from_bytes(f"opsica-{random_number}".encode(), byteorder="big")
	ca_crt.set_serial_number(ca_serial_number)
	ca_crt.gmtime_adj_notBefore(0)
	ca_crt.gmtime_adj_notAfter(ca_days * 60 * 60 * 24)

	ca_crt.set_version(2)
	ca_crt.set_pubkey(ca_key)

	logger.devel("SUBJECT: %s", ca_crt.get_subject())
	if not ca_subject:
		ca_subject = ca_crt.get_subject()
		ca_subject.C = "DE"
		ca_subject.ST = "RP"
		ca_subject.L = "MAINZ"
		ca_subject.O = "uib"
		ca_subject.OU = f"opsi@{domain}"
		ca_subject.CN = "opsi CA"
		ca_subject.emailAddress = f"opsi@{domain}"
		

	ca_crt.set_issuer(ca_subject)
	logger.devel("SUBJECT: %s", ca_crt.get_subject())

	ca_crt.add_extensions([
		crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_crt),
		crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE")
	])
	ca_crt.sign(ca_key, 'sha256')

	return (ca_crt, ca_key)

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
	
	ca_key = None
	ca_crt = None
		
	if not os.path.exists(config.ssl_ca_key) or not os.path.exists(config.ssl_ca_cert):
		logger.info("Creating opsi CA")

		logger.devel(ca_key)
		logger.devel("create ca crt")
		ca_crt, ca_key = create_ca()
		logger.devel(ca_crt)
		logger.devel(ca_key)

		if os.path.exists(config.ssl_ca_key):
			os.unlink(config.ssl_ca_key)
		if not os.path.exists(os.path.dirname(config.ssl_ca_key)):
			os.makedirs(os.path.dirname(config.ssl_ca_key))
			os.chmod(path=os.path.dirname(config.ssl_ca_key), mode=0o700)
		with open(config.ssl_ca_key, "ab") as out:
			out.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
		
		if os.path.exists(config.ssl_ca_cert):
			os.unlink(config.ssl_ca_cert)
		if not os.path.exists(os.path.dirname(config.ssl_ca_cert)):
			os.makedirs(os.path.dirname(config.ssl_ca_cert))
			os.chmod(path=os.path.dirname(config.ssl_ca_cert), mode=0o700)
		with open(config.ssl_ca_cert, "ab") as out:
			out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_crt))
		
		setup_ssl_file_permissions()
		
	if os.path.exists(config.ssl_server_key) or not os.path.exists(config.ssl_server_cert):

		if not ca_key:
			with open(config.ssl_ca_key, "r") as file:
				ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM,  file.read())
		if not ca_crt:
			with open(config.ssl_ca_cert, "r") as file:
				ca_crt = crypto.load_certificate(crypto.FILETYPE_PEM,  file.read())

		# Chrome requires Subject Alt Name
		ips = ["127.0.0.1", "::1"]
		for a in get_ip_addresses():
			if a["family"] == "ipv4" and a["address"] not in ips:
				ips.append(a["address"])
		ips = ", ".join([f"IP:{ip}" for ip in ips])

		alt_names = f"DNS:{fqdn}, DNS:localhost, {ips}"

		srv_key = crypto.PKey()
		srv_key.generate_key(crypto.TYPE_RSA, 4096)

		srv_crt = crypto.X509()
		srv_crt.set_version(2)

		srv_subject= srv_crt.get_subject()
		srv_subject.C = "DE"
		srv_subject.ST = "RP"
		srv_subject.L = "MAINZ"
		srv_subject.O = "uib"
		srv_subject.OU = f"opsi@{domain}"
		srv_subject.CN = f"{fqdn}"
		srv_subject.emailAddress = f"opsi@{domain}"

		ca_srl = os.path.splitext(config.ssl_ca_key)[0] + ".srl"
		used_serial_numbers = []
		if os.path.exists(ca_srl):
			with open(ca_srl, "r") as file:
				used_serial_numbers = [serial_number.rstrip() for serial_number in file]
		srv_serial_number = None
		count = 0
		while not srv_serial_number or hex(srv_serial_number)[2:] in used_serial_numbers:
			count += 1
			random_number = random.getrandbits(32)
			srv_serial_number = int.from_bytes(f"opsiconfd-{random_number}".encode(), byteorder="big") 
			if count > 10:
				logger.warning("No new serial number for ssl cert found!")
				break

		srv_crt.set_serial_number(srv_serial_number)
		srv_crt.gmtime_adj_notBefore(0)
		srv_crt.gmtime_adj_notAfter(cert_days * 60 * 60 * 24)
		srv_crt.set_issuer(ca_crt.get_subject())
		srv_crt.set_subject(srv_subject)

		srv_crt.add_extensions([
			crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_crt),
			crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
			crypto.X509Extension(b"keyUsage", True, b"nonRepudiation, digitalSignature, keyEncipherment"),
			crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth, clientAuth, codeSigning, emailProtection"),
			crypto.X509Extension(b"subjectAltName", False, alt_names.encode())
		])

		srv_crt.set_pubkey(srv_key)
		srv_crt.sign(ca_key, "sha256")
		
		logger.info("Creating opsiconfd cert")

		if os.path.exists(config.ssl_server_key):
			os.unlink(config.ssl_server_key)
		if os.path.exists(config.ssl_server_cert):
			os.unlink(config.ssl_server_cert)
		
		if not os.path.exists(os.path.dirname(config.ssl_server_key)):
			os.makedirs(os.path.dirname(config.ssl_server_key))
			os.chmod(path=os.path.dirname(config.ssl_server_key), mode=0o700)

		with open(ca_srl, "a") as out:
			out.write(hex(srv_serial_number)[2:])
			out.write("\n")

		with open(config.ssl_server_key, "ab") as out:
			out.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, srv_key))
		if not os.path.exists(os.path.dirname(config.ssl_server_cert)):
			os.makedirs(os.path.dirname(config.ssl_server_cert))
			os.chmod(path=os.path.dirname(config.ssl_server_cert), mode=0o700)

		with open(config.ssl_server_cert, "ab") as out:
			out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, srv_crt))
		
		setup_ssl_file_permissions()

def setup_files():
	log_dir = os.path.dirname(config.log_file)
	if not os.path.isdir(log_dir):
		os.makedirs(log_dir)

def setup_ssl_file_permissions():
	# Key and cert can be the same file.
	# Order is important!
	# Set permission of cert first, key afterwards.
	for fn in (config.ssl_ca_cert, config.ssl_ca_key):
		if os.path.exists(fn):
			shutil.chown(path=fn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
			mode = 0o644 if fn == config.ssl_ca_cert else 0o600
			os.chmod(path=fn, mode=mode)
			dn = os.path.dirname(fn)
			if dn.count('/') >= 3:
				shutil.chown(path=dn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
				os.chmod(path=dn, mode=0o770)
	
	for fn in (config.ssl_server_cert, config.ssl_server_key):
		if os.path.exists(fn):
			shutil.chown(path=fn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
			mode = 0o644 if fn == config.ssl_server_cert else 0o600
			os.chmod(path=fn, mode=mode)
			dn = os.path.dirname(fn)
			if dn.count('/') >= 3:
				shutil.chown(path=dn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
				os.chmod(path=dn, mode=0o770)

def setup_file_permissions():
	logger.info("Setup file permissions")
	
	setup_ssl_file_permissions()

	dhcpd_config_file = locateDHCPDConfig("/etc/dhcp3/dhcpd.conf")
	for fn in ("/var/log/opsi/opsiconfd/opsiconfd.log", dhcpd_config_file):
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

