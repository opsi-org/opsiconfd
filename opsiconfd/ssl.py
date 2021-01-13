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
import datetime
import random
import shutil

from typing import Tuple

# from OpenSSL import crypto
from OpenSSL.crypto import (
	FILETYPE_PEM, TYPE_RSA,
	dump_privatekey, dump_certificate, load_privatekey, load_certificate,
	X509, PKey, X509Name, X509Extension
)

from OPSI.Util import getfqdn
from OPSI.Config import OPSI_ADMIN_GROUP

from .config import config
from .logging import logger
from .utils import get_ip_addresses

CA_DAYS = 730
CERT_DAYS = 365


def setup_ssl(): # pylint: disable=too-many-branches
	logger.info("Setup ssl")
	if (
		os.path.exists(config.ssl_ca_key) and os.path.exists(config.ssl_ca_cert) and
		os.path.exists(config.ssl_server_key) and os.path.exists(config.ssl_server_cert)
	):
		return

	ca_key = None
	ca_crt = None

	if not os.path.exists(config.ssl_ca_key) or not os.path.exists(config.ssl_ca_cert):
		logger.info("Creating opsi CA")

		ca_crt, ca_key = create_ca()

		if os.path.exists(config.ssl_ca_key):
			os.unlink(config.ssl_ca_key)
		if not os.path.exists(os.path.dirname(config.ssl_ca_key)):
			os.makedirs(os.path.dirname(config.ssl_ca_key))
			os.chmod(path=os.path.dirname(config.ssl_ca_key), mode=0o700)
		with open(config.ssl_ca_key, "wb") as out:
			out.write(dump_privatekey(FILETYPE_PEM, ca_key))

		if os.path.exists(config.ssl_ca_cert):
			os.unlink(config.ssl_ca_cert)
		if not os.path.exists(os.path.dirname(config.ssl_ca_cert)):
			os.makedirs(os.path.dirname(config.ssl_ca_cert))
			os.chmod(path=os.path.dirname(config.ssl_ca_cert), mode=0o700)
		with open(config.ssl_ca_cert, "wb") as out:
			out.write(dump_certificate(FILETYPE_PEM, ca_crt))

		setup_ssl_file_permissions()

	if os.path.exists(config.ssl_server_key) or not os.path.exists(config.ssl_server_cert):

		if not ca_key:
			with open(config.ssl_ca_key, "r") as file:
				ca_key = load_privatekey(FILETYPE_PEM,  file.read())
		if not ca_crt:
			with open(config.ssl_ca_cert, "r") as file:
				ca_crt = load_certificate(FILETYPE_PEM,  file.read())

		srv_crt, srv_key = create_crt(ca_crt, ca_key)

		if os.path.exists(config.ssl_server_key):
			os.unlink(config.ssl_server_key)
		if os.path.exists(config.ssl_server_cert):
			os.unlink(config.ssl_server_cert)

		if not os.path.exists(os.path.dirname(config.ssl_server_key)):
			os.makedirs(os.path.dirname(config.ssl_server_key))
			os.chmod(path=os.path.dirname(config.ssl_server_key), mode=0o700)

		with open(config.ssl_server_cert, "ab") as out:
			out.write(dump_certificate(FILETYPE_PEM, srv_crt))

		with open(config.ssl_server_key, "ab") as out:
			out.write(dump_privatekey(FILETYPE_PEM, srv_key))
		if not os.path.exists(os.path.dirname(config.ssl_server_cert)):
			os.makedirs(os.path.dirname(config.ssl_server_cert))
			os.chmod(path=os.path.dirname(config.ssl_server_cert), mode=0o700)

		setup_ssl_file_permissions()

def setup_ssl_file_permissions():
	# Key and cert can be the same file.
	# Order is important!
	# Set permission of cert first, key afterwards.
	for fn in (config.ssl_ca_cert, config.ssl_ca_key): # pylint: disable=invalid-name
		if os.path.exists(fn):
			shutil.chown(path=fn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
			mode = 0o644 if fn == config.ssl_ca_cert else 0o600
			os.chmod(path=fn, mode=mode)
			dn = os.path.dirname(fn) # pylint: disable=invalid-name
			if dn.count('/') >= 3:
				shutil.chown(path=dn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
				os.chmod(path=dn, mode=0o770)

	for fn in (config.ssl_server_cert, config.ssl_server_key): # pylint: disable=invalid-name
		if os.path.exists(fn):
			shutil.chown(path=fn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
			mode = 0o644 if fn == config.ssl_server_cert else 0o600
			os.chmod(path=fn, mode=mode)
			dn = os.path.dirname(fn) # pylint: disable=invalid-name
			if dn.count('/') >= 3:
				shutil.chown(path=dn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
				os.chmod(path=dn, mode=0o770)

def check_ssl_expiry():
	for cert in (config.ssl_ca_cert, config.ssl_server_cert):
		if os.path.exists(cert):
			logger.info("Checking expiry of certificate: %s", cert)

			with open(cert, "r") as file:
				cert = load_certificate(FILETYPE_PEM,  file.read())

			enddate = datetime.datetime.strptime(cert.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%SZ")
			diff = (enddate - datetime.datetime.now()).days

			if diff <= 0:
				logger.error("Certificate '%s' expired on %s", cert, enddate)
			elif diff < 30:
				logger.warning("Certificate '%s' will expire in %d days", cert, diff)

def renew_ca() -> Tuple[X509, PKey]:

	if os.path.exists(config.ssl_ca_cert):
		logger.debug("Rename old ca.")
		shutil.move(config.ssl_ca_cert, f"{config.ssl_ca_cert}.old")

	ca_key = None
	if os.path.exists(config.ssl_ca_key):
		logger.info("Using existing key to create new ca.")
		with open(config.ssl_ca_key, "r") as file:
			ca_key = load_privatekey(FILETYPE_PEM,  file.read())
	else:
		logger.info("Key not found. Create new ca with new key.")
		ca_key = PKey()
		ca_key.generate_key(TYPE_RSA, 4096)

	return create_ca(ca_key)


def create_ca(ca_key: PKey = None, ca_subject: X509Name = None) -> Tuple[X509, PKey]:
	logger.info("Creating opsi CA")

	if not ca_key:
		ca_key = PKey()
		ca_key.generate_key(TYPE_RSA, 4096)

	ca_crt = X509()
	ca_crt.set_version(2)
	random_number = random.getrandbits(32)
	ca_serial_number = int.from_bytes(f"opsica-{random_number}".encode(), byteorder="big")
	ca_crt.set_serial_number(ca_serial_number)
	ca_crt.gmtime_adj_notBefore(0)
	ca_crt.gmtime_adj_notAfter(CA_DAYS * 60 * 60 * 24)

	ca_crt.set_version(2)
	ca_crt.set_pubkey(ca_key)

	if not ca_subject:
		ca_subject = create_x590Name({"CN": "opsi CA"})

	ca_crt.set_issuer(ca_subject)
	ca_crt.set_subject(ca_subject)
	ca_crt.add_extensions([
		X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_crt),
		X509Extension(b"basicConstraints", True, b"CA:TRUE")
	])
	ca_crt.sign(ca_key, 'sha256')

	return (ca_crt, ca_key)


def create_crt(ca_crt: X509, ca_key: PKey, srv_subject: X509Name = None) -> Tuple[X509, PKey]: # pylint: disable=too-many-locals
	logger.info("Creating opsiconfd cert")
	fqdn = getfqdn()
	domain = '.'.join(fqdn.split('.')[1:])

	# Chrome requires Subject Alt Name
	ips = ["127.0.0.1", "::1"]
	for a in get_ip_addresses(): # pylint: disable=invalid-name
		if a["family"] == "ipv4" and a["address"] not in ips:
			ips.append(a["address"])
	ips = ", ".join([f"IP:{ip}" for ip in ips])

	alt_names = f"DNS:{fqdn}, DNS:localhost, {ips}"

	srv_key = PKey()
	srv_key.generate_key(TYPE_RSA, 4096)

	srv_crt = X509()
	srv_crt.set_version(2)

	if not srv_subject:
		srv_subject = create_x590Name({"CN": f"{domain}"})
	srv_crt.set_subject(srv_subject)

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
	srv_crt.gmtime_adj_notAfter(CERT_DAYS * 60 * 60 * 24)
	srv_crt.set_issuer(ca_crt.get_subject())
	srv_crt.set_subject(srv_subject)

	srv_crt.add_extensions([
		X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_crt),
		X509Extension(b"basicConstraints", True, b"CA:FALSE"),
		X509Extension(b"keyUsage", True, b"nonRepudiation, digitalSignature, keyEncipherment"),
		X509Extension(b"extendedKeyUsage", False, b"serverAuth, clientAuth, codeSigning, emailProtection"),
		X509Extension(b"subjectAltName", False, alt_names.encode())
	])

	srv_crt.set_pubkey(srv_key)
	srv_crt.sign(ca_key, "sha256")

	with open(ca_srl, "a") as out:
		out.write(hex(srv_serial_number)[2:])
		out.write("\n")

	return (srv_crt, srv_key)


def create_x590Name(subj: dict = None) -> X509Name: # pylint: disable=invalid-name, too-many-branches

	fqdn = getfqdn()
	domain = '.'.join(fqdn.split('.')[1:])

	subject = {
		"C": "DE",
		"ST": "RP",
		"L": "MAINZ",
		"O": "uib",
		"OU": f"opsi@{domain}",
		"CN": "opsi",
		"emailAddress": f"opsi@{domain}"
	}
	subject.update(subj)

	x509_name = X509Name(X509().get_subject())
	if subject.get("countryName"):
		x509_name.countryName = subject.get("countryName")
	if subject.get("C"):
		x509_name.C = subject.get("C")
	if subject.get("stateOrProvinceName"):
		x509_name.stateOrProvinceName = subject.get("stateOrProvinceName")
	if subject.get("ST"):
		x509_name.ST = subject.get("ST")
	if subject.get("localityName"):
		x509_name.localityName = subject.get("localityName")
	if subject.get("L"):
		x509_name.L = subject.get("L")
	if subject.get("organizationName"):
		x509_name.organizationName = subject.get("organizationName")
	if subject.get("O"):
		x509_name.O = subject.get("O")
	if subject.get("organizationalUnitName"):
		x509_name.organizationalUnitName = subject.get("organizationalUnitName")
	if subject.get("OU"):
		x509_name.OU = subject.get("OU")
	if subject.get("commonName"):
		x509_name.commonName = subject.get("commonName")
	if subject.get("CN"):
		x509_name.CN = subject.get("CN")
	if subject.get("emailAddress"):
		x509_name.emailAddress = subject.get("emailAddress")

	return x509_name
