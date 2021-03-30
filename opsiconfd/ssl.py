# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

import os
import datetime
import random
import socket
import ipaddress

from typing import Tuple

from OpenSSL.crypto import (
	FILETYPE_PEM, TYPE_RSA,
	dump_privatekey, dump_certificate, load_privatekey, load_certificate,
	X509, PKey, X509Name, X509Extension
)
from OpenSSL.crypto import Error as CryptoError

from OPSI.Util import getfqdn
from OPSI.Util.Task.Rights import PermissionRegistry, FilePermission, set_rights
from OPSI.Config import OPSI_ADMIN_GROUP

from opsicommon.ssl import install_ca

from .config import (
	config,
	CA_DAYS, CA_RENEW_DAYS, CERT_DAYS, CERT_RENEW_DAYS,
	PRIVATE_KEY_CIPHER,
	CA_KEY_DEFAULT_PASSPHRASE,
	SERVER_KEY_DEFAULT_PASSPHRASE
)
from .logging import logger
from .utils import get_ip_addresses
from .backend import get_server_role, get_backend

def get_ips():
	ips = {"127.0.0.1", "::1"}
	for addr in get_ip_addresses():
		if addr["family"] in ("ipv4", "ipv6") and addr["address"] not in ips:
			if addr["address"].startswith("fe80"):
				continue
			try:
				ips.add(ipaddress.ip_address(addr["address"]).compressed)
			except ValueError as err:
				logger.warning(err)
	return ips


def get_server_cn():
	return getfqdn()


def get_hostnames():
	names = {"localhost"}
	names.add(get_server_cn())
	for addr in get_ips():
		try:
			(hostname, aliases, _addr) = socket.gethostbyaddr(addr)
			names.add(hostname)
			for alias in aliases:
				names.add(alias)
		except socket.error as err:
			logger.info("No hostname for %s: %s", addr, err)
	return names


def get_domain():
	return '.'.join(get_server_cn().split('.')[1:])


def create_x590_name(subj: dict = None) -> X509Name: # pylint: disable=too-many-branches
	domain = get_domain()
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


def setup_ssl_file_permissions() -> None:
	ca_srl = os.path.join(os.path.dirname(config.ssl_ca_key), "opsi-ca.srl")
	permissions = (
		FilePermission(config.ssl_ca_cert, config.run_as_user, OPSI_ADMIN_GROUP, 0o644),
		#FilePermission(f"{config.ssl_ca_cert}.old", config.run_as_user, OPSI_ADMIN_GROUP, 0o644),
		FilePermission(ca_srl, config.run_as_user, OPSI_ADMIN_GROUP, 0o600),
		#FilePermission(config.ssl_ca_key, config.run_as_user, OPSI_ADMIN_GROUP, 0o600),
		FilePermission(config.ssl_ca_key, "root", "root", 0o600),
		FilePermission(config.ssl_server_cert, config.run_as_user, OPSI_ADMIN_GROUP, 0o600),
		FilePermission(config.ssl_server_key, config.run_as_user, OPSI_ADMIN_GROUP, 0o600)
	)
	PermissionRegistry().register_permission(*permissions)
	for permission in permissions:
		set_rights(permission.path)


KEY_CACHE = {}
def store_key(key_file: str, passphrase: str, key: PKey) -> None:
	if os.path.exists(key_file):
		os.unlink(key_file)
	if not os.path.exists(os.path.dirname(key_file)):
		os.makedirs(os.path.dirname(key_file))
	KEY_CACHE[key_file] = as_pem(key, passphrase)
	with open(key_file, "w") as out:
		out.write(KEY_CACHE[key_file])
	setup_ssl_file_permissions()


def load_key(key_file: str, passphrase: str, use_cache: bool = True) -> PKey:
	try:
		if key_file not in KEY_CACHE or not use_cache:
			with open(key_file, "r") as file:
				KEY_CACHE[key_file] = file.read()

		return load_privatekey(
			FILETYPE_PEM,
			KEY_CACHE[key_file],
			passphrase=passphrase.encode("utf-8")
		)
	except CryptoError as err:
		raise RuntimeError(
			f"Failed to load private key from '{key_file}': {err}"
		) from err


def store_cert(cert_file: str, cert: X509) -> None:
	if os.path.exists(cert_file):
		os.unlink(cert_file)
	if not os.path.exists(os.path.dirname(cert_file)):
		os.makedirs(os.path.dirname(cert_file))
	with open(cert_file, "w") as out:
		out.write(as_pem(cert))
	setup_ssl_file_permissions()


def load_cert(cert_file: str) -> X509:
	with open(cert_file, "r") as file:
		try:
			return load_certificate(FILETYPE_PEM, file.read())
		except CryptoError as err:
			raise RuntimeError(
				f"Failed to load CA cert from '{cert_file}': {err}"
			) from err


def store_ca_key(ca_key: PKey) -> None:
	store_key(config.ssl_ca_key, config.ssl_ca_key_passphrase, ca_key)


def load_ca_key(use_cache: bool = True) -> PKey:
	try:
		return load_key(config.ssl_ca_key, config.ssl_ca_key_passphrase, use_cache)
	except RuntimeError:
		if config.ssl_ca_key_passphrase == CA_KEY_DEFAULT_PASSPHRASE:
			raise
		# Wrong passphrase, try to load with default passphrase
		key = load_key(config.ssl_ca_key, CA_KEY_DEFAULT_PASSPHRASE)
		# Store with configured passphrase
		store_ca_key(key)
		return key


def store_ca_cert(ca_cert: X509) -> None:
	store_cert(config.ssl_ca_cert, ca_cert)


def load_ca_cert() -> X509:
	return load_cert(config.ssl_ca_cert)


def as_pem(cert_or_key, passphrase=None):
	if isinstance(cert_or_key, X509):
		return dump_certificate(
			FILETYPE_PEM,
			cert_or_key
		).decode("ascii")
	if isinstance(cert_or_key, PKey):
		return dump_privatekey(
			FILETYPE_PEM,
			cert_or_key,
			cipher=None if passphrase is None else PRIVATE_KEY_CIPHER,
			passphrase=None if passphrase is None else passphrase.encode("utf-8")
		).decode("ascii")
	raise TypeError(f"Invalid type: {cert_or_key}")


def get_ca_cert_as_pem() -> str:
	return as_pem(load_ca_cert())


def create_ca(renew: bool = True) -> Tuple[X509, PKey]:
	ca_key = None
	if renew:
		logger.notice("Renewing opsi CA")
		ca_key = load_ca_key()
	else:
		logger.notice("Creating opsi CA")
		ca_key = PKey()
		ca_key.generate_key(TYPE_RSA, 4096)

	ca_crt = X509()
	ca_crt.set_version(2)
	random_number = random.getrandbits(32)
	ca_serial_number = int.from_bytes(f"opsi-ca-{random_number}".encode(), byteorder="big")
	ca_crt.set_serial_number(ca_serial_number)
	ca_crt.gmtime_adj_notBefore(0)
	ca_crt.gmtime_adj_notAfter(CA_DAYS * 60 * 60 * 24)

	ca_crt.set_version(2)
	ca_crt.set_pubkey(ca_key)

	ca_subject = create_x590_name({"CN": "opsi CA"})

	ca_crt.set_issuer(ca_subject)
	ca_crt.set_subject(ca_subject)
	ca_crt.add_extensions([
		X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_crt),
		X509Extension(b"basicConstraints", True, b"CA:TRUE")
	])
	ca_crt.sign(ca_key, 'sha256')

	return (ca_crt, ca_key)


def store_local_server_key(srv_key: PKey) -> None:
	store_key(config.ssl_server_key, config.ssl_server_key_passphrase, srv_key)


def load_local_server_key(use_cache: bool = True) -> PKey:
	try:
		return load_key(config.ssl_server_key, config.ssl_server_key_passphrase, use_cache)
	except RuntimeError:
		if config.ssl_ca_key_passphrase == SERVER_KEY_DEFAULT_PASSPHRASE:
			raise
		# Wrong passphrase, try to load with default passphrase
		key = load_key(config.ssl_server_key, SERVER_KEY_DEFAULT_PASSPHRASE)
		# Store with configured passphrase
		store_local_server_key(key)
		return key


def store_local_server_cert(server_cert: X509) -> None:
	store_cert(config.ssl_server_cert, server_cert)


def load_local_server_cert() -> X509:
	return load_cert(config.ssl_server_cert)


def create_server_cert(common_name: str, ip_addresses: set, hostnames: set, key: PKey = None) -> Tuple[X509, PKey]:  # pylint: disable=too-many-locals
	if not key:
		logger.info("Creating server key pair")
		key = PKey()
		key.generate_key(TYPE_RSA, 4096)

	ca_key = load_ca_key()
	ca_crt = load_ca_cert()

	# Chrome requires CN from Subject also as Subject Alt
	hostnames.add(common_name)
	hns = ", ".join([f"DNS:{str(hn).strip()}" for hn in hostnames])
	ips = ", ".join([f"IP:{str(ip).strip()}" for ip in ip_addresses])
	alt_names = ""
	if hns:
		alt_names += hns
	if ips:
		if alt_names:
			alt_names += ", "
		alt_names += ips

	crt = X509()
	crt.set_version(2)

	srv_subject = create_x590_name({"CN": f"{common_name}"})
	crt.set_subject(srv_subject)

	ca_srl = os.path.join(os.path.dirname(config.ssl_ca_key), "opsi-ca.srl")
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

	crt.set_serial_number(srv_serial_number)
	crt.gmtime_adj_notBefore(0)
	crt.gmtime_adj_notAfter(CERT_DAYS * 60 * 60 * 24)
	crt.set_issuer(ca_crt.get_subject())
	crt.set_subject(srv_subject)

	crt.add_extensions([
		X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_crt),
		X509Extension(b"basicConstraints", True, b"CA:FALSE"),
		X509Extension(b"keyUsage", True, b"nonRepudiation, digitalSignature, keyEncipherment"),
		X509Extension(b"extendedKeyUsage", False, b"serverAuth, clientAuth, codeSigning, emailProtection")
	])
	if alt_names:
		crt.add_extensions([
			X509Extension(b"subjectAltName", False, alt_names.encode("utf-8"))
		])
	crt.set_pubkey(key)
	crt.sign(ca_key, "sha256")

	with open(ca_srl, "a") as out:
		out.write(hex(srv_serial_number)[2:])
		out.write("\n")

	return (crt, key)

def create_local_server_cert(renew: bool = True) -> Tuple[X509, PKey]: # pylint: disable=too-many-locals
	key = None
	if renew:
		logger.notice("Renewing server cert")
		key = load_local_server_key()

	return create_server_cert(
		common_name=get_server_cn(),
		ip_addresses=get_ips(),
		hostnames=get_hostnames(),
		key=key
	)


def depotserver_setup_ca() -> bool:
	logger.info("Updating CA cert from configserver")
	ca_crt = load_certificate(FILETYPE_PEM, get_backend().getOpsiCACert())  # pylint: disable=no-member
	store_ca_cert(ca_crt)
	install_ca(ca_crt)
	return False

def configserver_setup_ca() -> bool:
	logger.info("Checking CA")

	create = False
	renew = False

	if not os.path.exists(config.ssl_ca_key) or not os.path.exists(config.ssl_ca_cert):
		create = True
	else:
		ca_crt = load_ca_cert()
		enddate = datetime.datetime.strptime(ca_crt.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%SZ")
		diff = (enddate - datetime.datetime.now()).days

		logger.info("CA '%s' will expire in %d days", ca_crt.get_subject().CN, diff)
		if diff <= CA_RENEW_DAYS:
			logger.notice("CA '%s' will expire in %d days, renewing", ca_crt.get_subject().CN, diff)
			renew = True

	if create or renew:
		(ca_crt, ca_key) = create_ca(renew=renew)
		store_ca_key(ca_key)
		store_ca_cert(ca_crt)
		install_ca(ca_crt)
		return True

	logger.info("Server cert is up to date")
	return False


def setup_ca() -> bool:
	server_role = get_server_role()
	if config.ssl_ca_key == config.ssl_ca_cert:
		raise ValueError("CA key and cert cannot be stored in the same file")

	if server_role == "config":
		return configserver_setup_ca()
	if server_role == "depot":
		return depotserver_setup_ca()

	raise ValueError(f"Invalid server role: {server_role}")


def setup_server_cert():  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
	logger.info("Checking server cert")
	server_role = get_server_role()
	if server_role not in ("config", "depot"):
		raise ValueError(f"Invalid server role: {server_role}")

	if config.ssl_server_key == config.ssl_server_cert:
		raise ValueError("SSL server key and cert cannot be stored in the same file")

	create = False

	if (
		os.path.exists(os.path.join(os.path.dirname(config.ssl_server_cert), "opsiconfd.pem")) and
		os.path.basename(config.ssl_server_key) != "opsiconfd.pem" and
		os.path.basename(config.ssl_server_cert) != "opsiconfd.pem"
	):
		# Remove old default file
		os.remove(os.path.join(os.path.dirname(config.ssl_server_cert), "opsiconfd.pem"))

	server_cn = get_server_cn()
	if not os.path.exists(config.ssl_server_key) or not os.path.exists(config.ssl_server_cert):  # pylint: disable=too-many-nested-blocks
		create = True
	else:
		srv_crt = load_local_server_cert()
		enddate = datetime.datetime.strptime(srv_crt.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%SZ")
		diff = (enddate - datetime.datetime.now()).days

		logger.info("Server cert '%s' will expire in %d days", srv_crt.get_subject().CN, diff)
		if diff <= CERT_RENEW_DAYS:
			logger.notice("Server cert '%s' will expire in %d days, recreating", srv_crt.get_subject().CN, diff)
			create = True
		else:
			if server_cn != srv_crt.get_subject().CN:
				logger.notice(
					"Server CN has changed from '%s' to '%s', creating new server cert",
					srv_crt.get_subject().CN, server_cn
				)
				create = True
			elif server_role == "config":
				cert_hns = set()
				cert_ips = set()
				for idx in range(srv_crt.get_extension_count()):
					ext = srv_crt.get_extension(idx)
					if ext.get_short_name() == b"subjectAltName":
						for alt_name in str(ext).split(","):
							alt_name = alt_name.strip()
							if alt_name.startswith("DNS:"):
								cert_hns.add(alt_name.split(":", 1)[-1].strip())
							elif alt_name.startswith(("IP:", "IP Address:")):
								addr = alt_name.split(":", 1)[-1].strip()
								addr = ipaddress.ip_address(addr)
								cert_ips.add(addr.compressed)
						break
				hns = get_hostnames()
				if cert_hns != hns:
					logger.notice(
						"Server hostnames have changed from %s to %s, creating new server cert",
						cert_hns, hns
					)
					create = True
				else:
					ips = get_ips()
					if cert_ips != ips:
						logger.notice(
							"Server IPs have changed from %s to %s, creating new server cert",
							cert_ips, ips
						)
						create = True

	if create:
		(srv_crt, srv_key) = (None, None)
		if server_role == "config":
			# It is safer to create a new server cert with a new key pair
			# For cases where the server key got compromised
			(srv_crt, srv_key) = create_local_server_cert(renew=False)
		else:
			pem = get_backend().host_getTLSCertificate(server_cn)  # pylint: disable=no-member
			srv_crt = load_certificate(FILETYPE_PEM, pem)
			srv_key = load_privatekey(FILETYPE_PEM, pem)

		store_local_server_key(srv_key)
		store_local_server_cert(srv_crt)
		return True

	logger.info("Server cert is up to date")
	return False


def setup_ssl():
	logger.info("Setup ssl")
	server_role = get_server_role()
	setup_ca()
	setup_server_cert()
	if server_role == "config":
		# Read CA key as root to fill key cache
		# so run_as_user can use key from cache
		load_ca_key()


def get_ca_info():
	cert = load_ca_cert()
	expiration = (
		datetime.datetime.strptime(cert.get_notAfter().decode("utf-8"),"%Y%m%d%H%M%SZ") -
		datetime.datetime.now()
	).days

	return {
		"issuer": cert.get_issuer(),
		"subject": cert.get_subject(),
		"serial_number": ':'.join(('%X' % cert.get_serial_number()).zfill(36)[i:i+2] for i in range(0, 36, 2)),
		"expiration": expiration
	}


def get_cert_info():
	cert = load_local_server_cert()
	alt_names = ""
	for i in range(0, cert.get_extension_count()):
		if cert.get_extension(i).get_short_name() == b'subjectAltName':
			alt_names = cert.get_extension(i)

	expiration = (
		datetime.datetime.strptime(cert.get_notAfter().decode("utf-8"),"%Y%m%d%H%M%SZ") -
		datetime.datetime.now()
	).days

	return {
		"issuer": cert.get_issuer(),
		"subject": cert.get_subject(),
		"serial_number": ':'.join(('%X' % cert.get_serial_number()).zfill(36)[i:i+2] for i in range(0, 36, 2)),
		"alt_names": alt_names,
		"expiration": expiration
	}
