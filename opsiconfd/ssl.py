# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.ssl
"""

import datetime
import os
from pathlib import Path
import re
import socket
import time
from ipaddress import ip_address
from re import DOTALL, finditer
from socket import gethostbyaddr
from typing import Any

from OpenSSL.crypto import (
	FILETYPE_PEM,
	X509,
	PKey,
	X509Name,
	X509Store,
	X509StoreContext,
	X509StoreContextError,
	dump_publickey,
	load_certificate,
	load_privatekey,
)
from OpenSSL.crypto import Error as CryptoError
from opsicommon.server.rights import FilePermission, PermissionRegistry, set_rights
from opsicommon.ssl import as_pem, create_ca, create_server_cert, install_ca
from requests.exceptions import ConnectionError as RequestsConnectionError

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.config import (
	CA_KEY_DEFAULT_PASSPHRASE,
	FQDN,
	SERVER_KEY_DEFAULT_PASSPHRASE,
	config,
	get_depotserver_id,
	opsi_config,
)
from opsiconfd.logging import logger
from opsiconfd.utils import get_ip_addresses


def get_ips() -> set[str]:
	ips = {"127.0.0.1", "::1"}
	for addr in get_ip_addresses():
		if addr["family"] in ("ipv4", "ipv6") and addr["address"] not in ips:
			if addr["address"].startswith("fe80"):
				continue
			try:
				ips.add(ip_address(addr["address"]).compressed)
			except ValueError as err:
				logger.warning(err)
	return ips


def get_server_cn() -> str:
	return opsi_config.get("host", "id")


def get_hostnames() -> set[str]:
	names = {"localhost"}
	names.add(FQDN)
	names.add(get_server_cn())
	for addr in get_ips():
		try:
			(hostname, aliases, _addr) = gethostbyaddr(addr)
			names.add(hostname)
			for alias in aliases:
				names.add(alias)
		except socket.error as err:
			logger.info("No hostname for %s: %s", addr, err)
	return names


def get_domain() -> str:
	return ".".join(FQDN.split(".")[1:])


def setup_ssl_file_permissions() -> None:
	admin_group = opsi_config.get("groups", "admingroup")
	permissions = (
		FilePermission(config.ssl_ca_cert, config.run_as_user, admin_group, 0o644),
		FilePermission(config.ssl_ca_key, config.run_as_user, admin_group, 0o600),
		FilePermission(config.ssl_server_cert, config.run_as_user, admin_group, 0o600),
		FilePermission(config.ssl_server_key, config.run_as_user, admin_group, 0o600),
	)
	PermissionRegistry().register_permission(*permissions)
	for permission in permissions:
		set_rights(permission.path)


def store_key(key_file: str | Path, passphrase: str, key: PKey) -> None:
	if not isinstance(key_file, Path):
		key_file = Path(key_file)

	key_file.unlink(missing_ok=True)
	key_file.parent.mkdir(parents=True, exist_ok=True)
	key_file.write_text(as_pem(key, passphrase), encoding="utf-8")
	setup_ssl_file_permissions()


def load_key(key_file: str | Path, passphrase: str) -> PKey:
	if not isinstance(key_file, Path):
		key_file = Path(key_file)
	try:
		return load_privatekey(FILETYPE_PEM, key_file.read_text(encoding="utf-8"), passphrase=passphrase.encode("utf-8"))
	except CryptoError as err:
		raise RuntimeError(f"Failed to load private key from '{key_file}': {err}") from err


def store_cert(cert_file: str | Path, cert: X509, keep_others: bool = False) -> None:
	if not isinstance(cert_file, Path):
		cert_file = Path(cert_file)

	cert_file.parent.mkdir(parents=True, exist_ok=True)
	certs = []
	if cert_file.exists() and keep_others:
		certs = [c for c in load_certs(cert_file) if c.get_subject().CN != cert.get_subject().CN]
	certs.append(cert)
	cert_file.write_text("".join(as_pem(c) for c in certs), encoding="utf-8")
	setup_ssl_file_permissions()


def load_certs(cert_file: Path | str) -> list[X509]:
	if not isinstance(cert_file, Path):
		cert_file = Path(cert_file)

	certs = []
	data = cert_file.read_text(encoding="utf-8")
	for match in re.finditer(r"(-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+)", data, re.DOTALL):
		try:
			certs.append(load_certificate(FILETYPE_PEM, match.group(1).encode("utf-8")))
		except CryptoError as err:
			logger.warning(err, exc_info=True)
	return certs


def load_cert(cert_file: Path | str, subject_cn: str | None = None) -> X509:
	if not isinstance(cert_file, Path):
		cert_file = Path(cert_file)

	for cert in load_certs(cert_file):
		if not subject_cn or cert.get_subject().CN == subject_cn:
			return cert

	raise RuntimeError(f"Failed to load {repr(subject_cn) if subject_cn else 'cert'} from '{cert_file}': Not found")


def store_ca_key(ca_key: PKey) -> None:
	store_key(config.ssl_ca_key, config.ssl_ca_key_passphrase, ca_key)


def load_ca_key() -> PKey:
	try:
		return load_key(config.ssl_ca_key, config.ssl_ca_key_passphrase)
	except RuntimeError:
		if config.ssl_ca_key_passphrase == CA_KEY_DEFAULT_PASSPHRASE:
			raise
		# Wrong passphrase, try to load with default passphrase
		key = load_key(config.ssl_ca_key, CA_KEY_DEFAULT_PASSPHRASE)
		# Store with configured passphrase
		store_ca_key(key)
		return key


def store_ca_cert(ca_cert: X509) -> None:
	store_cert(config.ssl_ca_cert, ca_cert, keep_others=True)


def load_ca_cert() -> X509:
	return load_cert(config.ssl_ca_cert, subject_cn=config.ssl_ca_subject_cn)


def get_ca_cert_as_pem() -> str:
	return as_pem(load_ca_cert())


def store_local_server_key(srv_key: PKey) -> None:
	store_key(config.ssl_server_key, config.ssl_server_key_passphrase, srv_key)


def load_local_server_key() -> PKey:
	try:
		return load_key(config.ssl_server_key, config.ssl_server_key_passphrase)
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


def create_local_server_cert(renew: bool = True) -> tuple[X509, PKey]:  # pylint: disable=too-many-locals
	ca_key = load_ca_key()
	ca_cert = load_ca_cert()
	domain = get_domain()

	key = None
	if renew:
		logger.notice("Renewing server cert")
		key = load_local_server_key()

	return create_server_cert(
		subject={"CN": get_server_cn(), "OU": f"opsi@{domain}", "emailAddress": f"opsi@{domain}"},
		valid_days=config.ssl_server_cert_valid_days,
		ip_addresses=get_ips(),
		hostnames=get_hostnames(),
		ca_key=ca_key,
		ca_cert=ca_cert,
		key=key,
	)


def depotserver_setup_ca() -> bool:
	logger.info("Updating CA cert from configserver")
	ca_crt = load_certificate(FILETYPE_PEM, get_unprotected_backend().getOpsiCACert())  # pylint: disable=no-member
	store_ca_cert(ca_crt)
	install_ca(ca_crt)
	return False


def get_ca_subject() -> dict[str, str]:
	domain = get_domain()
	return {
		"C": "DE",
		"ST": "RP",
		"L": "MAINZ",
		"O": "uib",
		"OU": f"opsi@{domain}",
		"CN": config.ssl_ca_subject_cn,
		"emailAddress": f"opsi@{domain}",
	}


def subject_to_dict(subject: X509Name) -> dict[str, str]:
	return {
		"C": subject.C,
		"ST": subject.ST,
		"L": subject.L,
		"O": subject.O,
		"OU": subject.OU,
		"CN": subject.CN,
		"emailAddress": subject.emailAddress,
	}


def configserver_setup_ca() -> bool:  # pylint: disable=too-many-branches
	logger.info("Checking CA")

	create = False
	renew = False
	try:
		ca_key = load_ca_key()
		try:
			ca_crt = load_ca_cert()
		except Exception:  # pylint: disable=broad-except
			ca_crt = None
			renew = True
	except Exception:  # pylint: disable=broad-except
		ca_key = None
		create = True

	if ca_key and ca_crt:
		if dump_publickey(FILETYPE_PEM, ca_key) != dump_publickey(FILETYPE_PEM, ca_crt.get_pubkey()):
			logger.warning("CA cert does not match CA key, creating new CA cert")
			renew = True
		else:
			not_after = ca_crt.get_notAfter()
			if not_after:
				enddate = datetime.datetime.strptime(not_after.decode("utf-8"), "%Y%m%d%H%M%SZ")
				diff = (enddate - datetime.datetime.now()).days

				logger.info("CA '%s' will expire in %d days", ca_crt.get_subject().CN, diff)
				if diff <= config.ssl_ca_cert_renew_days:
					logger.notice("CA '%s' will expire in %d days, renewing", ca_crt.get_subject().CN, diff)
					renew = True

	if create or renew:
		ca_subject = get_ca_subject()
		current_ca_subject = {}
		if os.path.exists(config.ssl_ca_cert):
			try:
				current_ca_subject = subject_to_dict(load_ca_cert().get_subject())
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to load CA cert: %s", err, exc_info=True)

		if current_ca_subject and ca_subject != current_ca_subject:
			logger.warning(
				"The subject of the CA has change from %r to %r."
				" If this change is intended, please delete"
				" the current CA certificate '%s' and restart opsiconfd."
				" Caution, clients that trust an opsi CA with the previous subject"
				" will not trust the CA with the changed subject!",
				current_ca_subject,
				ca_subject,
				config.ssl_ca_cert,
			)
			ca_subject = current_ca_subject

		cur_ca_key = None
		if renew:
			logger.notice("Renewing opsi CA")
			cur_ca_key = load_ca_key()
		else:
			logger.notice("Creating opsi CA")

		(ca_crt, ca_key) = create_ca(
			subject=ca_subject,
			valid_days=config.ssl_ca_cert_valid_days,
			key=cur_ca_key,
			permitted_domains=config.ssl_ca_permitted_domains or None,
		)
		if not cur_ca_key:
			store_ca_key(ca_key)
		store_ca_cert(ca_crt)
		install_ca(ca_crt)
		return True

	logger.info("CA is up to date")
	return False


def setup_ca() -> bool:
	server_role = opsi_config.get("host", "server-role")
	if config.ssl_ca_key == config.ssl_ca_cert:
		raise ValueError("CA key and cert cannot be stored in the same file")

	for name in ("opsi-ca-cert.srl", "opsi-ca.srl"):
		ca_srl = os.path.join(os.path.dirname(config.ssl_ca_key), name)
		if os.path.exists(ca_srl):
			# Remove obsolete file
			os.remove(ca_srl)

	if server_role == "configserver":
		return configserver_setup_ca()
	if server_role == "depotserver":
		return depotserver_setup_ca()

	raise ValueError(f"Invalid server role: {server_role}")


def validate_cert(cert: X509, ca_cert: X509 | None = None) -> None:
	"""Will throw a X509StoreContextError if cert is invalid"""
	store = X509Store()

	if os.path.exists(config.ssl_trusted_certs):
		with open(config.ssl_trusted_certs, "r", encoding="utf-8") as file:
			for match in finditer(r"(-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+)", file.read(), DOTALL):
				try:
					store.add_cert(load_certificate(FILETYPE_PEM, match.group(1).encode("ascii")))
				except Exception as err:  # pylint: disable=broad-except
					logger.error("Failed to load certificate from %r: %s", config.ssl_trusted_certs, err, exc_info=True)

	if ca_cert:
		store.add_cert(ca_cert)

	store_ctx = X509StoreContext(store, cert)
	store_ctx.verify_certificate()

	if ca_cert:
		ca_cert_not_before = ca_cert.get_notBefore()
		cert_not_before = cert.get_notBefore()
		if ca_cert_not_before and cert_not_before:
			dt_ca_cert_not_before = datetime.datetime.strptime(ca_cert_not_before.decode("utf-8"), "%Y%m%d%H%M%SZ")
			dt_cert_not_before = datetime.datetime.strptime(cert_not_before.decode("utf-8"), "%Y%m%d%H%M%SZ")
			if dt_ca_cert_not_before > dt_cert_not_before:
				raise X509StoreContextError(  # type: ignore[call-arg]
					message=f"CA is not valid before {dt_ca_cert_not_before} but certificate is valid before {dt_cert_not_before}",
					errors=[],
					certificate=ca_cert,
				)


def opsi_ca_is_self_signed(ca_cert: X509 | None = None) -> bool:
	ca_cert = ca_cert or load_ca_cert()
	return ca_cert.get_issuer().CN == ca_cert.get_subject().CN


def setup_server_cert(force_new: bool = False) -> bool:  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
	logger.info("Checking server cert")
	server_role = opsi_config.get("host", "server-role")
	if server_role not in ("configserver", "depotserver"):
		raise ValueError(f"Invalid server role: {server_role}")

	if config.ssl_server_key == config.ssl_server_cert:
		raise ValueError("SSL server key and cert cannot be stored in the same file")

	ca_cert = load_ca_cert()
	if not opsi_ca_is_self_signed():
		# opsi CA is not self-signed. opsi CA is an intermediate CA.
		try:
			validate_cert(ca_cert)
		except X509StoreContextError as err:
			issuer_subject = str(ca_cert.get_issuer()).split("'")[1]
			raise RuntimeError(
				f"Opsi CA is an intermediate CA, issuer is {issuer_subject!r}, {err}. "
				f"Make sure issuer certficate is in {config.ssl_trusted_certs!r} "
				"or specify a certificate database containing the issuer certificate via --ssl-trusted-certs."
			) from err

	create = force_new

	if (
		os.path.exists(os.path.join(os.path.dirname(config.ssl_server_cert), "opsiconfd.pem"))
		and os.path.basename(config.ssl_server_key) != "opsiconfd.pem"
		and os.path.basename(config.ssl_server_cert) != "opsiconfd.pem"
	):
		# Remove old default file
		os.remove(os.path.join(os.path.dirname(config.ssl_server_cert), "opsiconfd.pem"))

	server_cn = get_server_cn()
	if not os.path.exists(config.ssl_server_key) or not os.path.exists(config.ssl_server_cert):  # pylint: disable=too-many-nested-blocks
		create = True

	srv_key = None
	srv_crt = None
	if not create:
		try:
			srv_key = load_local_server_key()
		except PermissionError as err:
			logger.error(err, exc_info=True)
			raise
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Failed to load server key (%s), creating new server cert", err)
			create = True

	if not create:
		try:
			srv_crt = load_local_server_cert()
		except PermissionError as err:
			logger.error(err, exc_info=True)
			raise
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Failed to load server cert (%s), creating new server cert", err)
			create = True

	if not create and srv_key and srv_crt:
		if dump_publickey(FILETYPE_PEM, srv_key) != dump_publickey(FILETYPE_PEM, srv_crt.get_pubkey()):
			logger.warning("Server cert does not match server key, creating new server cert")
			create = True

	if not create and srv_crt:
		try:
			validate_cert(srv_crt, ca_cert)
		except X509StoreContextError as err:
			logger.warning("Failed to verify server cert with opsi CA (%s), creating new server cert", err)
			create = True

	if not create and srv_crt:
		not_after = srv_crt.get_notAfter()
		if not_after:
			enddate = datetime.datetime.strptime(not_after.decode("utf-8"), "%Y%m%d%H%M%SZ")
			diff = (enddate - datetime.datetime.now()).days

			logger.info("Server cert '%s' will expire in %d days", srv_crt.get_subject().CN, diff)
			if diff <= config.ssl_server_cert_renew_days:
				logger.notice("Server cert '%s' will expire in %d days, recreating", srv_crt.get_subject().CN, diff)
				create = True

	if not create and srv_crt:
		if server_cn != srv_crt.get_subject().CN:
			logger.notice("Server CN has changed from '%s' to '%s', creating new server cert", srv_crt.get_subject().CN, server_cn)
			create = True

	if not create and server_role == "configserver" and srv_crt:
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
						cert_ips.add(ip_address(addr).compressed)
				break
		hns = get_hostnames()
		if cert_hns != hns:
			logger.notice("Server hostnames have changed from %s to %s, creating new server cert", cert_hns, hns)
			create = True
		else:
			ips = get_ips()
			if cert_ips != ips:
				logger.notice("Server IPs have changed from %s to %s, creating new server cert", cert_ips, ips)
				create = True

	if create:
		logger.info("Creating new server cert")
		(srv_crt, srv_key, pem) = (None, None, None)
		if server_role == "configserver":
			# It is safer to create a new server cert with a new key pair
			# For cases where the server key got compromised
			(srv_crt, srv_key) = create_local_server_cert(renew=False)
		else:
			for attempt in (1, 2, 3, 4, 5):
				try:
					logger.info("Fetching certificate from config server (attempt #%d)", attempt)
					pem = get_unprotected_backend().host_getTLSCertificate(get_depotserver_id())  # pylint: disable=no-member
					break
				except RequestsConnectionError as err:
					if attempt == 5:
						raise
					logger.warning("Failed to fetch certificate from config server: %s, retrying in 5 seconds", err)
					time.sleep(5)
			if pem:
				srv_crt = load_certificate(FILETYPE_PEM, pem)
				srv_key = load_privatekey(FILETYPE_PEM, pem)

		if srv_key:
			store_local_server_key(srv_key)
		if srv_crt:
			serial = ":".join((f"{srv_crt.get_serial_number():x}").zfill(36)[i : i + 2] for i in range(0, 36, 2))
			logger.info("Storing new server cert with serial %s", serial)
			store_local_server_cert(srv_crt)
		return True

	logger.info("Server cert is up to date")
	return False


def setup_ssl() -> None:
	logger.info("Setup ssl")
	server_role = opsi_config.get("host", "server-role")
	force_new_server_cert = False
	if "opsi_ca" not in config.skip_setup:
		# Create new server cert if CA was created / renewed
		force_new_server_cert = setup_ca()
	if "server_cert" not in config.skip_setup:
		setup_server_cert(force_new_server_cert)
	if server_role == "configserver":
		# Read CA key as root to fill key cache
		# so run_as_user can use key from cache
		load_ca_key()


def get_cert_info(cert: X509, renew_days: int) -> dict[str, Any]:
	alt_names = ""
	for idx in range(0, cert.get_extension_count()):
		if cert.get_extension(idx).get_short_name() == b"subjectAltName":
			alt_names = str(cert.get_extension(idx))

	dt_not_before = None
	dt_not_after = None
	expires_in_days = 0
	not_before = cert.get_notBefore()
	not_after = cert.get_notAfter()
	if not_before and not_after:
		dt_not_before = datetime.datetime.strptime(not_before.decode("utf-8"), "%Y%m%d%H%M%SZ")
		dt_not_after = datetime.datetime.strptime(not_after.decode("utf-8"), "%Y%m%d%H%M%SZ")
		expires_in_days = (dt_not_after - datetime.datetime.now()).days

	return {
		"issuer": cert.get_issuer(),
		"subject": cert.get_subject(),
		"serial_number": ":".join((f"{cert.get_serial_number():x}").zfill(36)[i : i + 2] for i in range(0, 36, 2)).upper(),
		"fingerprint_sha1": cert.digest("sha1").decode("ascii"),
		"fingerprint_sha256": cert.digest("sha256").decode("ascii"),
		"not_before": dt_not_before,
		"not_after": dt_not_after,
		"expires_in_days": expires_in_days,
		"renewal_in_days": expires_in_days - renew_days,
		"alt_names": alt_names,
	}


def get_ca_cert_info() -> dict[str, Any]:
	return get_cert_info(load_ca_cert(), config.ssl_ca_cert_renew_days)


def get_server_cert_info() -> dict[str, Any]:
	return get_cert_info(load_local_server_cert(), config.ssl_server_cert_renew_days)
