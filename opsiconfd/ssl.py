# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.ssl
"""

from __future__ import annotations

import datetime
import os
import re
import shutil
import socket
import threading
import time
from contextlib import nullcontext
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from re import DOTALL, finditer
from socket import gethostbyaddr
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import verification  # type: ignore[attr-defined]
from opsicommon.server.rights import DirPermission, FilePermission, PermissionRegistry, set_rights
from opsicommon.ssl import (
	as_pem,
	create_ca,
	create_server_cert,
	create_server_cert_signing_request,
	install_ca,
	is_self_signed,
	load_key,
	x509_name_to_dict,
)
from requests.exceptions import ConnectionError as RequestsConnectionError

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.config import (
	CA_KEY_DEFAULT_PASSPHRASE,
	FQDN,
	SERVER_KEY_DEFAULT_PASSPHRASE,
	config,
	get_depotserver_id,
	get_server_role,
	opsi_config,
)
from opsiconfd.letsencrypt import perform_certificate_signing_request
from opsiconfd.logging import logger
from opsiconfd.utils import get_ip_addresses

if TYPE_CHECKING:
	from opsicommon.client.opsiservice import ServiceClient

	from opsiconfd.backend.rpc.main import Backend


def get_ips(public_only: bool = False) -> set[str]:
	"""
	Get all IP addresses of the host.
	If public_only is True, only public IP addresses are returned.
	"""
	ips = {ip_address("127.0.0.1"), ip_address("::1")}
	for addr in get_ip_addresses():
		if addr["family"] in ("ipv4", "ipv6") and addr["address"] not in ips:
			if addr["address"].startswith("fe80"):
				continue
			try:
				ips.add(ip_address(addr["address"]))
			except ValueError as err:
				logger.warning(err)
	for san in config.ssl_server_cert_sans:
		try:
			ips.add(ip_address(san))
		except ValueError:
			pass

	return {ip.compressed for ip in ips if not public_only or not ip.is_private}


def get_server_cn() -> str:
	"""
	Get the common name for the server certificate.
	"""
	return opsi_config.get("host", "id")


def get_hostnames() -> set[str]:
	"""
	Get all hostnames of the host.
	"""
	names = {"localhost", FQDN, get_server_cn()}
	for addr in get_ips():
		try:
			(hostname, aliases, _addr) = gethostbyaddr(addr)
			names.add(hostname)
			for alias in aliases:
				names.add(alias)
		except socket.error as err:
			logger.info("No hostname for %s: %s", addr, err)
	for san in config.ssl_server_cert_sans:
		try:
			ip_address(san)
		except ValueError:
			names.add(san)
	return names


def get_domain() -> str:
	"""
	Get the DNS domain of the host.
	"""
	return ".".join(FQDN.split(".")[1:])


def setup_ssl_file_permissions() -> None:
	"""
	Set the permissions for the SSL files.
	"""
	admin_group = opsi_config.get("groups", "admingroup")
	permissions = (
		DirPermission("/etc/opsi/ssl", config.run_as_user, admin_group, 0o600, 0o750, recursive=False),
		FilePermission(config.ssl_ca_cert, config.run_as_user, admin_group, 0o644),
		FilePermission(config.ssl_ca_key, config.run_as_user, admin_group, 0o600),
		FilePermission(config.ssl_server_cert, config.run_as_user, admin_group, 0o640),
		FilePermission(config.ssl_server_key, config.run_as_user, admin_group, 0o640),
	)
	PermissionRegistry().register_permission(*permissions)
	for permission in permissions:
		set_rights(permission.path)


def get_not_before_and_not_after(
	cert: x509.Certificate,
) -> tuple[datetime.datetime, int, datetime.datetime, int]:
	"""
	Get the not before and not after dates of a certificate.
	Returns the dates as datetime and the number of days remaining until the dates occur.
	"""
	return (
		cert.not_valid_before_utc,
		(cert.not_valid_before_utc - datetime.datetime.now(tz=datetime.timezone.utc)).days,
		cert.not_valid_after_utc,
		(cert.not_valid_after_utc - datetime.datetime.now(tz=datetime.timezone.utc)).days,
	)


def get_cert_info(cert: x509.Certificate, renew_days: int | None = None) -> dict[str, Any]:
	"""
	Get information about a certificate.
	"""
	alt_names = [extension for extension in cert.extensions if extension.oid == x509.OID_SUBJECT_ALTERNATIVE_NAME]
	alt_names_str = (
		[str(a) for a in alt_names[0].value.get_values_for_type(x509.DNSName) + alt_names[0].value.get_values_for_type(x509.IPAddress)]
		if alt_names
		else []
	)

	dt_not_before, _not_before_days, dt_not_after, not_after_days = get_not_before_and_not_after(cert)

	return {
		"issuer": x509_name_to_dict(cert.issuer),
		"subject": x509_name_to_dict(cert.subject),
		"serial_number": ":".join((f"{cert.serial_number:x}").zfill(40)[i : i + 2] for i in range(0, 40, 2)).upper(),
		"fingerprint_sha1": ":".join(cert.fingerprint(hashes.SHA1()).hex()[i : i + 2] for i in range(0, 40, 2)).upper(),
		"fingerprint_sha256": ":".join(cert.fingerprint(hashes.SHA256()).hex()[i : i + 2] for i in range(0, 64, 2)).upper(),
		"not_before": dt_not_before,
		"not_after": dt_not_after,
		"expires_in_days": not_after_days,
		"renewal_in_days": None if renew_days is None else ((not_after_days or 0) - renew_days),
		"alt_names": alt_names_str,
	}


def get_ca_certs_info() -> list[dict[str, Any]]:
	"""
	Get information about all CA certificates.
	"""
	return [
		get_cert_info(
			cert,
			renew_days=config.ssl_ca_cert_renew_days
			if cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == config.ssl_ca_subject_cn
			else None,
		)
		for cert in get_ca_certs()
	]


def get_opsi_ca_cert_info() -> dict[str, Any]:
	"""
	Get information about the opsi CA certificate.
	"""
	return get_cert_info(load_opsi_ca_cert(), config.ssl_ca_cert_renew_days)


def get_server_cert_info() -> dict[str, Any]:
	"""
	Get information about the server certificate.
	"""
	return get_cert_info(load_local_server_cert(), config.ssl_server_cert_renew_days)


def store_key(key_file: str | Path, passphrase: str, key: rsa.RSAPrivateKey) -> None:
	"""
	Save a private key to a file.
	"""
	if not isinstance(key_file, Path):
		key_file = Path(key_file)

	key_file.unlink(missing_ok=True)
	key_file.parent.mkdir(parents=True, exist_ok=True)
	key_file.write_text(as_pem(key, passphrase), encoding="utf-8")
	setup_ssl_file_permissions()


def store_cert(cert_file: str | Path, cert: x509.Certificate, keep_others: bool = False) -> None:
	"""
	Save a certificate to a file.
	If keep_others is True, existing certificates with different common names are kept.
	"""
	if not isinstance(cert_file, Path):
		cert_file = Path(cert_file)

	cert_file.parent.mkdir(parents=True, exist_ok=True)
	certs = []
	if cert_file.exists() and keep_others:
		certs = [
			c
			for c in load_certs(cert_file)
			if c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
			!= cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
		]
	certs.append(cert)
	cert_file.write_text("".join(as_pem(c) for c in certs), encoding="utf-8")
	setup_ssl_file_permissions()
	_clear_ca_certs_cache()


def load_certs(cert_file: Path | str) -> list[x509.Certificate]:
	"""
	Load all certificates from a file.
	"""
	if not isinstance(cert_file, Path):
		cert_file = Path(cert_file)

	if not cert_file.exists():
		logger.warning("Certificate file '%s' not found", cert_file)
		return []

	certs = []
	data = cert_file.read_text(encoding="utf-8")
	for match in re.finditer(r"(-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+)", data, re.DOTALL):
		try:
			certs.append(x509.load_pem_x509_certificate(match.group(1).encode("utf-8")))
		except ValueError as err:
			logger.warning(err, exc_info=True)
	return certs


def load_cert(cert_file: Path | str, subject_cn: str | None = None) -> x509.Certificate:
	"""
	Load a certificate from a file.
	If subject_cn is given, only the certificate with the matching common name is returned.
	IF subject_cn is not given, the first certificate is returned.
	"""
	if not isinstance(cert_file, Path):
		cert_file = Path(cert_file)

	for cert in load_certs(cert_file):
		if not subject_cn or cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == subject_cn:
			return cert

	raise RuntimeError(f"Failed to load {repr(subject_cn) if subject_cn else 'cert'} from '{cert_file}': Not found")


def store_opsi_ca_key(ca_key: rsa.RSAPrivateKey) -> None:
	"""
	Save the opsi CA key to the configured file.
	"""
	store_key(config.ssl_ca_key, config.ssl_ca_key_passphrase, ca_key)


def load_opsi_ca_key() -> rsa.RSAPrivateKey:
	"""
	Load the opsi CA key from the configured file.
	"""
	try:
		return load_key(config.ssl_ca_key, config.ssl_ca_key_passphrase)
	except RuntimeError:
		if config.ssl_ca_key_passphrase == CA_KEY_DEFAULT_PASSPHRASE:
			raise
		# Wrong passphrase, try to load with default passphrase
		key = load_key(config.ssl_ca_key, CA_KEY_DEFAULT_PASSPHRASE)
		# Store with configured passphrase
		store_opsi_ca_key(key)
		return key


def store_opsi_ca_cert(ca_cert: x509.Certificate) -> None:
	"""
	Save the opsi CA certificate to the configured file.
	"""
	store_cert(config.ssl_ca_cert, ca_cert, keep_others=True)


_check_certs_modified_lock = threading.Lock()
_opsi_ca_cert_modification_date = 0.0


def _clear_ca_certs_cache(lock: bool = True) -> None:
	"""
	Clear the cache for the CA certificates.
	"""
	with _check_certs_modified_lock if lock else nullcontext():  # type: ignore[attr-defined]
		global _opsi_ca_cert_modification_date
		_opsi_ca_cert_modification_date = 0.0
		_load_opsi_ca_cert.cache_clear()
		_get_opsi_ca_cert_as_pem.cache_clear()
		_get_ca_certs.cache_clear()
		_get_ca_certs_as_pem.cache_clear()


def _check_certs_modified() -> bool:
	"""
	Check if the stored CA certificates have been modified.
	"""
	global _opsi_ca_cert_modification_date

	with _check_certs_modified_lock:
		m_date = Path(config.ssl_ca_cert).stat().st_mtime if os.path.exists(config.ssl_ca_cert) else 0.0
		if m_date == _opsi_ca_cert_modification_date:
			return False

		_clear_ca_certs_cache(lock=False)

		_opsi_ca_cert_modification_date = m_date
		return True


@lru_cache
def _load_opsi_ca_cert() -> x509.Certificate:
	"""
	Load the opsi CA certificate from the configured file (cached).
	"""
	return load_cert(config.ssl_ca_cert, subject_cn=config.ssl_ca_subject_cn)


def load_opsi_ca_cert() -> x509.Certificate:
	"""
	Load the opsi CA certificate from the configured file.
	"""
	_check_certs_modified()
	return _load_opsi_ca_cert()


@lru_cache
def _get_opsi_ca_cert_as_pem() -> str:
	"""
	Get the opsi CA certificate and return it in PEM format (cached).
	"""
	return as_pem(load_opsi_ca_cert())


def get_opsi_ca_cert_as_pem() -> str:
	"""
	Get the opsi CA certificate and return it in PEM format.
	"""
	_check_certs_modified()
	return _get_opsi_ca_cert_as_pem()


@lru_cache
def _get_ca_certs() -> list[x509.Certificate]:
	"""
	Get all CA certificates (cached).
	"""
	return load_certs(config.ssl_ca_cert)


def get_ca_certs() -> list[x509.Certificate]:
	"""
	Get all CA certificates.
	"""
	_check_certs_modified()
	return _get_ca_certs()


@lru_cache
def _get_ca_certs_as_pem() -> str:
	"""
	Get all CA certificates and return them in PEM format (cached).
	"""
	return "\n".join(as_pem(cert) for cert in get_ca_certs())


def get_ca_certs_as_pem() -> str:
	"""
	Get all CA certificates and return them in PEM format.
	"""
	_check_certs_modified()
	return _get_ca_certs_as_pem()


def store_local_server_key(srv_key: rsa.RSAPrivateKey) -> None:
	"""
	Save the server private key to the configured file.
	"""
	store_key(config.ssl_server_key, config.ssl_server_key_passphrase, srv_key)


def load_local_server_key() -> rsa.RSAPrivateKey:
	"""
	Load the server private key from the configured file.
	"""
	error: Exception | None = None
	# Try to load key with configured passphrase, default passphrase and unencrypted
	passphrases = [("configured", config.ssl_server_key_passphrase), ("no", None)]
	if config.ssl_server_key_passphrase != SERVER_KEY_DEFAULT_PASSPHRASE:
		passphrases.insert(1, ("default", SERVER_KEY_DEFAULT_PASSPHRASE))
	for idx, (passphrase_type, passphrase) in enumerate(passphrases):
		try:
			key = load_key(config.ssl_server_key, passphrase)
			if passphrase_type != "configured":
				# Store with configured passphrase
				store_local_server_key(key)
			return key
		except (RuntimeError, TypeError) as err:
			if not error:
				error = err
			next_passphrase_type = passphrases[idx + 1][0] if idx < len(passphrases) else None
			if next_passphrase_type:
				logger.warning(
					"Failed to load server key with %s passphrase (%s), retrying with %s passphrase",
					passphrase_type,
					str(err).rstrip("."),
					next_passphrase_type,
				)
	# Raise first error
	assert error
	raise error


def store_local_server_cert(server_cert: x509.Certificate) -> None:
	"""
	Save the server certificate to the configured file.
	"""
	store_cert(config.ssl_server_cert, server_cert)


def load_local_server_cert() -> x509.Certificate:
	"""
	Load the server certificate from the configured file.
	"""
	return load_cert(config.ssl_server_cert)


def create_local_server_cert(renew: bool = True) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
	"""
	Create or renew the server certificate.
	"""
	ca_key = load_opsi_ca_key()
	ca_cert = load_opsi_ca_cert()
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


def create_letsencrypt_certificate() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
	"""
	Create a server certificate with Let's Encrypt.
	"""
	ca_certs = get_ca_certs()
	server_cn = get_server_cn()
	contact_email = config.letsencrypt_contact_email or f"opsiconfd@{server_cn}"

	logger.notice("Requesting Let's Encrypt certificate for %r", server_cn)
	csr, key = create_server_cert_signing_request(
		subject={"CN": server_cn, "emailAddress": contact_email},
		ip_addresses=set(),
		hostnames=set(),
	)
	certificates = perform_certificate_signing_request(csr, contact_email)
	server_cert: x509.Certificate | None = None
	new_ca_certs = []
	for cert in certificates:
		cert_cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
		if not isinstance(cert_cn, str):
			cert_cn = cert_cn.decode("utf-8")
		if cert_cn == server_cn:
			server_cert = cert
		elif not any(
			cur_cert for cur_cert in ca_certs if cert.subject == cur_cert.subject and cert.serial_number == cur_cert.serial_number
		):
			new_ca_certs.append(cert)

	if not server_cert:
		raise RuntimeError("Failed to get server certificate from Let's Encrypt")

	for cert in new_ca_certs:
		logger.info("Storing Let's Encrypt CA cert %s / %s", cert.subject, cert.serial_number)
		store_opsi_ca_cert(cert)

	return server_cert, key


def depotserver_setup_opsi_ca() -> bool:
	"""
	Setup the opsi CA on a depot server.
	"""
	logger.info("Updating CA cert from configserver")
	ca_crt = x509.load_pem_x509_certificate(get_unprotected_backend().getOpsiCACert().encode("utf-8"))
	store_opsi_ca_cert(ca_crt)
	install_ca(ca_crt)
	return False


def get_opsi_ca_subject() -> dict[str, str]:
	"""
	Get the subject for the opsi CA certificate.
	"""
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


def configserver_setup_opsi_ca() -> bool:
	"""
	Setup the opsi CA on a config server.
	"""
	logger.info("Checking opsi CA")

	create = False
	renew = False
	is_intermediate_ca = False
	cur_ca_key = None
	cur_ca_crt = None

	if not os.path.exists(config.ssl_ca_key):
		logger.info("opsi CA key file %r not found, creating new CA key and cert", config.ssl_ca_key)
		create = True
	elif not os.path.exists(config.ssl_ca_cert):
		logger.info("opsi CA cert file %r not found, creating new CA cert", config.ssl_ca_cert)
		renew = True
	else:
		try:
			cur_ca_key = load_opsi_ca_key()
			try:
				cur_ca_crt = load_opsi_ca_cert()
				is_intermediate_ca = not is_self_signed(cur_ca_crt)
			except Exception as err_cert:
				logger.warning("Failed to load opsi CA cert (%s), creating new CA cert", err_cert)
				renew = True
		except Exception as err_key:
			logger.warning("Failed to load opsi CA key (%s), creating new CA key and cert", err_key)
			create = True

	if cur_ca_key and cur_ca_crt:
		if cur_ca_key.public_key().public_bytes(
			encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1
		) != cur_ca_crt.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1):
			logger.warning("opsi CA cert does not match opsi  CA key, creating new opsi  CA cert")
			renew = True
		else:
			not_after_days = get_not_before_and_not_after(cur_ca_crt)[3]
			if not_after_days:
				logger.info(
					"opsi CA '%s' will expire in %d days",
					cur_ca_crt.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
					not_after_days,
				)
				if not_after_days <= config.ssl_ca_cert_renew_days:
					logger.notice(
						"opsi CA '%s' will expire in %d days, renewing",
						cur_ca_crt.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
						not_after_days,
					)
					renew = True

	if is_intermediate_ca and (create or renew):
		assert cur_ca_crt
		issuer_subject = cur_ca_crt.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
		raise RuntimeError(
			f"opsi CA needs to be {'renewed' if renew else 'recreated'} and is an intermediate CA (issuer={issuer_subject!r}). "
			f"Please update the current CA certificate '{config.ssl_ca_cert}' and key '{config.ssl_ca_key}' manually."
		)

	if create:
		for filename in (config.ssl_ca_cert, config.ssl_ca_key):
			if os.path.exists(filename) and os.stat(filename).st_size > 0:
				logger.info("Creating backup of %r", filename)
				try:
					backup = f"{filename}.bak"
					if os.path.exists(backup):
						os.remove(backup)
					shutil.copy(filename, backup)
					os.chmod(backup, 0o600)
				except Exception as err:
					logger.error("Failed to create backup of %r: %s", filename, err)

	if create or renew:
		ca_subject = get_opsi_ca_subject()
		current_ca_subject = {}
		if os.path.exists(config.ssl_ca_cert):
			try:
				current_ca_subject = x509_name_to_dict(load_opsi_ca_cert().subject)
			except Exception as err:
				logger.error("Failed to load opsi CA cert: %s", err, exc_info=True)

		if current_ca_subject and ca_subject != current_ca_subject:
			logger.warning(
				"The subject of the CA has changed from %r to %r."
				" If this change is intended, please delete"
				" the current CA certificate '%s' and restart opsiconfd."
				" Caution, clients that trust an opsi CA with the previous subject"
				" will not trust the CA with the changed subject!",
				current_ca_subject,
				ca_subject,
				config.ssl_ca_cert,
			)
			ca_subject = current_ca_subject

		if renew:
			logger.notice("Renewing opsi CA")
		else:
			logger.notice("Creating opsi CA")

		(ca_crt, ca_key) = create_ca(
			subject=ca_subject,
			valid_days=config.ssl_ca_cert_valid_days,
			key=cur_ca_key if renew else None,
			permitted_domains=config.ssl_ca_permitted_domains or None,
		)
		if create:
			store_opsi_ca_key(ca_key)
		store_opsi_ca_cert(ca_crt)
		install_ca(ca_crt)
		return True

	logger.info("opsi CA is up to date")
	return False


def setup_opsi_ca() -> bool:
	"""
	Setup the opsi CA.
	"""
	server_role = get_server_role()
	if config.ssl_ca_key == config.ssl_ca_cert:
		raise ValueError("CA key and cert cannot be stored in the same file")

	for name in ("opsi-ca-cert.srl", "opsi-ca.srl"):
		ca_srl = os.path.join(os.path.dirname(config.ssl_ca_key), name)
		if os.path.exists(ca_srl):
			# Remove obsolete file
			os.remove(ca_srl)

	if server_role == "configserver":
		return configserver_setup_opsi_ca()
	if server_role == "depotserver":
		return depotserver_setup_opsi_ca()

	raise ValueError(f"Invalid server role: {server_role}")


def get_trusted_certs() -> list[x509.Certificate]:
	"""
	Get trusted certificates from the configured file.
	"""
	ca_certs = []
	if os.path.exists(config.ssl_trusted_certs):
		with open(config.ssl_trusted_certs, "r", encoding="utf-8") as file:
			for match in finditer(r"(-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+)", file.read(), DOTALL):
				try:
					ca_certs.append(x509.load_pem_x509_certificate(match.group(1).encode("ascii")))
				except Exception as err:
					logger.error("Failed to load certificate from %r: %s", config.ssl_trusted_certs, err, exc_info=True)
	return ca_certs


def validate_cert(cert: x509.Certificate, ca_certs: list[x509.Certificate] | x509.Certificate) -> None:
	"""
	Validate a certificate against one or a list of CA certificates.
	"""
	if not isinstance(ca_certs, list):
		ca_certs = [ca_certs]

	issuer_cert = None
	for icert in ca_certs:
		logger.debug("Checking if %r is issuer of %r", icert.subject, cert.subject)
		if icert.subject == cert.issuer:
			try:
				logger.debug("Checking if %r is directly issued by %r", cert.subject, icert.subject)
				cert.verify_directly_issued_by(icert)
				issuer_cert = icert
				break
			except Exception as err:
				logger.debug("%r is not directly issued by %r: %s", cert.subject, icert.subject, err)
				continue
	if not issuer_cert:
		raise verification.VerificationError("Failed to verify certificate")

	dt_ca_cert_not_before = get_not_before_and_not_after(issuer_cert)[0]
	dt_cert_not_before = get_not_before_and_not_after(cert)[0]
	if dt_ca_cert_not_before and dt_cert_not_before and dt_ca_cert_not_before > dt_cert_not_before:
		raise verification.VerificationError(
			f"CA is not valid before {dt_ca_cert_not_before} but certificate is valid before {dt_cert_not_before}"
		)

	is_ca = any(ext for ext in cert.extensions if ext.oid == x509.OID_BASIC_CONSTRAINTS and ext.value.ca)
	if is_ca:
		return

	# Extended validation for server certificates
	store = verification.Store([issuer_cert])
	builder = verification.PolicyBuilder().store(store)
	common_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
	if not isinstance(common_name, str):
		common_name = common_name.decode("utf-8")
	verifier = builder.build_server_verifier(x509.DNSName(common_name))
	verifier.verify(cert, [])


def opsi_ca_is_self_signed() -> bool:
	"""
	Check if the opsi CA is self-signed.
	"""
	return is_self_signed(load_opsi_ca_cert())


def check_intermediate_ca(ca_cert: x509.Certificate) -> bool:
	"""
	Check if the opsi CA is an intermediate CA.
	"""
	if is_self_signed(ca_cert):
		return False

	# opsi CA is not self-signed. opsi CA is an intermediate CA.
	ca_certs = [
		cert
		for cert in load_certs(config.ssl_ca_cert)
		if cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value != config.ssl_ca_subject_cn
	]
	try:
		validate_cert(ca_cert, ca_certs + get_trusted_certs())
	except verification.VerificationError as err:
		issuer_subject = ca_cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
		raise RuntimeError(
			f"opsi CA is an intermediate CA, issuer is {issuer_subject!r}, {err}. "
			f"Make sure issuer certficate is in {config.ssl_ca_cert!r} or {config.ssl_trusted_certs!r} "
			"or specify a certificate database containing the issuer certificate via --ssl-trusted-certs."
		) from err
	return True


def fetch_server_cert(backend: ServiceClient | Backend, server_id: str | None = None) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
	"""
	Fetch a new server certificate from the opsi service.
	"""
	pem = backend.host_getTLSCertificate(server_id or get_depotserver_id())  # type: ignore[union-attr]
	pem_bytes = pem.encode("utf-8")
	srv_crt = x509.load_pem_x509_certificate(pem_bytes)
	srv_key = serialization.load_pem_private_key(pem_bytes, password=None)
	if not isinstance(srv_key, rsa.RSAPrivateKey):
		raise ValueError(f"Not a RSA private key, but {srv_key.__class__.__name__}")
	return (srv_crt, srv_key)


def setup_server_cert(force_new: bool = False) -> bool:
	"""
	Setup the server certificate.
	"""
	logger.info("Checking server cert")
	server_role = get_server_role()
	if server_role not in ("configserver", "depotserver"):
		raise ValueError(f"Invalid server role: {server_role}")

	if config.ssl_server_key == config.ssl_server_cert:
		raise ValueError("SSL server key and cert cannot be stored in the same file")

	ca_cert: x509.Certificate | None = None
	if config.ssl_server_cert_type == "opsi-ca":
		ca_cert = load_opsi_ca_cert()
		check_intermediate_ca(ca_cert)

	create = force_new

	if (
		os.path.exists(os.path.join(os.path.dirname(config.ssl_server_cert), "opsiconfd.pem"))
		and os.path.basename(config.ssl_server_key) != "opsiconfd.pem"
		and os.path.basename(config.ssl_server_cert) != "opsiconfd.pem"
	):
		# Remove old default file
		os.remove(os.path.join(os.path.dirname(config.ssl_server_cert), "opsiconfd.pem"))

	server_cn = get_server_cn()
	if not os.path.exists(config.ssl_server_key) or not os.path.exists(config.ssl_server_cert):
		create = True

	srv_key = None
	srv_crt = None
	crt_err: str | None = None
	if not create:
		try:
			srv_key = load_local_server_key()
		except PermissionError as err:
			logger.error(err, exc_info=True)
			raise
		except Exception as err:
			crt_err = f"Failed to load server key ({err})"
			logger.warning("%s, new server cert needed", crt_err)
			create = True

	if not create:
		try:
			srv_crt = load_local_server_cert()
		except PermissionError as err:
			logger.error(err, exc_info=True)
			raise
		except Exception as err:
			crt_err = f"Failed to load server cert ({err})"
			logger.warning("%s, new server cert needed", crt_err)
			create = True

	if srv_crt and srv_crt.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "uib opsi CA":
		logger.warning(
			"Server cert is issued by 'uib opsi CA', keeping cert. "
			f"Please delete server cert '{config.ssl_ca_cert}' and key '{config.ssl_ca_key}' manually to return to a local certificate."
		)
		return False

	if not create and srv_key and srv_crt:
		if srv_key.public_key().public_bytes(
			encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1
		) != srv_crt.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1):
			crt_err = "Server cert does not match server key"
			logger.warning("%s, new server cert needed", crt_err)
			create = True

	if not create and srv_crt:
		try:
			validate_cert(srv_crt, get_ca_certs())
		except verification.VerificationError as err:
			crt_err = f"Failed to verify server cert with CA certs ({err})"
			logger.warning("%s, new server cert needed", crt_err)
			create = True

	ssl_server_cert_renew_days = config.ssl_server_cert_renew_days
	if config.ssl_server_cert_type == "letsencrypt" and ssl_server_cert_renew_days > 30:
		logger.warning("Setting ssl-server-cert-renew-days to 30, which is the maximum values for Let's Encrypt certificates")
		ssl_server_cert_renew_days = 30

	if not create and srv_crt:
		not_after_days = get_not_before_and_not_after(srv_crt)[3]
		if not_after_days:
			common_name = srv_crt.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
			logger.info("Server cert '%s' will expire in %d days", common_name, not_after_days)
			if not_after_days <= ssl_server_cert_renew_days:
				crt_err = f"Server cert '{str(common_name)}' will expire in {not_after_days} days"
				logger.notice("%s, new server cert needed", crt_err)
				create = True

	if not create and srv_crt:
		common_name = srv_crt.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
		if server_cn != common_name:
			crt_err = f"Server CN has changed from '{str(common_name)}' to '{server_cn}'"
			logger.notice("%s, new server cert needed", crt_err)
			create = True

	if not create and server_role == "configserver" and srv_crt:
		cert_hns = set()
		cert_ips = set()
		alt_names = [extension for extension in srv_crt.extensions if extension.oid == x509.OID_SUBJECT_ALTERNATIVE_NAME]
		if alt_names:
			cert_hns = {str(v) for v in alt_names[0].value.get_values_for_type(x509.DNSName)}
			cert_ips = {str(v) for v in alt_names[0].value.get_values_for_type(x509.IPAddress)}

		if config.ssl_server_cert_type == "letsencrypt":
			hns = {server_cn}
		else:
			hns = get_hostnames()

		if cert_hns != hns:
			crt_err = f"Server hostnames have changed from {cert_hns} to {hns}"
			logger.notice("%s, new server cert needed", crt_err)
			create = True
		else:
			ips = set() if config.ssl_server_cert_type == "letsencrypt" else get_ips()

			if cert_ips != ips:
				crt_err = f"Server IPs have changed from {cert_ips} to {ips}"
				logger.notice("%s, new server cert needed", crt_err)
				create = True

	if create:
		if config.ssl_server_cert_type == "unmanaged":
			raise RuntimeError(
				f"{crt_err}. New server cert is needed, but ssl-server-cert-type is 'unmanaged'. Please create a new server cert manually."
			)

		logger.info("Creating new server cert")
		(srv_crt, srv_key) = (None, None)
		if config.ssl_server_cert_type == "letsencrypt":
			(srv_crt, srv_key) = create_letsencrypt_certificate()
		else:
			if server_role == "configserver":
				# It is safer to create a new server cert with a new key pair
				# For cases where the server key got compromised
				(srv_crt, srv_key) = create_local_server_cert(renew=False)
			else:
				for attempt in (1, 2, 3, 4, 5):
					try:
						logger.info("Fetching certificate from config server (attempt #%d)", attempt)
						(srv_crt, srv_key) = fetch_server_cert(get_unprotected_backend())
						break
					except RequestsConnectionError as err:
						if attempt == 5:
							raise
						logger.warning("Failed to fetch certificate from config server: %s, retrying in 5 seconds", err)
						time.sleep(5)

		if srv_key:
			store_local_server_key(srv_key)
		if srv_crt:
			serial = ":".join((f"{srv_crt.serial_number:x}").zfill(40)[i : i + 2] for i in range(0, 40, 2))
			logger.info("Storing new server cert with serial %s", serial)
			store_local_server_cert(srv_crt)
		return True

	logger.info("Server cert is up to date")
	return False


def setup_ssl() -> bool:
	"""
	Setup SSL.
	"""
	if "opsi_ca" in config.skip_setup and "server_cert" in config.skip_setup:
		return False

	logger.info("Setup SSL")
	force_new_server_cert = False
	changed = False
	if "opsi_ca" not in config.skip_setup:
		# Create new server cert if opsi CA was created / renewed
		force_new_server_cert = setup_opsi_ca()
	if "server_cert" not in config.skip_setup:
		changed = setup_server_cert(force_new_server_cert)
	return changed
