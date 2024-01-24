# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
ssl tests
"""
import datetime
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

import mock  # type: ignore[import]
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import verification  # type: ignore[attr-defined]

import opsiconfd.ssl
from opsiconfd.application.main import get_ssl_ca_cert
from opsiconfd.config import config
from opsiconfd.ssl import (
	CA_KEY_DEFAULT_PASSPHRASE,
	SERVER_KEY_DEFAULT_PASSPHRASE,
	as_pem,
	create_ca,
	create_local_server_cert,
	get_ca_cert_info,
	get_hostnames,
	get_ips,
	get_server_cert_info,
	load_ca_cert,
	load_ca_key,
	load_cert,
	load_certs,
	load_key,
	load_local_server_cert,
	load_local_server_key,
	setup_ca,
	setup_server_cert,
	store_ca_cert,
	store_ca_key,
	store_cert,
	store_local_server_cert,
	store_local_server_key,
	validate_cert,
	x509_name_to_dict,
)

from .utils import get_config


def test_get_ips() -> None:
	ips = get_ips()
	assert "::1" in ips
	assert "0:0:0:0:0:0:0:1" not in ips
	assert "127.0.0.1" in ips


def test_get_hostnames() -> None:
	hns = get_hostnames()
	assert "localhost" in hns


def test_ssl_ca_cert_and_key_in_different_files() -> None:
	config.ssl_ca_cert = config.ssl_ca_key = "opsi-ca.pem"
	with pytest.raises(ValueError, match=r".*cannot be stored in the same file.*"):
		setup_ca()


def test_ssl_server_cert_and_key_in_different_files() -> None:
	config.ssl_server_cert = config.ssl_server_key = "opsiconfd.pem"
	with pytest.raises(ValueError, match=r".*cannot be stored in the same file.*"):
		setup_server_cert()


def test_store_load_cert(tmpdir: Path) -> None:
	ssl_ca_cert = tmpdir / "opsi-ca-cert.pem"
	ssl_ca_key = tmpdir / "opsi-ca-key.pem"
	config.ssl_ca_cert = str(ssl_ca_cert)
	config.ssl_ca_key = str(ssl_ca_key)
	config.ssl_ca_key_passphrase = "secret"
	with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
		with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmpdir), "echo")):
			# Test one cert in file
			setup_ca()

			certs = load_certs(ssl_ca_cert)
			assert len(certs) == 1
			assert certs[0].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi CA"
			assert load_ca_cert().subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi CA"
			assert (
				load_cert(ssl_ca_cert, subject_cn="opsi CA").subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi CA"
			)

			# Add another cert to file
			(ca_crt, _ca_key) = create_ca(subject={"CN": "other CA"}, valid_days=100)
			store_cert(cert_file=ssl_ca_cert, cert=ca_crt, keep_others=True)
			certs = load_certs(ssl_ca_cert)
			assert len(certs) == 2
			assert certs[0].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi CA"
			assert certs[1].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "other CA"
			assert load_ca_cert().subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi CA"
			assert (
				load_cert(ssl_ca_cert, subject_cn="other CA").subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
				== "other CA"
			)

			# Replace certs in file
			store_cert(cert_file=ssl_ca_cert, cert=ca_crt, keep_others=False)
			certs = load_certs(ssl_ca_cert)
			assert len(certs) == 1
			assert certs[0].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "other CA"
			with pytest.raises(RuntimeError, match="Failed to load 'opsi CA' from.*"):
				load_ca_cert()
			assert (
				load_cert(ssl_ca_cert, subject_cn="other CA").subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
				== "other CA"
			)

			# Test keep other CA
			setup_ca()
			certs = load_certs(ssl_ca_cert)
			assert len(certs) == 2
			assert certs[0].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "other CA"
			assert certs[1].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi CA"
			cert = load_ca_cert()
			assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi CA"

			response = get_ssl_ca_cert(None)  # type: ignore
			assert response.body.decode("ascii") == "".join(as_pem(c) for c in certs)


def test_create_ca(tmpdir: Path) -> None:
	ssl_ca_cert = tmpdir / "opsi-ca-cert.pem"
	ssl_ca_key = tmpdir / "opsi-ca-key.pem"
	config.ssl_ca_cert = str(ssl_ca_cert)
	config.ssl_ca_key = str(ssl_ca_key)
	# config.run_as_user = getpass.getuser()
	config.ssl_ca_key_passphrase = "secret"
	with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
		with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmpdir), "echo")):
			setup_ca()
			assert "-----BEGIN CERTIFICATE-----" in ssl_ca_cert.read_text(encoding="utf-8")
			assert "-----BEGIN ENCRYPTED PRIVATE KEY-----" in ssl_ca_key.read_text(encoding="utf-8")
			key = load_key(config.ssl_ca_key, "secret")
			assert isinstance(key, rsa.RSAPrivateKey)
			key = load_ca_key()
			assert isinstance(key, rsa.RSAPrivateKey)
			with pytest.raises(RuntimeError, match=r".*Bad decrypt. Incorrect password\?.*"):
				load_key(config.ssl_ca_key, "wrong")
			cert = load_ca_cert()
			assert isinstance(cert, x509.Certificate)
			cert = load_cert(config.ssl_ca_cert)
			assert isinstance(cert, x509.Certificate)

			ca_crt = load_ca_cert()
			assert (ca_crt.not_valid_after_utc - datetime.datetime.now(tz=datetime.timezone.utc)).days == config.ssl_ca_cert_valid_days - 1

			info = get_ca_cert_info()

			out = subprocess.check_output(["openssl", "x509", "-noout", "-text", "-in", config.ssl_ca_cert]).decode("utf-8")
			match = re.search(r"Serial Number:\s*\n\s*([a-f0-9:]+)", out)
			assert match
			openssl_serial = match.group(1)
			assert info["serial_number"].lstrip("0") == openssl_serial.lstrip("0").upper()

			out = subprocess.check_output(["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-in", config.ssl_ca_cert]).decode(
				"utf-8"
			)
			match = re.search(r"sha256 Fingerprint=([A-F0-9:]+)", out)
			assert match
			openssl_fingerprint_sha256 = match.group(1)
			assert info["fingerprint_sha256"].lstrip("0") == openssl_fingerprint_sha256.lstrip("0").upper()

			out = subprocess.check_output(["openssl", "x509", "-noout", "-fingerprint", "-sha1", "-in", config.ssl_ca_cert]).decode("utf-8")
			match = re.search(r"sha1 Fingerprint=([A-F0-9:]+)", out)
			assert match
			openssl_fingerprint_sha1 = match.group(1)
			assert info["fingerprint_sha1"].lstrip("0") == openssl_fingerprint_sha1.lstrip("0").upper()


def test_create_ca_permitted_domains(tmpdir: Path) -> None:
	ssl_ca_cert = tmpdir / "opsi-ca-cert.pem"
	ssl_ca_key = tmpdir / "opsi-ca-key.pem"
	ssl_ca_permitted_domains = ["mycompany1.tld", "mycompany2.tld"]
	with (
		mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None),
		mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmpdir), "echo")),
		get_config(
			{
				"ssl_ca_key_passphrase": "secret",
				"ssl_ca_cert": str(ssl_ca_cert),
				"ssl_ca_key": str(ssl_ca_key),
				"ssl_ca_permitted_domains": ssl_ca_permitted_domains,
			}
		),
	):
		setup_ca()
		ca_cert = load_ca_cert()

		name_constraints = [extension for extension in ca_cert.extensions if extension.oid == x509.OID_NAME_CONSTRAINTS][0]
		assert name_constraints.critical
		assert name_constraints.value.permitted_subtrees[0].value == ssl_ca_permitted_domains[0]
		assert name_constraints.value.permitted_subtrees[1].value == ssl_ca_permitted_domains[1]


def test_ca_key_fallback(tmpdir: Path) -> None:
	ssl_ca_cert = tmpdir / "opsi-ca-cert.pem"
	ssl_ca_key = tmpdir / "opsi-ca-key.pem"
	config.ssl_ca_cert = str(ssl_ca_cert)
	config.ssl_ca_key = str(ssl_ca_key)
	config.ssl_ca_key_passphrase = CA_KEY_DEFAULT_PASSPHRASE
	with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
		(ca_crt, ca_key) = create_ca(subject={"CN": "opsi CA", "OU": "opsi@opsi.org", "emailAddress": "opsi@opsi.org"}, valid_days=100)
		store_ca_key(ca_key)
		store_ca_cert(ca_crt)

		with pytest.raises(RuntimeError, match=r".*Bad decrypt. Incorrect password\?.*"):
			load_key(config.ssl_ca_key, "wrong")

		config.ssl_ca_key_passphrase = "wrong"
		# Test fallback
		load_ca_key()


def test_server_key_fallback(tmpdir: Path) -> None:
	ssl_ca_cert = tmpdir / "opsi-ca-cert.pem"
	ssl_ca_key = tmpdir / "opsi-ca-key.pem"
	config.ssl_ca_cert = str(ssl_ca_cert)
	config.ssl_ca_key = str(ssl_ca_key)
	config.ssl_ca_key_passphrase = "ca-secret"

	ssl_server_cert = tmpdir / "opsi-server-cert.pem"
	ssl_server_key = tmpdir / "opsi-server-key.pem"
	config.ssl_server_cert = str(ssl_server_cert)
	config.ssl_server_key = str(ssl_server_key)
	config.ssl_server_key_passphrase = SERVER_KEY_DEFAULT_PASSPHRASE
	with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
		with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmpdir), "echo")):
			setup_ca()

			(srv_crt, srv_key) = create_local_server_cert(renew=False)
			store_local_server_key(srv_key)
			store_local_server_cert(srv_crt)

			with pytest.raises(RuntimeError, match=r".*Bad decrypt. Incorrect password\?.*"):
				load_key(config.ssl_server_key, "wrong")

			config.ssl_server_key_passphrase = "wrong"
			# Test fallback
			load_local_server_key()


def test_recreate_ca(tmpdir: Path) -> None:
	ssl_ca_cert = tmpdir / "opsi-ca-cert.pem"
	ssl_ca_key = tmpdir / "opsi-ca-key.pem"
	config.ssl_ca_cert = str(ssl_ca_cert)
	config.ssl_ca_key = str(ssl_ca_key)
	config.ssl_ca_key_passphrase = "secret"
	subject = {"CN": "opsi CA", "OU": "opsi@opsi.org", "emailAddress": "opsi@opsi.org"}
	valid_days = 100

	with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
		with pytest.raises(FileNotFoundError):
			create_ca(subject=subject, valid_days=valid_days, key=load_ca_key())

		(ca_crt, ca_key) = create_ca(subject=subject, valid_days=valid_days)
		store_ca_key(ca_key)
		store_ca_cert(ca_crt)

		key1 = load_ca_key()
		assert ca_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		) == key1.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		)

		# Keep key
		(ca_crt, ca_key) = create_ca(subject=subject, valid_days=valid_days, key=load_ca_key())
		assert ca_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		) == key1.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		)

		(ca_crt, ca_key) = create_ca(subject=subject, valid_days=valid_days, key=load_ca_key())
		assert ca_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		) == key1.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		)

		# New key
		(ca_crt, ca_key) = create_ca(subject=subject, valid_days=valid_days)
		assert ca_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		) != key1.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		)


def test_renew_expired_ca(tmpdir: Path) -> None:  # pylint: disable=too-many-statements
	ssl_ca_cert = tmpdir / "opsi-ca-cert.pem"
	ssl_ca_key = tmpdir / "opsi-ca-key.pem"
	ssl_server_cert = tmpdir / "opsiconfd-cert.pem"
	ssl_server_key = tmpdir / "opsiconfd-key.pem"
	config.ssl_ca_cert = str(ssl_ca_cert)
	config.ssl_ca_key = str(ssl_ca_key)
	config.ssl_ca_key_passphrase = "secret"
	config.ssl_ca_cert_valid_days = 300
	config.ssl_server_cert = str(ssl_server_cert)
	config.ssl_server_key = str(ssl_server_key)

	class MockCertificateBuilder(x509.CertificateBuilder):
		def __init__(self, **kwargs: Any) -> None:
			kwargs["not_valid_before"] = kwargs["not_valid_before"] - datetime.timedelta(days=10)
			super().__init__(**kwargs)

	ca_subject = {
		"C": "DE",
		"ST": "RP",
		"L": "MAINZ",
		"O": "uib",
		"OU": "opsi@mydom.tld",
		"CN": "opsi CA",
		"emailAddress": "opsi@mydom.tld",
	}

	with (
		mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None),
		mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmpdir), "echo")),
		mock.patch("opsiconfd.ssl.get_ca_subject", lambda: ca_subject),
	):
		with mock.patch("opsicommon.ssl.common.CertificateBuilder", MockCertificateBuilder):
			setup_ca()
			setup_server_cert()

		# Check CA
		assert (datetime.datetime.now(tz=datetime.timezone.utc) - get_ca_cert_info()["not_before"]).days >= 10
		ca_crt = load_ca_cert()
		assert (ca_crt.not_valid_after_utc - datetime.datetime.now(tz=datetime.timezone.utc)).days == 299

		assert os.path.exists(config.ssl_ca_key)
		assert os.path.exists(config.ssl_ca_cert)
		mtime = ssl_ca_cert.lstat().mtime  # type: ignore[attr-defined]
		ca_key = load_ca_key()

		# Check server_cert
		assert (datetime.datetime.now(tz=datetime.timezone.utc) - get_server_cert_info()["not_before"]).days >= 10
		server_crt = load_local_server_cert()
		validate_cert(server_crt, ca_crt)

		# Change subject
		orig_ca_subject = ca_subject.copy()
		ca_subject["OU"] = "opsi@mynewdom.tld"
		ca_subject["emailAddress"] = "opsi@mynewdom.tld"
		assert ca_subject != orig_ca_subject

		config.ssl_ca_cert_renew_days = 100
		# Recreation not needed
		time.sleep(2)
		setup_ca()
		assert mtime == ssl_ca_cert.lstat().mtime  # type: ignore[attr-defined]
		# Key must stay the same
		assert load_ca_key().private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		) == ca_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		)

		# Subject must stay the same
		ca_crt = load_ca_cert()
		assert x509_name_to_dict(ca_crt.subject) == orig_ca_subject

		config.ssl_ca_cert_renew_days = 300
		# Recreation needed
		time.sleep(2)
		setup_ca()
		assert (datetime.datetime.now(tz=datetime.timezone.utc) - get_ca_cert_info()["not_before"]).days == 0
		ca_crt = load_ca_cert()
		assert mtime != ssl_ca_cert.lstat().mtime  # type: ignore[attr-defined]
		# Key must stay the same
		assert load_ca_key().private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		) == ca_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		)
		# Subject must stay the same
		assert x509_name_to_dict(ca_crt.subject) == orig_ca_subject

		# Check server cert validity
		with pytest.raises(verification.VerificationError, match=r"CA is not valid before.*but certificate is valid before"):
			validate_cert(server_crt, ca_crt)

		setup_server_cert()
		server_crt = load_local_server_cert()
		validate_cert(server_crt, ca_crt)

		# Delete the CA cert => old subject unknown
		os.unlink(config.ssl_ca_cert)
		setup_ca()
		# Key must stay the same
		assert load_ca_key().private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		) == ca_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption(),
		)
		# Subject must be changed
		ca_crt = load_ca_cert()
		new_subject = x509_name_to_dict(ca_crt.subject)
		assert new_subject != orig_ca_subject
		assert new_subject == ca_subject


def test_create_local_server_cert(tmpdir: Path) -> None:
	ssl_ca_cert = tmpdir / "opsi-ca-cert.pem"
	ssl_ca_key = tmpdir / "opsi-ca-key.pem"
	config.ssl_ca_cert = str(ssl_ca_cert)
	config.ssl_ca_key = str(ssl_ca_key)
	config.ssl_ca_key_passphrase = "secret"

	ssl_server_cert = tmpdir / "opsi-server-cert.pem"
	ssl_server_key = tmpdir / "opsi-server-key.pem"
	config.ssl_server_cert = str(ssl_server_cert)
	config.ssl_server_key = str(ssl_server_key)
	config.ssl_server_key_passphrase = "secret"

	with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
		with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmpdir), "echo")):
			setup_ca()
			setup_server_cert()
			assert "-----BEGIN CERTIFICATE-----" in ssl_server_cert.read_text(encoding="utf-8")
			assert "-----BEGIN ENCRYPTED PRIVATE KEY-----" in ssl_server_key.read_text(encoding="utf-8")
			key = load_key(config.ssl_server_key, "secret")
			assert isinstance(key, rsa.RSAPrivateKey)
			key = load_local_server_key()
			assert isinstance(key, rsa.RSAPrivateKey)
			with pytest.raises(RuntimeError, match=r".*Bad decrypt. Incorrect password\?.*"):
				key = load_key(config.ssl_server_key, "wrong")
			cert = load_local_server_cert()
			assert isinstance(cert, x509.Certificate)
			cert = load_cert(config.ssl_server_cert)
			assert isinstance(cert, x509.Certificate)

			srv_crt = load_local_server_cert()
			assert (
				srv_crt.not_valid_after_utc - datetime.datetime.now(tz=datetime.timezone.utc)
			).days == config.ssl_server_cert_valid_days - 1


def test_recreate_server_key(tmpdir: Path) -> None:
	ssl_ca_cert = tmpdir / "opsi-ca-cert.pem"
	ssl_ca_key = tmpdir / "opsi-ca-key.pem"
	config.ssl_ca_cert = str(ssl_ca_cert)
	config.ssl_ca_key = str(ssl_ca_key)
	config.ssl_ca_key_passphrase = "secret"

	ssl_server_cert = tmpdir / "opsi-server-cert.pem"
	ssl_server_key = tmpdir / "opsi-server-key.pem"
	config.ssl_server_cert = str(ssl_server_cert)
	config.ssl_server_key = str(ssl_server_key)
	config.ssl_server_key_passphrase = "secret"

	with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
		with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmpdir), "echo")):
			setup_ca()

			(srv_crt, srv_key) = create_local_server_cert(renew=False)
			store_local_server_key(srv_key)
			store_local_server_cert(srv_crt)

			key1 = load_local_server_key()
			assert srv_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			) == key1.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)

			# Keep key
			(srv_crt, srv_key) = create_local_server_cert(renew=True)
			assert srv_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			) == key1.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)

			(srv_crt, srv_key) = create_local_server_cert(renew=True)
			assert srv_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			) == key1.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)

			# New key
			(srv_crt, srv_key) = create_local_server_cert(renew=False)
			assert srv_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			) != key1.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)


def test_change_hostname(tmpdir: Path) -> None:
	ssl_ca_cert = tmpdir / "opsi-ca-cert.pem"
	ssl_ca_key = tmpdir / "opsi-ca-key.pem"
	config.ssl_ca_cert = str(ssl_ca_cert)
	config.ssl_ca_key = str(ssl_ca_key)
	config.ssl_ca_key_passphrase = "secret"

	ssl_server_cert = tmpdir / "opsi-server-cert.pem"
	ssl_server_key = tmpdir / "opsi-server-key.pem"
	config.ssl_server_cert = str(ssl_server_cert)
	config.ssl_server_key = str(ssl_server_key)
	config.ssl_server_key_passphrase = "secret"

	with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
		with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmpdir), "echo")):
			setup_ca()
			with mock.patch("opsiconfd.ssl.get_server_cn", lambda: "host.domain.tld"):
				assert opsiconfd.ssl.get_server_cn() == "host.domain.tld"
				setup_server_cert()

				cert1 = load_local_server_cert()
				key1 = load_local_server_key()

				assert cert1.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "host.domain.tld"

				alt_names = [extension for extension in cert1.extensions if extension.oid == x509.OID_SUBJECT_ALTERNATIVE_NAME]
				cert_hns = [str(v) for v in alt_names[0].value.get_values_for_type(x509.DNSName)]
				assert "host.domain.tld" in cert_hns

			with mock.patch("opsiconfd.ssl.get_server_cn", lambda: "new-host.domain.tld"):
				setup_server_cert()

				cert2 = load_local_server_cert()
				key2 = load_local_server_key()

				assert cert2.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "new-host.domain.tld"

				alt_names = [extension for extension in cert2.extensions if extension.oid == x509.OID_SUBJECT_ALTERNATIVE_NAME]
				cert_hns = [str(v) for v in alt_names[0].value.get_values_for_type(x509.DNSName)]
				assert "new-host.domain.tld" in cert_hns

				assert key2.private_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PrivateFormat.TraditionalOpenSSL,
					encryption_algorithm=serialization.NoEncryption(),
				) != key1.private_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PrivateFormat.TraditionalOpenSSL,
					encryption_algorithm=serialization.NoEncryption(),
				)


def test_change_ip(tmpdir: Path) -> None:
	ssl_ca_cert = tmpdir / "opsi-ca-cert.pem"
	ssl_ca_key = tmpdir / "opsi-ca-key.pem"
	config.ssl_ca_cert = str(ssl_ca_cert)
	config.ssl_ca_key = str(ssl_ca_key)
	config.ssl_ca_key_passphrase = "secret"

	ssl_server_cert = tmpdir / "opsi-server-cert.pem"
	ssl_server_key = tmpdir / "opsi-server-key.pem"
	config.ssl_server_cert = str(ssl_server_cert)
	config.ssl_server_key = str(ssl_server_key)
	config.ssl_server_key_passphrase = "secret"

	with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
		with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmpdir), "echo")):
			setup_ca()
			with mock.patch("opsiconfd.ssl.get_ips", lambda: {"127.0.0.1", "1.1.1.1"}):
				assert opsiconfd.ssl.get_ips() == {"127.0.0.1", "1.1.1.1"}
				setup_server_cert()

				cert1 = load_local_server_cert()
				key1 = load_local_server_key()

				alt_names = [extension for extension in cert1.extensions if extension.oid == x509.OID_SUBJECT_ALTERNATIVE_NAME]
				cert_ips = {str(v) for v in alt_names[0].value.get_values_for_type(x509.IPAddress)}
				assert "1.1.1.1" in cert_ips

			with mock.patch("opsiconfd.ssl.get_ips", lambda: {"127.0.0.1", "2.2.2.2"}):
				setup_server_cert()

				cert2 = load_local_server_cert()
				key2 = load_local_server_key()

				alt_names = [extension for extension in cert2.extensions if extension.oid == x509.OID_SUBJECT_ALTERNATIVE_NAME]
				cert_ips = {str(v) for v in alt_names[0].value.get_values_for_type(x509.IPAddress)}
				assert "2.2.2.2" in cert_ips
				assert "1.1.1.1" not in cert_ips

				assert key2.private_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PrivateFormat.TraditionalOpenSSL,
					encryption_algorithm=serialization.NoEncryption(),
				) != key1.private_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PrivateFormat.TraditionalOpenSSL,
					encryption_algorithm=serialization.NoEncryption(),
				)
