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
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import mock  # type: ignore[import]
import pytest
from OpenSSL.crypto import (
	FILETYPE_PEM,
	TYPE_RSA,
	X509,
	X509StoreContextError,
	dump_privatekey,
)

import opsiconfd.ssl
from opsiconfd.config import config
from opsiconfd.ssl import (
	CA_KEY_DEFAULT_PASSPHRASE,
	SERVER_KEY_DEFAULT_PASSPHRASE,
	create_ca,
	create_local_server_cert,
	get_ca_cert_info,
	get_hostnames,
	get_ips,
	get_server_cert_info,
	load_ca_cert,
	load_ca_key,
	load_cert,
	load_key,
	load_local_server_cert,
	load_local_server_key,
	setup_ca,
	setup_server_cert,
	store_ca_cert,
	store_ca_key,
	store_local_server_cert,
	store_local_server_key,
	subject_to_dict,
	validate_cert,
)


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
			key = load_ca_key()
			assert key.type() == TYPE_RSA
			with pytest.raises(RuntimeError, match=r".*pkcs12 cipherfinal error.*"):
				key = load_key(config.ssl_ca_key, "wrong")
			cert = load_ca_cert()
			assert isinstance(cert, X509)
			cert = load_cert(config.ssl_ca_cert)
			assert isinstance(cert, X509)

			ca_crt = load_ca_cert()
			enddate = datetime.datetime.strptime((ca_crt.get_notAfter() or b"").decode("utf-8"), "%Y%m%d%H%M%SZ")
			assert (enddate - datetime.datetime.now()).days == config.ssl_ca_cert_valid_days - 1

			out = subprocess.check_output(["openssl", "x509", "-noout", "-text", "-in", config.ssl_ca_cert]).decode("utf-8")
			match = re.search(r"Serial Number:\s*\n\s*([a-f0-9:]+)", out)
			assert match
			openssl_serial = match.group(1)

			info = get_ca_cert_info()
			assert info["serial_number"].replace(":", "").lstrip("0") == openssl_serial.replace(":", "").lstrip("0").upper()


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

		with pytest.raises(RuntimeError, match=r".*pkcs12 cipherfinal error.*"):
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

			with pytest.raises(RuntimeError, match=r".*pkcs12 cipherfinal error.*"):
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
		assert dump_privatekey(FILETYPE_PEM, ca_key) == dump_privatekey(FILETYPE_PEM, key1)

		# Keep key
		(ca_crt, ca_key) = create_ca(subject=subject, valid_days=valid_days, key=load_ca_key())
		assert dump_privatekey(FILETYPE_PEM, ca_key) == dump_privatekey(FILETYPE_PEM, key1)

		(ca_crt, ca_key) = create_ca(subject=subject, valid_days=valid_days, key=load_ca_key())
		assert dump_privatekey(FILETYPE_PEM, ca_key) == dump_privatekey(FILETYPE_PEM, key1)

		# New key
		(ca_crt, ca_key) = create_ca(subject=subject, valid_days=valid_days)
		assert dump_privatekey(FILETYPE_PEM, ca_key) != dump_privatekey(FILETYPE_PEM, key1)


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

	def mock_gmtime_adj_notBefore(self: Any, amount: int) -> None:  # pylint: disable=invalid-name,unused-argument
		from OpenSSL._util import (  # type: ignore[import]  # pylint: disable=import-outside-toplevel
			lib,
		)

		notBefore = lib.X509_getm_notBefore(self._x509)  # pylint: disable=invalid-name,protected-access
		lib.X509_gmtime_adj(notBefore, -3600 * 24 * 10)  # 10 days in the past

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
		with mock.patch("OpenSSL.crypto.X509.gmtime_adj_notBefore", mock_gmtime_adj_notBefore):
			setup_ca()
			setup_server_cert()

		# Check CA
		assert (datetime.datetime.now() - get_ca_cert_info()["not_before"]).days >= 10
		ca_crt = load_ca_cert()
		enddate = datetime.datetime.strptime((ca_crt.get_notAfter() or b"").decode("utf-8"), "%Y%m%d%H%M%SZ")
		assert (enddate - datetime.datetime.now()).days == 299

		assert os.path.exists(config.ssl_ca_key)
		assert os.path.exists(config.ssl_ca_cert)
		mtime = ssl_ca_cert.lstat().mtime  # type: ignore[attr-defined]
		ca_key = load_ca_key()

		# Check server_cert
		assert (datetime.datetime.now() - get_server_cert_info()["not_before"]).days >= 10
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
		assert dump_privatekey(FILETYPE_PEM, load_ca_key()) == dump_privatekey(FILETYPE_PEM, ca_key)
		# Subject must stay the same
		ca_crt = load_ca_cert()
		assert subject_to_dict(ca_crt.get_subject()) == orig_ca_subject

		config.ssl_ca_cert_renew_days = 300
		# Recreation needed
		time.sleep(2)
		setup_ca()
		assert (datetime.datetime.now() - get_ca_cert_info()["not_before"]).days == 0
		ca_crt = load_ca_cert()
		assert mtime != ssl_ca_cert.lstat().mtime  # type: ignore[attr-defined]
		# Key must stay the same
		assert dump_privatekey(FILETYPE_PEM, load_ca_key()) == dump_privatekey(FILETYPE_PEM, ca_key)
		# Subject must stay the same
		assert subject_to_dict(ca_crt.get_subject()) == orig_ca_subject

		# Check server cert validity
		with pytest.raises(X509StoreContextError, match=r"CA is not valid before.*but certificate is valid before"):
			validate_cert(server_crt, ca_crt)

		setup_server_cert()
		server_crt = load_local_server_cert()
		validate_cert(server_crt, ca_crt)

		# Delete the CA cert => old subject unknown
		os.unlink(config.ssl_ca_cert)
		setup_ca()
		# Key must stay the same
		assert dump_privatekey(FILETYPE_PEM, load_ca_key()) == dump_privatekey(FILETYPE_PEM, ca_key)
		# Subject must be changed
		ca_crt = load_ca_cert()
		new_subject = subject_to_dict(ca_crt.get_subject())
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
			key = load_local_server_key()
			assert key.type() == TYPE_RSA
			with pytest.raises(RuntimeError, match=r".*pkcs12 cipherfinal error.*"):
				key = load_key(config.ssl_server_key, "wrong")
			cert = load_local_server_cert()
			assert isinstance(cert, X509)
			cert = load_cert(config.ssl_server_cert)
			assert isinstance(cert, X509)

			srv_crt = load_local_server_cert()
			enddate = datetime.datetime.strptime((srv_crt.get_notAfter() or b"").decode("utf-8"), "%Y%m%d%H%M%SZ")
			assert (enddate - datetime.datetime.now()).days == config.ssl_server_cert_valid_days - 1


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
			assert dump_privatekey(FILETYPE_PEM, srv_key) == dump_privatekey(FILETYPE_PEM, key1)

			# Keep key
			(srv_crt, srv_key) = create_local_server_cert(renew=True)
			assert dump_privatekey(FILETYPE_PEM, srv_key) == dump_privatekey(FILETYPE_PEM, key1)

			(srv_crt, srv_key) = create_local_server_cert(renew=True)
			assert dump_privatekey(FILETYPE_PEM, srv_key) == dump_privatekey(FILETYPE_PEM, key1)

			# New key
			(srv_crt, srv_key) = create_local_server_cert(renew=False)
			assert dump_privatekey(FILETYPE_PEM, srv_key) != dump_privatekey(FILETYPE_PEM, key1)


def test_key_cache(tmpdir: Path) -> None:
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

			(_srv_crt, srv_key) = create_local_server_cert(renew=False)
			store_local_server_key(srv_key)

			shutil.move(config.ssl_server_key, config.ssl_server_key + ".renamed")

			key1 = load_local_server_key()
			assert dump_privatekey(FILETYPE_PEM, srv_key) == dump_privatekey(FILETYPE_PEM, key1)

			with pytest.raises(FileNotFoundError):
				key2 = load_local_server_key(use_cache=False)
				assert dump_privatekey(FILETYPE_PEM, srv_key) == dump_privatekey(FILETYPE_PEM, key2)

			(_srv_crt, srv_key) = create_local_server_cert(renew=False)
			store_local_server_key(srv_key)

			key1 = load_local_server_key(use_cache=False)
			assert dump_privatekey(FILETYPE_PEM, srv_key) == dump_privatekey(FILETYPE_PEM, key1)

			shutil.move(config.ssl_server_key, config.ssl_server_key + ".renamed2")

			key2 = load_local_server_key(use_cache=True)
			assert dump_privatekey(FILETYPE_PEM, srv_key) == dump_privatekey(FILETYPE_PEM, key2)


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

				assert cert1.get_subject().CN == "host.domain.tld"
				alt_names = ""
				for idx in range(cert1.get_extension_count()):
					ext = cert1.get_extension(idx)
					if ext.get_short_name() == b"subjectAltName":
						alt_names = str(ext)

				assert "DNS:host.domain.tld" in alt_names

			with mock.patch("opsiconfd.ssl.get_server_cn", lambda: "new-host.domain.tld"):
				setup_server_cert()

				cert2 = load_local_server_cert()
				key2 = load_local_server_key()

				assert cert2.get_subject().CN == "new-host.domain.tld"
				alt_names = ""
				for idx in range(cert2.get_extension_count()):
					ext = cert2.get_extension(idx)
					if ext.get_short_name() == b"subjectAltName":
						alt_names = str(ext)

				assert "DNS:new-host.domain.tld" in alt_names

				assert dump_privatekey(FILETYPE_PEM, key2) != dump_privatekey(FILETYPE_PEM, key1)


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

				alt_names = ""
				for idx in range(cert1.get_extension_count()):
					ext = cert1.get_extension(idx)
					if ext.get_short_name() == b"subjectAltName":
						alt_names = str(ext)

				assert "IP Address:1.1.1.1" in alt_names

			with mock.patch("opsiconfd.ssl.get_ips", lambda: {"127.0.0.1", "2.2.2.2"}):
				setup_server_cert()

				cert2 = load_local_server_cert()
				key2 = load_local_server_key()

				alt_names = ""
				for idx in range(cert2.get_extension_count()):
					ext = cert2.get_extension(idx)
					if ext.get_short_name() == b"subjectAltName":
						alt_names = str(ext)

				assert "IP Address:2.2.2.2" in alt_names
				assert "IP Address:1.1.1.1" not in alt_names

				assert dump_privatekey(FILETYPE_PEM, key2) != dump_privatekey(FILETYPE_PEM, key1)
