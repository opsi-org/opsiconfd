# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
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
from opsiconfd.config import get_configserver_id
from opsiconfd.ssl import (
	CA_KEY_DEFAULT_PASSPHRASE,
	SERVER_KEY_DEFAULT_PASSPHRASE,
	_check_certs_modified,
	as_pem,
	create_ca,
	create_local_server_cert,
	get_ca_cert_info,
	get_ca_certs,
	get_ca_certs_as_pem,
	get_hostnames,
	get_ips,
	get_opsi_ca_cert_as_pem,
	get_server_cert_info,
	get_trusted_certs,
	is_self_signed,
	load_cert,
	load_certs,
	load_key,
	load_local_server_cert,
	load_local_server_key,
	load_opsi_ca_cert,
	load_opsi_ca_key,
	opsi_ca_is_self_signed,
	setup_ca,
	setup_server_cert,
	store_cert,
	store_local_server_cert,
	store_local_server_key,
	store_opsi_ca_cert,
	store_opsi_ca_key,
	validate_cert,
	x509_name_to_dict,
)

from .test_letsencrypt import LETSENCRYPT_STAGING_DIRECTORY_URL
from .utils import get_config

GLOBALSIGN_ROOT_CA = """
-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG
A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv
b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw
MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT
aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ
jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp
xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp
1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG
snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ
U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8
9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B
AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz
yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE
38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP
AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad
DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME
HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==
-----END CERTIFICATE-----
"""

DIGICERT_GLOBAL_ROOT_CA = """
-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----
"""


def test_get_ips() -> None:
	with get_config({"ssl_server_cert_sans": ["2a00:1450:4001:81c::2003", "216.58.206.35"]}):
		ips = get_ips()
		assert "::1" in ips
		assert "0:0:0:0:0:0:0:1" not in ips
		assert "127.0.0.1" in ips
		assert "216.58.206.35" in ips
		assert "2a00:1450:4001:81c::2003" in ips

		ips = get_ips(public_only=True)
		assert "::1" not in ips
		assert "127.0.0.1" not in ips
		assert "216.58.206.35" in ips
		assert "2a00:1450:4001:81c::2003" in ips


def test_get_hostnames() -> None:
	hns = get_hostnames()
	assert "localhost" in hns


def test_ssl_ca_cert_and_key_in_different_files() -> None:
	with get_config({"ssl_ca_cert": "opsi-ca.pem", "ssl_ca_key": "opsi-ca.pem"}):
		with pytest.raises(ValueError, match=r".*cannot be stored in the same file.*"):
			setup_ca()


def test_ssl_server_cert_and_key_in_different_files() -> None:
	with get_config({"ssl_server_cert": "opsiconfd.pem", "ssl_server_key": "opsiconfd.pem"}):
		with pytest.raises(ValueError, match=r".*cannot be stored in the same file.*"):
			setup_server_cert()


def test_store_load_cert(tmp_path: Path) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	with get_config({"ssl_ca_cert": str(ssl_ca_cert), "ssl_ca_key": str(ssl_ca_key), "ssl_ca_key_passphrase": "secret"}):
		with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
			with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmp_path), "echo")):
				# Test one cert in file
				setup_ca()

				certs = load_certs(ssl_ca_cert)
				assert len(certs) == 1
				assert certs[0].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi CA"
				assert load_opsi_ca_cert().subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi CA"
				assert (
					load_cert(ssl_ca_cert, subject_cn="opsi CA").subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
					== "opsi CA"
				)

				# Add another cert to file
				(ca_crt, _ca_key) = create_ca(subject={"CN": "other CA"}, valid_days=100)
				store_cert(cert_file=ssl_ca_cert, cert=ca_crt, keep_others=True)
				certs = load_certs(ssl_ca_cert)
				assert len(certs) == 2
				assert certs[0].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi CA"
				assert certs[1].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "other CA"
				assert load_opsi_ca_cert().subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi CA"
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
					load_opsi_ca_cert()
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
				cert = load_opsi_ca_cert()
				assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi CA"

				response = get_ssl_ca_cert(None)  # type: ignore
				assert response.body.decode("ascii") == "".join(as_pem(c) for c in certs)


def test_create_ca(tmp_path: Path) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"

	with get_config({"ssl_ca_cert": str(ssl_ca_cert), "ssl_ca_key": str(ssl_ca_key), "ssl_ca_key_passphrase": "secret"}) as conf:
		with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
			with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmp_path), "echo")):
				setup_ca()
				assert "-----BEGIN CERTIFICATE-----" in ssl_ca_cert.read_text(encoding="utf-8")
				assert "-----BEGIN ENCRYPTED PRIVATE KEY-----" in ssl_ca_key.read_text(encoding="utf-8")
				key = load_key(conf.ssl_ca_key, "secret")
				assert isinstance(key, rsa.RSAPrivateKey)
				key = load_opsi_ca_key()
				assert isinstance(key, rsa.RSAPrivateKey)
				with pytest.raises(RuntimeError, match=r".*Bad decrypt. Incorrect password\?.*"):
					load_key(conf.ssl_ca_key, "wrong")
				cert = load_opsi_ca_cert()
				assert isinstance(cert, x509.Certificate)
				cert = load_cert(conf.ssl_ca_cert)
				assert isinstance(cert, x509.Certificate)

				ca_crt = load_opsi_ca_cert()
				assert (
					ca_crt.not_valid_after_utc - datetime.datetime.now(tz=datetime.timezone.utc)
				).days == conf.ssl_ca_cert_valid_days - 1

				info = get_ca_cert_info()

				out = subprocess.check_output(["openssl", "x509", "-noout", "-text", "-in", conf.ssl_ca_cert]).decode("utf-8")
				match = re.search(r"Serial Number:\s*\n\s*([a-f0-9:]+)", out)
				assert match
				openssl_serial = match.group(1)
				assert info["serial_number"].lstrip("0:") == openssl_serial.lstrip("0:").upper()
				out = subprocess.check_output(["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-in", conf.ssl_ca_cert]).decode(
					"utf-8"
				)
				match = re.search(r"sha256 Fingerprint=([A-F0-9:]+)", out, re.IGNORECASE)
				assert match
				openssl_fingerprint_sha256 = match.group(1)
				assert info["fingerprint_sha256"].lstrip("0:") == openssl_fingerprint_sha256.lstrip("0:").upper()

				out = subprocess.check_output(["openssl", "x509", "-noout", "-fingerprint", "-sha1", "-in", conf.ssl_ca_cert]).decode(
					"utf-8"
				)
				match = re.search(r"sha1 Fingerprint=([A-F0-9:]+)", out, re.IGNORECASE)
				assert match
				openssl_fingerprint_sha1 = match.group(1)
				assert info["fingerprint_sha1"].lstrip("0:") == openssl_fingerprint_sha1.lstrip("0:").upper()


def test_create_ca_permitted_domains(tmp_path: Path) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	ssl_ca_permitted_domains = ["mycompany1.tld", "mycompany2.tld"]
	with (
		mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None),
		mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmp_path), "echo")),
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
		ca_cert = load_opsi_ca_cert()

		name_constraints = [extension for extension in ca_cert.extensions if extension.oid == x509.OID_NAME_CONSTRAINTS][0]
		assert name_constraints.critical
		assert name_constraints.value.permitted_subtrees[0].value == ssl_ca_permitted_domains[0]
		assert name_constraints.value.permitted_subtrees[1].value == ssl_ca_permitted_domains[1]


def test_ca_key_fallback(tmp_path: Path) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	with get_config(
		{"ssl_ca_cert": str(ssl_ca_cert), "ssl_ca_key": str(ssl_ca_key), "ssl_ca_key_passphrase": CA_KEY_DEFAULT_PASSPHRASE}
	) as conf:
		with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
			(ca_crt, ca_key) = create_ca(subject={"CN": "opsi CA", "OU": "opsi@opsi.org", "emailAddress": "opsi@opsi.org"}, valid_days=100)
			store_opsi_ca_key(ca_key)
			store_opsi_ca_cert(ca_crt)

			with pytest.raises(RuntimeError, match=r".*Bad decrypt. Incorrect password\?.*"):
				load_key(conf.ssl_ca_key, "wrong")

			conf.ssl_ca_key_passphrase = "wrong"
			# Test fallback
			load_opsi_ca_key()


def test_server_key_fallback(tmp_path: Path) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	ssl_server_cert = tmp_path / "opsi-server-cert.pem"
	ssl_server_key = tmp_path / "opsi-server-key.pem"

	with get_config(
		{
			"ssl_ca_cert": str(ssl_ca_cert),
			"ssl_ca_key": str(ssl_ca_key),
			"ssl_ca_key_passphrase": "ca-secret",
			"ssl_server_cert": str(ssl_server_cert),
			"ssl_server_key": str(ssl_server_key),
			"ssl_server_key_passphrase": SERVER_KEY_DEFAULT_PASSPHRASE,
		}
	) as conf:
		with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
			with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmp_path), "echo")):
				setup_ca()

				(srv_crt, srv_key) = create_local_server_cert(renew=False)
				store_local_server_key(srv_key)
				store_local_server_cert(srv_crt)

				with pytest.raises(RuntimeError, match=r".*Bad decrypt. Incorrect password\?.*"):
					load_key(conf.ssl_server_key, "wrong")

				conf.ssl_server_key_passphrase = "wrong"
				# Test fallback
				load_local_server_key()


@pytest.mark.parametrize(
	"additional_certs",
	([], [GLOBALSIGN_ROOT_CA], [GLOBALSIGN_ROOT_CA, DIGICERT_GLOBAL_ROOT_CA]),
)
def test_recreate_ca(tmp_path: Path, additional_certs: list[str]) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	subject = {"CN": "opsi CA", "OU": "opsi@opsi.org", "emailAddress": "opsi@opsi.org"}
	valid_days = 100

	with get_config({"ssl_ca_cert": str(ssl_ca_cert), "ssl_ca_key": str(ssl_ca_key), "ssl_ca_key_passphrase": "secret"}):
		with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
			with pytest.raises(FileNotFoundError):
				create_ca(subject=subject, valid_days=valid_days, key=load_opsi_ca_key())

			(ca_crt, ca_key) = create_ca(subject=subject, valid_days=valid_days)
			store_opsi_ca_key(ca_key)
			store_opsi_ca_cert(ca_crt)
			if additional_certs:
				with ssl_ca_cert.open("a", encoding="utf-8") as file:
					file.write("\n".join(additional_certs))
				# print(ssl_ca_cert.read_text(encoding="utf-8"))

			assert load_opsi_ca_cert() == ca_crt
			key1 = load_opsi_ca_key()
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
			(ca_crt, ca_key) = create_ca(subject=subject, valid_days=valid_days, key=load_opsi_ca_key())
			assert ca_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			) == key1.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)

			if additional_certs:
				# Additional certs must be kept
				data = ssl_ca_cert.read_text(encoding="utf-8")
				for additional_cert in additional_certs:
					assert additional_cert.strip() in data

			(ca_crt, ca_key) = create_ca(subject=subject, valid_days=valid_days, key=load_opsi_ca_key())
			assert ca_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			) == key1.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)
			if additional_certs:
				# Additional certs must be kept
				data = ssl_ca_cert.read_text(encoding="utf-8")
				for additional_cert in additional_certs:
					assert additional_cert.strip() in data

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

			if additional_certs:
				# Additional certs must be kept
				data = ssl_ca_cert.read_text(encoding="utf-8")
				for additional_cert in additional_certs:
					assert additional_cert.strip() in data


@pytest.mark.parametrize(
	"additional_certs",
	([], [GLOBALSIGN_ROOT_CA], [GLOBALSIGN_ROOT_CA, DIGICERT_GLOBAL_ROOT_CA]),
)
def test_renew_expired_ca(tmp_path: Path, additional_certs: list[str]) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	ssl_ca_cert_bak = tmp_path / "opsi-ca-cert.pem.bak"
	ssl_ca_key_bak = tmp_path / "opsi-ca-key.pem.bak"
	ssl_server_cert = tmp_path / "opsiconfd-cert.pem"
	ssl_server_key = tmp_path / "opsiconfd-key.pem"

	with get_config(
		{
			"ssl_ca_cert": str(ssl_ca_cert),
			"ssl_ca_key": str(ssl_ca_key),
			"ssl_ca_key_passphrase": "secret",
			"ssl_ca_cert_valid_days": 300,
			"ssl_server_cert": str(ssl_server_cert),
			"ssl_server_key": str(ssl_server_key),
		}
	) as conf:

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
			mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmp_path), "echo")),
			mock.patch("opsiconfd.ssl.get_ca_subject", lambda: ca_subject),
			mock.patch("opsiconfd.ssl._check_certs_interval", 0.0),
		):
			if additional_certs:
				with ssl_ca_cert.open("w", encoding="utf-8") as file:
					file.write("\n".join(additional_certs))

			with mock.patch("opsicommon.ssl.common.CertificateBuilder", MockCertificateBuilder):
				setup_ca()
				assert opsi_ca_is_self_signed()
				setup_server_cert()

			if additional_certs:
				# Additional certs must be kept
				data = ssl_ca_cert.read_text(encoding="utf-8")
				for additional_cert in additional_certs:
					assert additional_cert.strip() in data

			# Check CA
			assert (datetime.datetime.now(tz=datetime.timezone.utc) - get_ca_cert_info()["not_before"]).days >= 10
			ca_crt = load_opsi_ca_cert()
			assert (ca_crt.not_valid_after_utc - datetime.datetime.now(tz=datetime.timezone.utc)).days == 299

			assert os.path.exists(conf.ssl_ca_key)
			assert os.path.exists(conf.ssl_ca_cert)
			mtime = ssl_ca_cert.lstat().st_mtime
			ca_key = load_opsi_ca_key()

			# Check server_cert
			assert (datetime.datetime.now(tz=datetime.timezone.utc) - get_server_cert_info()["not_before"]).days >= 10
			server_crt = load_local_server_cert()
			validate_cert(server_crt, ca_crt)

			# Change subject
			orig_ca_subject = ca_subject.copy()
			ca_subject["OU"] = "opsi@mynewdom.tld"
			ca_subject["emailAddress"] = "opsi@mynewdom.tld"
			assert ca_subject != orig_ca_subject

			conf.ssl_ca_cert_renew_days = 100
			# Recreation not needed
			time.sleep(2)
			setup_ca()
			assert mtime == ssl_ca_cert.lstat().st_mtime
			# Key must stay the same
			assert load_opsi_ca_key().private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			) == ca_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)

			if additional_certs:
				assert ssl_ca_cert_bak.exists() and not ssl_ca_key_bak.exists()
			else:
				assert not ssl_ca_cert_bak.exists() and not ssl_ca_key_bak.exists()

			if additional_certs:
				# Additional certs must be kept
				data = ssl_ca_cert.read_text(encoding="utf-8")
				for additional_cert in additional_certs:
					assert additional_cert.strip() in data

			# Subject must stay the same
			ca_crt = load_opsi_ca_cert()
			assert x509_name_to_dict(ca_crt.subject) == orig_ca_subject

			conf.ssl_ca_cert_renew_days = 300
			# Recreation needed
			time.sleep(2)
			setup_ca()
			assert (datetime.datetime.now(tz=datetime.timezone.utc) - get_ca_cert_info()["not_before"]).days == 0
			ca_crt = load_opsi_ca_cert()
			assert mtime != ssl_ca_cert.lstat().st_mtime
			# Key must stay the same
			assert load_opsi_ca_key().private_bytes(
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

			if additional_certs:
				assert ssl_ca_cert_bak.exists() and not ssl_ca_key_bak.exists()
			else:
				assert not ssl_ca_cert_bak.exists() and not ssl_ca_key_bak.exists()

			if additional_certs:
				# Additional certs must be kept
				data = ssl_ca_cert.read_text(encoding="utf-8")
				for additional_cert in additional_certs:
					assert additional_cert.strip() in data

			# Check server cert validity
			with pytest.raises(verification.VerificationError, match=r"CA is not valid before.*but certificate is valid before"):
				validate_cert(server_crt, ca_crt)

			setup_server_cert()
			server_crt = load_local_server_cert()
			validate_cert(server_crt, ca_crt)

			# Delete the CA cert => old subject unknown
			os.unlink(conf.ssl_ca_cert)
			setup_ca()
			# Key must stay the same
			assert load_opsi_ca_key().private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			) == ca_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)
			# Subject must be changed
			ca_crt = load_opsi_ca_cert()
			new_subject = x509_name_to_dict(ca_crt.subject)
			assert new_subject != orig_ca_subject
			assert new_subject == ca_subject

			if additional_certs:
				assert ssl_ca_cert_bak.exists() and not ssl_ca_key_bak.exists()
			else:
				assert not ssl_ca_cert_bak.exists() and not ssl_ca_key_bak.exists()


def test_intermediate_ca(tmp_path: Path) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	ssl_server_cert = tmp_path / "opsi-server-cert.pem"
	ssl_server_key = tmp_path / "opsi-server-key.pem"
	with get_config(
		{
			"ssl_ca_cert": str(ssl_ca_cert),
			"ssl_ca_key": str(ssl_ca_key),
			"ssl_ca_key_passphrase": "secret",
			"ssl_server_cert": str(ssl_server_cert),
			"ssl_server_key": str(ssl_server_key),
			"ssl_server_key_passphrase": "secret",
		}
	) as conf:
		ca_subject = {"CN": "ACME Root CA", "emailAddress": "ca@acme.org"}
		opsi_ca_subject = {"CN": "opsi CA", "emailAddress": "ca@opsi.org"}

		with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
			with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmp_path), "echo")):
				(ca_crt, ca_key) = create_ca(subject=ca_subject, valid_days=10000)
				(opsi_ca_crt, opsi_ca_key) = create_ca(
					subject=opsi_ca_subject, valid_days=conf.ssl_ca_cert_valid_days, ca_key=ca_key, ca_cert=ca_crt
				)

				assert is_self_signed(ca_crt)
				assert not is_self_signed(opsi_ca_crt)

				store_opsi_ca_key(opsi_ca_key)
				store_opsi_ca_cert(opsi_ca_crt)
				ssl_ca_cert.write_text(as_pem(ca_crt) + as_pem(opsi_ca_crt), encoding="utf-8")

				assert not opsi_ca_is_self_signed()

				validate_cert(opsi_ca_crt, ca_crt)
				with pytest.raises(verification.VerificationError, match=r".*Failed to verify certificate"):
					validate_cert(ca_crt, get_trusted_certs())

				# CA key and cert must not be changed
				setup_ca()
				assert opsi_ca_crt == load_opsi_ca_cert()
				assert opsi_ca_key.private_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PrivateFormat.TraditionalOpenSSL,
					encryption_algorithm=serialization.NoEncryption(),
				) == load_opsi_ca_key().private_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PrivateFormat.TraditionalOpenSSL,
					encryption_algorithm=serialization.NoEncryption(),
				)

				setup_server_cert()
				srv_crt = load_local_server_cert()
				assert isinstance(srv_crt, x509.Certificate)
				assert srv_crt.issuer == opsi_ca_crt.subject

				# Try to renew opsi CA which must fail
				(opsi_ca_crt, opsi_ca_key) = create_ca(
					subject=opsi_ca_subject, valid_days=conf.ssl_ca_cert_renew_days - 10, ca_key=ca_key, ca_cert=ca_crt
				)
				store_opsi_ca_key(opsi_ca_key)
				store_opsi_ca_cert(opsi_ca_crt)
				with pytest.raises(
					RuntimeError,
					match=(
						r"opsi CA needs to be renewed and is an intermediate CA \(issuer='ACME Root CA'\)\. "
						r"Please update the current CA certificate.*and key.*manually\."
					),
				):
					setup_ca()


def test_create_local_server_cert(tmp_path: Path) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	ssl_server_cert = tmp_path / "opsi-server-cert.pem"
	ssl_server_key = tmp_path / "opsi-server-key.pem"

	with get_config(
		{
			"ssl_ca_cert": str(ssl_ca_cert),
			"ssl_ca_key": str(ssl_ca_key),
			"ssl_ca_key_passphrase": "secret",
			"ssl_server_cert": str(ssl_server_cert),
			"ssl_server_key": str(ssl_server_key),
			"ssl_server_key_passphrase": "secret",
		}
	) as conf:
		with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
			with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmp_path), "echo")):
				setup_ca()
				setup_server_cert()
				assert "-----BEGIN CERTIFICATE-----" in ssl_server_cert.read_text(encoding="utf-8")
				assert "-----BEGIN ENCRYPTED PRIVATE KEY-----" in ssl_server_key.read_text(encoding="utf-8")
				key = load_key(conf.ssl_server_key, "secret")
				assert isinstance(key, rsa.RSAPrivateKey)
				key = load_local_server_key()
				assert isinstance(key, rsa.RSAPrivateKey)
				with pytest.raises(RuntimeError, match=r".*Bad decrypt. Incorrect password\?.*"):
					key = load_key(conf.ssl_server_key, "wrong")

				cert = load_cert(conf.ssl_server_cert)
				assert isinstance(cert, x509.Certificate)

				cert = load_local_server_cert()
				assert isinstance(cert, x509.Certificate)

				assert (
					cert.not_valid_after_utc - datetime.datetime.now(tz=datetime.timezone.utc)
				).days == conf.ssl_server_cert_valid_days - 1
				assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == get_configserver_id()
				assert cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "opsi CA"


def test_keep_uib_opsi_ca_server_cert(tmp_path: Path) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	ssl_server_cert = tmp_path / "opsi-server-cert.pem"
	ssl_server_key = tmp_path / "opsi-server-key.pem"

	with get_config(
		{
			"ssl_ca_cert": str(ssl_ca_cert),
			"ssl_ca_key": str(ssl_ca_key),
			"ssl_ca_key_passphrase": "secret",
			"ssl_ca_subject_cn": "uib opsi CA",
			"ssl_server_cert": str(ssl_server_cert),
			"ssl_server_key": str(ssl_server_key),
			"ssl_server_key_passphrase": "secret",
		}
	) as conf:
		with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
			with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmp_path), "echo")):
				setup_ca()
				setup_server_cert()
				cert = load_local_server_cert()
				assert isinstance(cert, x509.Certificate)

				assert cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "uib opsi CA"

				conf.ssl_ca_subject_cn = "opsi CA"
				ssl_ca_cert.unlink()
				ssl_ca_key.unlink()
				setup_ca()
				setup_server_cert()
				# Keep server cert issued by "uib opsi CA"
				assert cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "uib opsi CA"


def test_recreate_server_key(tmp_path: Path) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	ssl_server_cert = tmp_path / "opsi-server-cert.pem"
	ssl_server_key = tmp_path / "opsi-server-key.pem"

	with get_config(
		{
			"ssl_ca_cert": str(ssl_ca_cert),
			"ssl_ca_key": str(ssl_ca_key),
			"ssl_ca_key_passphrase": "secret",
			"ssl_server_cert": str(ssl_server_cert),
			"ssl_server_key": str(ssl_server_key),
			"ssl_server_key_passphrase": "secret",
		}
	):
		with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
			with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmp_path), "echo")):
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


def test_change_hostname(tmp_path: Path) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	ssl_server_cert = tmp_path / "opsi-server-cert.pem"
	ssl_server_key = tmp_path / "opsi-server-key.pem"

	with get_config(
		{
			"ssl_ca_cert": str(ssl_ca_cert),
			"ssl_ca_key": str(ssl_ca_key),
			"ssl_ca_key_passphrase": "secret",
			"ssl_server_cert": str(ssl_server_cert),
			"ssl_server_key": str(ssl_server_key),
			"ssl_server_key_passphrase": "secret",
		}
	):
		with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
			with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmp_path), "echo")):
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
					with get_config(
						{
							"ssl_server_cert_sans": ["alias1.domain.tld", "alias2.domain.tld", "172.16.1.2", "2001:db8:a0b:12f0::1"],
						}
					):
						setup_server_cert()

						cert3 = load_local_server_cert()
						key3 = load_local_server_key()

						assert cert3.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "new-host.domain.tld"

						alt_names = [extension for extension in cert3.extensions if extension.oid == x509.OID_SUBJECT_ALTERNATIVE_NAME]
						cert_hns = [str(v) for v in alt_names[0].value.get_values_for_type(x509.DNSName)]
						cert_ips = [str(v) for v in alt_names[0].value.get_values_for_type(x509.IPAddress)]
						assert "alias1.domain.tld" in cert_hns
						assert "alias2.domain.tld" in cert_hns
						assert "172.16.1.2" in cert_ips
						assert "2001:db8:a0b:12f0::1" in cert_ips

						assert key2.private_bytes(
							encoding=serialization.Encoding.PEM,
							format=serialization.PrivateFormat.TraditionalOpenSSL,
							encryption_algorithm=serialization.NoEncryption(),
						) != key3.private_bytes(
							encoding=serialization.Encoding.PEM,
							format=serialization.PrivateFormat.TraditionalOpenSSL,
							encryption_algorithm=serialization.NoEncryption(),
						)


def test_change_ip(tmp_path: Path) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	ssl_server_cert = tmp_path / "opsi-server-cert.pem"
	ssl_server_key = tmp_path / "opsi-server-key.pem"

	with get_config(
		{
			"ssl_ca_cert": str(ssl_ca_cert),
			"ssl_ca_key": str(ssl_ca_key),
			"ssl_ca_key_passphrase": "secret",
			"ssl_server_cert": str(ssl_server_cert),
			"ssl_server_key": str(ssl_server_key),
			"ssl_server_key_passphrase": "secret",
		}
	):
		with mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None):
			with mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmp_path), "echo")):
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


def test_ca_certs_dir(tmp_path: Path) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	ssl_ca_certs = tmp_path / "ca-certs"
	with (
		mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None),
		mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmp_path), "echo")),
		mock.patch("opsiconfd.ssl._check_certs_interval", 0.0),
		get_config(
			{
				"ssl_ca_key_passphrase": "secret",
				"ssl_ca_cert": str(ssl_ca_cert),
				"ssl_ca_key": str(ssl_ca_key),
				"ssl_ca_certs": str(ssl_ca_certs),
			}
		),
	):
		setup_ca()
		opsi_ca_cert_as_pem = get_opsi_ca_cert_as_pem()

		# Test with missing dir
		certs = get_ca_certs()
		assert len(certs) == 1
		assert certs[0] == load_opsi_ca_cert()

		# Test empty dir
		ssl_ca_certs.mkdir()
		certs = get_ca_certs()
		assert len(certs) == 1
		assert certs[0] == load_opsi_ca_cert()

		# Test with additional certs
		(ssl_ca_certs / "GLOBALSIGN_ROOT_CA.pem").write_text(GLOBALSIGN_ROOT_CA, encoding="utf-8")
		(ssl_ca_certs / "DIGICERT_GLOBAL_ROOT_CA.pem.hide").write_text(DIGICERT_GLOBAL_ROOT_CA, encoding="utf-8")

		certs = get_ca_certs()
		assert len(certs) == 2
		pem = get_ca_certs_as_pem()
		assert GLOBALSIGN_ROOT_CA in pem
		assert DIGICERT_GLOBAL_ROOT_CA not in pem
		assert opsi_ca_cert_as_pem in pem

		# Test with additional certs in dir and opsi ca file
		ssl_ca_cert.write_text(opsi_ca_cert_as_pem + "\n" + DIGICERT_GLOBAL_ROOT_CA, encoding="utf-8")
		certs = get_ca_certs()
		assert len(certs) == 3
		pem = get_ca_certs_as_pem()
		assert GLOBALSIGN_ROOT_CA in pem
		assert DIGICERT_GLOBAL_ROOT_CA in pem
		assert opsi_ca_cert_as_pem in pem


def test_ca_certs_cache(tmp_path: Path) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	ssl_ca_certs = tmp_path / "ca-certs"
	with (
		mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None),
		mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmp_path), "echo")),
		get_config(
			{
				"ssl_ca_key_passphrase": "secret",
				"ssl_ca_cert": str(ssl_ca_cert),
				"ssl_ca_key": str(ssl_ca_key),
				"ssl_ca_certs": str(ssl_ca_certs),
			}
		),
	):
		globalsign_root_ca = ssl_ca_certs / "GLOBALSIGN_ROOT_CA.pem"

		setup_ca()
		with mock.patch("opsiconfd.ssl._check_certs_interval", 5.0):
			assert _check_certs_modified()
			assert not _check_certs_modified()

		with mock.patch("opsiconfd.ssl._check_certs_interval", 0.0):
			assert not _check_certs_modified()

			time.sleep(0.01)
			ssl_ca_cert.touch()
			assert _check_certs_modified()
			assert not _check_certs_modified()

			ssl_ca_certs.mkdir()
			assert not _check_certs_modified()

			globalsign_root_ca.write_text(GLOBALSIGN_ROOT_CA, encoding="utf-8")
			assert _check_certs_modified()
			assert not _check_certs_modified()

			globalsign_root_ca.unlink()
			assert _check_certs_modified()
			assert not _check_certs_modified()


def test_setup_server_cert_letsencrypt(tmp_path: Path) -> None:
	ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
	ssl_ca_key = tmp_path / "opsi-ca-key.pem"
	ssl_server_cert = tmp_path / "opsi-server-cert.pem"
	ssl_server_key = tmp_path / "opsi-server-key.pem"
	letsecrypt_data_dir = tmp_path / "letsencrypt"
	with (
		get_config(
			{
				"ssl_ca_cert": str(ssl_ca_cert),
				"ssl_ca_key": str(ssl_ca_key),
				"ssl_ca_key_passphrase": "secret",
				"ssl_server_cert": str(ssl_server_cert),
				"ssl_server_key": str(ssl_server_key),
				"ssl_server_key_passphrase": "secret",
				"ssl_server_cert_type": "letsencrypt",
				"letsencrypt_directory_url": LETSENCRYPT_STAGING_DIRECTORY_URL,
				"letsencrypt_contact_email": "mail@domain.invalid",
			}
		),
		mock.patch("opsiconfd.ssl.setup_ssl_file_permissions", lambda: None),
		mock.patch("opsicommon.ssl.linux._get_cert_path_and_cmd", lambda: (str(tmp_path), "echo")),
		mock.patch("opsiconfd.letsencrypt.LETSENCRYPT_DATA_DIR", str(letsecrypt_data_dir)),
	):
		with pytest.raises(RuntimeError, match="The provided contact URI was invalid"):
			setup_server_cert()
