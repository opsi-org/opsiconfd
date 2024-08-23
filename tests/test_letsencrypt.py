# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test letsencrypt
"""

import json
from pathlib import Path
from unittest import mock

import pytest
from opsicommon.ssl import create_server_cert_signing_request

from opsiconfd.letsencrypt import _get_acme_client, perform_certificate_signing_request

from .utils import get_config

# Use staging directory for testing
LETSENCRYPT_STAGING_DIRECTORY_ID = "acme-staging-v02.api.letsencrypt.org"
LETSENCRYPT_STAGING_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"


def test_get_acme_client(tmp_path: Path) -> None:
	contact_email = "test@opsi.org"
	letsecrypt_data_dir = tmp_path / "letsencrypt"
	with (
		get_config({"letsencrypt_directory_url": LETSENCRYPT_STAGING_DIRECTORY_URL}),
		mock.patch("opsiconfd.letsencrypt.LETSENCRYPT_DATA_DIR", str(letsecrypt_data_dir)),
	):
		_get_acme_client(contact_email=contact_email)
		private_key_path = letsecrypt_data_dir / "accounts" / LETSENCRYPT_STAGING_DIRECTORY_ID / "private_key.json"
		private_key_data = json.loads(private_key_path.read_bytes())
		# print(private_key_data)
		for key in ("kty", "n", "e", "d", "p", "q", "dp", "dq", "qi"):
			assert private_key_data[key]

		registration_resource_path = letsecrypt_data_dir / "accounts" / LETSENCRYPT_STAGING_DIRECTORY_ID / "regr.json"
		registration_resource_data = json.loads(registration_resource_path.read_bytes())
		# print(registration_resource_data)
		assert registration_resource_data["body"]["contact"] == [f"mailto:{contact_email}"]
		assert registration_resource_data["body"]["status"] == "valid"
		for key in ("n", "e", "kty"):
			assert registration_resource_data["body"]["key"][key] == private_key_data[key]
		assert registration_resource_data["uri"].startswith(LETSENCRYPT_STAGING_DIRECTORY_URL.replace("/directory", "/acme/acct/"))
		assert registration_resource_data["terms_of_service"]

		# Test loading existing account key and registration resource
		_get_acme_client(contact_email=contact_email)
		assert json.loads(private_key_path.read_bytes()) == private_key_data
		assert json.loads(registration_resource_path.read_bytes()) == registration_resource_data

		# Test updating registration resource
		registration_resource_path.unlink()
		_get_acme_client(contact_email=contact_email)
		assert json.loads(private_key_path.read_bytes()) == private_key_data
		updated_registration_resource_data = json.loads(registration_resource_path.read_bytes())
		# print(updated_registration_resource_data)
		assert updated_registration_resource_data == registration_resource_data

		# Test changing contact email
		contact_email = "test.new@opsi.org"
		_get_acme_client(contact_email=contact_email)
		updated_registration_resource_data = json.loads(registration_resource_path.read_bytes())
		# print(updated_registration_resource_data)
		assert updated_registration_resource_data["body"]["contact"] == [f"mailto:{contact_email}"]


def test_perform_certificate_signing_request(tmp_path: Path) -> None:
	contact_email = "test@opsi.org"
	letsecrypt_data_dir = tmp_path / "letsencrypt"
	with (
		get_config({"letsencrypt_directory_url": LETSENCRYPT_STAGING_DIRECTORY_URL}),
		mock.patch("opsiconfd.letsencrypt.LETSENCRYPT_DATA_DIR", str(letsecrypt_data_dir)),
		mock.patch("opsiconfd.letsencrypt.CHALLENGE_TIMEOUT_SECONDS", 5),
	):
		server_cn = "test-dns-fail.opsi.org"
		csr, _key = create_server_cert_signing_request(
			subject={"CN": server_cn, "emailAddress": contact_email},
			ip_addresses=set(),
			hostnames={server_cn},
		)
		with pytest.raises(RuntimeError, match="There was a problem with a DNS query during identifier validation"):
			perform_certificate_signing_request(csr, contact_email)

		server_cn = "www.opsi.org"
		csr, _key = create_server_cert_signing_request(
			subject={"CN": server_cn, "emailAddress": contact_email},
			ip_addresses=set(),
			hostnames={server_cn},
		)
		with pytest.raises(RuntimeError, match="The client lacks sufficient authorization"):
			perform_certificate_signing_request(csr, contact_email)
