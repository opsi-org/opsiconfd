# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

from pathlib import Path
from unittest import mock

from opsiconfd.check.common import CheckStatus, check_manager
from opsiconfd.check.ssl import ssl_check
from opsiconfd.config import config
from opsiconfd.ssl import (
	create_ca,
	create_local_server_cert,
	get_ca_subject,
	store_local_server_cert,
	store_local_server_key,
	store_opsi_ca_cert,
	store_opsi_ca_key,
)
from tests.test_addon_manager import cleanup  # noqa: F401
from tests.utils import (  # noqa: F401
	cleanup_checks,
	get_config,
)
from tests.utils import (
	config as test_config,  # noqa: F401
)


def test_check_ssl(tmpdir: Path) -> None:
	check_manager.register(ssl_check)
	ssl_ca_cert = tmpdir / "opsi-ca-cert.pem"
	ssl_ca_key = tmpdir / "opsi-ca-key.pem"
	ssl_server_cert = tmpdir / "opsi-server-cert.pem"
	ssl_server_key = tmpdir / "opsi-server-key.pem"

	with get_config(
		{
			"ssl_ca_cert": str(ssl_ca_cert),
			"ssl_ca_key": str(ssl_ca_key),
			"ssl_server_cert": str(ssl_server_cert),
			"ssl_server_key": str(ssl_server_key),
		}
	):
		# CA key, CA cert, server key, server cert file missing
		result = check_manager.get("ssl").run(use_cache=False)
		assert result.check_status == CheckStatus.ERROR
		assert result.message == "5 issue(s) found."
		assert result.partial_results[0].message.startswith("A problem was found with the opsi CA certificate")
		assert result.partial_results[2].message.startswith("A problem was found with the opsi CA key")
		assert result.partial_results[3].message.startswith("A problem was found with the server certificate")
		assert result.partial_results[4].message.startswith("A problem was found with the server key")

		ca_subject = get_ca_subject()

		(ca_crt, ca_key) = create_ca(subject=ca_subject, valid_days=config.ssl_ca_cert_valid_days + 10)
		store_opsi_ca_key(ca_key)
		store_opsi_ca_cert(ca_crt)

		(srv_crt, srv_key) = create_local_server_cert(renew=False)
		store_local_server_cert(srv_crt)
		store_local_server_key(srv_key)

		result = check_manager.get("ssl").run(use_cache=False)
		assert result.check_status == CheckStatus.OK
		assert result.message == "No SSL issues found."
		assert (
			result.partial_results[0].message
			== f"The opsi CA certificate is OK and will expire in {config.ssl_ca_cert_valid_days + 9} days."
		)
		assert result.partial_results[1].check_status == CheckStatus.OK
		assert result.partial_results[1].message == "The opsi CA is not a intermediate CA."
		assert result.partial_results[2].message == "The opsi CA key is OK."

		with mock.patch(
			"opsiconfd.check.ssl.get_ca_subject",
			lambda: {
				"C": "DE",
				"ST": "RP",
				"L": "MAINZ",
				"O": "uib",
				"OU": "opsi@new.domain",
				"CN": config.ssl_ca_subject_cn,
				"emailAddress": "opsi@new.domain",
			},
		):
			result = check_manager.get("ssl").run(use_cache=False)
			assert result.check_status == CheckStatus.WARNING
			assert result.partial_results[0].message.startswith("The subject of the CA has changed from")

		(ca_crt, ca_key) = create_ca(subject=ca_subject, valid_days=config.ssl_ca_cert_renew_days - 10)
		store_opsi_ca_key(ca_key)
		store_opsi_ca_cert(ca_crt)

		result = check_manager.get("ssl").run(use_cache=False)

		assert result.check_status == CheckStatus.ERROR
		assert (
			result.partial_results[0].message
			== f"The opsi CA certificate is OK but will expire in {config.ssl_ca_cert_renew_days - 11} days."
		)
		assert result.partial_results[4].check_status == CheckStatus.ERROR
		assert result.partial_results[4].message == "Failed to verify server cert with opsi CA."
