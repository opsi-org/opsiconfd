# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
check tests
"""

from unittest import mock

import pytest

from opsiconfd.backend.rpc.main import Backend
from opsiconfd.check.common import check_manager
from opsiconfd.check.opsilicense import opsi_licenses_check
from tests.utils import cleanup_checks, get_config, get_opsi_config  # noqa: F401


def test_check_licenses() -> None:
	check_manager.register(opsi_licenses_check)
	result = check_manager.get("opsi_licenses").run(clear_cache=True)
	assert result.check_status == "ok"
	assert result.partial_results is not None


@pytest.mark.parametrize(
	"missing_module_ids, opsi_config, opsiconfd_config, expected_status, expected_message",
	(
		(
			["custom_ca"],
			[],
			{"ssl_server_cert_type": "opsi-ca"},
			"ok",
			"Module 'custom_ca' is not needed.",
		),
		(
			["letsencrypt"],
			[],
			{"ssl_server_cert_type": "opsi-ca"},
			"ok",
			"Module 'letsencrypt' is not needed.",
		),
		(
			["custom_ca"],
			[],
			{"ssl_server_cert_type": "custom-ca"},
			"error",
			"ssl-server-cert-type is set to 'custom-ca' in configuration but Custom CA module is not licensed.",
		),
		(
			["letsencrypt"],
			[],
			{"ssl_server_cert_type": "letsencrypt"},
			"error",
			"ssl-server-cert-type is set to 'letsencrypt' in configuration but Let's Encrypt module is not licensed.",
		),
		(
			["sso"],
			[],
			{"saml-idp-entity-id": ""},
			"ok",
			"Module 'sso' is not needed.",
		),
		(
			["sso"],
			[],
			{"saml-idp-entity-id": "https://keycloak.opsi.test/realms/master"},
			"error",
			"saml-idp-entity-id is set in configuration but Single Sign On module is not licensed.",
		),
		(
			["scalability1", "scalability_light"],
			[],
			{"workers": 1},
			"ok",
			"Scalability module is not needed.",
		),
		(
			["scalability1", "scalability_light"],
			[],
			{"workers": 2},
			"error",
			"The number of workers is set to 2 in configuration but no scalability module is licensed.",
		),
		(
			["scalability_light"],
			[],
			{"workers": 3},
			"ok",
			"The number of workers is set to 3 in configuration and a scalability module is licensed.",
		),
		(
			["scalability1"],
			[],
			{"workers": 3},
			"error",
			"The number of workers is set to 3 in configuration but no scalability module is licensed.",
		),
		(
			["scalability1"],
			[],
			{"workers": 2},
			"ok",
			"The number of workers is set to 2 in configuration and a scalability module is licensed.",
		),
		(
			["directory-connector"],
			[{"category": "ldap_auth", "config": "ldap_url", "value": ""}],
			{},
			"ok",
			"Module 'directory-connector' is not needed.",
		),
		(
			["directory-connector"],
			[{"category": "ldap_auth", "config": "ldap_url", "value": "ldaps:///ldap"}],
			{},
			"error",
			"ldap_auth is configured in opsi.conf but Directory Connector module is not licensed.",
		),
	),
)
def test_check_licenses_missing(
	missing_module_ids: list[str],
	opsi_config: list[dict[str, str]],
	opsiconfd_config: dict[str, str],
	expected_status: str,
	expected_message: str,
) -> None:
	check_manager.register(opsi_licenses_check)

	def mock_module_available(self: Backend, module: str) -> bool:
		return module not in missing_module_ids

	with mock.patch("opsiconfd.backend.rpc.main.Backend._module_available", mock_module_available):
		with get_opsi_config(opsi_config), get_config(opsiconfd_config):
			result = check_manager.get("opsi_licenses").run(clear_cache=True)
			for missing_module_id in missing_module_ids:
				cid = "scalability" if missing_module_id in ("scalability1", "scalability_light") else missing_module_id
				partial_result = next(r for r in result.partial_results if r.check.id == f"opsi_licenses:missing:{cid}")
				assert result.check_status == expected_status
				assert partial_result.check_status == expected_status
				assert partial_result.message == expected_message
