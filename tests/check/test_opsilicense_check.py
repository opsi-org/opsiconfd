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


def test_check_licenses() -> None:  # noqa: F811
	check_manager.register(opsi_licenses_check)
	result = check_manager.get("opsi_licenses").run(clear_cache=True)
	assert result.check_status == "ok"
	assert result.partial_results is not None


@pytest.mark.parametrize(
	"missing_module_ids, opsi_config, opsiconfd_config, expected_status",
	(
		(
			["custom_ca"],
			[],
			{"ssl_server_cert_type": "opsi-ca"},
			"ok",
		),
		(
			["letsencrypt"],
			[],
			{"ssl_server_cert_type": "opsi-ca"},
			"ok",
		),
		(
			["custom_ca"],
			[],
			{"ssl_server_cert_type": "custom-ca"},
			"error",
		),
		(
			["letsencrypt"],
			[],
			{"ssl_server_cert_type": "letsencrypt"},
			"error",
		),
		(
			["sso"],
			[],
			{"saml-idp-entity-id": ""},
			"ok",
		),
		(
			["sso"],
			[],
			{"saml-idp-entity-id": "https://keycloak.opsi.test/realms/master"},
			"error",
		),
		(
			["scalability1", "scalability_light"],
			[],
			{"workers": 1},
			"ok",
		),
		(
			["scalability1", "scalability_light"],
			[],
			{"workers": 2},
			"error",
		),
		(
			["scalability_light"],
			[],
			{"workers": 3},
			"ok",
		),
		(
			["scalability1"],
			[],
			{"workers": 3},
			"error",
		),
		(
			["scalability1"],
			[],
			{"workers": 2},
			"ok",
		),
		(
			["directory-connector"],
			[{"category": "ldap_auth", "config": "ldap_url", "value": ""}],
			{},
			"ok",
		),
		(
			["directory-connector"],
			[{"category": "ldap_auth", "config": "ldap_url", "value": "ldaps:///ldap"}],
			{},
			"error",
		),
	),
)
def test_check_licenses_missing(
	missing_module_ids: list[str], opsi_config: list[dict[str, str]], opsiconfd_config: dict[str, str], expected_status: str
) -> None:  # noqa: F811
	check_manager.register(opsi_licenses_check)

	def mock_module_available(self: Backend, module: str) -> bool:
		return module not in missing_module_ids

	with mock.patch("opsiconfd.backend.rpc.main.Backend._module_available", mock_module_available):
		with get_opsi_config(opsi_config), get_config(opsiconfd_config):
			result = check_manager.get("opsi_licenses").run(clear_cache=True)
			for missing_module_id in missing_module_ids:
				cid = "scalability" if missing_module_id in ("scalability1", "scalability_light") else missing_module_id
				partial_result = [r for r in result.partial_results if r.check.id == f"opsi_licenses:missing:{cid}"][0]
				assert result.check_status == expected_status
				assert partial_result.check_status == expected_status
				if expected_status == "error":
					assert "licensed" in partial_result.message
				else:
					partial_result.message == f"Module '{missing_module_id}' is not needed."
