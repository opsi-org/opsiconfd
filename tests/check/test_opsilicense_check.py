# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

from typing import Any
from unittest import mock

import pytest

from opsiconfd.backend import reinit_backend
from opsiconfd.backend.rpc.general import RPCGeneralMixin
from opsiconfd.backend.rpc.protocol import BackendProtocol
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
			["custom_ca", "enterprise"],
			[],
			{"ssl_server_cert_type": "opsi-ca"},
			"ok",
		),
		(
			["letsencrypt", "enterprise"],
			[],
			{"ssl_server_cert_type": "opsi-ca"},
			"ok",
		),
		(
			["custom_ca", "enterprise"],
			[],
			{"ssl_server_cert_type": "custom-ca"},
			"error",
		),
		(
			["letsencrypt", "enterprise"],
			[],
			{"ssl_server_cert_type": "letsencrypt"},
			"error",
		),
		(
			["sso", "enterprise"],
			[],
			{"saml-idp-entity-id": ""},
			"ok",
		),
		(
			["sso", "enterprise"],
			[],
			{"saml-idp-entity-id": "https://keycloak.opsi.test/realms/master"},
			"error",
		),
		(
			["scalability1", "enterprise"],
			[],
			{"workers": 1},
			"ok",
		),
		(
			["scalability1", "enterprise"],
			[],
			{"workers": 2},
			"error",
		),
		(
			["directory-connector", "basic", "professional", "enterprise"],
			[{"category": "ldap_auth", "config": "ldap_url", "value": ""}],
			{},
			"ok",
		),
		(
			["directory-connector", "basic", "professional", "enterprise"],
			[{"category": "ldap_auth", "config": "ldap_url", "value": "ldaps:///ldap"}],
			{},
			"error",
		),
	),
)
def test_check_licenses_missing(
	missing_module_ids: list[str], opsi_config: list[dict[str, str]], opsiconfd_config: dict[str, str], expected_status: str
) -> None:  # noqa: F811
	reinit_backend()
	check_manager.register(opsi_licenses_check)

	orig_backend_getLicensingInfo = RPCGeneralMixin.backend_getLicensingInfo

	def mock_licensing_info(
		self: BackendProtocol, licenses: bool = False, legacy_modules: bool = False, dates: bool = False, allow_cache: bool = True
	) -> dict[str, Any]:
		res = orig_backend_getLicensingInfo(self, licenses=licenses, legacy_modules=legacy_modules, dates=dates, allow_cache=allow_cache)
		res["available_modules"] = [m for m in res["available_modules"] if m not in missing_module_ids]
		return res

	with mock.patch("opsiconfd.backend.rpc.general.RPCGeneralMixin.backend_getLicensingInfo", mock_licensing_info):
		with get_opsi_config(opsi_config), get_config(opsiconfd_config):
			result = check_manager.get("opsi_licenses").run(clear_cache=True)
			partial_result = [r for r in result.partial_results if r.check.id == f"opsi_licenses:missing:{missing_module_ids[0]}"][0]
			assert result.check_status == expected_status
			assert partial_result.check_status == expected_status
			if expected_status == "error":
				assert "module is not licensed" in partial_result.message
			else:
				partial_result.message == f"Module '{missing_module_ids[0]}' is not needed."
