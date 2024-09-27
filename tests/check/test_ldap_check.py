# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

import opsiconfd.check.ldap  # noqa: F401
from opsiconfd.check.common import CheckStatus, check_manager
from tests.utils import (  # noqa: F401
	get_opsi_config,
)

DEPRECATED_METHOD = "getClientIds_list"


def test_check_ldap_connection() -> None:
	result = check_manager.get("ldap_connection").run(use_cache=False)
	assert result.check_status == CheckStatus.OK
	assert result.message == "LDAP authentication is not configured."
	with get_opsi_config([{"category": "ldap_auth", "config": "ldap_url", "value": "ldaps://no-server"}]):
		result = check_manager.get("ldap_connection").run(use_cache=False)
		assert result.check_status == CheckStatus.ERROR
		assert result.message == "Could not connect to LDAP Server."

	result = check_manager.get("ldap_connection").run(use_cache=False)
	assert result.check_status == CheckStatus.OK
	assert result.message == "LDAP authentication is not configured."
