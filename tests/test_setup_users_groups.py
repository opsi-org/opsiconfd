# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
setup users and groups tests
"""

from unittest.mock import patch

from opsiconfd.setup.system import setup_ucs_users_and_groups


# https://pypi.org/project/pytest-subprocess/
def test_ucs_create_users_and_groups_member(fp) -> None:  # type: ignore
	fp.register(["ucr", "get", "server/role"], stdout="memberserver")
	fp.register(["ucr", "get", "ldap/base"], stdout="dc=example,dc=org")
	with patch("opsiconfd.setup.system.is_ucs") as mock_is_ucs:
		mock_is_ucs.return_value = True
		assert setup_ucs_users_and_groups() is False


def test_ucs_create_users_and_groups_prim(fp) -> None:  # type: ignore
	fp.register(["ucr", "get", "server/role"], stdout="domaincontroller_prim")
	fp.register(["ucr", "get", "ldap/base"], stdout="dc=example,dc=org")
	fp.register(["udm", fp.any()], stdout="", returncode=0)
	fp.register([fp.any()])

	with patch("opsiconfd.setup.system.is_ucs") as mock_is_ucs:
		mock_is_ucs.return_value = True
		assert setup_ucs_users_and_groups() is True
