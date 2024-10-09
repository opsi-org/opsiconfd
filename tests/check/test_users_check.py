# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

from unittest import mock

from opsiconfd.check.common import CheckStatus, check_manager
from opsiconfd.check.register import register_checks
from opsiconfd.check.users import opsi_users_check
from opsiconfd.utils import NameService, UserInfo
from tests.utils import cleanup_checks, get_opsi_config  # noqa: F401


def test_check_opsi_users() -> None:
	register_checks()
	check_manager.register(opsi_users_check)
	result = check_manager.get("opsi_users").run(clear_cache=True)
	assert result.check_status == CheckStatus.OK

	# If the server is part of a domain and the opsi users are local users, a warning should be issued.
	with (
		mock.patch(
			"opsiconfd.check.users.get_user_passwd_details",
			return_value=(
				[
					UserInfo(
						username="pcpatch",
						uid=1000,
						gid=1000,
						gecos="PCPatch",
						home="/home/pcpatch",
						shell="/bin/bash",
						service=NameService(NameService.FILES),
					)
				]
			),
		),
		mock.patch("opsiconfd.check.users.get_passwd_services", return_value=([NameService.FILES, NameService.SSS])),
	):
		result = check_manager.get("opsi_users").run(clear_cache=True)
		assert result.check_status == CheckStatus.WARNING

	# If the server  is part of a domain and the opsi users are only domain users, no warning should be issued.
	with (
		mock.patch(
			"opsiconfd.check.users.get_user_passwd_details",
			return_value=(
				[
					UserInfo(
						username="pcpatch",
						uid=1000,
						gid=1000,
						gecos="PCPatch",
						home="/home/pcpatch",
						shell="/bin/bash",
						service=NameService.WINBIND,
					)
				]
			),
		),
		mock.patch(
			"opsiconfd.check.users.get_passwd_services", return_value=([NameService.FILES, NameService.SYSTEMD, NameService.WINBIND])
		),
	):
		result = check_manager.get("opsi_users").run(clear_cache=True)
		assert result.check_status == CheckStatus.OK

	# If the server is part of a domain and the opsi users are local and domain users, an error should be issued.
	with (
		mock.patch(
			"opsiconfd.check.users.get_user_passwd_details",
			return_value=(
				[
					UserInfo(
						username="pcpatch",
						uid=1000,
						gid=1000,
						gecos="PCPatch",
						home="/home/pcpatch",
						shell="/bin/bash",
						service=NameService.LDAP,
					),
					UserInfo(
						username="pcpatch",
						uid=111111,
						gid=111111,
						gecos="PCPatch",
						home="/home/pcpatch",
						shell="/bin/bash",
						service=NameService.COMPAT,
					),
				]
			),
		),
		mock.patch("opsiconfd.check.users.get_passwd_services", return_value=([NameService.COMPAT, NameService.SYSTEMD, NameService.LDAP])),
	):
		result = check_manager.get("opsi_users").run(clear_cache=True)
		assert result.check_status == CheckStatus.ERROR

	# If the server is not part of a domain and the opsi users are local users, no warning should be issued.
	with (
		mock.patch(
			"opsiconfd.check.users.get_user_passwd_details",
			return_value=(
				[
					UserInfo(
						username="pcpatch",
						uid=1000,
						gid=1000,
						gecos="PCPatch",
						home="/home/pcpatch",
						shell="/bin/bash",
						service=NameService.COMPAT,
					)
				]
			),
		),
		mock.patch("opsiconfd.check.users.get_passwd_services", return_value=([NameService.COMPAT, NameService.SYSTEMD])),
	):
		result = check_manager.get("opsi_users").run(clear_cache=True)
		assert result.check_status == CheckStatus.OK

	# check for missing user
	with get_opsi_config([{"category": "depot_user", "config": "username", "value": "pcpatch-local"}]):
		result = check_manager.get("opsi_users").run(clear_cache=True)
		assert result.check_status == CheckStatus.ERROR
		assert result.message == "1 issue(s) found."
