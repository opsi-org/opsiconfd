# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
check tests
"""

import os
from copy import deepcopy
from pathlib import Path
from unittest import mock

from opsiconfd.check.common import CheckStatus, check_manager
from opsiconfd.check.register import register_checks
from opsiconfd.check.users import opsi_users_check
from opsiconfd.utils import NameService, UserInfo
from tests.utils import cleanup_checks, get_opsi_config  # noqa: F401


def test_check_opsi_users(tmp_path: Path) -> None:
	opsiconfd_home = tmp_path / "opsiconfd_home"
	opsiconfd_home.mkdir()

	opsiconfd_infos = [
		UserInfo(
			username="opsiconfd",
			uid=os.geteuid(),
			gid=1000,
			gecos="opsiconfd",
			home=opsiconfd_home,
			shell=Path("/bin/bash"),
			service=NameService.FILES,
		)
	]
	pcpatch_infos = [
		UserInfo(
			username="pcpatch",
			uid=1000,
			gid=1000,
			gecos="PCPatch",
			home=Path("/var/lib/opsi"),
			shell=Path("/bin/false"),
			service=NameService.FILES,
		)
	]

	register_checks()
	check_manager.register(opsi_users_check)
	result = check_manager.get("opsi_users").run(clear_cache=True)
	assert result.check_status == CheckStatus.OK

	def get_user_passwd_details(username: str) -> list[UserInfo]:
		if username == "opsiconfd":
			return opsiconfd_infos
		if username == "pcpatch":
			return pcpatch_infos
		return []

	# If the server is part of a domain and the opsi users are local users, a warning should be issued.
	with (
		mock.patch("opsiconfd.check.users.get_user_passwd_details", get_user_passwd_details),
		mock.patch("opsiconfd.check.users.get_passwd_services", return_value=([NameService.FILES, NameService.SSS])),
	):
		result = check_manager.get("opsi_users").run(clear_cache=True)
		assert result.check_status == CheckStatus.WARNING

	# If the server  is part of a domain and the opsi users are only domain users, no warning should be issued.
	pcpatch_infos[0].service = NameService.WINBIND
	opsiconfd_infos[0].service = NameService.WINBIND
	with (
		mock.patch("opsiconfd.check.users.get_user_passwd_details", get_user_passwd_details),
		mock.patch(
			"opsiconfd.check.users.get_passwd_services", return_value=([NameService.FILES, NameService.SYSTEMD, NameService.WINBIND])
		),
	):
		result = check_manager.get("opsi_users").run(clear_cache=True)
		assert result.check_status == CheckStatus.OK

	# If the server is part of a domain and the opsi users are local and domain users, an error should be issued.
	pcpatch_infos[0].service = NameService.LDAP
	opsiconfd_infos[0].service = NameService.LDAP
	pcpatch_infos.append(deepcopy(pcpatch_infos[0]))
	pcpatch_infos[1].service = NameService.COMPAT
	pcpatch_infos[1].uid = 111111
	pcpatch_infos[1].gid = 111111
	with (
		mock.patch("opsiconfd.check.users.get_user_passwd_details", get_user_passwd_details),
		mock.patch("opsiconfd.check.users.get_passwd_services", return_value=([NameService.COMPAT, NameService.SYSTEMD, NameService.LDAP])),
	):
		result = check_manager.get("opsi_users").run(clear_cache=True)
		assert result.check_status == CheckStatus.ERROR

	# If the server is not part of a domain and the opsi users are local users, no warning should be issued.
	pcpatch_infos[0].service = NameService.COMPAT
	opsiconfd_infos[0].service = NameService.COMPAT
	del pcpatch_infos[1]
	with (
		mock.patch("opsiconfd.check.users.get_user_passwd_details", get_user_passwd_details),
		mock.patch("opsiconfd.check.users.get_passwd_services", return_value=([NameService.COMPAT, NameService.SYSTEMD])),
	):
		result = check_manager.get("opsi_users").run(clear_cache=True)
		assert result.check_status == CheckStatus.OK

	# Check opsiconfd missing home directory
	opsiconfd_infos[0].home = Path("/non/existing/home/dir")
	with (
		mock.patch("opsiconfd.check.users.get_user_passwd_details", get_user_passwd_details),
	):
		result = check_manager.get("opsi_users").run(clear_cache=True)
		assert result.check_status == CheckStatus.ERROR
		assert result.message == "1 issue(s) found."
		assert (
			"OPSI user 'opsiconfd' has a non existing home directory configured: '/non/existing/home/dir'"
			in result.partial_results[1].message
		)

	# Check opsiconfd owns home directory
	opsiconfd_infos[0].uid = 9999
	opsiconfd_infos[0].home = opsiconfd_home
	with (
		mock.patch("opsiconfd.check.users.get_user_passwd_details", get_user_passwd_details),
	):
		result = check_manager.get("opsi_users").run(clear_cache=True)
		assert result.check_status == CheckStatus.ERROR
		assert result.message == "1 issue(s) found."
		assert "not owned by the user" in result.partial_results[1].message
	opsiconfd_infos[0].uid = os.geteuid()

	# Check opsiconfd can access home directory
	with mock.patch("opsiconfd.check.users.get_user_passwd_details", get_user_passwd_details), mock.patch("os.access", return_value=False):
		result = check_manager.get("opsi_users").run(clear_cache=True)
		assert result.check_status == CheckStatus.ERROR
		assert result.message == "1 issue(s) found."
		assert "OPSI user 'opsiconfd' cannot access its home directory" in result.partial_results[1].message

	# Check for missing user
	with get_opsi_config([{"category": "depot_user", "config": "username", "value": "pcpatch-local"}]):
		result = check_manager.get("opsi_users").run(clear_cache=True)
		assert result.check_status == CheckStatus.ERROR
		assert result.message == "1 issue(s) found."
