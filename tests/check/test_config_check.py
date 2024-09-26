# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

import pprint
from pathlib import Path
from unittest import mock

import opsiconfd.check.config  # noqa: F401
from opsiconfd.check.common import CheckStatus, check_manager
from opsiconfd.config import OPSICONFD_HOME, opsi_config
from tests.test_addon_manager import cleanup  # noqa: F401
from tests.utils import (  # noqa: F401
	ACL_CONF_41,
	get_config,
)
from tests.utils import (
	config as test_config,  # noqa: F401
)


def test_check_opsiconfd_config(tmp_path: Path) -> None:
	acl_file = tmp_path / "acl.conf"
	acl_file.write_text(ACL_CONF_41, encoding="utf-8")
	with get_config({"log_level_stderr": 9, "debug_options": ["rpc-log", "asyncio"], "acl_file": str(acl_file)}):
		result = check_manager.get("opsiconfd_config").run(use_cache=False)
		# print(result)
		ids_found = 0
		assert result.check_status == CheckStatus.ERROR
		assert result.message == "3 issue(s) found."
		for partial_result in result.partial_results:
			assert partial_result.check.id.startswith("opsiconfd_config:")
			if partial_result.check.id == "opsiconfd_config:log-level-stderr":
				ids_found += 1
				assert partial_result.check_status == CheckStatus.ERROR
				assert partial_result.message == "Log level setting 'log-level-stderr=SECRET' is much to high for productive use."
				assert partial_result.details == {"config": "log-level-stderr", "value": 9}
			elif partial_result.check.id == "opsiconfd_config:debug_options":
				assert partial_result.check_status == CheckStatus.ERROR
				assert partial_result.message == "The following debug options are set: rpc-log, asyncio."
				assert partial_result.details == {
					"config": "debug-options",
					"value": ["rpc-log", "asyncio"],
				}
				ids_found += 1
			elif partial_result.check.id == "opsiconfd_config:acl_self_for_all":
				ids_found += 1
				assert partial_result.check_status == CheckStatus.ERROR
				assert partial_result.message == "'self' is allowed for '.*'."
		assert ids_found == 3


def test_check_run_as_user() -> None:
	class MockUser:
		pw_name = "opsiconfd"
		pw_gid = 103
		pw_dir = OPSICONFD_HOME

	class MockGroup:
		gr_name = "nogroup"
		gr_gid = 65534

	mock_user = MockUser()

	def mock_getgrnam(groupname: str) -> MockGroup:
		group = MockGroup()
		group.gr_name = groupname
		if groupname == "shadow":
			group.gr_gid = 101
		elif groupname == opsi_config.get("groups", "admingroup"):
			group.gr_gid = 102
		elif groupname == opsi_config.get("groups", "fileadmingroup"):
			group.gr_gid = 103
		return group

	with mock.patch("opsiconfd.check.config.os.getgrouplist", mock.PropertyMock(return_value=(101, 102, 103))):
		with mock.patch("opsiconfd.check.config.pwd.getpwnam", mock.PropertyMock(return_value=mock_user)), mock.patch(
			"opsiconfd.check.config.grp.getgrnam", mock_getgrnam
		):
			result = check_manager.get("run_as_user").run(use_cache=False)

			pprint.pprint(result)
			assert result.check_status == CheckStatus.OK

		with mock.patch("opsiconfd.check.config.pwd.getpwnam", mock.PropertyMock(return_value=mock_user)), mock.patch(
			"opsiconfd.check.config.grp.getgrnam", mock_getgrnam
		):
			mock_user.pw_dir = "/wrong/home"
			result = check_manager.get("run_as_user").run(use_cache=False)
			assert result.check_status == CheckStatus.WARNING
			assert result.partial_results[0].details["home_directory"] == "/wrong/home"
	with (
		mock.patch("opsiconfd.check.config.os.getgrouplist", mock.PropertyMock(return_value=(1, 2, 3))),
		mock.patch("opsiconfd.check.config.pwd.getpwnam", mock.PropertyMock(return_value=mock_user)),
		mock.patch("opsiconfd.check.config.grp.getgrnam", mock_getgrnam),
	):
		result = check_manager.get("run_as_user").run(use_cache=False)
		assert result.check_status == CheckStatus.ERROR
		print(result)
		for partial_result in result.partial_results:
			if partial_result.check.id.endswith("shadow"):
				assert partial_result.message == "User 'opsiconfd' is not a member of group 'shadow'."
				assert partial_result.check_status == CheckStatus.ERROR
			elif partial_result.check.id.endswith(opsi_config.get("groups", "admingroup")):
				assert partial_result.message == f"User 'opsiconfd' is not a member of group '{opsi_config.get('groups', 'admingroup')}'."
				assert partial_result.check_status == CheckStatus.ERROR
			elif partial_result.check.id.endswith(opsi_config.get("groups", "fileadmingroup")):
				assert (
					partial_result.message == f"User 'opsiconfd' is not a member of group '{opsi_config.get('groups', 'fileadmingroup')}'."
				)
				assert partial_result.check_status == CheckStatus.ERROR
