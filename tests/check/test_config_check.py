# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

from pathlib import Path

import opsiconfd.check.config  # noqa: F401
from opsiconfd.check.common import CheckStatus, check_manager
from tests.utils import (  # noqa: F401
	ACL_CONF_41,
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	clean_mysql,
	get_config,
	get_opsi_config,
	sync_clean_redis,
	test_client,
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
