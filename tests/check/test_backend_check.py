# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
check tests
"""

from opsicommon.objects import OpsiDepotserver

import opsiconfd.check.backend  # noqa: F401
from opsiconfd.check.common import CheckStatus, check_manager
from opsiconfd.config import get_configserver_id
from tests.test_addon_manager import cleanup  # noqa: F401
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	UnprotectedBackend,
	backend,
	clean_mysql,
	test_client,
)


def test_check_depotservers(backend: UnprotectedBackend) -> None:  # noqa: F811
	configserver_id = get_configserver_id()
	depotserver_id = "depot1-check.opsi.org"
	depot = OpsiDepotserver(
		id=depotserver_id,
		depotLocalUrl="file:///some/path/to/depot",
		depotRemoteUrl="smb://172.17.0.101/opsi_depot",
		repositoryLocalUrl="file:///some/path/to/repository",
		repositoryRemoteUrl="webdavs://172.17.0.101:4447/repository",
	)
	backend.host_createObjects(depot)

	for clear_cache in True, False:
		result = check_manager.get("depotservers").run(clear_cache=clear_cache)
		assert result.from_cache is not clear_cache
		assert result.check_status == CheckStatus.ERROR

		partial_results = sorted(result.partial_results, key=lambda x: x.check.id)
		# import pprint
		# pprint.pprint(partial_results)

		assert len(partial_results) == 6
		for partial_result in partial_results:
			assert partial_result.from_cache is not clear_cache

		assert partial_results[0].check.id == f"depotservers:{depotserver_id}:depot_path"
		assert partial_results[1].check.id == f"depotservers:{depotserver_id}:repository_path"
		assert partial_results[2].check.id == f"depotservers:{depotserver_id}:workbench_path"
		assert partial_results[3].check.id == f"depotservers:{configserver_id}:depot_path"
		assert partial_results[4].check.id == f"depotservers:{configserver_id}:repository_path"
		assert partial_results[5].check.id == f"depotservers:{configserver_id}:workbench_path"

		assert partial_results[0].check_status == CheckStatus.ERROR
		assert (
			partial_results[0].message
			== f"The local depot path is no longer configurable in version 4.3 and is set to '/some/path/to/depot' on depot '{depotserver_id}'."
		)
		assert partial_results[0].details == {"depot_id": depotserver_id, "depot_path": "/some/path/to/depot"}

		assert partial_results[1].check_status == CheckStatus.ERROR
		assert (
			partial_results[1].message
			== f"The local repository path is no longer configurable in version 4.3 and is set to '/some/path/to/repository' on depot '{depotserver_id}'."
		)
		assert partial_results[1].details == {"depot_id": depotserver_id, "repository_path": "/some/path/to/repository"}

		assert partial_results[2].check_status == CheckStatus.ERROR
		assert (
			partial_results[2].message
			== f"The local workbench path is no longer configurable in version 4.3 and is set to '' on depot '{depotserver_id}'."
		)
		assert partial_results[2].details == {"depot_id": depotserver_id, "workbench_path": ""}

		for partial_result in partial_results[3:]:
			assert partial_result.check_status == CheckStatus.OK
			assert "corresponds to the default." in partial_result.message
			assert partial_result.details["depot_id"] == configserver_id
