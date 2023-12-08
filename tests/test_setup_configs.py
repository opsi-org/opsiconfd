# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
setup tests
"""

from unittest.mock import PropertyMock, patch

from opsicommon.objects import OpsiDepotserver

from opsiconfd.setup.configs import _auto_correct_depot_urls, _get_windows_domain
from tests.utils import UnprotectedBackend, backend, clean_mysql  # pylint: disable=unused-import


def test_get_windows_domain() -> None:
	class Proc:  # pylint: disable=too-few-public-methods
		stdout = ""

	with patch("opsiconfd.setup.configs.run", PropertyMock(return_value=Proc())):
		Proc.stdout = (
			"SID for local machine MACHINE is: S-1-5-21-3621911554-2635998167-701618891\n"
			"SID for domain DOMAIN is: S-1-5-21-3621911554-701618891-2635998167\n"
		)
		assert _get_windows_domain() == "DOMAIN"

		Proc.stdout = "SID for local machine MACHINE is: S-1-5-21-3621911554-2635998167-701618891\nCould not fetch domain SID\n"
		assert _get_windows_domain() == "MACHINE"


def test_fix_urls(backend: UnprotectedBackend) -> None:  # pylint: disable=too-many-locals,redefined-outer-name
	depot = OpsiDepotserver(
		id="test-depot-1.opsi.org",
		depotLocalUrl="file:///var/lib/opsi/depot",
		depotRemoteUrl="smb:///test-depot-1.opsi.org/opsi_depot",
		depotWebdavUrl="webdavs:///test-depot-1.opsi.org:4447/opsi-web-interface",
		repositoryLocalUrl="file:///var/lib/opsi/repository",
		repositoryRemoteUrl="webdavs://test-depot-1.opsi.org:4447/repository",
		workbenchLocalUrl="file:///var/lib/opsi/workbench",
		workbenchRemoteUrl="webdavs:///test-depot-1.opsi.org:4447/workbench",
	)
	backend.host_createObjects([depot])
	_auto_correct_depot_urls(backend)

	depot_corrected = backend.host_getObjects(id=depot.id)[0]
	assert depot_corrected.depotLocalUrl == "file:///var/lib/opsi/depot"
	assert depot_corrected.depotRemoteUrl == "smb://test-depot-1.opsi.org/opsi_depot"
	assert depot_corrected.depotWebdavUrl == "webdavs://test-depot-1.opsi.org:4447/opsi-web-interface"
	assert depot_corrected.repositoryLocalUrl == "file:///var/lib/opsi/repository"
	assert depot_corrected.repositoryRemoteUrl == "webdavs://test-depot-1.opsi.org:4447/repository"
	assert depot_corrected.workbenchLocalUrl == "file:///var/lib/opsi/workbench"
	assert depot_corrected.workbenchRemoteUrl == "webdavs://test-depot-1.opsi.org:4447/workbench"
