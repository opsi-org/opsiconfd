# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
setup tests
"""

from unittest.mock import PropertyMock, patch

from opsicommon.objects import (
	ConfigState,
	LocalbootProduct,
	OpsiClient,
	OpsiDepotserver,
	ProductOnClient,
	ProductOnDepot,
)

from opsiconfd.setup.configs import _auto_correct_depot_urls, _cleanup_product_on_clients, _get_windows_domain
from tests.utils import UnprotectedBackend, backend, clean_mysql  # noqa: F401


def test_get_windows_domain() -> None:
	class Proc:
		stdout = ""

	with patch("opsiconfd.setup.configs.run", PropertyMock(return_value=Proc())):
		Proc.stdout = (
			"SID for local machine MACHINE is: S-1-5-21-3621911554-2635998167-701618891\n"
			"SID for domain DOMAIN is: S-1-5-21-3621911554-701618891-2635998167\n"
		)
		assert _get_windows_domain() == "DOMAIN"

		Proc.stdout = "SID for local machine MACHINE is: S-1-5-21-3621911554-2635998167-701618891\nCould not fetch domain SID\n"
		assert _get_windows_domain() == "MACHINE"


def test_fix_urls(backend: UnprotectedBackend) -> None:  # noqa: F811
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


def test_cleanup_product_on_clients(backend: UnprotectedBackend) -> None:  # noqa: F811
	depot1 = OpsiDepotserver(id="test-cleanup-depot-1.opsi.test")
	client1 = OpsiClient(id="test-cleanup-host-1.opsi.test")
	product1 = LocalbootProduct(
		id="test-cleanup-product1",
		productVersion="1",
		packageVersion="1",
		priority=100,
		setupScript="setup.opsiscript",
		uninstallScript="uninstall.opsiscript",
		alwaysScript="always.opsiscript",
		onceScript="once.opsiscript",
	)
	product2 = LocalbootProduct(
		id="test-cleanup-product2",
		productVersion="1",
		packageVersion="1",
		priority=0,
		setupScript="setup.opsiscript",
		uninstallScript="uninstall.opsiscript",
		alwaysScript="always.opsiscript",
		onceScript="once.opsiscript",
	)
	product_on_depot1 = ProductOnDepot(
		productId=product1.id,
		productType=product1.getType(),
		productVersion=product1.productVersion,
		packageVersion=product1.packageVersion,
		depotId=depot1.id,
	)
	product_on_client1 = ProductOnClient(
		productId=product1.id,
		productType=product1.getType(),
		productVersion=product1.productVersion,
		packageVersion=product1.packageVersion,
		clientId=client1.id,
		installationStatus="installed",
		actionRequest="setup",
	)
	product_on_client2 = ProductOnClient(
		productId=product2.id,
		productType=product2.getType(),
		productVersion=product2.productVersion,
		packageVersion=product2.packageVersion,
		clientId=client1.id,
		installationStatus="installed",
		actionRequest="setup",
	)
	config_state = ConfigState(configId="clientconfig.depot.id", objectId=client1.id, values=[depot1.id])

	backend.host_createObjects([depot1, client1])
	backend.configState_createObjects([config_state])
	backend.product_createObjects([product1, product2])
	backend.productOnDepot_createObjects([product_on_depot1])
	backend.productOnClient_createObjects([product_on_client1, product_on_client2])

	# product2 is not installed on depot, actionRequest must be set to "none"
	_cleanup_product_on_clients(backend)

	pocs = backend.productOnClient_getObjects(clientId=client1.id)
	assert len(pocs) == 2
	for poc in pocs:
		assert poc.productId in (product1.id, product2.id)
		if poc.productId == product1.id:
			assert poc.actionRequest == "setup"
		elif poc.productId == product2.id:
			assert poc.actionRequest == "none"
