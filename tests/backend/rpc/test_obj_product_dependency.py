# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.obj_product_dependency
"""


from itertools import permutations

import pytest
from opsicommon.objects import ConfigState, LocalbootProduct, ProductDependency, ProductOnClient, ProductOnDepot

from opsiconfd.backend.rpc.obj_product_dependency import OpsiProductNotAvailableOnDepotError
from opsiconfd.config import get_depotserver_id
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	UnprotectedBackend,
	backend,
	clean_mysql,
	clean_redis,
	get_config,
	test_client,
)

from .test_obj_product import create_test_products


def test_get_product_action_groups_1(
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	client_id = "test-client.opsi.org"
	depot_id = get_depotserver_id()

	config_state = ConfigState(configId="clientconfig.depot.id", objectId=client_id, values=[depot_id])
	backend.configState_createObjects([config_state])

	product1 = LocalbootProduct(
		id="opsi-client-agent", productVersion="4.3.0.0", packageVersion="1", priority=95, setupScript="setup.opsiscript"
	)
	product2 = LocalbootProduct(
		id="someapp6",
		productVersion="6.0",
		packageVersion="1",
		priority=0,
		setupScript="setup.opsiscript",
		uninstallScript="uninstall.opsiscript",
	)
	product3 = LocalbootProduct(id="someapp7", productVersion="7.0", packageVersion="1", priority=10, setupScript="setup.opsiscript")
	product4 = LocalbootProduct(id="someapp-config", productVersion="7.0", packageVersion="1", priority=20, setupScript="setup.opsiscript")
	product5 = LocalbootProduct(id="firefox", productVersion="115.0.2", packageVersion="1", priority=-80, setupScript="setup.opsiscript")
	product6 = LocalbootProduct(id="firefox-addon1", productVersion="1.0", packageVersion="1", priority=-10, setupScript="setup.opsiscript")
	product7 = LocalbootProduct(id="virscan", productVersion="1.0", packageVersion="1", priority=-10, setupScript="setup.opsiscript")
	product8 = LocalbootProduct(id="virconf", productVersion="1.0", packageVersion="1", priority=-30, setupScript="setup.opsiscript")
	product9 = LocalbootProduct(id="virdat", productVersion="1.0", packageVersion="1", priority=-90, setupScript="setup.opsiscript")
	product10 = LocalbootProduct(id="some-meta", productVersion="10.0", packageVersion="1", priority=0, setupScript="setup.opsiscript")

	product_dependency1 = ProductDependency(
		productId="someapp6",
		productVersion="6.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="someapp7",
		requiredInstallationStatus="not_installed",
		requirementType="before",
	)
	product_dependency2 = ProductDependency(
		productId="someapp6",
		productVersion="6.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="someapp-config",
		requiredAction="setup",
		requirementType="after",
	)
	product_dependency3 = ProductDependency(
		productId="someapp7",
		productVersion="7.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="someapp6",
		requiredInstallationStatus="not_installed",
		requirementType="before",
	)
	product_dependency4 = ProductDependency(
		productId="someapp7",
		productVersion="7.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="someapp-config",
		requiredAction="setup",
		requirementType="after",
	)
	product_dependency5 = ProductDependency(
		productId="firefox-addon1",
		productVersion="1.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="firefox",
		requiredProductVersion="115.0.2",
		requiredPackageVersion="1",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency6 = ProductDependency(
		productId="firefox-addon1",
		productVersion="1.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="not-available",
		requiredProductVersion="1.0",
		requiredPackageVersion="1",
		requiredAction="setup",
		requirementType="after",
	)
	product_dependency7 = ProductDependency(
		productId="virscan",
		productVersion="1.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="virdat",
		requiredInstallationStatus="installed",
		requirementType="after",
	)
	product_dependency8 = ProductDependency(
		productId="virscan",
		productVersion="1.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="virconf",
		requiredAction="setup",
		requirementType="after",
	)
	product_dependency9 = ProductDependency(
		productId="virdat",
		productVersion="1.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="virscan",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency10 = ProductDependency(
		productId="virconf",
		productVersion="1.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="virscan",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency11 = ProductDependency(
		productId="some-meta",
		productVersion="10.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="someapp7",
		requiredInstallationStatus="installed",
	)
	product_dependency12 = ProductDependency(
		productId="some-meta",
		productVersion="10.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="firefox",
		requiredInstallationStatus="installed",
	)

	product_on_depot1 = ProductOnDepot(
		productId="opsi-client-agent", productType="localboot", productVersion="4.3.0.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot2 = ProductOnDepot(
		productId="someapp6", productType="localboot", productVersion="6.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot3 = ProductOnDepot(
		productId="someapp7", productType="localboot", productVersion="7.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot4 = ProductOnDepot(
		productId="someapp-config", productType="localboot", productVersion="7.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot5 = ProductOnDepot(
		productId="firefox", productType="localboot", productVersion="115.0.2", packageVersion="1", depotId=depot_id
	)
	product_on_depot6 = ProductOnDepot(
		productId="firefox-addon1", productType="localboot", productVersion="1.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot7 = ProductOnDepot(
		productId="virscan", productType="localboot", productVersion="1.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot8 = ProductOnDepot(
		productId="virconf", productType="localboot", productVersion="1.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot9 = ProductOnDepot(
		productId="virdat", productType="localboot", productVersion="1.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot10 = ProductOnDepot(
		productId="some-meta", productType="localboot", productVersion="10.0", packageVersion="1", depotId=depot_id
	)

	product_on_client_be_1 = ProductOnClient(
		productId="someapp6",
		productType="localboot",
		productVersion="6.0",
		packageVersion="1",
		clientId=client_id,
		installationStatus="installed",
		actionRequest="none",
	)
	product_on_client_be_2 = ProductOnClient(
		productId="firefox",
		productType="localboot",
		productVersion="111.1.1",
		packageVersion="1",
		clientId=client_id,
		installationStatus="installed",
		actionRequest="none",
	)
	backend.host_createOpsiClient(id=client_id)
	backend.product_createObjects([product1, product2, product3, product4, product5, product6, product7, product8, product9, product10])
	backend.productDependency_createObjects(
		[
			product_dependency1,
			product_dependency2,
			product_dependency3,
			product_dependency4,
			product_dependency5,
			product_dependency6,
			product_dependency7,
			product_dependency8,
			product_dependency9,
			product_dependency10,
			product_dependency11,
			product_dependency12,
		]
	)
	backend.productOnDepot_createObjects(
		[
			product_on_depot1,
			product_on_depot2,
			product_on_depot3,
			product_on_depot4,
			product_on_depot5,
			product_on_depot6,
			product_on_depot7,
			product_on_depot8,
			product_on_depot9,
			product_on_depot10,
		]
	)
	backend.productOnClient_createObjects([product_on_client_be_1, product_on_client_be_2])
	product_on_client_1 = ProductOnClient(
		productId="opsi-client-agent",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	product_on_client_2 = ProductOnClient(
		productId="someapp7",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	product_on_client_3 = ProductOnClient(
		productId="firefox-addon1",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	product_on_client_4 = ProductOnClient(
		productId="virdat",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)

	for pocs in permutations([product_on_client_1, product_on_client_2, product_on_client_3, product_on_client_4]):
		res = backend.get_product_action_groups(list(pocs))[client_id]  # type: ignore[misc]
		assert len(res) == 4

		assert res[0].priority == 95
		assert len(res[0].product_on_clients) == 1
		assert res[0].product_on_clients[0].productId == "opsi-client-agent"
		assert res[0].product_on_clients[0].actionRequest == "setup"
		assert res[0].product_on_clients[0].actionSequence == 0

		assert res[1].priority == 20
		assert len(res[1].product_on_clients) == 3
		assert res[1].product_on_clients[0].productId == "someapp6"
		assert res[1].product_on_clients[0].actionRequest == "uninstall"
		assert res[1].product_on_clients[0].actionSequence == 1
		assert res[1].product_on_clients[1].productId == "someapp7"
		assert res[1].product_on_clients[1].actionRequest == "setup"
		assert res[1].product_on_clients[1].actionSequence == 2
		assert res[1].product_on_clients[2].productId == "someapp-config"
		assert res[1].product_on_clients[2].actionRequest == "setup"
		assert res[1].product_on_clients[2].actionSequence == 3

		assert res[2].priority == -80
		assert len(res[2].product_on_clients) == 2
		assert res[2].product_on_clients[0].productId == "firefox"
		assert res[2].product_on_clients[0].actionRequest == "setup"
		assert res[2].product_on_clients[0].actionSequence == 4
		assert res[2].product_on_clients[1].productId == "firefox-addon1"
		assert res[2].product_on_clients[1].actionRequest == "setup"
		assert res[2].product_on_clients[1].actionSequence == 5

		assert res[3].priority == -90
		assert len(res[3].product_on_clients) == 3
		assert res[3].product_on_clients[0].productId == "virscan"
		assert res[3].product_on_clients[0].actionRequest == "setup"
		assert res[3].product_on_clients[0].actionSequence == 6
		assert res[3].product_on_clients[1].productId == "virconf"
		assert res[3].product_on_clients[1].actionRequest == "setup"
		assert res[3].product_on_clients[1].actionSequence == 7
		assert res[3].product_on_clients[2].productId == "virdat"
		assert res[3].product_on_clients[2].actionRequest == "setup"
		assert res[3].product_on_clients[2].actionSequence == 8

		res2 = backend.productOnClient_generateSequence(pocs)
		assert len(res2) == 4
		assert res2[0].productId == "opsi-client-agent"
		assert res2[0].actionRequest == "setup"
		assert res2[0].actionSequence == 0
		assert res2[1].productId == "someapp7"
		assert res2[1].actionRequest == "setup"
		assert res2[1].actionSequence == 2
		assert res2[2].productId == "firefox-addon1"
		assert res2[2].actionRequest == "setup"
		assert res2[2].actionSequence == 5
		assert res2[3].productId == "virdat"
		assert res2[3].actionRequest == "setup"
		assert res2[3].actionSequence == 8

		res2 = backend.productOnClient_addDependencies(pocs)
		assert len(res2) == 9
		assert res2[0].productId == "opsi-client-agent"
		assert res2[0].actionRequest == "setup"
		assert res2[0].actionSequence == 0
		assert res2[1].productId == "someapp6"
		assert res2[1].actionRequest == "uninstall"
		assert res2[1].actionSequence == 1
		assert res2[2].productId == "someapp7"
		assert res2[2].actionRequest == "setup"
		assert res2[2].actionSequence == 2
		assert res2[3].productId == "someapp-config"
		assert res2[3].actionRequest == "setup"
		assert res2[3].actionSequence == 3
		assert res2[4].productId == "firefox"
		assert res2[4].actionRequest == "setup"
		assert res2[4].actionSequence == 4
		assert res2[5].productId == "firefox-addon1"
		assert res2[5].actionRequest == "setup"
		assert res2[5].actionSequence == 5
		assert res2[6].productId == "virscan"
		assert res2[6].actionRequest == "setup"
		assert res2[6].actionSequence == 6
		assert res2[7].productId == "virconf"
		assert res2[7].actionRequest == "setup"
		assert res2[7].actionSequence == 7
		assert res2[8].productId == "virdat"
		assert res2[8].actionRequest == "setup"
		assert res2[8].actionSequence == 8

	# Setup some-meta
	product_on_client_be_2 = ProductOnClient(
		productId="firefox",
		productType="localboot",
		productVersion="111.1.1",
		packageVersion="1",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="none",
	)
	backend.productOnClient_createObjects([product_on_client_be_2])

	product_on_client_1 = ProductOnClient(
		productId="some-meta",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	product_on_client_2 = ProductOnClient(
		productId="someapp7",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="none",
	)
	res = backend.get_product_action_groups(  # type: ignore[misc]
		[product_on_client_1, product_on_client_2],
	)[client_id]

	assert len(res) == 3

	assert res[0].priority == 20
	assert len(res[0].product_on_clients) == 3
	assert res[0].product_on_clients[0].productId == "someapp6"
	assert res[0].product_on_clients[0].actionRequest == "uninstall"
	assert res[0].product_on_clients[0].actionSequence == 0
	assert res[0].product_on_clients[1].productId == "someapp7"
	assert res[0].product_on_clients[1].actionRequest == "setup"
	assert res[0].product_on_clients[1].actionSequence == 1
	assert res[0].product_on_clients[2].productId == "someapp-config"
	assert res[0].product_on_clients[2].actionRequest == "setup"
	assert res[0].product_on_clients[2].actionSequence == 2

	assert res[1].priority == 0
	assert len(res[1].product_on_clients) == 1
	assert res[1].product_on_clients[0].productId == "some-meta"
	assert res[1].product_on_clients[0].actionRequest == "setup"
	assert res[1].product_on_clients[0].actionSequence == 3

	assert res[2].priority == -80
	assert len(res[2].product_on_clients) == 1
	assert res[2].product_on_clients[0].productId == "firefox"
	assert res[2].product_on_clients[0].actionRequest == "setup"
	assert res[2].product_on_clients[0].actionSequence == 4

	# Match required version
	product_on_client_be_2 = ProductOnClient(
		productId="firefox",
		productType="localboot",
		productVersion="115.0.2",
		packageVersion="1",
		clientId=client_id,
		installationStatus="installed",
		actionRequest="none",
	)
	backend.productOnClient_createObjects([product_on_client_be_2])

	res = backend.get_product_action_groups(  # type: ignore[misc]
		[product_on_client_3, product_on_client_1, product_on_client_2],
	)[client_id]

	assert res[2].priority == -10
	assert len(res[2].product_on_clients) == 1
	assert res[2].product_on_clients[0].productId == "firefox-addon1"
	assert res[2].product_on_clients[0].actionRequest == "setup"
	assert res[2].product_on_clients[0].actionSequence == 4

	with pytest.raises(
		OpsiProductNotAvailableOnDepotError,
		match=r"Product not available on depot: Product 'not-available' \(version: 1\.0-1\) not found on depot.*",
	):
		backend.get_product_action_groups(  # type: ignore[misc]
			[product_on_client_3, product_on_client_4, product_on_client_1, product_on_client_2], ignore_unavailable_products=False
		)

	product_on_client_1 = ProductOnClient(
		productId="some-meta",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	pocs = backend.productOnClient_addDependencies([product_on_client_1])
	backend.productOnClient_createObjects(pocs)
	res2 = backend.productOnClient_getObjectsWithSequence(clientId=client_id)

	assert len(res2) == 5

	assert res2[0].productId == "someapp6"
	assert res2[0].actionRequest == "uninstall"
	assert res2[0].actionSequence == 0
	assert res2[1].productId == "someapp7"
	assert res2[1].actionRequest == "setup"
	assert res2[1].actionSequence == 1
	assert res2[2].productId == "someapp-config"
	assert res2[2].actionRequest == "setup"
	assert res2[2].actionSequence == 2
	assert res2[3].productId == "firefox"
	assert res2[3].installationStatus == "installed"
	assert res2[3].actionSequence == -1
	assert res2[4].productId == "some-meta"
	assert res2[4].actionRequest == "setup"
	assert res2[4].actionSequence == 3

	product_on_client_1 = ProductOnClient(
		productId="firefox",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="none",
	)
	backend.productOnClient_createObjects([product_on_client_1])

	# Must not add dependent actions
	res2 = backend.productOnClient_getObjectsWithSequence(clientId=client_id)
	assert len(res2) == 5
	assert res2[4].productId == "firefox"
	assert res2[4].installationStatus == "not_installed"
	assert res2[4].actionRequest == "none"
	assert res2[4].actionSequence == -1

	# Delete all
	backend.productOnClient_deleteObjects(backend.productOnClient_getObjects(clientId=client_id))

	res2 = backend.productOnClient_getObjects(clientId=client_id)
	assert len(res2) == 0

	product_on_client_1 = ProductOnClient(
		productId="some-meta",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	pocs = backend.productOnClient_updateObjectsWithDependencies([product_on_client_1])
	res2 = backend.productOnClient_getObjects(clientId=client_id)
	assert len(res2) == 4
	res2 = sorted(res2, key=lambda p: p.productId)
	assert res2[0].productId == "firefox"
	assert res2[0].actionRequest == "setup"
	assert res2[1].productId == "some-meta"
	assert res2[1].actionRequest == "setup"
	assert res2[2].productId == "someapp-config"
	assert res2[2].actionRequest == "setup"
	assert res2[3].productId == "someapp7"
	assert res2[3].actionRequest == "setup"

	res2 = backend.productOnClient_getObjectsWithSequence(clientId=client_id)
	assert len(res2) == 4
	assert res2[0].productId == "someapp7"
	assert res2[0].actionRequest == "setup"
	assert res2[0].actionSequence == 0
	assert res2[1].productId == "someapp-config"
	assert res2[1].actionRequest == "setup"
	assert res2[1].actionSequence == 1
	assert res2[2].productId == "some-meta"
	assert res2[2].actionRequest == "setup"
	assert res2[2].actionSequence == 2
	assert res2[3].productId == "firefox"
	assert res2[3].actionRequest == "setup"
	assert res2[3].actionSequence == 3


def test_get_product_action_groups_no_dep_always_update(
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	client_id = "test-client.opsi.org"
	depot_id = get_depotserver_id()

	product1 = LocalbootProduct(
		id="swaudit",
		productVersion="4.3.0.0",
		packageVersion="1",
		priority=-90,
		setupScript="swaudit4.opsiscript",
		alwaysScript="swaudit4.opsiscript",
	)
	product2 = LocalbootProduct(id="dummy-update", productVersion="1.0", packageVersion="1", priority=0, updateScript="update.opsiscript")

	product_on_depot1 = ProductOnDepot(
		productId="swaudit", productType="localboot", productVersion="4.3.0.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot2 = ProductOnDepot(
		productId="dummy-update", productType="localboot", productVersion="1.0", packageVersion="1", depotId=depot_id
	)

	backend.host_createOpsiClient(id=client_id)
	backend.product_createObjects([product1, product2])
	backend.productOnDepot_createObjects([product_on_depot1, product_on_depot2])
	product_on_client_1 = ProductOnClient(
		productId="swaudit",
		productType="localboot",
		clientId=client_id,
		installationStatus="installed",
		actionRequest="always",
	)
	product_on_client_2 = ProductOnClient(
		productId="dummy-update",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="update",
	)

	res = backend.get_product_action_groups(  # type: ignore[misc]
		[product_on_client_1, product_on_client_2],
	)[client_id]

	assert len(res) == 2

	assert res[0].priority == 0
	assert len(res[0].product_on_clients) == 1
	assert res[0].product_on_clients[0].productId == "dummy-update"
	assert res[0].product_on_clients[0].actionRequest == "update"
	assert res[0].product_on_clients[0].actionSequence == 0

	assert res[1].priority == -90
	assert len(res[1].product_on_clients) == 1
	assert res[1].product_on_clients[0].productId == "swaudit"
	assert res[1].product_on_clients[0].actionRequest == "always"
	assert res[1].product_on_clients[0].actionSequence == 1

	product_ordering = backend.getProductOrdering(depotId=depot_id)
	assert product_ordering["not_sorted"] == [
		"dummy-update",
		"swaudit",
	]
	assert product_ordering["sorted"] == [
		"dummy-update",
		"swaudit",
	]


def test_get_product_action_groups_messe(
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	client_id = "test-client.opsi.org"
	depot_id = get_depotserver_id()

	config_state = ConfigState(configId="clientconfig.depot.id", objectId=client_id, values=[depot_id])
	backend.configState_createObjects([config_state])

	product1 = LocalbootProduct(
		id="opsi-linux-client-agent", productVersion="4.3.0.0", packageVersion="1", priority=95, setupScript="setup.opsiscript"
	)
	product2 = LocalbootProduct(
		id="opsi-configed", productVersion="4.3.0.0", packageVersion="1", priority=1, setupScript="setup.opsiscript"
	)
	product3 = LocalbootProduct(
		id="l-system-update", productVersion="4.3.0.0", packageVersion="1", priority=98, setupScript="setup.opsiscript"
	)
	product4 = LocalbootProduct(
		id="l-opsi-server", productVersion="4.3.0.0", packageVersion="1", priority=0, setupScript="setup.opsiscript"
	)
	product5 = LocalbootProduct(
		id="l-messe-desktop", productVersion="4.3.0.0", packageVersion="1", priority=0, setupScript="setup.opsiscript"
	)
	product6 = LocalbootProduct(
		id="install-completed", productVersion="4.3.0.0", packageVersion="1", priority=-98, customScript="custom.opsiscript"
	)
	product7 = LocalbootProduct(
		id="shutdown-system", productVersion="4.3.0.0", packageVersion="1", priority=-99, onceScript="once.opsiscript"
	)

	product_dependency1 = ProductDependency(
		productId="l-opsi-server",
		productVersion="4.3.0.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="l-system-update",
		requiredAction="setup",
		requirementType="before",
	)
	product_dependency2 = ProductDependency(
		productId="l-messe-desktop",
		productVersion="4.3.0.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="l-opsi-server",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency3 = ProductDependency(
		productId="l-messe-desktop",
		productVersion="4.3.0.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="opsi-configed",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency4 = ProductDependency(
		productId="l-messe-desktop",
		productVersion="4.3.0.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="install-completed",
		requiredAction="custom",
	)

	product_on_depot1 = ProductOnDepot(
		productId="opsi-linux-client-agent", productType="localboot", productVersion="4.3.0.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot2 = ProductOnDepot(
		productId="opsi-configed", productType="localboot", productVersion="4.3.0.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot3 = ProductOnDepot(
		productId="l-system-update", productType="localboot", productVersion="4.3.0.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot4 = ProductOnDepot(
		productId="l-opsi-server", productType="localboot", productVersion="4.3.0.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot5 = ProductOnDepot(
		productId="l-messe-desktop", productType="localboot", productVersion="4.3.0.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot6 = ProductOnDepot(
		productId="install-completed", productType="localboot", productVersion="4.3.0.0", packageVersion="1", depotId=depot_id
	)
	product_on_depot7 = ProductOnDepot(
		productId="shutdown-system", productType="localboot", productVersion="4.3.0.0", packageVersion="1", depotId=depot_id
	)

	backend.host_createOpsiClient(id=client_id)
	backend.product_createObjects([product1, product2, product3, product4, product5, product6, product7])
	backend.productDependency_createObjects([product_dependency1, product_dependency2, product_dependency3, product_dependency4])
	backend.productOnDepot_createObjects(
		[
			product_on_depot1,
			product_on_depot2,
			product_on_depot3,
			product_on_depot4,
			product_on_depot5,
			product_on_depot6,
			product_on_depot7,
		]
	)
	product_on_client_1 = ProductOnClient(
		productId="opsi-linux-client-agent",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	product_on_client_2 = ProductOnClient(
		productId="l-messe-desktop",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	product_on_client_3 = ProductOnClient(
		productId="shutdown-system",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="once",
	)

	for pocs in permutations([product_on_client_1, product_on_client_2, product_on_client_3]):
		res = backend.get_product_action_groups(list(pocs))[client_id]  # type: ignore[misc]

		assert len(res) == 4

		assert res[0].priority == 98
		assert len(res[0].product_on_clients) == 4
		assert res[0].product_on_clients[0].productId == "l-system-update"
		assert res[0].product_on_clients[0].actionRequest == "setup"
		assert res[0].product_on_clients[0].actionSequence == 0
		assert res[0].product_on_clients[1].productId == "opsi-configed"
		assert res[0].product_on_clients[1].actionRequest == "setup"
		assert res[0].product_on_clients[1].actionSequence == 1
		assert res[0].product_on_clients[2].productId == "l-opsi-server"
		assert res[0].product_on_clients[2].actionRequest == "setup"
		assert res[0].product_on_clients[2].actionSequence == 2
		assert res[0].product_on_clients[3].productId == "l-messe-desktop"
		assert res[0].product_on_clients[3].actionRequest == "setup"
		assert res[0].product_on_clients[3].actionSequence == 3

		assert res[1].priority == 95
		assert len(res[1].product_on_clients) == 1
		assert res[1].product_on_clients[0].productId == "opsi-linux-client-agent"
		assert res[1].product_on_clients[0].actionRequest == "setup"
		assert res[1].product_on_clients[0].actionSequence == 4

		assert res[2].priority == -98
		assert len(res[2].product_on_clients) == 1
		assert res[2].product_on_clients[0].productId == "install-completed"
		assert res[2].product_on_clients[0].actionRequest == "custom"
		assert res[2].product_on_clients[0].actionSequence == 5

		assert res[3].priority == -99
		assert len(res[3].product_on_clients) == 1
		assert res[3].product_on_clients[0].productId == "shutdown-system"
		assert res[3].product_on_clients[0].actionRequest == "once"
		assert res[3].product_on_clients[0].actionSequence == 6

	product_ordering = backend.getProductOrdering(depotId=depot_id)
	assert product_ordering["not_sorted"] == [
		"install-completed",
		"l-messe-desktop",
		"l-opsi-server",
		"l-system-update",
		"opsi-configed",
		"opsi-linux-client-agent",
		"shutdown-system",
	]
	assert product_ordering["sorted"] == [
		"l-system-update",
		"opsi-configed",
		"l-opsi-server",
		"l-messe-desktop",
		"opsi-linux-client-agent",
		"install-completed",
		"shutdown-system",
	]


def test_get_product_action_groups_vmware(
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	client_id = "test-client.opsi.org"
	depot_id = get_depotserver_id()

	product1 = LocalbootProduct(
		id="vmware-app-volumes-agent",
		name="App Volumes Agent",
		productVersion="4.8.0.33",
		packageVersion="9",
		priority=-98,
		setupScript="action-local.opsiscript",
		uninstallScript="action-local.opsiscript",
	)
	product2 = LocalbootProduct(
		id="vmware-dem-enterprise",
		name="VMware Dynamic Environment Manager Enterprise",
		productVersion="2203.10.5",
		packageVersion="1",
		priority=92,
		setupScript="setup3264.opsiscript",
		uninstallScript="uninstall3264.opsiscript",
	)
	product3 = LocalbootProduct(
		id="vmware-horizon-agent",
		name="VMware Horizon Agent",
		productVersion="2209.8.7.0.20606795",
		packageVersion="8",
		priority=93,
		setupScript="action-local.opsiscript",
		uninstallScript="action-local.opsiscript",
	)
	product4 = LocalbootProduct(
		id="vmware-osot",
		name="VMware Horizon OS Optimization Tool",
		productVersion="1.1.2204.19587979",
		packageVersion="16",
		priority=-80,
		setupScript="setup3264.opsiscript",
		uninstallScript="uninstall3264.opsiscript",
	)
	product5 = LocalbootProduct(
		id="vmware-powercli",
		name="VMware.PowerCLI",
		productVersion="12.0.0.15947286",
		packageVersion="2",
		priority=0,
		setupScript="setup3264.opsiscript",
		uninstallScript="uninstall3264.opsiscript",
	)
	product6 = LocalbootProduct(
		id="vmware-tools", name="VMware Tools", productVersion="1.1", packageVersion="6", priority=94, setupScript="setup3264.opsiscript"
	)
	product7 = LocalbootProduct(
		id="customize-startmenu",
		name="Customize Startmenu",
		productVersion="1",
		packageVersion="6",
		priority=-1,
		setupScript="action-local.opsiscript",
		uninstallScript="action-local.opsiscript",
	)

	product_dependency1 = ProductDependency(
		productId="vmware-app-volumes-agent",
		productVersion="4.8.0.33",
		packageVersion="9",
		productAction="setup",
		requiredProductId="vmware-osot",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency2 = ProductDependency(
		productId="vmware-osot",
		productVersion="1.1.2204.19587979",
		packageVersion="16",
		productAction="setup",
		requiredProductId="customize-startmenu",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency3 = ProductDependency(
		productId="vmware-osot",
		productVersion="1.1.2204.19587979",
		packageVersion="16",
		productAction="setup",
		requiredProductId="vmware-app-volumes-agent",
		requiredInstallationStatus="not_installed",
		requirementType="before",
	)
	product_dependency4 = ProductDependency(
		productId="vmware-osot",
		productVersion="1.1.2204.19587979",
		packageVersion="16",
		productAction="setup",
		requiredProductId="vmware-dem-enterprise",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency5 = ProductDependency(
		productId="vmware-osot",
		productVersion="1.1.2204.19587979",
		packageVersion="16",
		productAction="setup",
		requiredProductId="vmware-horizon-agent",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency6 = ProductDependency(
		productId="vmware-osot",
		productVersion="1.1.2204.19587979",
		packageVersion="16",
		productAction="setup",
		requiredProductId="vmware-tools",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency7 = ProductDependency(
		productId="vmware-tools",
		productVersion="1.1",
		packageVersion="6",
		productAction="setup",
		requiredProductId="vmware-app-volumes-agent",
		requiredInstallationStatus="not_installed",
		requirementType="before",
	)
	product_dependency8 = ProductDependency(
		productId="vmware-tools",
		productVersion="1.1",
		packageVersion="6",
		productAction="setup",
		requiredProductId="vmware-powercli",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency9 = ProductDependency(
		productId="vmware-app-volumes-agent",
		productVersion="4.8.0.33",
		packageVersion="9",
		productAction="setup",
		requiredProductId="vmware-dem-enterprise",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency10 = ProductDependency(
		productId="vmware-app-volumes-agent",
		productVersion="4.8.0.33",
		packageVersion="9",
		productAction="setup",
		requiredProductId="vmware-horizon-agent",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency11 = ProductDependency(
		productId="vmware-app-volumes-agent",
		productVersion="4.8.0.33",
		packageVersion="9",
		productAction="setup",
		requiredProductId="vmware-osot",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency12 = ProductDependency(
		productId="vmware-app-volumes-agent",
		productVersion="4.8.0.33",
		packageVersion="9",
		productAction="setup",
		requiredProductId="vmware-tools",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency13 = ProductDependency(
		productId="vmware-dem-enterprise",
		productVersion="2203.10.5",
		packageVersion="1",
		productAction="setup",
		requiredProductId="vmware-app-volumes-agent",
		requiredInstallationStatus="not_installed",
		requirementType="before",
	)
	product_dependency14 = ProductDependency(
		productId="vmware-dem-enterprise",
		productVersion="2203.10.5",
		packageVersion="1",
		productAction="setup",
		requiredProductId="vmware-horizon-agent",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency15 = ProductDependency(
		productId="vmware-dem-enterprise",
		productVersion="2203.10.5",
		packageVersion="1",
		productAction="setup",
		requiredProductId="vmware-tools",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency16 = ProductDependency(
		productId="vmware-horizon-agent",
		productVersion="2209.8.7.0.20606795",
		packageVersion="8",
		productAction="setup",
		requiredProductId="vmware-app-volumes-agent",
		requiredInstallationStatus="not_installed",
		requirementType="before",
	)
	product_dependency17 = ProductDependency(
		productId="vmware-horizon-agent",
		productVersion="2209.8.7.0.20606795",
		packageVersion="8",
		productAction="setup",
		requiredProductId="vmware-tools",
		requiredInstallationStatus="installed",
		requirementType="before",
	)

	product_on_depot1 = ProductOnDepot(
		productId="vmware-app-volumes-agent", productType="localboot", productVersion="4.8.0.33", packageVersion="9", depotId=depot_id
	)
	product_on_depot2 = ProductOnDepot(
		productId="vmware-dem-enterprise", productType="localboot", productVersion="2203.10.5", packageVersion="1", depotId=depot_id
	)
	product_on_depot3 = ProductOnDepot(
		productId="vmware-horizon-agent",
		productType="localboot",
		productVersion="2209.8.7.0.20606795",
		packageVersion="8",
		depotId=depot_id,
	)
	product_on_depot4 = ProductOnDepot(
		productId="vmware-osot", productType="localboot", productVersion="1.1.2204.19587979", packageVersion="16", depotId=depot_id
	)
	product_on_depot5 = ProductOnDepot(
		productId="vmware-powercli", productType="localboot", productVersion="12.0.0.15947286", packageVersion="2", depotId=depot_id
	)
	product_on_depot6 = ProductOnDepot(
		productId="vmware-tools", productType="localboot", productVersion="1.1", packageVersion="6", depotId=depot_id
	)
	product_on_depot7 = ProductOnDepot(
		productId="customize-startmenu", productType="localboot", productVersion="1", packageVersion="6", depotId=depot_id
	)

	backend.host_createOpsiClient(id=client_id)
	backend.product_createObjects([product1, product2, product3, product4, product5, product6, product7])
	backend.productDependency_createObjects(
		[
			product_dependency1,
			product_dependency2,
			product_dependency3,
			product_dependency4,
			product_dependency5,
			product_dependency6,
			product_dependency7,
			product_dependency8,
			product_dependency9,
			product_dependency10,
			product_dependency11,
			product_dependency12,
			product_dependency13,
			product_dependency14,
			product_dependency15,
			product_dependency16,
			product_dependency17,
		]
	)
	backend.productOnDepot_createObjects(
		[
			product_on_depot1,
			product_on_depot2,
			product_on_depot3,
			product_on_depot4,
			product_on_depot5,
			product_on_depot6,
			product_on_depot7,
		]
	)

	product_on_client_1 = ProductOnClient(
		productId="customize-startmenu",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	product_on_client_2 = ProductOnClient(
		productId="vmware-dem-enterprise",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	product_on_client_3 = ProductOnClient(
		productId="vmware-horizon-agent",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	product_on_client_4 = ProductOnClient(
		productId="vmware-osot",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	product_on_client_5 = ProductOnClient(
		productId="vmware-powercli",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	product_on_client_6 = ProductOnClient(
		productId="vmware-tools",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)

	for product_on_clients in (
		[product_on_client_4],
		[product_on_client_1, product_on_client_2, product_on_client_3, product_on_client_4, product_on_client_5, product_on_client_6],
	):
		res = backend.get_product_action_groups(product_on_clients)[client_id]  # type: ignore[misc]

		assert len(res) == 1
		assert res[0].priority == 94
		assert len(res[0].product_on_clients) == 6
		assert res[0].product_on_clients[0].productId == "vmware-powercli"
		assert res[0].product_on_clients[0].actionRequest == "setup"
		assert res[0].product_on_clients[0].actionSequence == 0
		assert res[0].product_on_clients[1].productId == "vmware-tools"
		assert res[0].product_on_clients[1].actionRequest == "setup"
		assert res[0].product_on_clients[1].actionSequence == 1
		assert res[0].product_on_clients[2].productId == "vmware-horizon-agent"
		assert res[0].product_on_clients[2].actionRequest == "setup"
		assert res[0].product_on_clients[2].actionSequence == 2
		assert res[0].product_on_clients[3].productId == "vmware-dem-enterprise"
		assert res[0].product_on_clients[3].actionRequest == "setup"
		assert res[0].product_on_clients[3].actionSequence == 3
		assert res[0].product_on_clients[4].productId == "customize-startmenu"
		assert res[0].product_on_clients[4].actionRequest == "setup"
		assert res[0].product_on_clients[4].actionSequence == 4
		assert res[0].product_on_clients[5].productId == "vmware-osot"
		assert res[0].product_on_clients[5].actionRequest == "setup"
		assert res[0].product_on_clients[5].actionSequence == 5


def test_get_product_action_groups_meta_ubuntu(
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	client_id = "test-client.opsi.org"
	depot_id = get_depotserver_id()

	config_state = ConfigState(configId="clientconfig.depot.id", objectId=client_id, values=[depot_id])
	backend.configState_createObjects([config_state])

	product1 = LocalbootProduct(
		id="l-grubww",
		name="l-grubww",
		productVersion="1.0",
		packageVersion="1",
		priority=0,
		setupScript="setup.opsiscript",
	)
	product2 = LocalbootProduct(
		id="l-finish-server",
		name="l-finish-server",
		productVersion="1.0",
		packageVersion="1",
		priority=-90,
		setupScript="setup.opsiscript",
	)
	product3 = LocalbootProduct(
		id="l-motd",
		name="l-motd",
		productVersion="1.0",
		packageVersion="1",
		priority=-10,
		setupScript="setup.opsiscript",
	)
	product4 = LocalbootProduct(
		id="meta-ubuntu",
		name="meta-ubuntu",
		productVersion="1.0",
		packageVersion="1",
		priority=0,
		setupScript="setup.opsiscript",
	)

	product_dependency1 = ProductDependency(
		productId="meta-ubuntu",
		productVersion="1.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="l-grubww",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency2 = ProductDependency(
		productId="meta-ubuntu",
		productVersion="1.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="l-finish-server",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_dependency3 = ProductDependency(
		productId="meta-ubuntu",
		productVersion="1.0",
		packageVersion="1",
		productAction="setup",
		requiredProductId="l-motd",
		requiredInstallationStatus="installed",
		requirementType="before",
	)

	product_on_depot1 = ProductOnDepot(
		productId="l-grubww",
		productType="localboot",
		productVersion="1.0",
		packageVersion="1",
		depotId=depot_id,
	)
	product_on_depot2 = ProductOnDepot(
		productId="l-finish-server",
		productType="localboot",
		productVersion="1.0",
		packageVersion="1",
		depotId=depot_id,
	)
	product_on_depot3 = ProductOnDepot(
		productId="l-motd",
		productType="localboot",
		productVersion="1.0",
		packageVersion="1",
		depotId=depot_id,
	)
	product_on_depot4 = ProductOnDepot(
		productId="meta-ubuntu",
		productType="localboot",
		productVersion="1.0",
		packageVersion="1",
		depotId=depot_id,
	)

	backend.host_createOpsiClient(id=client_id)
	backend.product_createObjects([product1, product2, product3, product4])
	backend.productDependency_createObjects([product_dependency1, product_dependency2, product_dependency3])
	backend.productOnDepot_createObjects([product_on_depot1, product_on_depot2, product_on_depot3, product_on_depot4])

	product_on_client_1 = ProductOnClient(
		productId="l-grubww",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)
	product_on_client_2 = ProductOnClient(
		productId="l-finish-server",
		productType="localboot",
		productVersion="1.0",
		packageVersion="1",
		clientId=client_id,
		installationStatus="installed",
		actionRequest="setup",
	)
	product_on_client_3 = ProductOnClient(
		productId="l-motd",
		productType="localboot",
		productVersion="1.0",
		packageVersion="1",
		clientId=client_id,
		installationStatus="installed",
		actionRequest="setup",
	)
	product_on_client_4 = ProductOnClient(
		productId="meta-ubuntu",
		productType="localboot",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)

	for pocs in permutations([product_on_client_1, product_on_client_2, product_on_client_3, product_on_client_4]):
		res = backend.get_product_action_groups(list(pocs))[client_id]  # type: ignore[misc]

		assert len(res) == 1
		assert res[0].priority == -90
		assert len(res[0].product_on_clients) == 4
		assert res[0].product_on_clients[0].productId == "l-grubww"
		assert res[0].product_on_clients[0].actionRequest == "setup"
		assert res[0].product_on_clients[0].actionSequence == 0
		assert res[0].product_on_clients[1].productId == "l-motd"
		assert res[0].product_on_clients[1].actionRequest == "setup"
		assert res[0].product_on_clients[1].actionSequence == 1
		assert res[0].product_on_clients[2].productId == "l-finish-server"
		assert res[0].product_on_clients[2].actionRequest == "setup"
		assert res[0].product_on_clients[2].actionSequence == 2
		assert res[0].product_on_clients[3].productId == "meta-ubuntu"
		assert res[0].product_on_clients[3].actionRequest == "setup"
		assert res[0].product_on_clients[3].actionSequence == 3


def create_test_product_dependencies(test_client: OpsiconfdTestClient) -> tuple:  # noqa: F811
	product1, product2 = create_test_products(test_client)

	product_dependency1 = {
		"productId": product1["id"],
		"productVersion": product1["productVersion"],
		"packageVersion": product1["packageVersion"],
		"productAction": "setup",
		"requiredProductId": product2["id"],
		"requiredProductVersion": product2["productVersion"],
		"requiredPackageVersion": product2["packageVersion"],
	}
	product_dependency2 = {
		"productId": product2["id"],
		"productVersion": product2["productVersion"],
		"packageVersion": product2["packageVersion"],
		"productAction": "setup",
		"requiredProductId": product1["id"],
		"requiredProductVersion": product1["productVersion"],
		"requiredPackageVersion": product1["packageVersion"],
	}

	# Create product 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_insertObject", "params": [product_dependency1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create product 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_insertObject", "params": [product_dependency2]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	return (product_dependency1, product_dependency2)


def check_products_dependencies(
	test_client: OpsiconfdTestClient,  # noqa: F811
	product_dependencies: list,
) -> None:
	for product_dependency in product_dependencies:
		rpc = {
			"jsonrpc": "2.0",
			"id": 1,
			"method": "productDependency_getObjects",
			"params": [[], {"productId": product_dependency["productId"]}],
		}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res
		print(res)
		dependency = res["result"][0]
		for attr, val in product_dependency.items():
			assert val == dependency[attr]


def test_product_dependency_insertObject(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_dependency1, product_dependency2 = create_test_product_dependencies(test_client)

	# productDependency 1 and 2 should be created
	check_products_dependencies(test_client, [product_dependency1, product_dependency2])


def test_product_dependency_createObject(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	product1, product2 = create_test_products(test_client)

	product_dependency1 = {
		"productId": product1["id"],
		"productVersion": product1["productVersion"],
		"packageVersion": product1["packageVersion"],
		"productAction": "setup",
		"requiredProductId": product2["id"],
		"requiredProductVersion": product2["productVersion"],
		"requiredPackageVersion": product2["packageVersion"],
	}
	product_dependency2 = {
		"productId": product2["id"],
		"productVersion": product2["productVersion"],
		"packageVersion": product2["packageVersion"],
		"productAction": "setup",
		"requiredProductId": product1["id"],
		"requiredProductVersion": product1["productVersion"],
		"requiredPackageVersion": product1["packageVersion"],
	}

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_createObjects", "params": [[product_dependency1, product_dependency2]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# productDependency 1 and 2 should be created
	check_products_dependencies(test_client, [product_dependency1, product_dependency2])


def test_product_dependency_create(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	product1, product2 = create_test_products(test_client)

	product3 = {
		"name": "test-backend-rpc-product-3",
		"licenseRequired": False,
		"setupScript": "setup.opsiscript",
		"uninstallScript": "uninstall.opsiscript",
		"updateScript": "update.opsiscript",
		"priority": -100,
		"description": "test-backend-rpc-product 2",
		"advice": "Some advice ",
		"id": "test-backend-rpc-product-2",
		"productVersion": "5.3.0",
		"packageVersion": "2",
		"type": "LocalbootProduct",
	}
	# Create product 3
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_insertObject", "params": [product3]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	product_dependency1 = {
		"productId": product2["id"],
		"productVersion": product2["productVersion"],
		"packageVersion": product2["packageVersion"],
		"productAction": "setup",
		"requiredProductId": product1["id"],
		"requiredProductVersion": product1["productVersion"],
		"requiredPackageVersion": product1["packageVersion"],
	}
	product_dependency2 = {
		"productId": product1["id"],
		"productVersion": product1["productVersion"],
		"packageVersion": product1["packageVersion"],
		"productAction": "setup",
		"requiredProductId": product3["id"],
		"requiredProductVersion": product3["productVersion"],
		"requiredPackageVersion": product3["packageVersion"],
	}

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_create", "params": list(product_dependency1.values())}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_create", "params": list(product_dependency2.values())}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# productDependency 2 should be created
	check_products_dependencies(test_client, [product_dependency1, product_dependency2])


def test_product_dependency_updateObject(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_dependency1, product_dependency2 = create_test_product_dependencies(test_client)

	# product 1 and 2 should be created
	check_products_dependencies(test_client, [product_dependency1, product_dependency2])

	# Update product 1
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_updateObject",
		"params": [
			{
				"productId": product_dependency1["productId"],
				"productVersion": product_dependency1["productVersion"],
				"packageVersion": product_dependency1["packageVersion"],
				"productAction": product_dependency1["productAction"],
				"requiredProductId": product_dependency1["requiredProductId"],
				"requiredAction": "none",
			}
		],
	}
	print(rpc)
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product_dependency = res["result"][0]
	for attr, val in product_dependency1.items():
		if attr == "requiredAction":
			assert product_dependency[attr] == "none"
		else:
			assert product_dependency[attr] == val

	# No new product dependency should be created.
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_updateObject",
		"params": [
			{
				"productId": product_dependency1["productId"],
				"productVersion": product_dependency1["productVersion"],
				"packageVersion": product_dependency1["packageVersion"],
				"productAction": product_dependency1["productAction"],
				"requiredProductId": "new-product",
				"requiredAction": "none",
			}
		],
	}

	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_getObjects", "params": [[], {"productId": "new-product"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 0

	# update 2 product dependencies
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_updateObjects",
		"params": [
			[
				{
					"productId": product_dependency1["productId"],
					"productVersion": product_dependency1["productVersion"],
					"packageVersion": product_dependency1["packageVersion"],
					"productAction": product_dependency1["productAction"],
					"requiredProductId": product_dependency1["requiredProductId"],
					"requiredAction": "none",
				},
				{
					"productId": product_dependency2["productId"],
					"productVersion": product_dependency2["productVersion"],
					"packageVersion": product_dependency2["packageVersion"],
					"productAction": product_dependency2["productAction"],
					"requiredProductId": product_dependency2["requiredProductId"],
					"requiredAction": "none",
				},
			]
		],
	}
	print(rpc)
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_getObjects",
		"params": [[], {"productId": product_dependency1["productId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)

	for product_dependency in res["result"]:
		for attr, val in product_dependency1.items():
			if attr == "requiredAction":
				assert product_dependency[attr] == "none"
			else:
				assert product_dependency[attr] == val


@pytest.mark.filterwarnings("ignore:.*calling deprecated method.*")
def test_product_dependency_getHashes(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_dependency1, product_dependency2 = create_test_product_dependencies(test_client)

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_getHashes",
		"params": [[], {"productId": product_dependency1["productId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	poc = res["result"][0]
	for attr, val in product_dependency1.items():
		assert val == poc[attr]

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_getHashes",
		"params": [[], {"productId": product_dependency2["productId"]}],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	poc = res["result"][0]
	for attr, val in product_dependency2.items():
		assert val == poc[attr]


def test_product_dependency_getIdents(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_dependency1, product_dependency2 = create_test_product_dependencies(test_client)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_getIdents", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	assert res["result"] == [
		(
			f"{product_dependency1['productId']};"
			f"{product_dependency1['productVersion']};"
			f"{product_dependency1['packageVersion']};"
			f"{product_dependency1['productAction']};"
			f"{product_dependency1['requiredProductId']}"
		),
		(
			f"{product_dependency2['productId']};"
			f"{product_dependency2['productVersion']};"
			f"{product_dependency2['packageVersion']};"
			f"{product_dependency2['productAction']};"
			f"{product_dependency2['requiredProductId']}"
		),
	]


def test_product_dependency_delete(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product_dependency1, product_dependency2 = create_test_product_dependencies(test_client)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_getObjects", "params": [[], {}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 2

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_delete",
		"params": [
			product_dependency1["productId"],
			product_dependency1["productVersion"],
			product_dependency1["packageVersion"],
			product_dependency1["productAction"],
			product_dependency1["requiredProductId"],
		],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 1

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "productDependency_delete",
		"params": [
			product_dependency2["productId"],
			product_dependency2["productVersion"],
			product_dependency2["packageVersion"],
			product_dependency2["productAction"],
			product_dependency2["requiredProductId"],
		],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productDependency_getObjects", "params": [[], {"productId": "test-backend-rpc-product*"}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert len(res["result"]) == 0
