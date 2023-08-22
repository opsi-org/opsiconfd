# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.host_control
"""

from typing import Any
import pytest
from unittest import mock

from opsiconfd.config import get_depotserver_id

from opsicommon.objects import ProductDependency, ProductOnDepot, ProductOnClient, LocalbootProduct, OpsiClient
from tests.utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_redis,
	test_client,
	UnprotectedBackend,
	backend,
)


@pytest.mark.asyncio
async def test_hostControl_processActionRequests(  # pylint: disable=invalid-name
	backend: UnprotectedBackend,  # pylint: disable=redefined-outer-name
) -> None:
	client_id = "test-client.opsi.org"
	depot_id = get_depotserver_id()

	messagebus_rpcs = []

	async def mock_messagebus_rpc(  # pylint: disable=too-many-locals,unused-argument
		self: UnprotectedBackend, client_ids: list[str], method: str, params: list[Any] | None = None, timeout: float | int | None = None
	) -> None:
		nonlocal messagebus_rpcs
		messagebus_rpcs.append((client_ids, method, params))

	client1 = OpsiClient(id=client_id)
	product1 = LocalbootProduct(id="prod1", productVersion="1", packageVersion="1", setupScript="setup.opsiscript")
	product2 = LocalbootProduct(id="prod2", productVersion="1", packageVersion="1", setupScript="setup.opsiscript")
	product3 = LocalbootProduct(id="prod3", productVersion="1", packageVersion="1", setupScript="setup.opsiscript")
	product_dependency1 = ProductDependency(
		productId="prod1",
		productVersion="1",
		packageVersion="1",
		productAction="setup",
		requiredProductId="prod2",
		requiredInstallationStatus="installed",
		requirementType="before",
	)
	product_on_depot1 = ProductOnDepot(productId="prod1", productType="localboot", productVersion="1", packageVersion="1", depotId=depot_id)
	product_on_depot2 = ProductOnDepot(productId="prod2", productType="localboot", productVersion="1", packageVersion="1", depotId=depot_id)
	product_on_depot3 = ProductOnDepot(productId="prod3", productType="localboot", productVersion="1", packageVersion="1", depotId=depot_id)

	product_on_client1 = ProductOnClient(
		productId="prod1",
		productType="localboot",
		productVersion="1",
		packageVersion="1",
		clientId=client_id,
		installationStatus="not_installed",
		actionRequest="setup",
	)

	backend.host_createObjects([client1])
	backend.product_createObjects([product1, product2, product3])
	backend.productDependency_createObjects([product_dependency1])
	backend.productOnDepot_createObjects([product_on_depot1, product_on_depot2, product_on_depot3])
	backend.productOnClient_createObjects([product_on_client1])

	with mock.patch("opsiconfd.backend.rpc.host_control.RPCHostControlMixin._host_control_use_messagebus", True), mock.patch(
		"opsiconfd.backend.rpc.host_control.RPCHostControlMixin._messagebus_rpc", mock_messagebus_rpc
	):
		# Dependent product must be added
		await backend.hostControl_processActionRequests(hostIds=[client_id], productIds=["prod1"])
		assert len(messagebus_rpcs) == 1
		assert messagebus_rpcs[0] == ([client_id], "processActionRequests", [["prod2", "prod1"]])
		pocs = backend.productOnClient_getObjects(clientId=client_id)
		assert len(pocs) == 2
		for poc in pocs:
			assert poc.productId in ("prod1", "prod2")
			assert poc.actionRequest == "setup"

		# Dependency fulfilled
		messagebus_rpcs = []
		product_on_client2 = ProductOnClient(
			productId="prod2",
			productType="localboot",
			productVersion="1",
			packageVersion="1",
			clientId=client_id,
			installationStatus="installed",
			actionRequest="none",
		)
		product_on_client3 = ProductOnClient(
			productId="prod3",
			productType="localboot",
			productVersion="1",
			packageVersion="1",
			clientId=client_id,
			installationStatus="not_installed",
			actionRequest="setup",
		)
		backend.productOnClient_createObjects([product_on_client1, product_on_client2, product_on_client3])
		await backend.hostControl_processActionRequests(hostIds=[client_id], productIds=["prod1"])
		assert len(messagebus_rpcs) == 1
		assert messagebus_rpcs[0] == ([client_id], "processActionRequests", [["prod1"]])

		pocs = backend.productOnClient_getObjects(clientId=client_id)
		assert len(pocs) == 3
		for poc in pocs:
			if poc.productId in ("prod1", "prod3"):
				assert poc.actionRequest == "setup"
			else:
				assert poc.actionRequest == "none"

		# No productId param
		messagebus_rpcs = []
		await backend.hostControl_processActionRequests(hostIds=[client_id])
		assert len(messagebus_rpcs) == 1
		assert messagebus_rpcs[0] == ([client_id], "processActionRequests", [])
