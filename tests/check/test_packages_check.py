# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check tests
"""

from opsicommon.objects import LocalbootProduct, OpsiClient, OpsiDepotserver, ProductOnClient, ProductOnDepot

import opsiconfd.check.opsipackages  # noqa: F401
from opsiconfd.check.common import CheckStatus, check_manager
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	test_client,
)


def _prepare_products(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	depot = OpsiDepotserver(id="test-check-depot-1.opsi.test")
	client = OpsiClient(id="test-check-client-1.opsi.test")
	client.setDefaults()
	product = LocalbootProduct(id="opsi-client-agent", productVersion="4.3.4.1", packageVersion="1")
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_createObjects", "params": [[product.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	product_on_depot = ProductOnDepot(
		productId=product.id,
		productType=product.getType(),
		productVersion=product.productVersion,
		packageVersion=product.packageVersion,
		depotId=depot.id,
	)
	product = LocalbootProduct(id="opsi-client-agent", productVersion="4.3.0.0", packageVersion="1")
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_createObjects", "params": [[product.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	product_on_client = ProductOnClient(
		productId=product.id,
		productVersion=product.productVersion,
		packageVersion=product.packageVersion,
		productType=product.getType(),
		clientId=client.id,
		installationStatus="installed",
	)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[depot.to_hash(), client.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnDepot_createObjects", "params": [[product_on_depot.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_createObjects", "params": [[product_on_client.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res


def test_check_product_on_depots(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	_prepare_products(test_client=test_client)
	result = check_manager.get("products_on_depots").run(use_cache=False)
	print(result)
	assert result.check_status == CheckStatus.ERROR
	assert "4 issue(s) found." in result.message
	assert result.upgrade_issue == "4.3"
	found = 0
	for partial_result in result.partial_results:
		# print(partial_result)
		if partial_result.check.id == "product_on_depot:test-check-depot-1.opsi.test:opsi-script":
			found += 1
			assert partial_result.check_status == CheckStatus.ERROR
			assert "not installed" in partial_result.message
			assert partial_result.upgrade_issue == "4.3"
		if partial_result.check.id == "product_on_depot:test-check-depot-1.opsi.test:opsi-client-agent":
			found += 1
			assert partial_result.check_status == CheckStatus.ERROR
			assert "is outdated" in partial_result.message
			assert partial_result.upgrade_issue == "4.3"
	assert found == 2


def test_check_product_on_clients(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	_prepare_products(test_client=test_client)
	result = check_manager.get("products_on_clients").run(use_cache=False)
	# print(result)
	assert result.check_status == CheckStatus.ERROR
	assert "are out of date" in result.message
	assert result.upgrade_issue == "4.3"

	found = 0
	for partial_result in result.partial_results:
		# print(partial_result)
		if partial_result.check.id == "products_on_clients:test-check-client-1.opsi.test:opsi-client-agent":
			found += 1
			assert partial_result.check_status == CheckStatus.ERROR
			assert "is outdated" in partial_result.message
			assert partial_result.upgrade_issue == "4.3"
	assert found == 1
