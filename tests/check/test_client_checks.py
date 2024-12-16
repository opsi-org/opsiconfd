# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
client check tests
"""

from datetime import datetime

from opsicommon.objects import LocalbootProduct, OpsiClient, ProductOnClient

from opsiconfd.check.clients import failed_clients_check, last_seen_check
from opsiconfd.check.common import CheckStatus, check_manager
from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	cache_clear,
	clean_mysql,
	clean_redis,
	cleanup_checks,
	test_client,
)


def _prepare_client(test_client: OpsiconfdTestClient) -> OpsiClient:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client = OpsiClient(id="test-check-client-1.opsi.test", lastSeen="2021-09-01 00:00:00")
	client.setDefaults()

	product = LocalbootProduct(id="opsi-client-agent", productVersion="4.3.0.1", packageVersion="1")
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_createObjects", "params": [[product.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	product_on_client = ProductOnClient(
		productId=product.id,
		productVersion=product.productVersion,
		packageVersion=product.packageVersion,
		productType=product.getType(),
		clientId=client.id,
		actionResult="failed",
		installationStatus="unknown",
	)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_createObjects", "params": [[product_on_client.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	return client


def _prepare_product(test_client: OpsiconfdTestClient, client: OpsiClient) -> ProductOnClient:  # noqa: F811
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	product = LocalbootProduct(id="opsi-client-agent", productVersion="4.3.0.1", packageVersion="1")
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_createObjects", "params": [[product.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	product_on_client = ProductOnClient(
		productId=product.id,
		productVersion=product.productVersion,
		packageVersion=product.packageVersion,
		productType=product.getType(),
		clientId=client.id,
		actionResult="failed",
		installationStatus="unknown",
	)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_createObjects", "params": [[product_on_client.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	return product_on_client


def test_opsi_active_clients_check(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	client = _prepare_client(test_client)

	check_manager.register(last_seen_check)
	result = check_manager.get("opsi_active_clients").run(clear_cache=True)

	assert result.check_status == CheckStatus.WARNING

	now = datetime.now()
	client.lastSeen = now.strftime("%Y-%m-%d %H:%M:%S")
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_createObjects", "params": [[client.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	result = check_manager.get("opsi_active_clients").run(clear_cache=True)

	assert result.check_status == CheckStatus.OK


def test_opsi_failed_clients_check(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	client = _prepare_client(test_client)
	product_on_client = _prepare_product(test_client, client)
	check_manager.register(failed_clients_check)
	result = check_manager.get("opsi_failed_clients").run(clear_cache=True)

	assert result.check_status == CheckStatus.ERROR

	product_on_client.actionResult = "successful"
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "productOnClient_createObjects", "params": [[product_on_client.to_hash()]]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	result = check_manager.get("opsi_failed_clients").run(clear_cache=True)

	assert result.check_status == CheckStatus.OK
