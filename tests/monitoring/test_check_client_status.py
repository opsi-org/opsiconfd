# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application check client status
"""

import json

from fastapi import status

from opsiconfd.application.monitoring.check_client_status import check_client_status
from opsiconfd.config import get_configserver_id
from tests.utils import (  # noqa: F401
	OpsiconfdTestClient,
	UnprotectedBackend,
	backend,
	client_jsonrpc,
	get_dummy_products,
	poc_jsonrpc,
	products_jsonrpc,
	test_client,
)


def test_check_client_status(backend: UnprotectedBackend, test_client: OpsiconfdTestClient) -> None:  # noqa: F811  # noqa: F811
	client_id = "test-client0815.uib.local"

	# check client that does not exists -> result sould be UNKNOWN
	result = check_client_status(backend, client_id=client_id)
	assert result.status_code == status.HTTP_200_OK
	body = json.loads(result.body.decode("utf-8"))
	assert body.get("state") == 3
	assert body.get("message") == f"UNKNOWN: opsi-client: '{client_id}' not found"

	with client_jsonrpc(test_client, "", client_id):
		# check client without products -> state sould be OK
		result = check_client_status(backend, client_id=client_id)

		assert result.status_code == status.HTTP_200_OK
		body = json.loads(result.body.decode("utf-8"))
		assert body.get("state") == 0
		assert body.get("message") == (f"OK: opsi-client {client_id} has been seen today. No failed products and no actions set for client")

		products = get_dummy_products(3)
		product_ids = [p["id"] for p in products]
		with (
			products_jsonrpc(test_client, "", products, depots=[get_configserver_id()]),
			poc_jsonrpc(test_client, "", client_id, product_ids[0], install_state="installed"),
		):
			result = check_client_status(backend, client_id=client_id)
			assert result.status_code == status.HTTP_200_OK
			body = json.loads(result.body.decode("utf-8"))
			assert body.get("state") == 0
			assert body.get("message") == (
				f"OK: opsi-client {client_id} has been seen today. No failed products and no actions set for client"
			)
		with (
			products_jsonrpc(test_client, "", products, depots=[get_configserver_id()]),
			poc_jsonrpc(test_client, "", client_id, product_ids[0], action_request="setup"),
		):
			result = check_client_status(backend, client_id=client_id)
			assert result.status_code == status.HTTP_200_OK
			body = json.loads(result.body.decode("utf-8"))
			print(body)
			assert body.get("state") == 1
			assert body.get("message") == (
				f"WARNING: opsi-client {client_id} has been seen today. Actions set for products: 'dummy-prod-0 (setup)'."
			)
		with (
			products_jsonrpc(test_client, "", products, depots=[get_configserver_id()]),
			poc_jsonrpc(test_client, "", client_id, product_ids[0], action_result="failed"),
		):
			result = check_client_status(backend, client_id=client_id)
			assert result.status_code == status.HTTP_200_OK
			body = json.loads(result.body.decode("utf-8"))
			print(body)
			assert body.get("state") == 2
			assert body.get("message") == (
				f"CRITICAL: opsi-client {client_id} has been seen today. Products: 'dummy-prod-0' are in failed state. "
			)
		with (
			products_jsonrpc(test_client, "", products, depots=[get_configserver_id()]),
			poc_jsonrpc(test_client, "", client_id, product_ids[0], action_request="setup"),
			poc_jsonrpc(test_client, "", client_id, product_ids[1], action_result="failed"),
			poc_jsonrpc(test_client, "", client_id, product_ids[2], action_result="failed"),
		):
			result = check_client_status(backend, client_id=client_id)
			assert result.status_code == status.HTTP_200_OK
			body = json.loads(result.body.decode("utf-8"))
			print(body)
			assert body.get("state") == 2
			assert body.get("message") == (
				f"CRITICAL: opsi-client {client_id} has been seen today. "
				"Products: 'dummy-prod-1, dummy-prod-2' are in failed state. "
				"Actions set for products: 'dummy-prod-0 (setup)'."
			)