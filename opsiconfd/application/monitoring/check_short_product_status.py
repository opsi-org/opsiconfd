# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check short product status
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from opsiconfd.logging import logger

from .utils import State, generate_response, remove_percent

if TYPE_CHECKING:
	from opsiconfd.backend.rpc.main import Backend


def check_short_product_status(
	backend: Backend, product_id: str | None = None, thresholds: dict[str, str] | None = None
) -> JSONResponse:
	thresholds = thresholds or {}
	if isinstance(product_id, list):
		try:
			product_id = product_id[0]
		except IndexError as err:
			logger.debug("Error while reading product_id: %s. Setting product_id to None.", err)
			product_id = None
	if not product_id:
		return generate_response(State.UNKNOWN, "No ProductId given.")

	action_request_on_clients = []
	product_problems_on_clients = []
	product_version_problems_on_clients = []
	uptodate_clients = []
	target_product_version = None
	target_packacke_version = None

	state = State.OK

	message = []

	warning = thresholds.get("warning", "20")
	critical = thresholds.get("critical", "20")
	warning_flt = float(remove_percent(warning))
	critical_flt = float(remove_percent(critical))

	logger.debug("Checking shortly the productStates on Clients")
	config_server = backend.host_getObjects(type="OpsiConfigserver")[0]

	for pod in backend.productOnDepot_getObjects(depotId=config_server.id, productId=product_id):
		target_product_version = pod.productVersion
		target_packacke_version = pod.packageVersion

	product_on_clients = backend.productOnClient_getObjects(productId=product_id)
	if not product_on_clients:
		return generate_response(State.UNKNOWN, f"No ProductStates found for product '{product_id}'")

	for poc in product_on_clients:
		if poc.installationStatus != "not_installed" and poc.actionResult != "successful" and poc.actionResult != "none":
			if poc.clientId not in product_problems_on_clients:
				product_problems_on_clients.append(poc.clientId)
				continue

		if poc.actionRequest != "none":
			if poc.clientId not in action_request_on_clients:
				action_request_on_clients.append(poc.clientId)
				continue

		if not poc.productVersion or not poc.packageVersion:
			continue

		if poc.productVersion != target_product_version or poc.packageVersion != target_packacke_version:
			product_version_problems_on_clients.append(poc.clientId)
			continue

		if poc.actionResult == "successful":
			uptodate_clients.append(poc.clientId)

	message.append(
		f"{len(product_on_clients)} ProductStates for product: '{product_id}' found; "
		f"checking for Version: '{target_product_version}' and Package: '{target_packacke_version}'"
	)
	if uptodate_clients:
		message.append(f"{len(uptodate_clients)} Clients are up to date")
	if action_request_on_clients and len(action_request_on_clients) * 100 / len(product_on_clients) > warning_flt:
		state = State.WARNING
		message.append(f"ActionRequest set on {len(action_request_on_clients)} clients")
	if product_problems_on_clients:
		message.append(f"Problems found on {len(product_problems_on_clients)} clients")
	if product_version_problems_on_clients:
		message.append(f"Version difference found on {len(product_version_problems_on_clients)} clients")

	problem_clients_count = len(product_problems_on_clients) + len(product_version_problems_on_clients)
	if problem_clients_count * 100 / len(product_on_clients) > critical_flt:
		state = State.CRITICAL

	return generate_response(state, "; ".join(message))
