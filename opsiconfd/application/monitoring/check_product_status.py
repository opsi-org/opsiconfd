# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.application.monitoring.check_product_status
"""

from collections import defaultdict
from typing import Dict, List, Set

from fastapi.responses import JSONResponse
from OPSI.Backend import BackendManager  # type: ignore[import]
from OPSI.Backend.Backend import temporaryBackendOptions  # type: ignore[import]

from opsiconfd.logging import logger

from .utils import State, generate_response


def check_product_status(  # pylint: disable=too-many-arguments, too-many-locals, too-many-branches, too-many-statements
	backend: BackendManager,
	product_ids: List[str] | Set[str] | None = None,
	product_groups: List[str] | None = None,
	host_group_ids: List[str] | None = None,
	depot_ids: List[str] | None = None,
	exclude: List[str] | None = None,
	verbose: bool = False,
	strict: bool = False,
) -> JSONResponse:
	product_groups = product_groups or []
	host_group_ids = host_group_ids or []
	depot_ids = depot_ids or []
	exclude = exclude or []
	if not product_ids:
		product_ids = set()
		for product in backend.objectToGroup_getIdents(groupType="ProductGroup", groupId=product_groups):
			product = product.split(",")[2]
			if product not in exclude:
				product_ids.add(product)

	if not product_ids:
		return generate_response(State.UNKNOWN, "Neither productId nor productGroup given, nothing to check!")

	server_type = "OpsiDepotserver"
	if not depot_ids:
		server_type = "OpsiConfigserver"

	depots_objects = backend.host_getObjects(attributes=["id"], type=server_type)
	depots = list(set(depot.id for depot in depots_objects))
	del depots_objects
	if not depot_ids or depot_ids[0] == "all":
		depot_ids = depots
	else:
		for depot_id in depot_ids:
			if depot_id not in depots:
				return generate_response(State.UNKNOWN, f"Depot '{depot_id}' not found")
	del depots

	if host_group_ids:
		object_to_groups = backend.objectToGroup_getObjects(groupId=host_group_ids, groupType="HostGroup")
		if object_to_groups:
			client_ids = [object_to_group.objectId for object_to_group in object_to_groups]
		else:
			client_ids = []  # pylint: disable=use-tuple-over-list
	else:
		client_ids = backend.host_getIdents(type="OpsiClient")

	clients_on_depot = defaultdict(list)
	for config_object, config_state in backend.configState_getValues(
		config_ids=["clientconfig.depot.id"], object_ids=client_ids, with_defaults=True
	).items():
		if not config_state.get("clientconfig.depot.id") or not config_state.get("clientconfig.depot.id")[0]:
			logger.error("No depot server configured for client '%s'", config_object)
			continue

		depot_id = config_state.get("clientconfig.depot.id")[0]
		if depot_id not in depot_ids:
			continue

		clients_on_depot[depot_id].append(config_object)

	if not clients_on_depot:
		return generate_response(
			State.UNKNOWN, f"Depots and clients dont match. Selected depots: {depot_ids}, selected clients: {client_ids}"
		)
	product_on_depot_info: Dict[str, Dict[str, Dict[str, str]]] = defaultdict(dict)

	for pod in backend.productOnDepot_getObjects(depotId=depot_ids, productId=list(product_ids)):
		product_on_depot_info[pod.depotId][pod.productId] = {"productVersion": pod.productVersion, "packageVersion": pod.packageVersion}

	state = State.OK
	product_version_problems_on_client: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
	product_problems_on_client: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
	action_request_on_client: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
	missing_products = {}
	action_requests_to_ignore = set([None, "none", "always"])

	for depot_id in depot_ids:
		if depot_id not in clients_on_depot.keys():
			continue

		poducts_on_client = backend.productOnClient_getObjects(productId=list(product_ids), clientId=clients_on_depot.get(depot_id, None))

		not_installed = set(product_ids.copy())
		for poc in poducts_on_client:  # pylint: disable=protected-access, line-too-long
			not_installed.discard(poc.productId)
			if poc.actionRequest not in action_requests_to_ignore:
				if state != State.CRITICAL:
					state = State.WARNING

				action_request_on_client[depot_id][poc.productId].append(  # pylint: disable=loop-invariant-statement
					f"{poc.clientId} ({ poc.actionRequest})"
				)

			if poc.installationStatus != "not_installed" and poc.actionResult != "successful" and poc.actionResult != "none":
				if state != State.CRITICAL:
					state = State.CRITICAL

				product_problems_on_client[depot_id][poc.productId].append(  # pylint: disable=loop-invariant-statement
					f"{poc.clientId} ({poc.actionResult} lastAction: [{poc.lastAction}])"
				)

			if not poc.productVersion or not poc.packageVersion:
				continue

			if depot_id not in product_on_depot_info:  # pylint: disable=loop-invariant-statement
				continue

			try:  # pylint: disable=loop-try-except-usage
				product_on_depot = product_on_depot_info[depot_id][poc.productId]  # pylint: disable=loop-invariant-statement
			except KeyError:
				logger.debug("Product %s not found on depot %s", poc.productId, depot_id)
				continue

			if poc.productVersion != product_on_depot["productVersion"] or poc.packageVersion != product_on_depot["packageVersion"]:
				if state != State.CRITICAL:
					state = State.WARNING

				product_version_problems_on_client[depot_id][poc.productId].append(  # pylint: disable=loop-invariant-statement
					f"{poc.clientId} ({poc.productVersion}-{poc.packageVersion})"
				)

		if strict and not_installed:
			missing_products[depot_id] = not_installed
			state = State.CRITICAL

	message = ""
	for depot_id in depot_ids:
		if (
			depot_id in action_request_on_client
			or depot_id in product_problems_on_client
			or depot_id in product_version_problems_on_client
			or missing_products.get(depot_id)
		):
			message += f"\nResult for Depot: '{depot_id}':\n"
		else:
			continue

		if depot_id in action_request_on_client:
			for product, clients in action_request_on_client[depot_id].items():
				message += f"For product '{product}' action set on {len(clients)} clients!\n"
		if depot_id in product_problems_on_client:
			for product, clients in product_problems_on_client[depot_id].items():
				message += f"For product '{product}' problems found on {len(clients)} clients!\n"
		if depot_id in product_version_problems_on_client:
			for product, clients in product_version_problems_on_client[depot_id].items():
				message += f"For product '{product}' version difference problems found on {len(clients)} clients!\n"
		if missing_products.get(depot_id):
			for product in missing_products[depot_id]:
				message += f"Product '{product}' not found on any client assigned to depot {depot_id}."

	if not verbose:
		if state == State.OK:
			products = ",".join(product_ids)
			message = f"No Problem found for productIds: '{products}'"
		return generate_response(state, message)

	for depot_id in depot_ids:
		if depot_id in action_request_on_client or depot_id in product_problems_on_client or depot_id in product_version_problems_on_client:
			message += f"\nResult for Depot: '{depot_id}':\n"
		else:
			continue

		if depot_id in action_request_on_client:
			for product, clients in action_request_on_client[depot_id].items():
				message += f"\n  Action Request set for product '{product}':\n"
				for client in clients:
					message += f"    {client}\n"

		if depot_id in product_problems_on_client:
			for product, clients in product_problems_on_client[depot_id].items():
				message += f"\n  Product Problems for product '{product}':\n"
				for client in clients:
					message += f"    {client}\n"

		if depot_id in product_version_problems_on_client:
			for product, clients in product_version_problems_on_client[depot_id].items():
				message += f"\n  Product Version difference found for product '{product}': \n"
				for client in clients:
					message += f"    {client}\n"

	if state == State.OK:
		if product_groups:
			message = f"No Problem found for product groups '{','.join(product_groups)}'"
		else:
			message = f"No Problem found for productIds '{','.join(product_ids)}'"
	return generate_response(state, message)
