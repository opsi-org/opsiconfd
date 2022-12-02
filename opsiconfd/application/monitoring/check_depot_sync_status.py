# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
check depot sync status
"""

from collections import defaultdict
from typing import Dict, List

from fastapi.responses import JSONResponse
from OPSI.Backend.BackendManager import BackendManager  # type: ignore[import]
from opsicommon.objects import ProductOnDepot  # type: ignore[import]

from .utils import State, generate_response


def check_depot_sync_status(  # pylint: disable=too-many-arguments, too-many-locals, too-many-branches, too-many-statements
	backend: BackendManager,
	depot_ids: List[str],
	product_ids: List[str] | None,
	exclude: List[str] | None,
	strict: bool = False,
	verbose: bool = False,
) -> JSONResponse:
	product_ids = product_ids or []
	exclude = exclude or []
	if not depot_ids or "all" in depot_ids:
		depots = backend.host_getObjects(type="OpsiDepotserver")
		depot_ids = [depot.id for depot in depots]

	product_on_depots = backend.productOnDepot_getObjects(depotId=depot_ids, productId=product_ids)
	product_ids_set = set()
	product_on_depot_info: Dict[str, Dict[str, ProductOnDepot]] = defaultdict(dict)
	for pod in product_on_depots:
		product_ids_set.add(pod.productId)
		product_on_depot_info[pod.depotId][pod.productId] = pod

	difference_products: Dict[str, Dict[str, str]] = defaultdict(dict)
	for product_id in product_ids_set:
		if product_id in exclude:
			continue
		differs = False
		product_version = ""
		package_version = ""
		for depot_id in depot_ids:
			product_on_depot = product_on_depot_info[depot_id].get(product_id)
			if not product_on_depot:
				if not strict:  # pylint: disable=loop-invariant-statement
					continue
				difference_products[product_id][depot_id] = "not installed"  # pylint: disable=loop-invariant-statement
				continue

			if not product_version:
				product_version = product_on_depot.productVersion
			elif product_version != product_on_depot.productVersion:
				differs = True

			if not package_version:
				package_version = product_on_depot.packageVersion
			elif package_version != product_on_depot.packageVersion:
				differs = True

			if differs:
				difference_products[product_id][depot_id] = "different"  # pylint: disable=loop-invariant-statement

	state = State.OK
	message = ""
	if difference_products:  # pylint: disable=too-many-nested-blocks
		state = State.WARNING
		message += f"Differences found for {len(difference_products)} products"

		if verbose:
			message += ":\n"
			for product_id in sorted(difference_products):
				message += f"product '{product_id}': "
				for depot_id in depot_ids:
					depot_product_version = ""
					depot_package_version = ""
					try:  # pylint: disable=loop-try-except-usage
						if difference_products.get(product_id, {}).get(depot_id) == "not installed":
							message += f"{depot_id} (not installed) \n"
						else:
							depot_product_version = product_on_depot_info[depot_id][product_id].productVersion
							depot_package_version = product_on_depot_info[depot_id][product_id].packageVersion
							message += f"{depot_id} ({depot_product_version}-{depot_package_version}) \n"
					except KeyError:
						if not product_on_depot_info.get(depot_id, {}).get(product_id, None):
							continue
						message += f"{depot_id} ({depot_product_version}-{depot_package_version}) "
	else:
		message += f"Syncstate ok for depots {', '.join(depot_ids)}"
	return generate_response(state, message)
