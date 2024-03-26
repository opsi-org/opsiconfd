# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.application.monitoring.check_locked_products
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from .utils import State, generate_response

if TYPE_CHECKING:
	from opsiconfd.backend.rpc.main import Backend


def check_locked_products(backend: Backend, depot_ids: list[str] | None = None, product_ids: list[str] | None = None) -> JSONResponse:
	product_ids = product_ids or []
	if not depot_ids or "all" in depot_ids:
		depots = backend.host_getObjects(type="OpsiDepotserver")
		depot_ids = [depot.id for depot in depots]

	locked_products = backend.productOnDepot_getObjects(depotId=depot_ids, productId=product_ids, locked=True)

	state = State.OK
	if locked_products:
		state = State.WARNING

		message = f"{len(locked_products)} products are in locked state."
		for prod_on_depot in locked_products:
			message += f"\nProduct {prod_on_depot.productId} locked on depot {prod_on_depot.depotId}"
	else:
		message = f"No products locked on depots: {','.join(depot_ids)}"

	return generate_response(state, message)
