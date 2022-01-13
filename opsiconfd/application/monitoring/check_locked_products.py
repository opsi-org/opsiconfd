# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.application.monitoring.check_locked_products
"""

from .utils import State, generate_response


def check_locked_products(backend, depot_ids=None, product_ids=[]):  # pylint: disable=dangerous-default-value
	if not depot_ids or 'all' in depot_ids:
		depots = backend._executeMethod(methodName="host_getObjects", type="OpsiDepotserver")  # pylint: disable=protected-access
		depot_ids = [depot.id for depot in depots]

	locked_products = backend.productOnDepot_getObjects(depotId=depot_ids, productId=product_ids, locked=True)

	state = State.OK
	if locked_products:
		state = State.WARNING

		message = f'{len(locked_products)} products are in locked state.'
		for prod_on_depot in locked_products:
			message += f"\nProduct {prod_on_depot.productId} locked on depot {prod_on_depot.depotId}"
	else:
		depot_ids = ",".join(depot_ids)
		message = f"No products locked on depots: {depot_ids}"

	return generate_response(state, message)
