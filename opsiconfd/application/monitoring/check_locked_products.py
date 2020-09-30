"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""
import orjson

from fastapi.responses import JSONResponse

from opsiconfd.logging import logger
from .utils import State, generateResponse 

def check_locked_products(backend, depotIds=None, productIds=[]):
	if not depotIds or 'all' in depotIds:
		depots = backend._executeMethod(methodName="host_getObjects", type="OpsiDepotserver")
		depotIds = [depot.id for depot in depots]

	lockedProducts = backend.productOnDepot_getObjects(depotId=depotIds, productId=productIds, locked=True)

	state = State.OK
	if lockedProducts:
		state = State.WARNING

		message = f'{len(lockedProducts)} products are in locked state.'
		for prodOnDepot in lockedProducts:
			message += f"\nProduct {prodOnDepot.productId} locked on depot {prodOnDepot.depotId}"
	else:
		depotIds = ",".join(depotIds)
		message = f"No products locked on depots: {depotIds}"

	return generateResponse(state, message)
