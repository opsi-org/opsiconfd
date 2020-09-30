"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""

from collections import defaultdict
from fastapi.responses import JSONResponse

from opsiconfd.logging import logger
from .utils import State, generateResponse

def check_depot_sync_status(backend, depotIds, productIds=[], exclude=[], strict=False, verbose=False) -> JSONResponse: 
	if not depotIds or 'all' in depotIds:
		depots = backend.host_getObjects(type="OpsiDepotserver")
		depotIds = [depot.id for depot in depots]

	productOnDepots = backend._executeMethod(methodName="productOnDepot_getObjects", depotId=depotIds, productId=productIds)
	productIds = set()
	productOnDepotInfo = defaultdict(dict)
	for pod in productOnDepots:
		productIds.add(pod.productId)
		productOnDepotInfo[pod.depotId][pod.productId] = pod

	differenceProducts = defaultdict(dict)
	for productId in productIds:
		if productId in exclude:
			continue
		differs = False
		productVersion = ""
		packageVersion = ""
		for depotId in depotIds:
			productOnDepot = productOnDepotInfo[depotId].get(productId)
			if not productOnDepot:
				if not strict:
					continue

				differenceProducts[productId][depotId] = "not installed"
				continue

			if not productVersion:
				productVersion = productOnDepot.productVersion
			elif productVersion != productOnDepot.productVersion:
				differs = True

			if not packageVersion:
				packageVersion = productOnDepot.packageVersion
			elif packageVersion != productOnDepot.packageVersion:
				differs = True

			if differs:
				differenceProducts[productId][depotId] = "different"

	state = State.OK
	message = ""
	if differenceProducts:
		state = State.WARNING
		message += f"Differences found for {len(differenceProducts)} products"

		if verbose:
			message += u":\n"
			for productId in sorted(differenceProducts):
				message += f"product '{productId}': "
				for depotId in depotIds:
					try:
						product_version = productOnDepotInfo[depotId][productId].productVersion
						package_version = productOnDepotInfo[depotId][productId].packageVersion
						if differenceProducts[productId][depotId] == "not installed":
							message += f"{depotId} (not installed) \n"
						else:
							
							message += f"{depotId} ({product_version}-{package_version}) \n"
					except KeyError:
						if not productOnDepotInfo.get(depotId, {}).get(productId, None):
							continue
						message += f"{depotId} ({product_version}-{package_version}) "
	else:
		message += "Syncstate ok for depots %s" % ", ".join(depotIds)

	return generateResponse(state, message)