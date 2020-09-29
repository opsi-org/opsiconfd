"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""

import orjson
import datetime

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from OPSI.Types import forceProductIdList

from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.backend import get_client_backend, get_backend

from .utils import State, generateResponse

def check_client_status(backend, clientId, excludeProductList=None) -> JSONResponse:
	logger.devel("checkClientStatus")
	
	state = State.OK	

	if not clientId:
		raise Exception("Failed to check: ClientId is needed for checkClientStatus")

	clientObj = backend._executeMethod("host_getObjects", id=clientId) 

	logger.devel("clientObj: %s", clientObj)
	if not clientObj:
		state = State.UNKNOWN
		return generateResponse(state, f"opsi-client: '{clientId}' not found")
	else:
		clientObj = clientObj[0]
	
	
	message = ''
	if not clientObj.lastSeen:
		state = State.WARNING
		message += f"opsi-client: '{clientId}' never seen, please check opsi-client-agent installation on client. "
	else:
		lastSeen = clientObj.lastSeen.split("-")
		year = int(lastSeen[0])
		month = int(lastSeen[1])
		day = int(lastSeen[2].split()[0])

		today = datetime.date.today()
		delta = None

		if year and month and day:
			lastSeenDate = datetime.date(year, month, day)
			delta = today - lastSeenDate
		elif state == State.OK:
			state = State.WARNING
			message += f"opsi-client: '{clientId}' never seen, please check opsi-client-agent installation on client. "

		if delta.days >= 30:
			state = State.WARNING
			message += f"opsi-client {clientId} has not been seen, since {delta.days} days. Please check opsi-client-agent installation on client or perhaps a client that can be deleted. "
		elif delta.days == 0:
			message += f"opsi-client {clientId} has been seen today. "
		else:
			message += f"opsi-client {clientId} has been seen {delta.days} days before. "

	failedProducts = backend._executeMethod(
			methodName="productOnClient_getObjects",
			clientId=clientId,
			actionResult='failed'
		)
	logger.devel("failedProducts: %s", failedProducts)

	logger.devel("excludeProductList %s", excludeProductList)

	if excludeProductList:
			productsToExclude = set(forceProductIdList(excludeProductList))
	else:
		productsToExclude = []

	logger.devel("productsToExclude: %s", productsToExclude)

	failedProducts = [
		product for product in failedProducts
		if product.productId not in productsToExclude
	]

	logger.devel(failedProducts)

	if failedProducts:
		state = State.CRITICAL
		products =  [product.productId for product in failedProducts]
		message += f"Products: '{', '.join(products)}' are in failed state. "

	actionProducts =backend._executeMethod(
			methodName="productOnClient_getObjects",
			clientId=clientId, 
			actionRequest=['setup', 'update', 'uninstall']
		)

	actionProducts = [
		product for product in actionProducts
		if product.productId not in productsToExclude
	]
	
	logger.devel("actionProducts: %s", actionProducts)

	if actionProducts:
		if state != State.CRITICAL:
			state = State.WARNING
		products = ["%s (%s)" % (product.productId, product.actionRequest) for product in actionProducts]
		message += f"Actions set for products: '{', '.join(products)}'."

	if state == State.OK:
		message += "No failed products and no actions set for client"

	
	return  generateResponse(state, message)