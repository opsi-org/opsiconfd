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

from .utils import State, generateResponse, removePercent


def check_short_product_status(backend, productId=None, thresholds={}) -> JSONResponse:
	logger.devel("checkShortProductStatus")
	actionRequestOnClients = []
	productProblemsOnClients = []
	productVersionProblemsOnClients = []
	uptodateClients = []
	targetProductVersion = None
	targetPackackeVersion = None

	state = State.OK

	message = []

	warning = thresholds.get("warning", "20")
	critical = thresholds.get("critical", "20")
	warning = float(removePercent(warning))
	critical = float(removePercent(critical))

	logger.debug("Checking shortly the productStates on Clients")
	configServer = backend._executeMethod(methodName="host_getObjects", type="OpsiConfigserver")[0]

	logger.devel("configServer: %s", configServer)

	for pod in backend._executeMethod(methodName="productOnDepot_getObjects", depotId=configServer.id, productId=productId):
		targetProductVersion = pod.productVersion
		targetPackackeVersion = pod.packageVersion

	productOnClients = backend._executeMethod(methodName="productOnClient_getObjects", productId=productId)

	if not productOnClients:
		return generateResponse(State.UNKNOWN, f"No ProductStates found for product '{productId}'")

	for poc in productOnClients:
		if poc.installationStatus != "not_installed" and poc.actionResult != "successful" and poc.actionResult != "none":
			if poc.clientId not in productProblemsOnClients:
				productProblemsOnClients.append(poc.clientId)
				continue

		if poc.actionRequest != 'none':
			if poc.clientId not in actionRequestOnClients:
				actionRequestOnClients.append(poc.clientId)
				continue

		if not poc.productVersion or not poc.packageVersion:
			continue

		if poc.productVersion != targetProductVersion or poc.packageVersion != targetPackackeVersion:
			productVersionProblemsOnClients.append(poc.clientId)
			continue

		if poc.actionResult == "successful":
			uptodateClients.append(poc.clientId)

	message.append(f"{len(productOnClients)} ProductStates for product: '{productId}' found; checking for Version: '{targetProductVersion}' and Package: '{targetPackackeVersion}'")
	if uptodateClients:
		message.append(f"{len(uptodateClients)} Clients are up to date")
	if actionRequestOnClients and len(actionRequestOnClients) * 100 / len(productOnClients) > warning:
		state = State.WARNING
		message.append(f"ActionRequest set on {len(actionRequestOnClients)} clients")
	if productProblemsOnClients:
		message.append(f"Problems found on {len(productProblemsOnClients)} clients")
	if productVersionProblemsOnClients:
		message.append(f"Version difference found on {len(productVersionProblemsOnClients)} clients")

	problemClientsCount = len(productProblemsOnClients) + len(productVersionProblemsOnClients)
	if problemClientsCount * 100 / len(productOnClients) > critical:
		state = State.CRITICAL

	return generateResponse(state, "; ".join(message))
