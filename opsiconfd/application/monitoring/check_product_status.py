"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""

from collections import defaultdict

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from OPSI.Types import forceProductIdList
from OPSI.Backend.Backend import temporaryBackendOptions

from opsiconfd.logging import logger

from .utils import State, generateResponse

def check_product_status(backend, productIds=[], productGroups=[], hostGroupIds=[], depotIds=[], exclude=[], verbose=False):
	if not productIds:
		productIds = set()
		for product in backend._executeMethod(methodName="objectToGroup_getIdents", groupType='ProductGroup', groupId=productGroups):
			product = product.split(";")[2]
			if product not in exclude:
				productIds.add(product)

	if not productIds:
		return generateResponse(State.UNKNOWN, "Neither productId nor productGroup given, nothing to check!")

	serverType = None
	if not depotIds:
		serverType = "OpsiConfigserver"
	elif 'all' in depotIds:
		serverType = "OpsiDepotserver"

	if serverType:
		depots = backend._executeMethod(methodName="host_getObjects", attributes=['id'], type=serverType)
		depotIds = set(depot.id for depot in depots)
		del depots

	if hostGroupIds:
		objectToGroups = backend._executeMethod(methodName="objectToGroup_getObjects", groupId=hostGroupIds, groupType="HostGroup")
		if objectToGroups:
			clientIds = [objectToGroup.objectId for objectToGroup in objectToGroups]
		else:
			clientIds = []
	else:
		clientIds = backend._executeMethod(methodName="host_getIdents", type="OpsiClient")

	clientsOnDepot = defaultdict(list)
	with temporaryBackendOptions(backend, addConfigStateDefaults=True):
		for configState in backend._executeMethod(methodName="configState_getObjects", configId=u'clientconfig.depot.id', objectId=clientIds):
			if not configState.values or not configState.values[0]:
				logger.error("No depot server configured for client '%s'", configState.objectId)
				continue

			depotId = configState.values[0]
			if depotId not in depotIds:
				continue

			clientsOnDepot[depotId].append(configState.objectId)

	productOnDepotInfo = defaultdict(dict)
	for pod in backend._executeMethod(methodName="productOnDepot_getObjects", depotId=depotIds, productId=productIds):
		productOnDepotInfo[pod.depotId][pod.productId] = {
			"productVersion": pod.productVersion,
			"packageVersion": pod.packageVersion
		}

	state = State.OK
	productVersionProblemsOnClient = defaultdict(lambda: defaultdict(list))
	productProblemsOnClient = defaultdict(lambda: defaultdict(list))
	actionRequestOnClient = defaultdict(lambda: defaultdict(list))

	actionRequestsToIgnore = set([None, 'none', 'always'])

	for depotId in depotIds:
		for poc in backend._executeMethod(methodName="productOnClient_getObjects", productId=productIds, clientId=clientsOnDepot.get(depotId, None)):
			if poc.actionRequest not in actionRequestsToIgnore:
				if state != State.CRITICAL:
					state = State.WARNING

				actionRequestOnClient[depotId][poc.productId].append(f"{poc.clientId} ({ poc.actionRequest})")

			if poc.installationStatus != "not_installed" and poc.actionResult != "successful" and poc.actionResult != "none":
				if state != State.CRITICAL:
					state = State.CRITICAL

				productProblemsOnClient[depotId][poc.productId].append(f"{poc.clientId} ({poc.actionResult} lastAction: [{poc.lastAction}])")

			if not poc.productVersion or not poc.packageVersion:
				continue

			if depotId not in productOnDepotInfo:
				continue

			try:
				productOnDepot = productOnDepotInfo[depotId][poc.productId]
			except KeyError:
				logger.debug("Product %s not found on depot %s", poc.productId, depotId)
				continue

			if (poc.productVersion != productOnDepot["productVersion"] or
				poc.packageVersion != productOnDepot["packageVersion"]):

				if state != State.CRITICAL:
					state = State.WARNING

				productVersionProblemsOnClient[depotId][poc.productId].append(f"{poc.clientId} ({poc.productVersion}-{poc.packageVersion})")

	message = ""
	for depotId in depotIds:
		if depotId in actionRequestOnClient or depotId in productProblemsOnClient or depotId in productVersionProblemsOnClient:
			message += f"\nResult for Depot: '{depotId}':\n" 
		else:
			continue

		if depotId in actionRequestOnClient:
			for product, clients in actionRequestOnClient[depotId].items():
				message += f"For product '{product}' action set on {len(clients)} clients!\n"
		if depotId in productProblemsOnClient:
			for product, clients in productProblemsOnClient[depotId].items():
				message += f"For product '{product}' problems found on {len(clients)} clients!\n"
		if depotId in productVersionProblemsOnClient:
			for product, clients in productVersionProblemsOnClient[depotId].items():
				message += f"For product '{product}' version difference problems found on {len(clients)} clients!\n"

	if not verbose:
		if state == State.OK:
			products = ",".join(productIds)
			message = f"No Problem found for productIds: '{products}'"
		return generateResponse(state, message)

	for depotId in depotIds:
		if depotId in actionRequestOnClient or depotId in productProblemsOnClient or depotId in productVersionProblemsOnClient:
			message += f"\nResult for Depot: '{depotId}':\n"
		else:
			continue

		if depotId in actionRequestOnClient:
			for product, clients in actionRequestOnClient[depotId].items():
				message += f"\n  Action Request set for product '{product}':\n"
				for client in clients:
					message += f"    {client}\n"

		if depotId in productProblemsOnClient:
			for product, clients in productProblemsOnClient[depotId].items():
				message += f"\n  Product Problems for product '{product}':\n"
				for client in clients:
					message += f"    {client}\n"

		if depotId in productVersionProblemsOnClient:
			for product, clients in productVersionProblemsOnClient[depotId].items():
				message += f"\n  Product Version difference found for product '{product}': \n"
				for client in clients:
					message += f"    {client}\n"

	if state == State.OK:
		if productGroups:
			product_groups = ",".join(productGroups)
			message = f"No Problem found for product groups '{product_groups}'" 
		else:
			products = ",".join(productIds)
			message = f"No Problem found for productIds '{products}'"

	return generateResponse(state, message)
