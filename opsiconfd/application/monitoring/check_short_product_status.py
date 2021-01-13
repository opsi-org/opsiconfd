"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""

from fastapi.responses import JSONResponse

from opsiconfd.logging import logger

from .utils import State, generate_response, remove_percent


def check_short_product_status(backend, product_id=None, thresholds={}) -> JSONResponse: # pylint: disable=dangerous-default-value, too-many-locals, too-many-branches
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
	warning = float(remove_percent(warning))
	critical = float(remove_percent(critical))

	logger.debug("Checking shortly the productStates on Clients")
	config_server = backend._executeMethod(methodName="host_getObjects", type="OpsiConfigserver")[0] # pylint: disable=protected-access

	for pod in backend._executeMethod(methodName="productOnDepot_getObjects", depotId=config_server.id, productId=product_id): # pylint: disable=protected-access
		target_product_version = pod.productVersion
		target_packacke_version = pod.packageVersion

	product_on_clients = backend._executeMethod(methodName="productOnClient_getObjects", productId=product_id) # pylint: disable=protected-access

	if not product_on_clients:
		return generate_response(State.UNKNOWN, f"No ProductStates found for product '{product_id}'")

	for poc in product_on_clients:
		if poc.installationStatus != "not_installed" and poc.actionResult != "successful" and poc.actionResult != "none":
			if poc.clientId not in product_problems_on_clients:
				product_problems_on_clients.append(poc.clientId)
				continue

		if poc.actionRequest != 'none':
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

	message.append(f"{len(product_on_clients)} ProductStates for product: '{product_id}' found; checking for Version: '{target_product_version}' and Package: '{target_packacke_version}'") # pylint: disable=line-too-long
	if uptodate_clients:
		message.append(f"{len(uptodate_clients)} Clients are up to date")
	if action_request_on_clients and len(action_request_on_clients) * 100 / len(product_on_clients) > warning:
		state = State.WARNING
		message.append(f"ActionRequest set on {len(action_request_on_clients)} clients")
	if product_problems_on_clients:
		message.append(f"Problems found on {len(product_problems_on_clients)} clients")
	if product_version_problems_on_clients:
		message.append(f"Version difference found on {len(product_version_problems_on_clients)} clients")

	problem_clients_count = len(product_problems_on_clients) + len(product_version_problems_on_clients)
	if problem_clients_count * 100 / len(product_on_clients) > critical:
		state = State.CRITICAL

	return generate_response(state, "; ".join(message))
