"""
:copyright: uib GmbH <info@uib.de>
This file is part of opsi - https://www.opsi.org

:license: GNU Affero General Public License version 3
See LICENSES/README.md for more Information
"""

import datetime

from fastapi.responses import JSONResponse

from OPSI.Types import forceProductIdList

from .utils import State, generate_response

def check_client_status(backend, client_id, exclude_product_list=None) -> JSONResponse: # pylint: disable=too-many-locals, too-many-branches, too-many-statements
	state = State.OK

	if not client_id:
		raise Exception("Failed to check: ClientId is needed for checkClientStatus")

	client_obj = backend._executeMethod("host_getObjects", id=client_id) # pylint: disable=protected-access

	if not client_obj:
		state = State.UNKNOWN
		return generate_response(state, f"opsi-client: '{client_id}' not found")

	client_obj = client_obj[0]

	message = ''
	if not client_obj.lastSeen:
		state = State.WARNING
		message += f"opsi-client: '{client_id}' never seen, please check opsi-client-agent installation on client. "
	else:
		last_seen = client_obj.lastSeen.split("-")
		year = int(last_seen[0])
		month = int(last_seen[1])
		day = int(last_seen[2].split()[0])

		today = datetime.date.today()
		delta = None

		if year and month and day:
			last_seen_date = datetime.date(year, month, day)
			delta = today - last_seen_date
		elif state == State.OK:
			state = State.WARNING
			message += f"opsi-client: '{client_id}' never seen, please check opsi-client-agent installation on client. "

		if delta.days >= 30:
			state = State.WARNING
			message += f"opsi-client {client_id} has not been seen, since {delta.days} days. Please check opsi-client-agent installation on client or perhaps a client that can be deleted. " # pylint: disable=line-too-long
		elif delta.days == 0:
			message += f"opsi-client {client_id} has been seen today. "
		else:
			message += f"opsi-client {client_id} has been seen {delta.days} days before. "

	failed_products = backend._executeMethod( # pylint: disable=protected-access
			methodName="productOnClient_getObjects",
			clientId=client_id,
			actionResult='failed'
		)

	if exclude_product_list:
		products_to_exclude = set(forceProductIdList(exclude_product_list))
	else:
		products_to_exclude = []

	failed_products = [
		product for product in failed_products
		if product.productId not in products_to_exclude
	]

	if failed_products:
		state = State.CRITICAL
		products =  [product.productId for product in failed_products]
		message += f"Products: '{', '.join(products)}' are in failed state. "

	action_products = backend._executeMethod( # pylint: disable=protected-access
			methodName="productOnClient_getObjects",
			clientId=client_id,
			actionRequest=['setup', 'update', 'uninstall']
		)

	action_products = [
		product for product in action_products
		if product.productId not in products_to_exclude
	]

	if action_products:
		if state != State.CRITICAL:
			state = State.WARNING
		products = ["%s (%s)" % (product.productId, product.actionRequest) for product in action_products]
		message += f"Actions set for products: '{', '.join(products)}'."
	if state == State.OK:
		message += "No failed products and no actions set for client"

	return  generate_response(state, message)
