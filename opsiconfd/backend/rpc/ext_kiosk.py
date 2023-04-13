# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
rpc methods kiosk
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from opsicommon.exceptions import BackendMissingDataError  # type: ignore[import]
from opsicommon.types import forceBool  # type: ignore[import]

from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RPCExtKioskMixin(Protocol):  # pylint: disable=too-few-public-methods
	def _get_software_on_demand_groups(self: BackendProtocol, client_id: str) -> set[str]:
		"""
		Get the software-on-demand groups for the given client.

		:param client_id: The ID of the client to check for.
		:type client_id: str
		:return: The software-on-demand groups set for the client.
		:rtype: set([str, ...])
		"""
		group_ids = set()
		for values in self.configState_getValues(config_ids=["software-on-demand.product-group-ids"], object_ids=[client_id])[
			client_id
		].values():
			for value in values:
				for group_id in str(value).split(","):
					group_id = group_id.strip()
					if group_id:
						group_ids.add(group_id)
		return group_ids

	@rpc_method(deprecated=False, check_acl=False)
	def getKioskProductInfosForClient(  # pylint: disable=invalid-name,too-many-locals,too-many-statements,too-many-branches
		self: BackendProtocol, clientId: str, addConfigs: bool = False
	) -> dict | list:
		"""
		Collect the data as required by the opsi kiosk client.

		:param clientId: ID of the client for whom the data gets collected.
		:type clientId: str
		:param addConfigs: If True configStates will be returned. Returns a dict.
		:type addConfigs: bool
		:rtype: list of dicts
		:raises BackendMissingDataError: If no client with clientId exists.
		:raises RuntimeError: In case something goes wrong.
		"""
		if not self.host_getIdents(id=clientId, type="OpsiClient"):
			raise BackendMissingDataError(f"Client {clientId!r} does not exist")

		try:
			software_on_demand_groups = self._get_software_on_demand_groups(clientId)
			product_ids = set(
				o.objectId for o in self.objectToGroup_getObjects(groupId=software_on_demand_groups, groupType="ProductGroup")
			)
			depot_id = self.getDepotId(clientId)
			product_on_depots = {p.productId: p for p in self.productOnDepot_getObjects(depotId=depot_id, productId=product_ids)}
			product_dependencies = self.productDependency_getObjects(productId=product_ids)
			product_on_clients = {poc.productId: poc for poc in self.productOnClient_getObjects(clientId=clientId, productId=product_ids)}
			products = self.product_getObjects(id=product_ids)
			if addConfigs:
				config_state_values = {}
				cst = self.configState_getValues(config_ids=["software-on-demand.*"], object_ids=[clientId])
				if cst:
					config_state_values = cst.get(clientId, {})

		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)
			raise RuntimeError(f"Failed to collect kiosk data: {err}") from err

		products_result = []
		for product_id in product_ids:
			pod = product_on_depots.get(product_id)
			if not pod:
				logger.debug("Missing product %r on depot %r", product_id, depot_id)
				continue

			product_data_record = {
				"productId": product_id,
				"productVersion": pod.productVersion,
				"packageVersion": pod.packageVersion,
				"versionStr": f"{pod.productVersion}-{pod.packageVersion}",
				"installedVerStr": "",
				"installedProdVer": "",
				"installedPackVer": "",
				"updatePossible": False,
				"possibleAction": "",
				"installationStatus": "",
				"actionRequest": "",
				"actionResult": "",
			}

			requirements = []
			for dep in product_dependencies:
				if dep.productId != product_id:
					continue

				requirement = {
					"requiredProductId": dep.requiredProductId,
					"required": "",
					"preRequired": "",
					"postRequired": "",
				}

				if dep.requirementType == "before":
					destination = "prerequired"
				elif dep.requirementType == "after":
					destination = "postrequired"
				else:
					destination = "required"

				if dep.requiredAction:
					requirement[destination] = dep.requiredAction
				elif dep.requiredInstallationStatus:
					requirement[destination] = dep.requiredInstallationStatus
				requirements.append(requirement)
			product_data_record["requirements"] = requirements

			for prod in products:
				if (
					prod.id != product_id
					or prod.productVersion != product_data_record["productVersion"]
					or prod.packageVersion != product_data_record["packageVersion"]
				):
					continue

				product_data_record["hasSetup"] = forceBool(prod.setupScript)
				product_data_record["hasUninstall"] = forceBool(prod.uninstallScript)
				product_data_record["productName"] = prod.name
				product_data_record["description"] = prod.description
				product_data_record["advice"] = prod.advice
				product_data_record["priority"] = prod.priority
				product_data_record["productType"] = prod.getType()

				break

			poc = product_on_clients.get(product_id)
			if poc:
				product_data_record["installationStatus"] = poc.installationStatus
				product_data_record["actionRequest"] = poc.actionRequest
				product_data_record["actionResult"] = poc.actionResult
				product_data_record["installedProdVer"] = poc.productVersion
				product_data_record["installedPackVer"] = poc.packageVersion
				product_data_record["installedVerStr"] = f"{poc.productVersion}-{poc.packageVersion}"
				product_data_record["updatePossible"] = product_data_record["installedVerStr"] != product_data_record["versionStr"]

				if poc.installationStatus == "not_installed" and product_data_record["hasSetup"]:
					product_data_record["possibleAction"] = "setup"
				elif poc.installationStatus == "installed" and product_data_record["hasUninstall"]:
					product_data_record["possibleAction"] = "uninstall"
			else:
				logger.debug("Unable to find product %s on client %s", product_id, clientId)

			products_result.append(product_data_record)

		if addConfigs:
			return {"configStates": config_state_values, "products": products_result}

		return products_result
