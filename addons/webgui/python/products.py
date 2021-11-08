# -*- coding: utf-8 -*- # pylint: disable=too-many-lines

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webgui product methods
"""

from typing import Dict, List, Optional
from functools import lru_cache
from sqlalchemy import select, text, and_, alias, column
from sqlalchemy.dialects.mysql import insert
from sqlalchemy.sql.expression import table, update

from pydantic import BaseModel # pylint: disable=no-name-in-module
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse

from opsicommon.objects import ProductOnClient

from opsiconfd.logging import logger
from opsiconfd.backend import get_mysql, execute_on_secondary_backends
from opsiconfd.rest import OpsiApiException, order_by, pagination, common_query_parameters, rest_api
from opsiconfd.application.utils import (
	get_configserver_id,
	bool_product_property,
	unicode_product_property,
	merge_dicts
)

from .utils import (
	get_depot_of_client,
	parse_depot_list,
	parse_client_list,
	parse_selected_list
)
from .utils import mysql

product_router = APIRouter()

@lru_cache(maxsize=1000)
def depot_get_product_version(depot, product):
	version = None
	params = {}
	with mysql.session() as session:

		params["depot"] = depot
		params["product"] = product
		where = text("pod.depotId = :depot AND pod.productId = :product")

		query = select(text("CONCAT(pod.productVersion,'-',pod.packageVersion) AS version"))\
			.select_from(text("PRODUCT_ON_DEPOT AS pod"))\
			.where(where)

		result = session.execute(query, params)
		result = result.fetchone()

		if result:
			version = dict(result).get("version")

		return version

def get_product_description(product, product_version, package_version):
	description = None
	params = {}
	with mysql.session() as session:

		params["product"] = product
		params["product_version"] = product_version
		params["package_version"] = package_version
		where = text("p.productId = :product AND p.productVersion = :product_version AND p.packageVersion = :package_version")

		query = select(text("description"))\
			.select_from(text("PRODUCT AS p"))\
			.where(where)

		result = session.execute(query, params)
		result = result.fetchone()

		if result:
			description = dict(result).get("description")

		return description

@lru_cache(maxsize=1000)
def get_product_type(product_id, product_version, package_version):
	with mysql.session() as session:
		query = select(text("type"))\
			.select_from(text("PRODUCT"))\
			.where(text("productId = :product_id AND productVersion = :product_version AND packageVersion = :package_version"))

		result = session.execute(query, {
			"product_id": product_id,
			"product_version": product_version,
			"package_version": package_version
		})
		res = result.fetchone()
		if not res:
			return None
		return res[0]

def get_product_actions(product, version, package_version):

	params = {}
	params["product"] = product
	params["version"] = version
	params["package_version"] = package_version
	where = text("productId = :product AND productVersion = :version AND packageVersion = :package_version")

	with mysql.session() as session:
		actions = []
		query = select(text("""
			CONCAT_WS(',',
				IF(setupScript <> '','setup', NULL),
				IF(uninstallScript <> '','uninstall',NULL),
				IF(updateScript <> '','update',NULL),
				IF(alwaysScript <> '','always',NULL),
				IF(customScript <> '','custom',NULL),
				IF(onceScript <> '','once',NULL),
				"none"
			) as actions
		"""))\
			.select_from(text("PRODUCT"))\
			.where(where)

		result = session.execute(query, params)
		result = result.fetchone()

		if result:
			actions = dict(result).get("actions").split(",")
		return actions

def is_product_on_depot(product, version, package_version, depot):

	params = {}
	params["product"] = product
	params["version"] = version
	params["package_version"] = package_version
	params["depot"] = depot

	with mysql.session() as session:
		query = select(text("productId"))\
			.select_from(text("PRODUCT_ON_DEPOT"))\
			.where(text("""
				productId = :product AND
				productVersion = :version AND
				packageVersion = :package_version AND
				depotId = :depot
			"""))

	result = session.execute(query, params)
	result = result.fetchone()

	if result:
		return True
	return False


class Product(BaseModel): # pylint: disable=too-few-public-methods
	productId: str
	name: str
	description: str
	selectedDepots: List[str]
	depotVersions: List[str]
	depot_version_diff: bool
	selctedClients: List[str]
	clientVersions: List[str]
	client_version_outdated: bool
	actions: List[str]
	productType: str
	installationStatus: str
	actionRequest: str
	actionProgress: str
	actionResult: str



@product_router.get("/api/opsidata/products", response_model=List[Product])
@rest_api
def products(
	commons: dict = Depends(common_query_parameters),
	type: str = "LocalbootProduct",
	selectedClients: List[str] = Depends(parse_client_list),
	selectedDepots: List[str] = Depends(parse_depot_list),
	selected: Optional[List[str]] = Depends(parse_selected_list)
): # pylint: disable=too-many-locals, too-many-branches, too-many-statements, redefined-builtin, invalid-name
	"""
	Get products from selected depots and clients.
	"""

	params = {}
	params["product_type"] = type
	if selectedClients == [] or selectedClients is None:
		params["clients"] = [""]
	else:
		params["clients"] = selectedClients
	if selectedDepots == [] or selectedDepots is None:
		params["depots"] = [get_configserver_id()]
	else:
		params["depots"] = selectedDepots
	if selected:
		params["selected"] = selected
	else:
		params["selected"] = [""]

	with mysql.session() as session:
		where = text("pod.depotId IN :depots AND pod.producttype = :product_type")
		if commons.get("filterQuery"):
			where = and_(
				where,
				text("(pod.productId LIKE :search)")
			)
			params["search"] = f"%{commons['filterQuery']}%"

		query = select(text("""
			pod.productId AS productId,
			p.name AS name,
			p.description AS description,
			GROUP_CONCAT(pod.depotId SEPARATOR ',') AS selectedDepots,
			(
				SELECT GROUP_CONCAT(poc.clientId SEPARATOR ',')
				FROM PRODUCT_ON_CLIENT AS poc WHERE poc.clientId IN :clients AND poc.productId=pod.productId
				ORDER BY poc.clientId
			) AS selectedClients,
			(
				SELECT GROUP_CONCAT(IFNULL(poc.installationStatus, "not_installed") SEPARATOR ',')
				FROM PRODUCT_ON_CLIENT AS poc WHERE poc.productId=pod.productId AND poc.clientId IN :clients
				ORDER BY poc.clientId
			) AS installationStatusDetails,
			(	SELECT
					IF(
						JSON_LENGTH(CONCAT('[',GROUP_CONCAT(DISTINCT CONCAT('"', poc.installationStatus, '"') SEPARATOR ','),']')) > 1,
						"mixed",
						IFNULL(poc.installationStatus, "not_installed")
					)
				FROM PRODUCT_ON_CLIENT AS poc WHERE poc.productId=pod.productId AND poc.clientId IN :clients
			) AS installationStatus,
			(
				SELECT GROUP_CONCAT(IFNULL(poc.actionRequest, "none") SEPARATOR ',')
				FROM PRODUCT_ON_CLIENT AS poc WHERE poc.productId=pod.productId AND poc.clientId IN :clients
				ORDER BY poc.clientId
			) AS actionRequestDetails,
			(	SELECT
					IF(
						JSON_LENGTH(CONCAT('[',GROUP_CONCAT(DISTINCT CONCAT('"', poc.actionRequest, '"') SEPARATOR ','),']')) > 1,
						"mixed",
						poc.actionRequest
					)
				FROM PRODUCT_ON_CLIENT AS poc WHERE poc.productId=pod.productId AND poc.clientId IN :clients
			) AS actionRequest,
			(
				SELECT GROUP_CONCAT(IFNULL(poc.actionProgress, "none") SEPARATOR ',')
				FROM PRODUCT_ON_CLIENT AS poc WHERE poc.productId=pod.productId AND poc.clientId IN :clients
				ORDER BY poc.clientId
			) AS actionProgressDetails,
			(	SELECT
					IF(
						JSON_LENGTH(CONCAT('[',GROUP_CONCAT(DISTINCT CONCAT('"', poc.actionProgress, '"') SEPARATOR ','),']')) > 1,
						"mixed",
						poc.actionProgress
					)
				FROM PRODUCT_ON_CLIENT AS poc WHERE poc.productId=pod.productId AND poc.clientId IN :clients
			) AS actionProgress,
			(
				SELECT GROUP_CONCAT(IFNULL(poc.actionResult, "none") SEPARATOR ',')
				FROM PRODUCT_ON_CLIENT AS poc WHERE poc.productId=pod.productId AND poc.clientId IN :clients
				ORDER BY poc.clientId
			) AS actionResultDetails,
			(	SELECT
					IF(
						JSON_LENGTH(CONCAT('[',GROUP_CONCAT(DISTINCT CONCAT('"', poc.actionResult, '"') SEPARATOR ','),']')) > 1,
						"mixed",
						poc.actionResult
					)
				FROM PRODUCT_ON_CLIENT AS poc WHERE poc.productId=pod.productId AND poc.clientId IN :clients
			) AS actionResult,
			(
				SELECT GROUP_CONCAT(CONCAT(poc.productVersion,'-',poc.packageVersion) SEPARATOR ',')
				FROM PRODUCT_ON_CLIENT AS poc WHERE poc.productId=pod.productId AND poc.clientId IN :clients
				ORDER BY poc.clientId
			) AS clientVersions,
			0 IN (
				SELECT if(
						CONCAT(poc.productVersion, '-', poc.packageVersion) = CONCAT(p.productVersion, '-', p.packageVersion) OR poc.productVersion IS NULL,
						TRUE,
						FALSE
					)
				FROM PRODUCT_ON_DEPOT as p
					JOIN CONFIG_STATE AS cs ON cs.configId = 'clientconfig.depot.id'
					AND cs.objectId IN :clients
					AND p.depotId = JSON_UNQUOTE(JSON_EXTRACT(cs.values, "$[0]"))
					JOIN PRODUCT_ON_CLIENT AS poc ON poc.clientId = cs.objectId
					AND poc.productId = p.productId
				WHERE p.productId = pod.productId
			) AS client_version_outdated,
			(
				SELECT CONCAT_WS(',',
					IF(setupScript <> '','setup', NULL),
					IF(uninstallScript <> '','uninstall',NULL),
					IF(updateScript <> '','update',NULL),
					IF(alwaysScript <> '','always',NULL),
					IF(customScript <> '','custom',NULL),
					IF(onceScript <> '','once',NULL),
					"none"
				)
				FROM PRODUCT AS p
				WHERE p.productId=pod.productId AND
					p.productVersion=pod.productVERSION AND p.packageVersion=pod.packageVersion
			) AS actions,
			IF(
				JSON_LENGTH(CONCAT('[',GROUP_CONCAT(DISTINCT CONCAT('"',pod.productVersion,'-',pod.packageVersion,'"') SEPARATOR ','),']')) > 1,
				TRUE,
				FALSE
			) AS depot_version_diff,
			GROUP_CONCAT(CONCAT(pod.productVersion,'-',pod.packageVersion) SEPARATOR ',') AS depotVersions,
			pod.productType AS productType,
			IF(
				pod.productId IN :selected,
				TRUE,
				FALSE
			) AS selected
		"""
		))\
		.select_from(text("PRODUCT_ON_DEPOT AS pod")).where(where).group_by(text("pod.productId"))\
		.join(text("PRODUCT AS p"),
			text("""
				p.productId=pod.productId
					AND p.productVersion=pod.productVersion
					AND p.packageVersion=pod.packageVersion
			"""
			)
		)

		query = order_by(query, commons)
		query = pagination(query, commons)

		result = session.execute(query, params)
		result = result.fetchall()

		products = [] # pylint: disable=redefined-outer-name
		for row in result:
			if row is not None:
				product = dict(row)

				for value in ["installationStatus", "actionRequest", "actionProgress", "actionResult"]:
					if product[value] != "mixed":
						del product[f"{value}Details"]

				for value in [
					"selectedDepots",
					"actions",
					"depotVersions",
					"selectedClients",
					"installationStatusDetails",
					"actionRequestDetails",
					"actionProgressDetails",
					"actionResultDetails",
					"clientVersions"
				]:
					if product.get(value):
						product[value] = product.get(value).split(",")

			product["depot_version_diff"] = bool(product.get("depot_version_diff", False))
			product["client_version_outdated"] = bool(product.get("client_version_outdated", False))
			products.append(product)

		products_on_depots = alias(select(text("*"))\
			.select_from(text("PRODUCT_ON_DEPOT AS pod"))\
			.where(where)\
			.group_by(text("pod.productId"))
		)
		total = session.execute(
			select(text("COUNT(*)")).select_from(products_on_depots),
			params
		).fetchone()[0]

		return {
			"data": products,
			"total": total
		}

class PocItem(BaseModel): # pylint: disable=too-few-public-methods
	clientIds: List[str]
	productIds: List[str]
	actionRequest: Optional[str] = None
	actionProgress: Optional[str] = None
	actionResult: Optional[str] = None
	installationStatus: Optional[str] = None

@product_router.post("/api/opsidata/clients/products")
@rest_api
def save_poduct_on_client(data: PocItem): # pylint: disable=too-many-locals, too-many-statements, too-many-branches
	"""
	Save a Product On Client object.
	"""
	http_status = status.HTTP_200_OK
	result_data = {}
	depot_product_version = {}
	product_actions = {}

	get_product_type.cache_clear()
	depot_get_product_version.cache_clear()

	for client_id in data.clientIds:
		if not client_id in result_data:
			result_data[client_id] = {}

		depot_id = get_depot_of_client(client_id)

		for product_id in data.productIds:
			if not depot_id in depot_product_version:
				depot_product_version[depot_id] = {}
			if not product_id in depot_product_version[depot_id]:
				depot_product_version[depot_id][product_id] = depot_get_product_version(depot_id, product_id)
			if not depot_product_version[depot_id][product_id]:
				http_status = status.HTTP_400_BAD_REQUEST
				result_data[client_id][product_id] = f"Product '{product_id}' not available on depot '{depot_id}'."
				continue

			version = depot_product_version[depot_id][product_id]
			product_version, package_version = version.split("-", 1)

			if not product_id in product_actions:
				product_actions[product_id] = {}
			if not product_version in product_actions[product_id]:
				product_actions[product_id][product_version] = {}
			if not package_version in product_actions[product_id][product_version]:
				product_actions[product_id][product_version][package_version] = get_product_actions(
					product_id, product_version, package_version
				)
			actions = product_actions[product_id][product_version][package_version]

			if data.actionRequest not in actions:
				http_status = status.HTTP_400_BAD_REQUEST
				logger.warning("Action request '%s' not supported by product '%s' version '%s'.", data.actionRequest, product_id, version)
				raise OpsiApiException(
					message =  f"Action request '{data.actionRequest}' not supported by product '{product_id}' version '{version}'.",
					http_status = status.HTTP_400_BAD_REQUEST
				)

			values = {
				"clientId": client_id,
				"productId": product_id,
				"productType": get_product_type(product_id, product_version, package_version),
				"productVersion": product_version,
				"packageVersion": package_version
			}
			for attr in ("actionRequest", "actionProgress", "actionResult", "installationStatus"):
				if getattr(data, attr) is not None:
					values[attr] = getattr(data, attr)

			try:
				with mysql.session() as session:
					stmt = insert(
						table("PRODUCT_ON_CLIENT", *[column(name) for name in values.keys()]) # pylint: disable=consider-iterating-dictionary
					).values(**values).on_duplicate_key_update(**values)
					session.execute(stmt)

				result_data[client_id][product_id] = values
				poc = ProductOnClient(
					clientId=values.get("clientId"),
					productId=values.get("productId"),
					productType=values.get("productType"),
					productVersion=values.get("productVersion"),
					packageVersion=values.get("packageVersion"),
					actionRequest=values.get("actionRequest"),
					actionProgress=values.get("actionProgress"),
					actionResult=values.get("actionResult"),
					installationStatus=values.get("installationStatus")
				)
				execute_on_secondary_backends("productOnClient_updateObject", productOnClient=poc)
			except Exception as err: # pylint: disable=broad-except
				if isinstance(err, OpsiApiException):
					raise err
				logger.error("Could not create ProductOnClient: %s", err)
				session.rollback()
				raise OpsiApiException(
					message = "Could not create ProductOnClient.",
					http_status = status.HTTP_400_BAD_REQUEST,
					error=err
				) from err

	return {"http_status": http_status, "data": result_data}


@product_router.get("/api/opsidata/products/groups")
@rest_api
def get_product_groups(): # pylint: disable=too-many-locals
	"""
	Get all product groups as a tree of groups.
	"""

	params = {}
	where = text("g.`type` = 'ProductGroup'")

	with mysql.session() as session:

		query = select(text("""
			g.parentGroupId AS parent_id,
			g.groupId AS group_id,
			og.objectId AS object_id
		"""))\
		.select_from(text("`GROUP` AS g"))\
		.join(text("OBJECT_TO_GROUP AS og"), text("og.groupType = g.`type` AND og.groupId = g.groupId"), isouter=True)\
		.where(where)

		result = session.execute(query, params)
		result = result.fetchall()
		root_group = {
					"id": "root",
					"type": "ProductGroup",
					"text": "root",
					"parent": None
				}
		all_groups = {}
		for row in result:
			if not row["group_id"] in all_groups:
				all_groups[row["group_id"]] = {
					"id":row["group_id"],
					"type": "ProductGroup",
					"text": row["group_id"],
					"parent": row["parent_id"] or root_group["id"]
				}
			if row["object_id"]:
				if not "children" in all_groups[row["group_id"]]:
					all_groups[row["group_id"]]["children"] = {}
				if row.group_id == row.parent_id:
					if not row["object_id"] in all_groups:
						all_groups[row["object_id"]] = {
							"id": f'{row["object_id"]};{row["parent_id"]}',
							"type": "ProductGroup",
							"text": row["object_id"],
							"parent": row["parent_id"] or root_group["id"]
						}
				else:
					all_groups[row["group_id"]]["children"][row["object_id"]] = {
						"id": f'{row["object_id"]};{row["group_id"]}',
						"type": "ObjectToGroup",
						"text": row["object_id"],
						"parent": row["group_id"],
					}

		return {"data":{"groups": all_groups}}


@product_router.get("/api/opsidata/producticons")
async def product_icons():
	return JSONResponse({
		"result": {"opsi-client-agent": "assets/images/product_icons/opsi-logo.png"}
	})

class Property(BaseModel): # pylint: disable=too-few-public-methods
	productId: str
	propertyId: str
	type: Optional[str] = "UnicodeProductProperty"
	version: Optional[str]
	versionDetails: Optional[dict]
	allValues: Optional[List[str]] = ["value1"]
	possibleValues: Optional[List[str]] = ["value1"]
	editable: Optional[bool] = True
	editableDetails: Optional[dict] = True
	multiValue: Optional[bool]
	multiValueDetails: Optional[dict]
	description: Optional[str]
	descriptionDetails: Optional[dict]
	default: Optional[List[str]] = ["value1"]
	depots: Optional[dict] = {"depot1": ["value1"]}
	clients: Optional[dict] = {"client1": ["value1"]}
	allClientValuesEqual: Optional[bool] = True
	anyDepotDifferentFromDefault: Optional[bool] = False
	anyClientDifferentFromDepot: Optional[bool] = False
	newValue: Optional[str] = ""
	newValues: Optional[str] = [""]

@product_router.get("/api/opsidata/products/{productId}/properties", response_model=Dict[str, Property])
@rest_api
def product_properties(
	productId: str,
	selectedClients: List[str] = Depends(parse_client_list),
	selectedDepots: List[str] = Depends(parse_depot_list)
): # pylint: disable=too-many-locals, too-many-branches, too-many-statements, redefined-builtin, invalid-name
	"""
	Get products propertiers.
	"""

	data = {}
	params = {}
	data["properties"] = {}
	params["productId"] = productId
	params["depots"] = []
	where = text("pp.productId = :productId")
	clients_on_depot = {}

	depot_get_product_version.cache_clear()

	if not selectedClients and not selectedDepots:
		raise OpsiApiException(
			message = "No clients and no depots were selected.",
			http_status = status.HTTP_400_BAD_REQUEST,
		)
	if selectedClients:
		for client in selectedClients:
			depot = get_depot_of_client(client)
			if depot not in clients_on_depot:
				clients_on_depot[depot] = []
				params["depots"].append(depot)
			clients_on_depot[depot].append(client)
	if selectedDepots:
		for depot in selectedDepots:
			if depot not in clients_on_depot:
				clients_on_depot[depot] = []
				params["depots"].append(depot)
	where = and_(
			where,
			text("(pod.depotId IN :depots)")
		)
	with mysql.session() as session:

		try: # pylint: disable=too-many-nested-blocks
			query = select(text("""
				pp.productId,
				pp.propertyId,
				CONCAT(pp.productVersion,'-',pp.packageVersion) AS version,
				pp.type,
				pp.description AS description,
				pp.multiValue as multiValue,
				pp.editable AS editable,
				GROUP_CONCAT(ppv.value SEPARATOR ',') AS `values`,
				(SELECT GROUP_CONCAT(`value` SEPARATOR ',') FROM PRODUCT_PROPERTY_VALUE WHERE propertyId = pp.propertyId AND productId = pp.productId AND productVersion = pp.productVersion AND packageVersion = pp.packageVersion AND (isDefault = 1 OR ppv.isDefault is NULL)) AS `defaultDetails`,
				GROUP_CONCAT(pod.depotId SEPARATOR ',') AS depots
			"""))\
			.select_from(text("PRODUCT_PROPERTY AS pp"))\
			.join(text("PRODUCT_ON_DEPOT AS pod"), text("""
				pod.productId = pp.productId AND
				pod.productVersion = pp.productVersion AND
				pod.packageVersion = pp.packageVersion
			"""))\
			.join(text("PRODUCT_PROPERTY_VALUE AS ppv"), text("""
				pp.propertyId = ppv.propertyId AND
				pp.productId = ppv.productId AND
				ppv.productVersion = pp.productVersion AND
				ppv.packageVersion = pp.packageVersion
			"""), isouter=True)\
			.where(where)\
			.group_by(text("pp.productId, pp.propertyId, version")) # pylint: disable=redefined-outer-name

			result = session.execute(query, params)
			result = result.fetchall()

			for row in result:
				if row is not None:
					property = dict(row)
					if not data["properties"].get(property["propertyId"]):
						data["properties"][property["propertyId"]] = {}
					_depots = list(set(property["depots"].split(",")))
					property["depots"] = {}
					property["clients"] = {}
					property["allValues"] = set()
					property["versionDetails"] = {}
					property["descriptionDetails"] = {}
					property["multiValueDetails"] = {}
					property["editableDetails"] = {}
					property["defaultDetails"] = {}
					property["possibleValues"] = {}

					for depot in _depots:
						property["versionDetails"][depot] = property["version"]
						property["descriptionDetails"][depot] = property["description"]
						property["multiValueDetails"][depot] = bool(property["multiValue"])
						property["editableDetails"][depot] = bool(property["editable"])

						if property["type"] == "BoolProductProperty":
							property["allValues"].update([bool_product_property(value) for value in property["values"].split(",")])
							property["defaultDetails"][depot] = [bool_product_property(property["defaultDetails"])]
							property["possibleValues"][depot] = [bool_product_property(value) for value in property["values"].split(",")]
						else:
							property["allValues"].update(unicode_product_property(property["values"]))
							property["defaultDetails"][depot] = unicode_product_property(property["defaultDetails"])
							property["possibleValues"][depot] = unicode_product_property(property["values"])


						query = select(text("""
							pps.values
						"""))\
						.select_from(text("PRODUCT_PROPERTY_STATE AS pps"))\
						.where(text("pps.productId = :product AND pps.propertyId = :property AND pps.objectId = :depot"))
						values = session.execute(query, {"product": productId, "property": property["propertyId"], "depot": depot})
						values = values.fetchone()

						if values is not None:
							if property["type"] == "BoolProductProperty":
								property["depots"][depot] = [bool_product_property(dict(values).get("values"))]
								property["allValues"].update([bool_product_property(dict(values).get("values"))])
							else:
								property["depots"][depot] = unicode_product_property(dict(values).get("values"))
								property["allValues"].update(unicode_product_property(dict(values).get("values")))
							if property["depots"][depot] != property["defaultDetails"][depot]:
								property["anyDepotDifferentFromDefault"] = True

						else:
							property["depots"][depot] = property["defaultDetails"][depot]

						# if not clients_on_depot.get(depot):
						# 	continue
						for client in clients_on_depot.get(depot):
							query = select(text("""
								pps.values
							"""))\
							.select_from(text("PRODUCT_PROPERTY_STATE AS pps"))\
							.where(text("pps.productId = :product AND pps.propertyId = :property AND pps.objectId = :client"))
							values = session.execute(query, {"product": productId, "property": property["propertyId"], "client": client})
							values = values.fetchone()

							if values is not None:
								if property["type"] == "BoolProductProperty":
									property["clients"][client] = [bool_product_property(dict(values).get("values"))]
									property["allValues"].update([bool_product_property(dict(values).get("values"))])
								else:
									property["clients"][client] = unicode_product_property(dict(values).get("values"))
									property["allValues"].update(unicode_product_property(dict(values).get("values")))
								if property["clients"][client] != property["depots"][depot]:
									property["anyClientDifferentFromDepot"] = True
							elif property["depots"][depot] is not None:
								property["clients"][client] = property["depots"][depot]
							else:
								property["clients"][client] = property["defaultDetails"][depot]
					del property["version"]
					del property["description"]
					del property["multiValue"]
					del property["editable"]
					del property["values"]
					property["allValues"] = list(property.get("allValues"))
					data["properties"][property["propertyId"]] = merge_dicts(property, data["properties"][property["propertyId"]])

			data["productVersions"] = {}
			data["productDescriptionDetails"] = {}

			for depot in clients_on_depot:
				data["productVersions"][depot] = depot_get_product_version(depot, productId)
				if data["productVersions"][depot]:
					data["productDescriptionDetails"][depot] = get_product_description(productId, *data["productVersions"][depot].split("-"))

			if all(description == list(data["productDescriptionDetails"].values())[0] for description in data["productDescriptionDetails"].values()):
				data["productDescription"] = list(data["productDescriptionDetails"].values())[0]
			else:
				data["productDescription"] = "mixed"

			for id in data["properties"]:
				property = data["properties"][id]

				for key in ("version", "description", "multiValue", "editable", "default"):
					values = property.get(f"{key}Details").values()
					first_value = list(values)[0]
					if all(value == first_value  for value in values):
						property[key] = first_value
					else:
						property[key] = "mixed"

				client_values = property["clients"].values()
				if all(value == list(client_values)[0]  for value in client_values):
					property["allClientValuesEqual"] = True
				else:
					property["allClientValuesEqual"] = False

				if property["editable"] is True or property["editable"] == "mixed":
					property["newValue"] = str()
					property["newValues"] = []

				if not property.get("anyDepotDifferentFromDefault"):
					property["anyDepotDifferentFromDefault"] = False
				if not property.get("anyClientDifferentFromDepot"):
					property["anyClientDifferentFromDepot"] = False

			return {"data": data}

		except Exception as err: # pylint: disable=broad-except
			if isinstance(err, OpsiApiException):
				raise err
			logger.error("Could not get properties.")
			logger.error(err)
			raise OpsiApiException(
				message = "Could not get properties.",
				http_status = status.HTTP_500_INTERNAL_SERVER_ERROR,
				error=err
			) from err


@lru_cache(maxsize=1000)
def get_product_properties(product, version):

	product_version, package_version = version.split("-", 1)
	with mysql.session() as session:
		query = select(text("propertyId"))\
			.select_from(text("PRODUCT_PROPERTY"))\
			.where(text("productId = :product_id AND productVersion = :product_version AND packageVersion = :package_version"))

		result = session.execute(query, {
			"product_id": product,
			"product_version": product_version,
			"package_version": package_version
		})
		result = result.fetchall()
		properties = []
		for row in result:
			if row is not None:
				properties.append(dict(row).get("propertyId"))
	return properties

def get_product_product_property_state(object_id, product_id, property_id):

	with mysql.session() as session:
		query = select(text("""
			pps.objectId AS objectId,
			pps.productId AS productId,
			pps.propertyId AS propertyId,
			pps.`values` AS `values`
		"""))\
			.select_from(text("PRODUCT_PROPERTY_STATE AS pps"))\
			.where(text("productId = :product_id AND objectId = :object_id AND propertyId = :property_id"))

		result = session.execute(query, {
			"product_id": product_id,
			"property_id": property_id,
			"object_id": object_id
		})
		res = result.fetchone()
		if not res:
			return None
		return res[0]


class ProductProperty(BaseModel): # pylint: disable=too-few-public-methods
	clientIds: Optional[List[str]] = []
	depotIds: Optional[List[str]] = []
	properties: dict

@product_router.post("/api/opsidata/products/{productId}/properties")
@rest_api
def save_poduct_property(productId: str, data: ProductProperty): # pylint: disable=invalid-name, too-many-locals, too-many-statements, too-many-branches
	"""
	Save Product Properties.
	"""

	get_product_properties.cache_clear()
	depot_get_product_version.cache_clear()

	result_data = {}
	depot_product_version = {}

	objects = []
	if data.clientIds and data.depotIds:
		raise OpsiApiException(
			message = "Clients and depots set. Only one is allowed.",
			http_status = status.HTTP_400_BAD_REQUEST,
		)
	if data.clientIds:
		objects =  objects + data.clientIds
	elif data.depotIds:
		objects = objects + data.depotIds
	else:
		raise OpsiApiException(
			message = "No clients or depots set.",
			http_status = status.HTTP_400_BAD_REQUEST,
		)

	with mysql.session() as session:
		for object_id in objects:
			if not object_id in result_data:
				result_data[object_id] = {}

			depot_id = get_depot_of_client(object_id)

			if not depot_id in depot_product_version:
				depot_product_version[depot_id] = {}
				depot_product_version[depot_id][productId] = depot_get_product_version(depot_id, productId)

			version = depot_product_version[depot_id][productId]

			available_properties = get_product_properties(productId, version)

			for property_id in data.properties:

				if property_id not in available_properties:
					logger.error("Propertiy %s does not exist on %s.", property_id, depot_id)
					raise OpsiApiException(
						message = f"Failed to set Property: {property_id} for {productId} on {object_id}. Property does not exist.",
						http_status = status.HTTP_400_BAD_REQUEST,
					)
				if isinstance(data.properties[property_id], bool):
					pp_values = (f'[{data.properties[property_id]}]'.lower())
				elif isinstance(data.properties[property_id], list):
					pp_values = f"{data.properties[property_id]}"
				else:
					pp_values = (f'["{data.properties[property_id]}"]')

				values = {
					"objectId": object_id,
					"productId": productId,
					"propertyId": property_id,
					"values": pp_values
				}

				try:
					if get_product_product_property_state(object_id, productId, property_id):
						stmt = update(
							table("PRODUCT_PROPERTY_STATE", *[column(name) for name in values.keys()]) # pylint: disable=consider-iterating-dictionary
						)\
						.where(text(f"productId = '{productId}' AND objectId = '{object_id}' AND propertyId = '{property_id}'"))\
						.values(**values)
						session.execute(stmt, values)
					else:
						stmt = insert(
							table("PRODUCT_PROPERTY_STATE", *[column(name) for name in values.keys()]) # pylint: disable=consider-iterating-dictionary
						).values(**values).on_duplicate_key_update(**values)
						session.execute(stmt)

					result_data[object_id][property_id] = values
				except Exception as err: # pylint: disable=broad-except
					if isinstance(err, OpsiApiException):
						raise err
					logger.error("Could not save product property state: %s", err)
					session.rollback()
					raise OpsiApiException(
						message = f"Failed to set Property: {property_id} for {productId} on {object_id}.",
						http_status = status.HTTP_400_BAD_REQUEST,
						error=err
					) from err


	return {"http_status": status.HTTP_200_OK, "data": result_data}


class Dependency(BaseModel): # pylint: disable=too-few-public-methods
	productId: str
	productAction: str
	version: str
	requiredProductId: str
	requiredVersion: str
	requiredAction: str
	requiredInstallationStatus: str
	requirementType: str


class ProductDependenciesResponse(BaseModel): # pylint: disable=too-few-public-methods
	status: int
	error: dict
	data: List[Dependency]

@product_router.get("/api/opsidata/products/{productId}/dependencies", response_model=ProductDependenciesResponse)
@rest_api
def product_dependencies(
	productId: str,
	selectedClients: List[str] = Depends(parse_client_list),
): # pylint: disable=too-many-locals, too-many-branches, too-many-statements, redefined-builtin, invalid-name
	"""
	Get products dependencies.
	"""

	status_code = status.HTTP_200_OK
	data = {}
	params = {}
	data["dependencies"] = []
	params["productId"] = productId
	where = text("pd.productId = :productId")
	depots = set()
	depots.add(get_configserver_id())
	if selectedClients:
		for client in selectedClients:
			depots.add(get_depot_of_client(client))

	params["depots"] = list(depots)
	where = and_(
		where,
		text("(pod.depotId IN :depots)")
	)

	with mysql.session() as session:

		try:
			query = select(text("""
				pd.productId,
				pd.productAction,
				CONCAT(pd.productVersion,'-',pd.packageVersion) AS version,
				pd.requiredProductId,
				CONCAT(pd.requiredProductVersion,'-',pd.requiredPackageVersion) AS requiredVersion,
				pd.requiredAction,
				pd.requiredInstallationStatus,
				pd.requirementType
			"""))\
			.select_from(text("PRODUCT_DEPENDENCY AS pd"))\
			.join(text("PRODUCT_ON_DEPOT AS pod"), text("""
				pod.productId = pd.productId AND
				pod.productVersion = pd.productVersion AND
				pod.packageVersion = pd.packageVersion
			"""))\
			.where(where) # pylint: disable=redefined-outer-name

			result = session.execute(query, params)
			result = result.fetchall()

			for row in result:
				if row is not None:
					dependency = dict(row)
					data["dependencies"].append(dependency)

			data["productVersions"] = {}
			data["productDescriptionDetails"] = {}


			for depot in depots:
				data["productVersions"][depot] = depot_get_product_version(depot, productId)
				if data["productVersions"][depot]:
					data["productDescriptionDetails"][depot] = get_product_description(productId, *data["productVersions"][depot].split("-"))

			if all(description == list(data["productDescriptionDetails"].values())[0] for description in data["productDescriptionDetails"].values()):
				data["productDescription"] = list(data["productDescriptionDetails"].values())[0]
			else:
				data["productDescription"] = "mixed"

		except Exception as err: # pylint: disable=broad-except
			if isinstance(err, OpsiApiException):
				raise err
			logger.error("Could not get dependencies.")
			logger.error(err)
			raise OpsiApiException(
				message = "Could not get dependencies.",
				http_status = status.HTTP_500_INTERNAL_SERVER_ERROR,
				error=err
			) from err

	return {"http_status": status_code, "data": data}
