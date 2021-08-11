# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webgui product methods
"""

from typing import List, Optional
from sqlalchemy import select, text, and_, column, alias
from sqlalchemy.dialects import mysql
from sqlalchemy.dialects.mysql import insert
from sqlalchemy.sql.expression import table

from pydantic import BaseModel # pylint: disable=no-name-in-module
from fastapi import Body, APIRouter, Depends
from fastapi.responses import JSONResponse

from opsiconfd.logging import logger

from .utils import (
	get_mysql,
	get_configserver_id,
	order_by,
	pagination,
	get_depot_of_client,
	common_query_parameters,
	parse_depot_list,
	parse_client_list
)

mysql = get_mysql()
product_router = APIRouter()


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
				IF(onceScript <> '','once',NULL)
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


class ProductsResponse(BaseModel): # pylint: disable=too-few-public-methods
	class Result(BaseModel): # pylint: disable=too-few-public-methods
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

		products: List[Product]
		total: int
	result: Result
	configserver: str


@product_router.get("/api/opsidata/products", response_model=ProductsResponse)
def products(
	commons: dict = Depends(common_query_parameters),
	type: str = "LocalbootProduct",
	selectedClients: List[str] = Depends(parse_client_list),
	selectedDepots: List[str] = Depends(parse_depot_list),
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
						SELECT GROUP_CONCAT(poc.installationStatus SEPARATOR ',')
						FROM PRODUCT_ON_CLIENT AS poc WHERE poc.productId=pod.productId AND poc.clientId IN :clients
					) AS installationStatusDetails,
					(
						SELECT GROUP_CONCAT(poc.actionRequest SEPARATOR ',')
						FROM PRODUCT_ON_CLIENT AS poc WHERE poc.productId=pod.productId AND poc.clientId IN :clients
					) AS actionRequestDetails,
					(
						SELECT GROUP_CONCAT(poc.actionProgress SEPARATOR ',')
						FROM PRODUCT_ON_CLIENT AS poc WHERE poc.productId=pod.productId AND poc.clientId IN :clients
					) AS actionProgressDetails,
					(
						SELECT GROUP_CONCAT(poc.actionResult SEPARATOR ',')
						FROM PRODUCT_ON_CLIENT AS poc WHERE poc.productId=pod.productId AND poc.clientId IN :clients
					) AS actionResultDetails,
					(
						SELECT GROUP_CONCAT(CONCAT(poc.productVersion,'-',poc.packageVersion) SEPARATOR ',')
						FROM PRODUCT_ON_CLIENT AS poc WHERE poc.productId=pod.productId AND poc.clientId IN :clients
						ORDER BY poc.clientId
					) AS clientVersions,
					(
						SELECT CONCAT_WS(',',
							IF(setupScript <> '','setup', NULL),
							IF(uninstallScript <> '','uninstall',NULL),
							IF(updateScript <> '','update',NULL),
							IF(alwaysScript <> '','always',NULL),
							IF(customScript <> '','custom',NULL),
							IF(onceScript <> '','once',NULL)
						)
						FROM PRODUCT AS p
						WHERE p.productId=pod.productId AND
							p.productVersion=pod.productVERSION AND p.packageVersion=pod.packageVersion
					) AS actions,
					GROUP_CONCAT(CONCAT(pod.productVersion,'-',pod.packageVersion) SEPARATOR ',') AS depotVersions,
					pod.productType AS productType
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
				if product.get("selectedDepots"):
					product["selectedDepots"] = product.get("selectedDepots").split(",")
				if product.get("actions"):
					product["actions"] = product.get("actions").split(",")
				if product.get("depotVersions"):
					product["depotVersions"] = product.get("depotVersions").split(",")
					if any(version != product.get("depotVersions")[0] for version in product.get("depotVersions")):
						product["depot_version_diff"] = True
					else:
						product["depot_version_diff"] = False
				if product.get("selectedClients"):
					product["selectedClients"] = product.get("selectedClients").split(",")
				if product.get("installationStatusDetails"):
					product["installationStatusDetails"] = product.get("installationStatusDetails").split(",")
					if all(value == product.get("installationStatusDetails")[0]  for value in product.get("installationStatusDetails")):
						product["installationStatus"] = product.get("installationStatusDetails")[0]
					else:
						product["installationStatus"] = "mixed"
				else:
					product["installationStatus"] = "not_installed"
					del product["installationStatusDetails"]
				if product.get("actionRequestDetails"):
					product["actionRequestDetails"] = product.get("actionRequestDetails").split(",")
					if all(value == product.get("actionRequestDetails")[0]  for value in product.get("actionRequestDetails")):
						product["actionRequest"] = product.get("actionRequestDetails")[0]
					else:
						product["actionRequest"] = "mixed"
				else:
					product["actionRequest"] = None
					del product["actionRequestDetails"]
				if product.get("actionProgressDetails"):
					product["actionProgressDetails"] = product.get("actionProgressDetails").split(",")
					if all(value == product.get("actionProgressDetails")[0]  for value in product.get("actionProgressDetails")):
						product["actionProgress"] = product.get("actionProgressDetails")[0]
					else:
						product["actionProgress"] = "mixed"
				else:
					product["actionProgress"] = None
					del product["actionProgressDetails"]
				if product.get("actionResultDetails"):
					product["actionResultDetails"] = product.get("actionResultDetails").split(",")
					if all(value == product.get("actionResultDetails")[0]  for value in product.get("actionResultDetails")):
						product["actionResult"] = product.get("actionResultDetails")[0]
					else:
						product["actionResult"] = "mixed"
				else:
					product["actionResult"] = None
					del product["actionResultDetails"]
				if product.get("clientVersions"):
					product["clientVersions"] = product.get("clientVersions").split(",")

					product["client_version_outdated"] = False
					for idx, client in enumerate(product.get("selectedClients")):
						depot = get_depot_of_client(client)
						client_version = product.get("clientVersions")[idx]
						product.get("depotVersions")
						if depot not in product.get("selectedDepots"):
							depot_version = depot_get_product_version(depot, product.get("productId"))
						else:
							depot_version = product.get("depotVersions")[product.get("selectedDepots").index(depot)]
						if client_version != depot_version:
							product["client_version_outdated"] = True
							break

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

		response_data = {
			"result": {
				"products": products,
				"total": total
			},
			"configserver": get_configserver_id()
		}
		return JSONResponse(response_data)


class PocItem(BaseModel): # pylint: disable=too-few-public-methods
	clientId: str
	productId: str
	productType: str
	version: Optional[str]
	actionRequest: Optional[str] = None
	actionProgress: Optional[str] = None
	actionResult: Optional[str] = None
	installationStatus: Optional[str] = None


@product_router.patch("/api/opsidata/clients/products")
def save_poduct_on_client(data: List[PocItem] = Body(..., embed=True)): # pylint: disable=too-many-locals, too-many-statements
	"""
	Save a Product On Client object.
	"""
	status = 200
	error = {}
	result_data = {}

	for poc in data:
		client = poc.clientId
		product = poc.productId
		version = poc.version
		action_request = poc.actionRequest

		try:
			result_data[client]
		except KeyError:
			result_data[client] = {}

		depot = get_depot_of_client(client)

		if not version:
			version = depot_get_product_version(depot, product)

		if not version:
			status = 400
			error[client] = f"Product '{product}' not on Depot.\n "
			result_data[client][product] = f"Product '{product}' not on Depot."
			continue

		product_version = version.split("-")[0]
		package_version = version.split("-")[1]


		if not is_product_on_depot(product, product_version, package_version, depot):
			status = 400
			error[client] = f"Product '{product}' Version {product_version}-{package_version} not on Depot.\n "
			result_data[client][product] = f"Product '{product}' Version {product_version}-{package_version} not on Depot."
			continue

		actions = get_product_actions(product, product_version, package_version)

		if action_request not in actions:
			status = 400
			error[client] = f"Action request '{action_request}' not supported by Product {product} Version {product_version}-{package_version}.\n "
			result_data[client][product] = f"Action request '{action_request}' not supported by Product '{product}' Version {product_version}-{package_version}." # pylint: disable=line-too-long
			continue

		params = {}
		params["clientId"] = client
		params["productId"] = product
		params["productType"] = poc.productType
		params["productVersion"] = product_version
		params["packageVersion"] = package_version
		params["actionRequest"] = poc.actionRequest
		params["actionProgress"] = poc.actionProgress
		params["actionResult"] = poc.actionResult
		params["installationStatus"] = poc.installationStatus

		values = {}

		for key in params.keys(): # pylint: disable=consider-iterating-dictionary
			if params.get(key):
				values[key] =  params.get(key)

		try:
			with mysql.session() as session:
				query = insert(table(
						"PRODUCT_ON_CLIENT",
						*[column(key) for key in values.keys()] # pylint: disable=consider-iterating-dictionary

					))\
					.values(values)\
					.on_duplicate_key_update(values)

				session.execute(query, params)

			result_data[client][product] = values
		except Exception as err: # pylint: disable=broad-except
			logger.error("Could not create product_on_client Object.")
			logger.error(err)
			error["Error"] = str(err)
			status = max(status, 500)

	return JSONResponse({"status": status, "error": error, "data": result_data})


@product_router.get("/api/opsidata/products/groups")
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
					"id": row["group_id"],
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
							"id": row["object_id"],
							"type": "ProductGroup",
							"text": row["object_id"],
							"parent": row["parent_id"] or root_group["id"]
						}
				else:
					all_groups[row["group_id"]]["children"][row["object_id"]] = {
						"id": row["object_id"],
						"type": "ObjectToGroup",
						"text": row["object_id"],
						"parent": row["group_id"],
					}

		response_data = {
			"result": {
				"groups": all_groups,
			}
		}
		return JSONResponse(response_data)


@product_router.get("/api/opsidata/producticons")
async def product_icons():
	return JSONResponse({
		"result": {"opsi-client-agent": "assets/images/product_icons/opsi-logo.png"}
	})
