# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webgui client methods
"""

from typing import Dict, List
from pydantic import BaseModel # pylint: disable=no-name-in-module
from sqlalchemy import select, text, and_, alias

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse


from .utils import get_mysql, order_by, pagination, get_configserver_id, common_parameters

mysql = get_mysql()

client_router = APIRouter()



class ClientsResponse(BaseModel): # pylint: disable=too-few-public-methods
	class Result(BaseModel): # pylint: disable=too-few-public-methods
		class Client(BaseModel): # pylint: disable=too-few-public-methods
			clientId: str
			ident: str
			macAddress: str
			description: str
			notes: str
			version_outdated: int
			installationStatus_unknown: int
			installationStatus_installed: int
			actionResult_failed: int
			actionResult_successful: int
		clients: List[Client]
		total: int
	result: Result
	configserver: str


@client_router.get("/api/opsidata/clients", response_model=ClientsResponse)
@client_router.post("/api/opsidata/clients", response_model=ClientsResponse)
def clients(commons: dict = Depends(common_parameters), selectedDepots: List[str] = []):  # pylint: disable=too-many-branches, dangerous-default-value, invalid-name
	"""
	Get Clients on selected depots with infos on the client.
	"""
	with mysql.session() as session:
		where = text("h.type = 'OpsiClient'")
		params = {}
		if commons.get("filterQuery"):
			where = and_(
				where,
				text("(h.hostId LIKE :search OR h.description LIKE :search)")
			)
			params["search"] = f"%{commons.get('filterQuery')}%"
		if selectedDepots:
			where = and_(
				where,
				text("""
				COALESCE(
					(
						SELECT TRIM(TRAILING '"]' FROM TRIM(LEADING '["' FROM cs.`values`)) FROM CONFIG_STATE AS cs
						WHERE cs.objectId = h.hostId AND cs.configId = 'clientconfig.depot.id'
					),
					(SELECT cv.value FROM CONFIG_VALUE AS cv WHERE cv.configId = 'clientconfig.depot.id' AND cv.isDefault = 1)
				) IN :depot_ids
				""")
			)
			params["depot_ids"] = selectedDepots

		client_with_depot = alias(
			select(text("""
				h.hostId AS clientId,
				h.hostId AS ident,
				h.hardwareAddress AS macAddress,
				h.description,
				h.notes,
				COALESCE(
					(
						SELECT TRIM(TRAILING '"]' FROM TRIM(LEADING '["' FROM cs.`values`)) FROM CONFIG_STATE AS cs
						WHERE cs.objectId = h.hostId AND cs.configId = 'clientconfig.depot.id'
					),
					(SELECT cv.value FROM CONFIG_VALUE AS cv WHERE cv.configId = 'clientconfig.depot.id' AND cv.isDefault = 1)
				) AS depotId
			""")) \
				.select_from(text("HOST AS h")) \
				.where(where)
			, name="hd"
		)
		query = select(text("""
			hd.clientId,
			hd.ident,
			hd.macAddress,
			hd.description,
			hd.notes,
			(
				SELECT
					COUNT(*)
				FROM
					PRODUCT_ON_DEPOT AS pod
				JOIN
					PRODUCT_ON_CLIENT AS poc ON
						pod.productId = poc.productId AND
						(pod.productVersion != poc.productVersion OR pod.packageVersion != poc.packageVersion)
				WHERE
					poc.clientId = hd.clientId AND
					pod.depotId = hd.depotId
			) AS version_outdated,
			(
				SELECT COUNT(*) FROM PRODUCT_ON_CLIENT AS poc
				WHERE poc.clientId = hd.clientId AND poc.installationStatus = 'unknown'
			) AS installationStatus_unknown,
			(
				SELECT COUNT(*) FROM PRODUCT_ON_CLIENT AS poc
				WHERE poc.clientId = hd.clientId AND poc.installationStatus = 'installed'
			) AS installationStatus_installed,
			(
				SELECT COUNT(*) FROM PRODUCT_ON_CLIENT AS poc
				WHERE poc.clientId = hd.clientId AND poc.actionResult = 'failed'
			) AS actionResult_failed,
			(
				SELECT COUNT(*) FROM PRODUCT_ON_CLIENT AS poc
				WHERE poc.clientId = hd.clientId AND poc.actionResult = 'successful'
			) AS actionResult_successful
		""")) \
		.select_from(client_with_depot)

		query = order_by(query, commons)
		query = pagination(query, commons)

		result = session.execute(query, params)
		result = result.fetchall()

		total = session.execute(
			select(text("COUNT(*)")).select_from(client_with_depot),
			params
		).fetchone()[0]

		response_data = {
			"result": {
				"clients": [ dict(row) for row in result if row is not None ],
				"total": total
			},
			"configserver": get_configserver_id()
		}
		return JSONResponse(response_data)

class DepotOfClientsResponse(BaseModel): # pylint: disable=too-few-public-methods
	result: Dict[str, str]

@client_router.post("/api/opsidata/clients/depots", response_model=DepotOfClientsResponse)
@client_router.get("/api/opsidata/clients/depots", response_model=DepotOfClientsResponse)
def depots_of_clients(selectedClients: List[str] = Body(default=[] , embed=True)): # pylint: disable=too-many-branches, redefined-builtin, dangerous-default-value, invalid-name
	"""
	Get a mapping of clients to depots.
	"""

#TODO check if clients of config server always work

	params = {}
	if selectedClients != [""] and selectedClients is not None:
		params["clients"] = selectedClients


	with mysql.session() as session:
		where = text("cs.configId='clientconfig.depot.id' AND cs.objectId IN :clients")

		query = select(text("cs.objectId AS client, cs.values"))\
			.select_from(text("CONFIG_STATE AS cs"))\
			.where(where)

		result = session.execute(query, params)
		result = result.fetchall()

		response = {}
		for row in result:
			tmp_dict = dict(row)
			response[tmp_dict.get("client")] = tmp_dict.get("values")[2:-2]
			params["clients"].remove(tmp_dict.get("client"))

		for client in params["clients"]:
			response[client] = get_configserver_id()


		response_data = {
			"result": response
		}
		return JSONResponse(response_data)
