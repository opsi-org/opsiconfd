# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webgui depot methods
"""

from typing import List
from pydantic import BaseModel  # pylint: disable=no-name-in-module
from sqlalchemy import select, text, and_, or_

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from .utils import get_mysql, order_by, pagination, get_configserver_id, common_query_parameters, parse_depot_list

mysql = get_mysql()

depot_router = APIRouter()

class DepotIdsResponse(BaseModel): # pylint: disable=too-few-public-methods
	result: List[str]

@depot_router.get("/api/opsidata/depotIds", response_model=DepotIdsResponse)
def depot_ids():
	"""
	Get all depotIds.
	"""
	with mysql.session() as session:
		query = (
			"SELECT hostId FROM HOST "
			"WHERE `type` IN ('OpsiConfigserver', 'OpsiDepotserver') "
			"ORDER BY hostId"
		)
		result = session.execute(query).fetchall()
		result = [ row[0] for row in result if row is not None ]
		return JSONResponse({
			"result": result
		})


class DepotResponse(BaseModel):  # pylint: disable=too-few-public-methods
	class Result(BaseModel):	# pylint: disable=too-few-public-methods
		class Depot(BaseModel):  # pylint: disable=too-few-public-methods
			depotId: str
			ident: str
			type: str
			ip: str
			description: str
		depots: List[Depot]
		total: int
	result: Result
	configserver: str

@depot_router.get("/api/opsidata/depots", response_model=DepotResponse)
def depots(commons: dict = Depends(common_query_parameters)):
	"""
	Get all depots with depotId, ident, type, ip and description.
	"""

	with mysql.session() as session:
		where = text("h.type IN ('OpsiConfigserver', 'OpsiDepotserver')")
		params = {}
		if commons.get("filterQuery"):
			where = and_(
				where,
				text("(h.hostId LIKE :search OR h.description LIKE :search)")
			)
			params["search"] = f"%{commons['filterQuery']}%"

		query = select(text(
				"h.hostId AS depotId, "
				"h.hostId AS ident, "
				"h.type, "
				"h.ipAddress AS ip, "
				"h.description "
			))\
			.select_from(text("HOST AS h"))\
			.where(where)
		query = order_by(query, commons)
		query = pagination(query, commons)

		result = session.execute(query, params)
		result = result.fetchall()

		total = session.execute(
			select(text("COUNT(*)"))\
			.select_from(text("HOST AS h"))\
			.where(where),
			params
		).fetchone()[0]

		response_data = {
			"result": {
				"depots": [ dict(row) for row in result if row is not None ],
				"total": total
			},
			"configserver": get_configserver_id()
		}
		return JSONResponse(response_data)

class ClientsOnDepotResponse(BaseModel): # pylint: disable=too-few-public-methods
	class Clients(BaseModel): # pylint: disable=too-few-public-methods
		clients: List[str]
	result: Clients


@depot_router.get("/api/opsidata/depots/clients", response_model=ClientsOnDepotResponse)
def clients_on_depots(selectedDepots: List[str] = Depends(parse_depot_list)): # pylint: disable=invalid-name
	"""
	Get all client ids on selected depots.
	"""

	params = {}
	if selectedDepots == [] or selectedDepots is None:
		params["depots"] = [get_configserver_id()]
	else:
		params["depots"] = selectedDepots

	with mysql.session() as session:
		where = text("h.type='OpsiClient'")
		for idx, depot in enumerate(params["depots"]):
			if idx > 0:
				where_depots = or_(where_depots,text(f"cs.values LIKE '%{depot}%'"))#
			else:
				where_depots = text(f"cs.values LIKE '%{depot}%'")
		if get_configserver_id() in params["depots"]:
			where_depots = or_(where_depots, text("cs.values IS NULL"))

		where = and_(where, where_depots)
		query = select(text("h.hostId AS client"))\
			.select_from(text("HOST AS h"))\
			.join(text("CONFIG_STATE AS cs"), text("h.hostId = cs.objectId AND cs.configId = 'clientconfig.depot.id'"), isouter=True)\
			.where(where)

		result = session.execute(query, params)
		result = result.fetchall()

		clients = [] # pylint: disable=redefined-outer-name
		for row in result:
			if row is not None:
				if dict(row).get("client"):
					clients.append( dict(row).get("client"))

		response_data = {
			"result": {
				"clients": clients,
			}
		}
		return JSONResponse(response_data)
