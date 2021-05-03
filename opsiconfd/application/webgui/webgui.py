# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webgui
"""

from sqlalchemy import select, text, and_, asc, desc, column

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from opsiconfd.logging import logger
from opsiconfd.backend import get_backend

webgui_router = APIRouter()
mysql = None  # pylint: disable=invalid-name

def webgui_setup(app):
	global mysql  # pylint: disable=invalid-name,global-statement
	app.include_router(webgui_router, prefix="/webgui")

	backend = get_backend()
	while getattr(backend, "_backend", None):
		backend = backend._backend  # pylint: disable=protected-access
		if backend.__class__.__name__ == "BackendDispatcher":
			mysql = backend._backends["mysql"]["instance"]._sql  # pylint: disable=protected-access


def order_by(query, params):
	if not params.get("sortBy"):
		return query
	func = asc
	if params.get("sortDesc", False):
		func = desc
	return query.order_by(func(column(params["sortBy"])))

def pagination(query, params):
	if not params.get("perPage"):
		return query
	query = query.limit(params["perPage"])
	if params.get("pageNumber") and params["pageNumber"] > 1:
		query = query.offset(params["pageNumber"] * params["perPage"])
	return query


@webgui_router.options("/api/{any:path}")
async def options():
	return Response(
		status_code=200
	)


@webgui_router.get("/api/opsidata/depotIds")
@webgui_router.post("/api/opsidata/depotIds")
@webgui_router.post("/api/opsidata/depotsIds")
async def depot_ids():
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


@webgui_router.get("/api/opsidata/depots")
@webgui_router.post("/api/opsidata/depots")
async def depots(request: Request):
	request_data = {}
	try:
		request_data = await request.json()
	except ValueError:
		pass

	logger.devel(request_data)

	with mysql.session() as session:
		configserver_id = session.execute(
			"SELECT hostId FROM HOST WHERE `type` = 'OpsiConfigserver'"
		).fetchone()[0]

		where = text("h.type IN ('OpsiConfigserver', 'OpsiDepotserver')")
		query = select(text(
				"h.hostId AS depotId, "
				"h.hostId AS ident, "
				"h.type, "
				"h.ipAddress AS ip, "
				"h.description "
			))\
			.select_from(text("HOST AS h"))\
			.where(where)
		query = order_by(query, request_data)
		query = pagination(query, request_data)

		logger.devel(query)
		result = session.execute(query)
		result = result.fetchall()

		total = session.execute(
			select(text("COUNT(*)"))\
			.select_from(text("HOST AS h"))\
			.where(where)
		).fetchone()[0]

		response_data = {
			"result": {
				"depots": [ dict(row) for row in result if row is not None ],
				"total": total
			},
			"configserver": configserver_id
		}
		return JSONResponse(response_data)


@webgui_router.get("/api/opsidata/clients")
@webgui_router.post("/api/opsidata/clients")
async def clients(request: Request):  # pylint: disable=too-many-branches
	# {"pageNumber":1,"perPage":10,"sortBy":"clientId","sortDesc":false,"filterQuery":"","selectedDepot":["anna-vm-24001.uib.local"]}
	request_data = {}
	try:
		request_data = await request.json()
	except ValueError:
		pass

	with mysql.session() as session:
		configserver_id = session.execute(
			"SELECT hostId FROM HOST WHERE `type` = 'OpsiConfigserver'"
		).fetchone()[0]

		where = text("h.type = 'OpsiClient'")
		params = {}
		if request_data.get("filterQuery"):
			where = and_(
				where,
				text("(h.hostId LIKE :search OR h.description LIKE :search)")
			)
			params = {"search": f"%{request_data['filterQuery']}%"}
		query = select(text("""
				h.hostId AS clientId,
				h.hostId AS ident,
				h.hardwareAddress AS macAddress,
				h.description,
				h.notes,
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
						poc.clientId = h.hostId AND
						pod.depotId = COALESCE(
							(
								SELECT TRIM(TRAILING '"]' FROM TRIM(LEADING '["' FROM cs.`values`)) FROM CONFIG_STATE AS cs
								WHERE cs.objectId = h.hostId AND cs.configId = 'clientconfig.depot.id'
							),
							(SELECT cv.value FROM CONFIG_VALUE AS cv WHERE cv.configId = 'clientconfig.depot.id' AND cv.isDefault = 1)
						)
				) AS version_outdated,
				(
					SELECT COUNT(*) FROM PRODUCT_ON_CLIENT AS poc
					WHERE poc.clientId = h.hostId AND poc.installationStatus = 'unknown'
				) AS installationStatus_unknown,
				(
					SELECT COUNT(*) FROM PRODUCT_ON_CLIENT AS poc
					WHERE poc.clientId = h.hostId AND poc.installationStatus = 'installed'
				) AS installationStatus_installed,
				(
					SELECT COUNT(*) FROM PRODUCT_ON_CLIENT AS poc
					WHERE poc.clientId = h.hostId AND poc.actionResult = 'failed'
				) AS actionResult_failed,
				(
					SELECT COUNT(*) FROM PRODUCT_ON_CLIENT AS poc
					WHERE poc.clientId = h.hostId AND poc.actionResult = 'successful'
				) AS actionResult_successful
			"""))\
			.select_from(text("HOST AS h"))\
			.where(where)

		query = order_by(query, request_data)
		query = pagination(query, request_data)

		result = session.execute(query, params)
		result = result.fetchall()

		total = session.execute(
			select(text("COUNT(*)")).select_from(text("HOST AS h")).where(where),
			params
		).fetchone()[0]

		response_data = {
			"result": {
				"clients": [ dict(row) for row in result if row is not None ],
				"total": total
			},
			"configserver": configserver_id
		}
		return JSONResponse(response_data)
