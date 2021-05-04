# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webgui
"""

import orjson as json
from orjson import JSONDecodeError
from sqlalchemy import select, text, and_, asc, desc, column

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from OPSI.Util import getfqdn

from opsiconfd import contextvar_client_session
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

def get_configserver_id():
	return getfqdn()

def get_user_privileges():
	username = "adminuser"
	#client_session = contextvar_client_session.get()
	#if not client_session:
	#	raise RuntimeError("Session invalid")
	#username = client_session.user_store.username

	privileges = {}
	with mysql.session() as session:
		for row in session.execute(
			"""
			SELECT
				cs.configId,
				cs.values
			FROM
				CONFIG_STATE AS cs
			WHERE
				cs.configId LIKE :config_id_filter
			GROUP BY
				cs.configId
			ORDER BY
				cs.configId
			""",
			{"config_id_filter": f"user.{{{username}}}.privilege.%"}
		).fetchall():
			try:
				priv = ".".join(row["configId"].split(".")[3:])
				vals = [ val for val in json.loads(row["values"]) if val != "" ]  # pylint: disable=c-extension-no-member
				privileges[priv] = vals
			except JSONDecodeError as err:
				logger.error("Failed to parse privilege %s: %s", row, err)

		return privileges


def get_allowed_objects():
	allowed = {
		"product_groups": ...,
		"host_groups": ...
	}
	privileges = get_user_privileges()
	if True in privileges.get("product.groupaccess.configured", [False]):
		allowed["product_groups"] = privileges.get("product.groupaccess.productgroups", [])
	if True in privileges.get("host.groupaccess.configured", [False]):
		allowed["host_groups"] = privileges.get("host.groupaccess.productgroups", [])
	return allowed


@webgui_router.options("/api/{any:path}")
async def options():
	return Response(
		status_code=200
	)



@webgui_router.get("/api/auth/login")
@webgui_router.post("/api/auth/login")
async def auth_login():
	return JSONResponse({
		"result": "Login success"
	})


@webgui_router.get("/api/user/opsiserver")
@webgui_router.post("/api/user/opsiserver")
async def user_opsiserver():
	return JSONResponse({
		"result": get_configserver_id()
	})


@webgui_router.get("/api/opsidata/modulesContent")
@webgui_router.post("/api/opsidata/modulesContent")
async def modules_content():
	return JSONResponse({
		"result": get_backend().backend_info()["modules"]
	})


@webgui_router.get("/api/opsidata/home")
@webgui_router.post("/api/opsidata/home")
async def home():
	allowed = get_allowed_objects()

	all_groups = {}
	with mysql.session() as session:
		for row in session.execute(
			"""
			SELECT
				g.parentGroupId AS parent_id,
				g.groupId AS group_id,
				og.objectId AS product_id
			FROM
				`GROUP` AS g
			LEFT JOIN
				OBJECT_TO_GROUP AS og ON og.groupType = g.`type` AND og.groupId = g.groupId
			WHERE
				g.`type` = "ProductGroup"
			ORDER BY
				parent_id,
				group_id,
				product_id
			"""
		).fetchall():
			if not row["group_id"] in all_groups:
				all_groups[row["group_id"]] = {
					"id": row["group_id"],
					"type": "ProductGroup",
					"text": row["group_id"],
					"parent": row["parent_id"],
					"allowed": True
				}
			if row["product_id"]:
				if not "children" in all_groups[row["group_id"]]:
					all_groups[row["group_id"]]["children"] = {}
				all_groups[row["group_id"]]["children"][row["product_id"]] = {
					"id": row["product_id"],
					"type": "ObjectToGroup",
					"text": row["product_id"],
					"parent": row["group_id"],
					"inDepot": "configserver" ############ TODO
				}

		def build_tree(group, groups):
			is_root_group = group["parent"] == "#"

			if not is_root_group and group["parent"] and group["parent"] not in all_groups:
				logger.error("Parent group '%s' of group '%s' not found", group["parent"], group["text"])

			children = {}
			for grp in groups:
				if (
					grp["parent"] == group["id"] or
					(grp["parent"] is None and is_root_group)
				):
					children[grp["id"]] = build_tree(grp, groups)
			if children:
				if not "children" in group:
					group["children"] = {}
				group["children"].update(children)

			if not is_root_group and "children" in group:
				# Correct ids for webgui
				for child in group["children"].values():
					child["id"] = f'{child["id"]};{group["id"]}'
			return group

		base_group = {
			"id": "productgroups",
			"type": "ProductGroup",
			"text": "productgroups",
			"parent": "#",
			"allowed": True
		}
		product_groups = build_tree(base_group, all_groups.values())

	return JSONResponse({
		"groups":{
			"productgroups": product_groups
		}
	})


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
			"configserver": get_configserver_id()
		}
		return JSONResponse(response_data)


@webgui_router.get("/api/opsidata/clients")
@webgui_router.post("/api/opsidata/clients")
async def clients(request: Request):  # pylint: disable=too-many-branches
	request_data = {}
	try:
		request_data = await request.json()
	except ValueError:
		pass

	with mysql.session() as session:
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
			"configserver": get_configserver_id()
		}
		return JSONResponse(response_data)
