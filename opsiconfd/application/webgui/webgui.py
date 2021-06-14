# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webgui
"""

from itertools import product
import os
import orjson as json
from orjson import JSONDecodeError  # pylint: disable=no-name-in-module
from sqlalchemy import select, text, and_, asc, desc, column, alias

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from opsiconfd import contextvar_client_session
from opsiconfd.config import FQDN
from opsiconfd.logging import logger
from opsiconfd.backend import get_backend

WEBGUI_APP_PATH = "/tmp/opsi-webgui"

webgui_router = APIRouter()
mysql = None  # pylint: disable=invalid-name

def webgui_setup(app):
	global mysql  # pylint: disable=invalid-name,global-statement
	app.include_router(webgui_router, prefix="/webgui")

	backend = get_backend()
	while getattr(backend, "_backend", None):
		backend = backend._backend  # pylint: disable=protected-access
		if backend.__class__.__name__ == "BackendDispatcher":
			try:
				mysql = backend._backends["mysql"]["instance"]._sql  # pylint: disable=protected-access
			except KeyError:
				# No mysql backend
				pass

	if os.path.isdir(WEBGUI_APP_PATH):
		app.mount("/webgui/app", StaticFiles(directory=WEBGUI_APP_PATH), name="app")

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
		query = query.offset((params["pageNumber"] - 1) * params["perPage"])
	return query


def get_configserver_id():
	return FQDN


def get_username():
	client_session = contextvar_client_session.get()
	if not client_session:
		raise RuntimeError("Session invalid")
	return client_session.user_store.username


def get_user_privileges():
	username = get_username()
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


@webgui_router.get("/api/auth/logout")
@webgui_router.post("/api/auth/logout")
async def auth_logout():
	client_session = contextvar_client_session.get()
	if client_session:
		client_session.delete()
	return JSONResponse({
		"result": "logout success"
	})


@webgui_router.get("/api/user/getsettings")
@webgui_router.post("/api/user/getsettings")
async def user_getsettings():
	return JSONResponse({
		"username": get_username(),
		"expertmode": False,
		"recentactivityexpiry": "3m"
	})


@webgui_router.get("/api/user/createactivity")
@webgui_router.post("/api/user/createactivity")
async def user_create_activity(request: Request):
	# {"username":"adminuser","type":"Login","status":"ok"}
	request_data = {}
	try:
		request_data = await request.json()
	except ValueError:
		pass
	if request_data.get("type").lower() == "login":
		pass
	return JSONResponse({"result":{}})


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


@webgui_router.get("/api/opsidata/log")
@webgui_router.post("/api/opsidata/log")
async def opsidata_log(request: Request):
	request_data = {}
	try:
		request_data = await request.json()
	except ValueError:
		pass

	return JSONResponse({
		"result": get_backend().readLog(  # pylint: disable=no-member
			type=request_data.get('selectedLogType'),
			objectId=request_data.get("selectedClient")
		).split("\n")
	})


@webgui_router.get("/api/opsidata/producticons")
@webgui_router.post("/api/opsidata/producticons")
async def product_icons():
	return JSONResponse({
		"result": {"opsi-client-agent": "assets/images/product_icons/opsi-logo.png"}
	})


def build_tree(group, groups, allowed, processed=None):
	if not processed:
		processed = []
	processed.append(group["id"])

	is_root_group = group["parent"] == "#"
	group["allowed"] = is_root_group or allowed == ... or group["id"] in allowed

	children = {}
	for grp in groups:
		if grp["id"] == group["id"]:
			continue
		if grp["parent"] == group["id"]:
			if grp["id"] in processed:
				logger.error("Loop: %s %s", grp["id"], processed)
			else:
				children[grp["id"]] = build_tree(grp, groups, allowed, processed)
	if children:
		if not "children" in group:
			group["children"] = {}
		group["children"].update(children)

	if not is_root_group and "children" in group:
		for child in group["children"].values():
			# Correct id for webgui
			child["id"] = f'{child["id"]};{group["id"]}'
			if child.get("allowed"):
				# Allow parent if child is allowed
				group["allowed"] = True

	return group

@webgui_router.get("/api/opsidata/home")
@webgui_router.post("/api/opsidata/home")
async def home():
	allowed = get_allowed_objects()

	with mysql.session() as session:
		product_groups = {}
		host_groups = {}

		for group_type in ("ProductGroup", "HostGroup"):
			all_groups = {}
			root_group = None
			if group_type == "ProductGroup":
				root_group = {
					"id": "productgroups",
					"type": group_type,
					"text": "productgroups",
					"parent": "#",
					"allowed": True
				}
			elif group_type == "HostGroup":
				root_group = {
					"id": "clientdirectory",
					"type": group_type,
					"text": "clientdirectory",
					"parent": "#",
					"allowed": True
				}

			for row in session.execute(
				"""
				SELECT
					g.parentGroupId AS parent_id,
					g.groupId AS group_id,
					og.objectId AS object_id
				FROM
					`GROUP` AS g
				LEFT JOIN
					OBJECT_TO_GROUP AS og ON og.groupType = g.`type` AND og.groupId = g.groupId
				WHERE
					g.`type` = :group_type
				ORDER BY
					parent_id,
					group_id,
					object_id
				""",
				{"group_type": group_type}
			).fetchall():
				if not row["group_id"] in all_groups:
					all_groups[row["group_id"]] = {
						"id": row["group_id"],
						"type": group_type,
						"text": row["group_id"],
						"parent": row["parent_id"] or root_group["id"],
						"allowed": True
					}
				if row["object_id"]:
					if not "children" in all_groups[row["group_id"]]:
						all_groups[row["group_id"]]["children"] = {}
					all_groups[row["group_id"]]["children"][row["object_id"]] = {
						"id": row["object_id"],
						"type": "ObjectToGroup",
						"text": row["object_id"],
						"parent": row["group_id"],
						"inDepot": "configserver" # TODO
					}

			if group_type == "ProductGroup":
				product_groups = build_tree(root_group, all_groups.values(), allowed["product_groups"])
			elif group_type == "HostGroup":
				host_groups = build_tree(root_group, list(all_groups.values()), allowed["host_groups"])

		return JSONResponse({
			"groups":{
				"productgroups": product_groups,
				"clientdirectory": host_groups
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
			params["search"] = f"%{request_data['filterQuery']}%"
		if request_data.get("selectedDepots"):
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
			params["depot_ids"] = request_data['selectedDepots']

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

		query = order_by(query, request_data)
		query = pagination(query, request_data)

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


@webgui_router.post("/api/opsidata/products")
async def products(request: Request):
	request_data = {}
	try:
		request_data = await request.json()
	except ValueError:
		pass

	product_type = request_data.get("type", "LocalbootProduct")
	client_list = request_data.get("clients", [""])
	depots_list = request_data.get("depots", [""])

	logger.devel(product_type)
	logger.devel(client_list)
	logger.devel(depots_list)

	clients = ""
	for idx, client in enumerate(client_list):
		clients += f"'{client}'"
		if idx < (len(client_list) - 1) and len(client_list) > 1:
			clients += ","

	depots = ""
	for idx, depot in enumerate(depots_list):
		depots += f"'{depot}'"
		if idx < (len(depots_list) - 1) and len(depots_list) > 1:
			depots += ","

	with mysql.session() as session:
		where = text(f"poc.productType='{product_type}' AND poc.clientId IN ({clients})")
		logger.devel(where)
		query = select(text(
				"poc.productId AS productId,"
				"poc.clientId AS clientId,"
				"poc.installationStatus AS installationStatus,"
				"poc.actionRequest AS actionRequest,"
				"poc.actionProgress AS actionProgress,"
				"poc.actionResult AS actionResult"
			))\
			.select_from(text("PRODUCT_ON_CLIENT AS poc"))\
			.where(where)\
			.union(
				select(text(
					"pod.productId AS productId,"
					"NULL AS clientId,"
					"NULL AS installationStatus,"
					"NULL AS actionRequest,"
					"NULL AS actionProgress,"
					"NULL AS actionResult"
				))\
				.select_from(text("PRODUCT_ON_DEPOT AS pod"))\
				.where(text(f"pod.productId NOT IN (SELECT poc.productId FROM PRODUCT_ON_CLIENT AS poc WHERE poc.clientId in ({clients})) AND pod.depotId in ({depots})")
			))
		query = order_by(query, request_data)
		query = pagination(query, request_data)

		result = session.execute(query)
		result = result.fetchall()

		products = [ dict(row) for row in result if row is not None ]

		total = len(products)

		response_data = {
			"result": {
				"products": products,
				"total": total
			},
			"configserver": get_configserver_id()
		}
		return JSONResponse(response_data)
