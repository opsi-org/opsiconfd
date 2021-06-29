# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webgui
"""

import os
import datetime
import orjson as json
from orjson import JSONDecodeError  # pylint: disable=no-name-in-module
from sqlalchemy import select, text, and_, or_, asc, desc, column, alias

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

	is_root_group = group["parent"] == "#" #or group["id"] == "clientdirectory"
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

@webgui_router.post("/api/opsidata/hosts/groups")
async def get_host_groups(request: Request): # pylint: disable=too-many-locals
	allowed = get_allowed_objects()
	request_data = {}
	try:
		request_data = await request.json()
	except ValueError:
		pass
	params = {}
	if request_data.get("selectedDepots") == []:
		params["depots"] = [get_configserver_id()]
	else:
		params["depots"] = request_data.get("selectedDepots", [get_configserver_id()])

	where = text("g.`type` = 'HostGroup'")

	for idx, depot in enumerate(params["depots"]):
		if idx > 0:
			where_depots = or_(where_depots,text(f"cs.values LIKE '%{depot}%'"))#
		else:
			where_depots = text(f"cs.values LIKE '%{depot}%'")

	with mysql.session() as session:

		query = select(text("""
			g.parentGroupId AS parent_id,
			g.groupId AS group_id,
			og.objectId AS object_id,
			TRIM(TRAILING '"]' FROM TRIM(LEADING '["' FROM cs.`values`)) AS depot_id
		"""))\
		.select_from(text("`GROUP` AS g"))\
		.join(text("OBJECT_TO_GROUP AS og"), text("og.groupType = g.`type` AND og.groupId = g.groupId"), isouter=True)\
		.join(
			text("CONFIG_STATE AS cs"),
			and_(text("og.objectId = cs.objectId"), or_(text("cs.configId = 'clientconfig.depot.id'"),text("cs.values IS NULL")), where_depots),
			isouter=True)\
		.where(where)

		result = session.execute(query, params)
		result = result.fetchall()

		root_group = {
			"id": "root",
			"type": "HostGroup",
			"text": "root",
			"parent": None,
			"allowed": True
		}
		all_groups = {}
		for row in result:
			if not row["group_id"] in all_groups:
				all_groups[row["group_id"]] = {
					"id": row["group_id"],
					"type": "HostGroup",
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
					"depot": row["depot_id"] or get_configserver_id()
				}

		host_groups = build_tree(root_group, list(all_groups.values()), allowed["host_groups"])

		response_data = {
			"result": {
				"groups": host_groups,
			}
		}
		return JSONResponse(response_data)


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
		params = {}
		if request_data.get("filterQuery"):
			where = and_(
				where,
				text("(h.hostId LIKE :search OR h.description LIKE :search)")
			)
			params["search"] = f"%{request_data['filterQuery']}%"

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


@webgui_router.post("/api/opsidata/depots/clients")
async def clients_on_depots(request: Request):
	request_data = {}
	try:
		request_data = await request.json()
	except ValueError:
		pass

	params = {}
	if request_data.get("selectedDepots") == []:
		params["depots"] = [get_configserver_id()]
	else:
		params["depots"] = request_data.get("selectedDepots", [get_configserver_id()])

	logger.devel(params)
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


@webgui_router.post("/api/opsidata/clients/depots")
async def depots_of_clients(request: Request):
	request_data = {}
	try:
		request_data = await request.json()
	except ValueError:
		pass

	params = {}
	if request_data.get("selectedClients") == []:
		params["clients"] = [""]
	else:
		params["clients"] = request_data.get("selectedClients", [""])

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

@webgui_router.post("/api/opsidata/hosts")
async def get_host_data(request: Request):
	request_data = {}
	try:
		request_data = await request.json()
	except ValueError:
		pass

	params = {}
	params["hosts"] = request_data.get("hosts")

	with mysql.session() as session:
		where = text("h.hostId IN :hosts")
		if request_data.get("type"):
			params["type"] = request_data.get("type")
			where = and_(where, text("h.type = :type"))
		query = select(text("""
			h.hostId AS hostId,
			h.type AS type,
			h.description AS description,
			h.notes AS notes,
			h.hardwareAddress AS hardwareAddress,
			h.ipAddress AS ipAddress,
			h.inventoryNumber AS inventoryNumber,
			h.created AS created,
			h.lastSeen AS lastSeen,
			h.opsiHostKey AS opsiHostKey,
			h.oneTimePassword AS oneTimePassword
		"""))\
		.select_from(text("`HOST` AS h"))\
		.where(where) # pylint: disable=redefined-outer-name

		query = order_by(query, request_data)
		query = pagination(query, request_data)

		result = session.execute(query, params)
		result = result.fetchall()

		host_data = []
		for row in result:
			if row is not None:
				row_dict = dict(row)
				for key in row_dict.keys():
					if isinstance(row_dict.get(key), (datetime.date, datetime.datetime)):
						row_dict[key] = row_dict.get(key).isoformat()
				host_data.append(row_dict)

		if len(host_data) == 1:
			response_data = {
				"result": host_data[0]
			}
		else:
			response_data = {
				"result": host_data
			}
		return JSONResponse(response_data)

@webgui_router.post("/api/opsidata/localbootproducts")
@webgui_router.post("/api/opsidata/products")
async def products(request: Request): # pylint: disable=too-many-locals, too-many-branches, too-many-statements
	request_data = {}
	try:
		request_data = await request.json()
	except ValueError:
		pass

	params = {}
	params["product_type"] = request_data.get("type", "LocalbootProduct")
	if request_data.get("selectedClients") == []:
		params["clients"] = [""]
	else:
		params["clients"] = request_data.get("selectedClients", [""])
	if request_data.get("selectedDepots") == []:
		params["depots"] = [get_configserver_id()]
	else:
		params["depots"] = request_data.get("selectedDepots", [get_configserver_id()])



	with mysql.session() as session:
		where = text("pod.depotId IN :depots AND pod.producttype = :product_type")
		if request_data.get("filterQuery"):
			where = and_(
				where,
				text("(pod.productId LIKE :search)")
			)
			params["search"] = f"%{request_data['filterQuery']}%"

		query = select(text("""
					pod.productId AS productId,
					p.name AS name,
					p.description AS description,
					GROUP_CONCAT(pod.depotId SEPARATOR ',') AS selectedDepots,
					(
						SELECT GROUP_CONCAT(poc.clientId SEPARATOR ',')
						FROM PRODUCT_ON_CLIENT AS poc WHERE poc.clientId IN :clients AND poc.productId=pod.productId
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
					) AS clientVersions,
					(
						SELECT CONCAT_WS(',',
							IF(setupScript <> '','setup', NULL),
							IF(uninstallScript <> '','uninstall',NULL),
							IF(updateScript <> '','update',NULL),
							IF(alwaysScript <> '','always',NULL),
							IF(customScript <> '','customScript',NULL),
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

		query = order_by(query, request_data)
		query = pagination(query, request_data)

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
					logger.devel("DEPOT VERSION: %s , %s",product["productId"], product.get("depotVersions")[0] )
					logger.devel(product.get("depotVersions"))
					logger.devel(any(version != product.get("depotVersions")[0] for version in product.get("depotVersions")))
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
					if any(version != product.get("depotVersions")[idx] for idx, version in enumerate(product.get("clientVersions"))):
						product["client_version_outdated"] = True
					else:
						product["client_version_outdated"] = False


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
