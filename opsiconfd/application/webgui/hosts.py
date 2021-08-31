# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webgui host methods
"""

import datetime
from typing import List, Optional

from pydantic import BaseModel # pylint: disable=no-name-in-module
from sqlalchemy import select, union, text, and_, or_

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from .utils import (
	get_mysql, order_by,
	pagination,
	get_allowed_objects,
	get_configserver_id,
	build_tree,
	common_query_parameters,
	parse_depot_list,
	parse_hosts_list
)


mysql = get_mysql()

host_router = APIRouter()

class HostDataResponse(BaseModel):  # pylint: disable=too-few-public-methods
	class HostData(BaseModel):  # pylint: disable=too-few-public-methods
		hostId: str
		type: str
		description: str
		notes: str
		hardwareAddress: str
		ipAddress: str
		inventoryNumber: str
		created: str
		lastSeen: str
		opsiHostKey: str
		oneTimePassword: str
	result: List[HostData]

@host_router.get("/api/opsidata/hosts", response_model=HostDataResponse)
def get_host_data(
	commons: dict = Depends(common_query_parameters),
	hosts: List[str] = Depends(parse_hosts_list),
	type: Optional[str] = None,
): # pylint: disable=redefined-builtin
	"""
	Get host data.
	"""
	params = {}
	params["hosts"] = hosts

	with mysql.session() as session:
		where = text("h.hostId IN :hosts")
		if type:
			params["type"] = type
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

		query = order_by(query, commons)
		query = pagination(query, commons)

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


@host_router.get("/api/opsidata/hosts/groups")
def get_host_groups(selectedDepots: List[str] = Depends(parse_depot_list), parentGroup: Optional[str] = []): # pylint: disable=too-many-locals, too-many-branches, invalid-name, dangerous-default-value
	"""
	Get host groups as tree.
	If a parent group (parentGroupId) is given only child groups will be returned.
	"""
	allowed = get_allowed_objects()

	params = {}
	if selectedDepots == [] or selectedDepots is None:
		params["depots"] = [get_configserver_id()]
	else:
		params["depots"] = selectedDepots

	root_group = {
		"id": "root",
		"type": "HostGroup",
		"text": "root",
		"parent": None
	}

	where = text("g.`type` = 'HostGroup'")

	if parentGroup:
		if parentGroup == "root":
			where = and_(where, text("g.parentGroupId IS NULL"))
			where_hosts = text("og.groupId IS NULL")
		else:
			params["parent"] = parentGroup
			where = and_(where, text("g.parentGroupId = :parent"))
			where_hosts = text("og.groupId = :parent")
			root_group = {
				"id": parentGroup,
				"type": "HostGroup",
				"text": parentGroup,
				"parent": None
			}

	for idx, depot in enumerate(params["depots"]):
		if idx > 0:
			where_depots = or_(where_depots,text(f"cs.values LIKE '%{depot}%'"))#
		else:
			where_depots = text(f"cs.values LIKE '%{depot}%'")

	with mysql.session() as session:

		if parentGroup:
			query = union(select(text("""
				g.parentGroupId AS parent_id,
				g.groupId AS group_id,
				NULL AS object_id
			"""))\
			.select_from(text("`GROUP` AS g"))\
			.where(where),
			select(text("""
				og.groupId AS group_id,
				og.groupId AS parent_Id,
				og.objectId AS object_id
			"""))\
			.select_from(text("OBJECT_TO_GROUP AS og"))\
			.where(where_hosts)
			)
		else:
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

		all_groups = {}
		for row in result:
			if not row["group_id"] in all_groups:
				all_groups[row["group_id"]] = {
					"id": row["group_id"],
					"type": "HostGroup",
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
							"type": "ObjectToGroup",
							"text": row["object_id"],
							"parent": row["parent_id"] or root_group["id"]
						}
				else:
					all_groups[row["group_id"]]["children"][row["object_id"]] = {
						"id": row["object_id"],
						"type": "ObjectToGroup",
						"text": row["object_id"],
						"parent": row["group_id"],
						"children": None
					}


		host_groups = build_tree(root_group, list(all_groups.values()), allowed["host_groups"])

		response_data = {
			"result": {
				"groups": host_groups,
			}
		}
		return JSONResponse(response_data)
