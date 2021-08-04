# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webgui utils
"""

from typing import Optional
import orjson as json
from orjson import JSONDecodeError  # pylint: disable=no-name-in-module
from sqlalchemy import select, text, asc, desc, column

from fastapi import Body

from opsiconfd import contextvar_client_session
from opsiconfd.config import FQDN
from opsiconfd.logging import logger
from opsiconfd.backend import get_backend

mysql = None  # pylint: disable=invalid-name

def get_mysql():
	global mysql  # pylint: disable=invalid-name,global-statement
	if not mysql:
		backend = get_backend()
		while getattr(backend, "_backend", None):
			backend = backend._backend  # pylint: disable=protected-access
			if backend.__class__.__name__ == "BackendDispatcher":
				try:
					mysql = backend._backends["mysql"]["instance"]._sql  # pylint: disable=protected-access
				except KeyError:
					# No mysql backend
					pass
	return mysql

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
	else:
		group["children"] = None

	if not is_root_group and group.get("children"):
		for child in group["children"].values():
			# Correct id for webgui
			child["id"] = f'{child["id"]};{group["id"]}'
			if child.get("allowed"):
				# Allow parent if child is allowed
				group["allowed"] = True

	return group




def get_depot_of_client(client):
	params = {}
	with mysql.session() as session:

		params["client"] = client
		where = text("cs.configId='clientconfig.depot.id' AND cs.objectId = :client")

		query = select(text("cs.objectId AS client, cs.values"))\
			.select_from(text("CONFIG_STATE AS cs"))\
			.where(where)

		result = session.execute(query, params)
		result = result.fetchone()

		if result:
			depot = dict(result).get("values")[2:-2]
		else:
			depot = get_configserver_id()
		return depot

def common_parameters(
		filterQuery: Optional[str] = Body(default=None , embed=True),
		pageNumber: Optional[int] = Body(default=1 , embed=True),
		perPage:  Optional[int] = Body(default=20 , embed=True),
		sortBy:  Optional[str] = Body(default=None , embed=True),
		sortDesc: Optional[bool] = Body(default=True , embed=True)
	): # pylint: disable=invalid-name
	return {
		"filterQuery": filterQuery,
		"pageNumber": pageNumber,
		"perPage": perPage,
		"sortBy": sortBy,
		"sortDesc": sortDesc
	}
