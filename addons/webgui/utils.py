# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webgui utils
"""

from typing import Optional, List
from functools import  wraps
import math
import traceback
import orjson
from sqlalchemy import select, text, asc, desc, column

from fastapi import Body, Query, status
from fastapi.responses import JSONResponse

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
	sort_list = []
	if isinstance(params["sortBy"], list):
		for col in params["sortBy"]:
			sort_list.append(func(column(col)))
	else:
		for col in params["sortBy"].split(","):
			sort_list.append(func(column(col)))
	return query.order_by(*sort_list)


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
				vals = [ val for val in orjson.loads(row["values"]) if val != "" ]  # pylint: disable=no-member
				privileges[priv] = vals
			except orjson.JSONDecodeError as err:  # pylint: disable=no-member
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
		if group["type"] == "HostGroup":
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

def common_query_parameters(
		filterQuery: Optional[str] = Query(default=None , embed=True),
		pageNumber: Optional[int] = Query(default=1 , embed=True),
		perPage:  Optional[int] = Query(default=20 , embed=True),
		sortBy:  Optional[List[str] ] = Query(default=None , embed=True),
		sortDesc: Optional[bool] = Query(default=True , embed=True)
	): # pylint: disable=invalid-name
	return {
		"filterQuery": filterQuery,
		"pageNumber": pageNumber,
		"perPage": perPage,
		"sortBy": parse_list(sortBy),
		"sortDesc": sortDesc
	}


def parse_hosts_list(hosts: List[str] = Query(None)) -> Optional[List]:
	return parse_list(hosts)

def parse_depot_list(selectedDepots: List[str] = Query(None)) -> Optional[List]: # pylint: disable=invalid-name
	return parse_list(selectedDepots)

def parse_client_list(selectedClients: List[str] = Query(None)) -> Optional[List]: # pylint: disable=invalid-name
	return parse_list(selectedClients)

def parse_selected_list(selected: List[str] = Query(None)) -> Optional[List]: # pylint: disable=invalid-name
	return parse_list(selected)

def parse_list(query_list):
	def remove_prefix(value: str, prefix: str):
		return value[value.startswith(prefix) and len(prefix):]

	def remove_postfix(value: str, postfix: str):
		if value.endswith(postfix):
			value = value[:-len(postfix)]
		return value

	if query_list is None:
		return None

	# we already have a list, we can return
	if len(query_list) > 1:
		return query_list

	# if we don't start with a "[" and end with "]" it's just a normal entry
	flat_list = query_list[0]
	if not flat_list.startswith("[") and not flat_list.endswith("]"):
		return query_list

	flat_list = remove_prefix(flat_list, "[")
	flat_list = remove_postfix(flat_list, "]")

	result_list = flat_list.split(",")
	result_list = [remove_prefix(n.strip(), "\"") for n in result_list]
	result_list = [remove_postfix(n.strip(), "\"") for n in result_list]

	return list(filter(None, result_list))


def bool_product_property(value):
	if value:
		if value.lower() == "[true]" or str(value) == "1":
			return True
	return False


def unicode_product_property(value):
	if value and isinstance(value, str):
		if value.startswith('["'):
			return orjson.loads(value)  # pylint: disable=no-member
		if value == "[]":
			return [""]
		return value.replace('\\"', '"').split(",")
	return [""]


def merge_dicts(dict_a, dict_b, path=None):
	if path is None:
		path = []
	for key in dict_b:
		if key in dict_a:
			if isinstance(dict_a[key], dict) and isinstance(dict_b[key], dict):
				merge_dicts(dict_a[key], dict_b[key], path + [str(key)])
			elif isinstance(dict_a[key], list) and isinstance(dict_b[key], list):
				dict_a[key] = list(set(dict_a[key]))
			elif dict_a[key] == dict_b[key]:
				pass
			else:
				raise Exception(f"Conflict at { '.'.join(path + [str(key)])}")
		else:
			dict_a[key] = dict_b[key]
	return dict_a


def opsi_api(func):
	name = func.__qualname__

	@wraps(func)
	def create_response(*args, **kwargs): # pylint: disable=too-many-branches
		logger.devel("create_response")
		logger.devel(name)
		content = {}
		try: # pylint: disable=too-many-branches,too-many-nested-blocks
			func_result = func(*args, **kwargs)
			headers = func_result.get("headers", {})
			http_status = func_result.get("http_status", status.HTTP_200_OK)

			if func_result.get("error"):
				if func_result.get("error_code"):
					content["code"] = func_result.get("error_code")
				if traceback.format_exc():
					content["traceback"] = str(traceback.format_exc())
				error = func_result.get("error")
				if isinstance(error, Exception):
					content["class"] = error.__class__.__name__
					content["details"] = str(error)
					logger.error(str(error.__traceback__))
					logger.error(error.__traceback__.__repr__())
					logger.error(str(traceback.format_exc()))
				else:
					content["class"] = error.get("class")
					content["details"] = error.get("details")
			if func_result.get("message"):
				content["message"] = func_result.get("message")
			if func_result.get("data"):
				content = func_result.get("data")

			# add header with total amount of Objects
			if func_result.get("total"):
				total = func_result.get("total")
				headers["X-Total-Count"] = str(total)
				# add link header next and last
				if kwargs.get("commons") and kwargs.get("request"):
					per_page = kwargs.get("commons",{}).get("perPage", 1)
					if total/per_page > 1:
						page_number = kwargs.get("commons",{}).get("pageNumber", 1)
						req = kwargs.get("request")
						url = req.url
						link = f"{url.scheme}://{url.hostname}:{url.port}{url.path}?"
						for param in url.query.split("&"):
							if param.startswith("pageNumber"):
								continue
							link += param + "&"
						headers["Link"] = f'<{link}pageNumber={page_number+1}>; rel="next", <{link}pageNumber={math.ceil(total/per_page)}>; rel="last"'

			return JSONResponse(content=content if content else None, status_code=http_status, headers=headers)

		except Exception as err: # pylint: disable=broad-except
			return JSONResponse(
				content={
					"class": err.__class__.__name__,
					"message": str(err),
					"details": str(traceback.format_exc())
				},
				status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
			)

	return create_response
