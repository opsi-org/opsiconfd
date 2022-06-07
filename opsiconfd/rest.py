# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd rest utils
"""


import asyncio
import math
import traceback
from functools import wraps
from typing import List, Optional

from fastapi import Body, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel  # pylint: disable=no-name-in-module
from sqlalchemy import asc, column, desc  # type: ignore[import]

from . import contextvar_client_session
from .application.utils import parse_list
from .logging import logger


class RestApiValidationError(BaseModel):  # pylint: disable=too-few-public-methods
	class_value: str = "RequestValidationError"
	message: str
	status: int = 422
	code: Optional[str]
	details: Optional[str]

	class Config:  # pylint: disable=too-few-public-methods
		fields = {"class_value": "class"}


class OpsiApiException(Exception):
	def __init__(self, message="An unknown error occurred.", http_status=status.HTTP_500_INTERNAL_SERVER_ERROR, code=None, error=None):
		self.message = message
		self.http_status = http_status
		self.code = code
		if isinstance(error, Exception):
			self.error_class = error.__class__.__name__
		else:
			self.error_class = self.__class__.__name__
		self.details = str(error)
		# self.details = traceback.format_exc()
		super().__init__(self.message)


def order_by(query, params):
	if not params.get("sortBy"):
		return query
	func = asc
	if params.get("sortDesc", False):
		func = desc
	sort_list = None
	if isinstance(params["sortBy"], list):
		sort_list = [func(column(col)) for col in params["sortBy"]]
	else:
		sort_list = [func(column(col)) for col in params["sortBy"].split(",")]
	return query.order_by(*sort_list)


def pagination(query, params):
	if not params.get("perPage"):
		return query
	query = query.limit(params["perPage"])
	if params.get("pageNumber") and params["pageNumber"] > 1:
		query = query.offset((params["pageNumber"] - 1) * params["perPage"])
	return query


def common_parameters(
	filterQuery: Optional[str] = Body(default=None, embed=True),
	pageNumber: Optional[int] = Body(default=1, embed=True),
	perPage: Optional[int] = Body(default=20, embed=True),
	sortBy: Optional[List[str]] = Body(default=None, embed=True),
	sortDesc: Optional[bool] = Body(default=True, embed=True),
):  # pylint: disable=invalid-name
	return {"filterQuery": filterQuery, "pageNumber": pageNumber, "perPage": perPage, "sortBy": sortBy, "sortDesc": sortDesc}


def common_query_parameters(
	filterQuery: Optional[str] = Query(default=None, embed=True),
	pageNumber: Optional[int] = Query(default=1, embed=True),
	perPage: Optional[int] = Query(default=20, embed=True),
	sortBy: Optional[List[str]] = Query(default=None, embed=True),
	sortDesc: Optional[bool] = Query(default=True, embed=True),
):  # pylint: disable=invalid-name
	return {"filterQuery": filterQuery, "pageNumber": pageNumber, "perPage": perPage, "sortBy": parse_list(sortBy), "sortDesc": sortDesc}


def rest_api(func):
	name = func.__qualname__

	async def exec_func(func, *args, **kwargs):
		if asyncio.iscoroutinefunction(func):
			return await func(*args, **kwargs)
		return func(*args, **kwargs)

	@wraps(func)
	async def create_response(*args, **kwargs):  # pylint: disable=too-many-branches,too-many-locals
		logger.debug("rest_api method name: %s", name)
		content = {}
		try:  # pylint: disable=too-many-branches,too-many-nested-blocks
			result = await exec_func(func, *args, **kwargs)
			headers = result.get("headers", {})
			headers["Access-Control-Expose-Headers"] = "x-total-count"
			http_status = result.get("http_status", status.HTTP_200_OK)

			if result.get("data"):
				content = result.get("data")

			# add header with total amount of Objects
			if result.get("total"):
				total = result.get("total")
				headers["X-Total-Count"] = str(total)
				# add link header next and last
				if kwargs.get("commons") and kwargs.get("request"):
					per_page = kwargs.get("commons", {}).get("perPage", 1)
					if total / per_page > 1:
						page_number = kwargs.get("commons", {}).get("pageNumber", 1)
						req = kwargs.get("request")
						url = req.url
						link = f"{url.scheme}://{url.hostname}:{url.port}{url.path}?"
						for param in url.query.split("&"):
							if param.startswith("pageNumber"):
								continue
							link += param + "&"
						headers[
							"Link"
						] = f'<{link}pageNumber={page_number+1}>; rel="next", <{link}pageNumber={math.ceil(total/per_page)}>; rel="last"'

			return JSONResponse(content=content if content else None, status_code=http_status, headers=headers)

		except Exception as err:  # pylint: disable=broad-except
			content = {}
			if isinstance(err, OpsiApiException):
				content = {
					"class": err.error_class,
					"code": err.code,
					"status": err.http_status,
					"message": err.message,
					"details": err.details,
				}
			else:
				content = {
					"class": err.__class__.__name__,
					"code": None,
					"status": status.HTTP_500_INTERNAL_SERVER_ERROR,
					"message": str(err),
					"details": str(traceback.format_exc()),
				}

			is_admin = False
			session = contextvar_client_session.get()
			if session and session.user_store:
				is_admin = session.user_store.isAdmin
			if not is_admin:
				del content["details"]
			return JSONResponse(content=content, status_code=content["status_code"])

	return create_response
