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
import warnings
from functools import wraps
from types import NoneType
from typing import Callable, List, Optional, Union

from fastapi import Body, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel  # pylint: disable=no-name-in-module
from sqlalchemy import asc, column, desc  # type: ignore[import]
from starlette.datastructures import URL

from . import contextvar_client_session
from .application.utils import merge_dicts, parse_list
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


class RESTResponse:  # pylint: disable=too-few-public-methods, too-many-instance-attributes

	def __init__(
		self,
		data: Union[None, int, str, list, dict] = None,
		total: Union[None, int] = None,
		http_status: int = status.HTTP_200_OK,
		headers: dict = {}
	):  # pylint: disable=dangerous-default-value
		self.status = http_status
		self.content = data
		self.total = total
		self.headers = headers

	@property
	def content(self) -> Union[NoneType, int, str, list, dict]:
		return self._content

	@content.setter
	def content(self, data: Union[NoneType, int, str, list, dict]):
		self._content = data
		self._content_type = type(data)

	@property
	def status(self) -> int:
		return self._status

	@status.setter
	def status(self, http_status: int):
		if not isinstance(http_status, int):
			raise TypeError("RESTResponse http status must be integer.")
		self._status = http_status

	@property
	def total(self) -> int:
		return self._total

	@total.setter
	def total(self, total: int):
		if not isinstance(total, (int, NoneType)):
			raise TypeError("RESTResponse total must be integer.")
		self._total = total

	@property
	def headers(self) -> dict:
		return self._headers

	@headers.setter
	def headers(self, headers: dict = {}):  # pylint: disable=dangerous-default-value
		if not isinstance(headers, dict):
			headers = {}
		self._headers = headers
		if self._total:
			self._headers["Access-Control-Expose-Headers"] = "x-total-count"
			self._headers["X-Total-Count"] = str(self._total)

	@property
	def type(self) -> type:
		return self._content_type

	def to_jsonresponse(self) -> JSONResponse:
		return JSONResponse(content=self._content, status_code=self._status, headers=self._headers)


class RESTErrorResponse(RESTResponse):

	def __init__(
		self,
		message: str = "An unknown error occurred.",
		details: Union[str, Exception] = None,
		error_class: str = None,
		code: str = None,
		http_status: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
		headers: dict = None
	):  # pylint: disable=too-many-arguments

		if isinstance(details, Exception):
			error_class = details.__class__.__name__
			details = str(details)

		is_admin = False
		session = contextvar_client_session.get()
		if session and session.user_store:
			is_admin = session.user_store.isAdmin
		if not is_admin:
			details = None
		super().__init__(
			data={
				"class": error_class,
				"code": code,
				"status": http_status,
				"message": message,
				"details": details,
			},
			http_status=http_status,
			headers=headers
		)


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


def create_link_header(total: int, commons: dict, url: URL) -> dict:
	# add link header next and last
	headers = {}
	if commons and url:
		per_page = commons.get("perPage", 1)
		if total / per_page > 1:
			page_number = commons.get("pageNumber", 1)
			link = f"{url.scheme}://{url.hostname}:{url.port}{url.path}?"
			for param in url.query.split("&"):
				if param.startswith("pageNumber"):
					continue
				link += param + "&"
			headers[
				"Link"
			] = f'<{link}pageNumber={page_number+1}>; rel="next", <{link}pageNumber={math.ceil(total/per_page)}>; rel="last"'
	return headers


def rest_api(default_error_status_code: Union[Callable, int, None] = None):  # pylint: disable=too-many-statements
	_func = None
	if callable(default_error_status_code):
		# Decorator used as @rest_api not @rest_api(...)
		_func = default_error_status_code
		default_error_status_code = None

	def decorator(func: Callable):  # pylint: disable=too-many-statements
		name = func.__qualname__

		async def exec_func(func, *args, **kwargs):
			if asyncio.iscoroutinefunction(func):
				return await func(*args, **kwargs)
			return func(*args, **kwargs)

		@wraps(func)
		async def create_response(*args, **kwargs):  # pylint: disable=too-many-branches,too-many-locals,too-many-statements
			logger.debug("rest_api method name: %s", name)
			content = None
			http_status = status.HTTP_200_OK
			headers = {}
			try:  # pylint: disable=too-many-branches,too-many-nested-blocks
				result = await exec_func(func, *args, **kwargs)
				if isinstance(result, RESTResponse):  # pylint: disable=no-else-return
					headers = create_link_header(result.total, kwargs.get("commons"), kwargs.get("request"))
					if result.headers and headers:
						result.headers = merge_dicts(result.headers, headers)
					else:
						result.headers = headers
					return result.to_jsonresponse()
				# Deprecated dict response.
				elif isinstance(result, dict) and result.get("data"):
					warnings.warn("opsi REST api data dict ist deprecated. All opsi api functions should return a RESTResponse.", DeprecationWarning)
					if result.get("data"):
						content = result.get("data")
					headers = create_link_header(result.total, kwargs.get("commons"), kwargs.get("request"))
				else:
					content = result
				return JSONResponse(content=content, status_code=http_status, headers=headers)

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
						"status": default_error_status_code or status.HTTP_500_INTERNAL_SERVER_ERROR,
						"message": str(err),
						"details": str(traceback.format_exc()),
					}

				is_admin = False
				session = contextvar_client_session.get()
				if session and session.user_store:
					is_admin = session.user_store.isAdmin
				if not is_admin:
					del content["details"]
				return JSONResponse(content=content, status_code=content["status"])
		return create_response

	if _func:
		return decorator(_func)
	return decorator
