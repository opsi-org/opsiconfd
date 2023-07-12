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
from typing import Any, Callable, Optional

import msgspec
from fastapi import Body, Query, status
from fastapi.responses import JSONResponse, Response
from pydantic import ConfigDict, BaseModel  # pylint: disable=no-name-in-module
from sqlalchemy import asc, column, desc  # type: ignore[import]
from sqlalchemy.orm import Query as SQLQuery  # type: ignore[import]
from starlette.datastructures import URL, MutableHeaders

from opsiconfd import contextvar_client_session
from opsiconfd.application.utils import parse_list
from opsiconfd.logging import logger


class RestApiValidationError(BaseModel):  # pylint: disable=too-few-public-methods
	class_value: str = "RequestValidationError"
	message: str
	status: int = 422
	code: Optional[str] = None
	details: Optional[str] = None
	model_config = ConfigDict()


class OpsiApiException(Exception):
	def __init__(
		self,
		message: str = "An unknown error occurred.",
		http_status: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
		code: int | None = None,
		error: Exception | str | None = None,
	):
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


class RESTResponse(Response):  # pylint: disable=too-few-public-methods, too-many-instance-attributes
	def __init__(
		self,
		data: None | int | str | list | dict = None,
		total: None | int = None,
		http_status: int = status.HTTP_200_OK,
		headers: dict[str, str] | None = None,
	):
		super().__init__()
		self.status = http_status
		self._headers = MutableHeaders(headers or {})
		self.content = data
		self.total = total

	@property
	def content(self) -> None | int | str | list | dict:
		return self._content

	@content.setter
	def content(self, data: None | int | str | list | dict) -> None:
		self._content = data
		self._content_type = type(data)

	@property
	def status(self) -> int:
		return self.status_code

	@status.setter
	def status(self, status_code: int) -> None:
		if not isinstance(status_code, int):
			raise TypeError("RESTResponse http status must be integer.")
		self.status_code = status_code

	@property
	def total(self) -> int | None:
		return self._total

	@total.setter
	def total(self, total: int | None) -> None:
		if not isinstance(total, (int, NoneType)):
			raise TypeError("RESTResponse total must be integer.")
		self._total = total
		if total is not None:
			self._headers["Access-Control-Expose-Headers"] = "x-total-count"
			self._headers["X-Total-Count"] = str(self._total)

	@property
	def headers(self) -> MutableHeaders:
		return self._headers

	@headers.setter
	def headers(self, headers: dict[str, str]) -> None:
		self._headers = MutableHeaders(headers or {})

	@property
	def type(self) -> type:
		return self._content_type

	def to_jsonresponse(self) -> JSONResponse:
		try:
			return JSONResponse(content=self.content, status_code=self.status, headers=dict(self._headers))
		except TypeError as error:
			logger.error(error)
			return JSONResponse(
				content=msgspec.json.decode(msgspec.json.encode(self.content)), status_code=self.status, headers=dict(self._headers)
			)


class RESTErrorResponse(RESTResponse):
	def __init__(
		self,
		message: str = "An unknown error occurred.",
		details: str | Exception | list[dict] | None = None,
		error_class: str | None = None,
		code: str | None = None,
		http_status: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
		headers: dict | None = None,
	):  # pylint: disable=too-many-arguments
		if isinstance(details, Exception):
			error_class = details.__class__.__name__
			details = str(details)

		session = contextvar_client_session.get()
		if not session or not session.is_admin:
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
			headers=headers or {},
		)


def order_by(query: SQLQuery, params: dict[str, Any]) -> SQLQuery:
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


def pagination(query: SQLQuery, params: dict[str, Any]) -> SQLQuery:
	if not params.get("perPage"):
		return query
	query = query.limit(params["perPage"])
	if params.get("pageNumber") and params["pageNumber"] > 1:
		query = query.offset((params["pageNumber"] - 1) * params["perPage"])
	return query


def common_parameters(
	filterQuery: Optional[str] = Body(default=None, embed=True),  # pylint: disable=invalid-name
	pageNumber: Optional[int] = Body(default=1, embed=True),  # pylint: disable=invalid-name
	perPage: Optional[int] = Body(default=20, embed=True),  # pylint: disable=invalid-name
	sortBy: Optional[list[str]] = Body(default=None, embed=True),  # pylint: disable=invalid-name
	sortDesc: Optional[bool] = Body(default=True, embed=True),  # pylint: disable=invalid-name
) -> dict[str, Any]:
	return {"filterQuery": filterQuery, "pageNumber": pageNumber, "perPage": perPage, "sortBy": sortBy, "sortDesc": sortDesc}


def common_query_parameters(
	filterQuery: Optional[str] = Query(default=None, embed=True),  # pylint: disable=invalid-name
	pageNumber: Optional[int] = Query(default=1, embed=True),  # pylint: disable=invalid-name
	perPage: Optional[int] = Query(default=20, embed=True),  # pylint: disable=invalid-name
	sortBy: Optional[list[str]] = Query(default=None, embed=True),  # pylint: disable=invalid-name
	sortDesc: Optional[bool] = Query(default=True, embed=True),  # pylint: disable=invalid-name
) -> dict[str, Any]:
	return {"filterQuery": filterQuery, "pageNumber": pageNumber, "perPage": perPage, "sortBy": parse_list(sortBy), "sortDesc": sortDesc}


def create_link_header(total: int, commons: dict[str, Any], url: URL) -> dict:
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
			headers["Link"] = f'<{link}pageNumber={page_number+1}>; rel="next", <{link}pageNumber={math.ceil(total/per_page)}>; rel="last"'
	return headers


def rest_api(default_error_status_code: Callable | int | None = None) -> Callable:  # pylint: disable=too-many-statements
	_func = None
	if callable(default_error_status_code):
		# Decorator used as @rest_api not @rest_api(...)
		_func = default_error_status_code
		default_error_status_code = None

	def decorator(func: Callable) -> Callable:  # pylint: disable=too-many-statements
		name = func.__qualname__

		async def exec_func(func: Callable, *args: Any, **kwargs: Any) -> Any:
			if asyncio.iscoroutinefunction(func):
				return await func(*args, **kwargs)
			return func(*args, **kwargs)

		@wraps(func)
		async def create_response(  # pylint: disable=too-many-branches,too-many-locals,too-many-statements
			*args: Any, **kwargs: Any
		) -> JSONResponse:
			logger.debug("rest_api method name: %s", name)
			content = None
			http_status = status.HTTP_200_OK
			try:  # pylint: disable=too-many-branches,too-many-nested-blocks
				result = await exec_func(func, *args, **kwargs)
				headers = {}
				if isinstance(result, RESTResponse):  # pylint: disable=no-else-return
					if result.total and kwargs.get("request"):
						headers = create_link_header(result.total, kwargs.get("commons", {}), kwargs["request"].url)
						result.headers.update(headers)
					return result.to_jsonresponse()
				# Deprecated dict response.
				elif isinstance(result, dict) and result.get("data") is not None:
					warnings.warn(
						"opsi REST api data dict ist deprecated. All opsi api functions should return a RESTResponse.", DeprecationWarning
					)
					if result.get("data"):
						content = result.get("data")
					if result.get("total") and kwargs.get("request"):
						headers = create_link_header(int(result.get("total", 0)), kwargs.get("commons", {}), kwargs["request"].url)
						headers["Access-Control-Expose-Headers"] = "x-total-count"
						headers["X-Total-Count"] = str(result.get("total"))
				else:
					content = result
				return JSONResponse(content=content, status_code=http_status, headers=headers)

			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)
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

				session = contextvar_client_session.get()
				if not session or not session.is_admin:
					del content["details"]
				return JSONResponse(content=content, status_code=content["status"])

		return create_response

	if _func:
		return decorator(_func)
	return decorator
