# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test rest
"""


from types import NoneType
from typing import Any

import pytest
from fastapi import status
from fastapi.responses import JSONResponse

from opsiconfd.rest import RESTErrorResponse, RESTResponse


@pytest.mark.parametrize(
	"data, output",
	[
		(
			{"content": None},
			{"content": None, "total": None, "http_status": status.HTTP_200_OK, "headers": {}, "type": NoneType},
		),
		(
			{"content": {"test": 1}, "http_status": status.HTTP_201_CREATED},
			{"content": {"test": 1}, "total": None, "http_status": status.HTTP_201_CREATED, "headers": {}, "type": dict},
		),
	],
)
def test_restresponse(data: Any, output: Any) -> None:
	rest_response = RESTResponse(
		data=data.get("content"),
		total=data.get("total"),
		http_status=data.get("http_status", status.HTTP_200_OK),
		headers=data.get("headers"),
	)
	print(rest_response.content)
	assert rest_response.content == output["content"]
	assert rest_response.total == output["total"]
	assert rest_response.status == output["http_status"]
	assert dict(rest_response.headers) == output["headers"]
	assert rest_response.type == output["type"]

	json_response = rest_response.to_jsonresponse()
	assert (
		json_response.status_code
		== JSONResponse(content=output["content"], status_code=output["http_status"], headers=output["headers"]).status_code
	)
	assert json_response.body == JSONResponse(content=output["content"], status_code=output["http_status"], headers=output["headers"]).body


def test_restresponse_status_error() -> None:
	with pytest.raises(TypeError, match="RESTResponse http status must be integer."):
		RESTResponse(http_status="test")  # type: ignore[arg-type]


def test_restresponse_toral_error() -> None:
	with pytest.raises(TypeError, match="RESTResponse total must be integer."):
		RESTResponse(total="test")  # type: ignore[arg-type]


@pytest.mark.parametrize(
	"data, output",
	[
		(
			{},
			{
				"total": None,
				"http_status": status.HTTP_500_INTERNAL_SERVER_ERROR,
				"headers": {},
				"code": None,
				"error_class": None,
				"message": "An unknown error occurred.",
				"details": None,
			},
		),
		(
			{"message": "Test Error"},
			{
				"total": None,
				"http_status": status.HTTP_500_INTERNAL_SERVER_ERROR,
				"headers": {},
				"code": None,
				"error_class": None,
				"message": "Test Error",
				"details": None,
			},
		),
		(
			{
				"message": "This is a error message.",
				"details": ValueError("Test Value error"),
				"http_status": status.HTTP_422_UNPROCESSABLE_ENTITY,
			},
			{
				"total": None,
				"http_status": status.HTTP_422_UNPROCESSABLE_ENTITY,
				"headers": {},
				"code": None,
				"error_class": "ValueError",
				"message": "This is a error message.",
				"details": "Test Value error",
			},
		),
	],
)
def test_resterrorresponse(data: Any, output: Any) -> None:
	rest_response = RESTErrorResponse(
		message=data.get("message", "An unknown error occurred."),
		details=data.get("details"),
		error_class=data.get("error_class"),
		code=data.get("code"),
		http_status=data.get("http_status", status.HTTP_500_INTERNAL_SERVER_ERROR),
		headers=data.get("headers"),
	)

	print(output)

	# details = None -> no admin user
	assert rest_response.content == {
		"class": output.get("error_class"),
		"code": output.get("code"),
		"status": output.get("http_status", status.HTTP_500_INTERNAL_SERVER_ERROR),
		"message": output.get("message"),
		"details": None,
	}
	assert rest_response.total == output["total"]
	assert rest_response.status == output["http_status"]
	assert dict(rest_response.headers) == output["headers"]
