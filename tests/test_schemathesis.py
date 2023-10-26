# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
schemathesis tests
"""

from typing import Any

import pytest
import pytest_asyncio.plugin
from schemathesis import from_file, from_pytest_fixture
from schemathesis.models import Case
from schemathesis.specs.openapi.schemas import BaseOpenAPISchema

from opsiconfd.application import app

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_mysql,
	sync_clean_redis,
	test_client,
)


# Workaround for error:
# AttributeError: 'function' object has no attribute 'hypothesis'
def _hypothesis_test_wraps_coroutine(function: Any) -> bool:  # pylint: disable=unused-argument
	return False


pytest_asyncio.plugin._hypothesis_test_wraps_coroutine = _hypothesis_test_wraps_coroutine  # pylint: disable=protected-access


@pytest.fixture
def get_schemathesis(test_client: OpsiconfdTestClient) -> BaseOpenAPISchema:  # pylint: disable=redefined-outer-name
	response = test_client.get("/openapi.json", auth=(ADMIN_USER, ADMIN_PASS))
	return from_file(response.text, app=app)


schema = from_pytest_fixture("get_schemathesis")


@pytest.mark.xfail(reason="The provided schema uses Open API 3.1.0, which is currently not supported.")
@schema.parametrize(endpoint="^/rpc$")
def test_rpc(case: Case, test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	sync_clean_redis()
	case.call(session=test_client)  # type: ignore[arg-type]


@pytest.mark.xfail(reason="The provided schema uses Open API 3.1.0, which is currently not supported.")
@schema.parametrize(endpoint="^/admin/(?!memory)")
def test_admin(case: Case, test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	sync_clean_redis()
	case.call(session=test_client)  # type: ignore[arg-type]


@pytest.mark.xfail(reason="The provided schema uses Open API 3.1.0, which is currently not supported.")
@schema.parametrize(endpoint="^/ssl")
def test_ssl(case: Case, test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	sync_clean_redis()
	case.call(session=test_client)  # type: ignore[arg-type]
	case.call(session=test_client)  # type: ignore[arg-type]
	sync_clean_redis()
	case.call(session=test_client)  # type: ignore[arg-type]
	case.call(session=test_client)  # type: ignore[arg-type]
