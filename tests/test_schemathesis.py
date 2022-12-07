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
import schemathesis

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	config,
	sync_clean_redis,
)


# Workaround for error:
# AttributeError: 'function' object has no attribute 'hypothesis'
def _hypothesis_test_wraps_coroutine(function: Any) -> bool:  # pylint: disable=unused-argument
	return False


pytest_asyncio.plugin._hypothesis_test_wraps_coroutine = _hypothesis_test_wraps_coroutine  # pylint: disable=protected-access


@pytest.fixture
def get_schemathesis(config: Config) -> schemathesis.specs.openapi.schemas.BaseOpenAPISchema:  # pylint: disable=redefined-outer-name
	return schemathesis.from_uri(f"{config.internal_url}/openapi.json", auth=(ADMIN_USER, ADMIN_PASS), verify=False)


schema = schemathesis.from_pytest_fixture("get_schemathesis")


@schema.parametrize(endpoint="^/rpc$")
def test_rpc(case: schemathesis.models.Case) -> None:  # pylint: disable=redefined-outer-name
	sync_clean_redis()
	# case.call_and_validate(auth=(ADMIN_USER, ADMIN_PASS))
	case.call(auth=(ADMIN_USER, ADMIN_PASS), verify=False)


@schema.parametrize(endpoint="^/admin/(?!memory)")
def test_admin(case: schemathesis.models.Case) -> None:  # pylint: disable=redefined-outer-name
	sync_clean_redis()
	# case.call_and_validate(auth=(ADMIN_USER, ADMIN_PASS))
	case.call(auth=(ADMIN_USER, ADMIN_PASS), verify=False)


@schema.parametrize(endpoint="^/ssl")
def test_ssl(case: schemathesis.models.Case) -> None:  # pylint: disable=redefined-outer-name
	sync_clean_redis()
	case.call(auth=(ADMIN_USER, ADMIN_PASS), verify=False)
