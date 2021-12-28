# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
schemathesis tests
"""

import schemathesis

import pytest

from .utils import (  # pylint: disable=unused-import
	config, sync_clean_redis, disable_request_warning,
	ADMIN_USER, ADMIN_PASS
)

@pytest.fixture
def get_schemathesis(config):  # pylint: disable=redefined-outer-name
	return schemathesis.from_uri(
		f"{config.external_url}/openapi.json",
		auth=(ADMIN_USER, ADMIN_PASS),
		verify=False
	)

schema = schemathesis.from_pytest_fixture("get_schemathesis")


@schema.parametrize(endpoint="^/rpc$")
def test_rpc(config, case):  # pylint: disable=redefined-outer-name
	sync_clean_redis(config.redis_internal_url)
	#case.call_and_validate(auth=(ADMIN_USER, ADMIN_PASS), verify=False)
	case.call(auth=(ADMIN_USER, ADMIN_PASS), verify=False)

@schema.parametrize(endpoint="^/admin/(?!memory)")
def test_admin(config, case):  # pylint: disable=redefined-outer-name
	sync_clean_redis(config.redis_internal_url)
	#case.call_and_validate(auth=(ADMIN_USER, ADMIN_PASS), verify=False)
	case.call(auth=(ADMIN_USER, ADMIN_PASS), verify=False)

@schema.parametrize(endpoint="^/ssl")
def test_ssl(config, case):  # pylint: disable=redefined-outer-name
	sync_clean_redis(config.redis_internal_url)
	case.call(auth=(ADMIN_USER, ADMIN_PASS), verify=False)

@schema.parametrize(endpoint="^/interface")
def test_interface(config, case):  # pylint: disable=redefined-outer-name
	sync_clean_redis(config.redis_internal_url)
	case.call(auth=(ADMIN_USER, ADMIN_PASS), verify=False)
