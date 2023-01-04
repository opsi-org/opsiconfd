# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test utils
"""

from typing import Generator

import pytest

from tests.utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	Connection,
	OpsiconfdTestClient,
	clean_redis,
	database_connection,
	get_config,
	test_client,
)


@pytest.fixture(autouse=False)
def cleanup_database(database_connection: Connection) -> Generator[None, None, None]:  # pylint: disable=redefined-outer-name
	cursor = database_connection.cursor()
	cursor.execute("DELETE FROM `PRODUCT_ON_CLIENT` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `PRODUCT_ON_DEPOT` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `PRODUCT_DEPENDENCY` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `PRODUCT_PROPERTY_VALUE` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `PRODUCT_PROPERTY` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `PRODUCT` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `HOST` WHERE hostId LIKE 'test-backend-rpc-host%'")
	database_connection.commit()
	yield
	cursor.execute("DELETE FROM `PRODUCT_ON_CLIENT` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `PRODUCT_ON_DEPOT` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `PRODUCT_DEPENDENCY` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `PRODUCT_PROPERTY_VALUE` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `PRODUCT_PROPERTY` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `PRODUCT` WHERE productId LIKE 'test-backend-rpc-product%'")
	cursor.execute("DELETE FROM `HOST` WHERE hostId LIKE 'test-backend-rpc-host%'")
	database_connection.commit()
	cursor.close()
