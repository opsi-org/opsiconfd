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


@pytest.fixture(autouse=True)
def cleanup_database(database_connection: Connection) -> Generator[None, None, None]:  # pylint: disable=redefined-outer-name
	cursor = database_connection.cursor()

	def _delete() -> None:
		cursor.execute("DELETE FROM `SOFTWARE_LICENSE_TO_LICENSE_POOL` WHERE softwareLicenseId LIKE 'test%'")
		cursor.execute("DELETE FROM `SOFTWARE_LICENSE` WHERE softwareLicenseId LIKE 'test%'")
		cursor.execute("DELETE FROM `LICENSE_POOL` WHERE licensePoolId LIKE 'test%'")
		cursor.execute("DELETE FROM `LICENSE_CONTRACT` WHERE licenseContractId LIKE 'test%'")
		cursor.execute("DELETE FROM `PRODUCT_ON_CLIENT` WHERE productId LIKE 'test%'")
		cursor.execute("DELETE FROM `PRODUCT_ON_DEPOT` WHERE productId LIKE 'test%'")
		cursor.execute("DELETE FROM `PRODUCT_DEPENDENCY` WHERE productId LIKE 'test%'")
		cursor.execute("DELETE FROM `PRODUCT_PROPERTY_VALUE` WHERE productId LIKE 'test%'")
		cursor.execute("DELETE FROM `PRODUCT_PROPERTY` WHERE productId LIKE 'test%'")
		cursor.execute("DELETE FROM `PRODUCT` WHERE productId LIKE 'test%'")
		cursor.execute("DELETE FROM `HOST` WHERE hostId LIKE 'test%'")
		database_connection.commit()

	_delete()
	yield
	_delete()
	cursor.close()
