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

from opsiconfd.config import get_configserver_id
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
		cursor.execute("DELETE FROM `LICENSE_ON_CLIENT`")
		cursor.execute("DELETE FROM `SOFTWARE_LICENSE_TO_LICENSE_POOL`")
		cursor.execute("DELETE FROM `SOFTWARE_LICENSE`")
		cursor.execute("DELETE FROM `LICENSE_POOL`")
		cursor.execute("DELETE FROM `LICENSE_CONTRACT`")
		cursor.execute("DELETE FROM `PRODUCT_ON_CLIENT`")
		cursor.execute("DELETE FROM `PRODUCT_ON_DEPOT`")
		cursor.execute("DELETE FROM `PRODUCT_DEPENDENCY`")
		cursor.execute("DELETE FROM `PRODUCT_PROPERTY_VALUE`")
		cursor.execute("DELETE FROM `PRODUCT_PROPERTY`")
		cursor.execute("DELETE FROM `PRODUCT`")
		cursor.execute(f"DELETE FROM `HOST` WHERE hostId != '{get_configserver_id()}'")
		database_connection.commit()

	_delete()
	yield
	_delete()
	cursor.close()
