# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
cleanup backend
"""

import pytest
from opsicommon.objects import Config
from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.backend.mysql.cleanup import convert_config_objects
from opsiconfd.backend.rpc.main import UnprotectedBackend
from tests.backend.rpc.test_config_state import _create_clients_and_depot
from tests.utils import ADMIN_PASS, ADMIN_USER, OpsiconfdTestClient, test_client, backend


def test_convert_config_objects(backend: UnprotectedBackend) -> None:  # pylint: disable=redefined-outer-name
	configs = []
	for i in range(0, 50):
		configs.append(Config(id=f"boolconfig-{i}", possibleValues=[True, False], defaultValues=[True], multiValue=False, editable=False))

	configs.append(Config(id=f"boolconfig-{111}", possibleValues=[True, False], defaultValues=[False], multiValue=False, editable=False))

	configs.append(Config(id=f"unicodeconfig-{1}", possibleValues=["bla", "blub"], defaultValues=["bla"], multiValue=False, editable=False))
	configs.append(Config(id=f"unicodeconfig-{2}", possibleValues=["bla", "blub"], defaultValues=["bla"], multiValue=True, editable=False))
	configs.append(Config(id=f"unicodeconfig-{3}", possibleValues=["bla", "blub"], defaultValues=["bla"], multiValue=True, editable=True))

	backend.config_updateObjects(configs)

	for obj in backend.config_getObjects(configId="boolconfig*"):
		assert obj.getType() == "Config"

	for obj in backend.config_getObjects(configId="unicodeconfig*"):
		assert obj.getType() == "Config"

	mysql = MySQLConnection()  # pylint: disable=invalid-name
	with mysql.connection():
		with mysql.session() as session:
			convert_config_objects(session)

	for obj in backend.config_getObjects():
		assert obj.getType() in ("BoolConfig", "UnicodeConfig")

	for obj in backend.config_getObjects(configId="boolconfig*"):
		assert obj.getType() == "BoolConfig"

	for obj in backend.config_getObjects(configId="unicodeconfig*"):
		assert obj.getType() == "UnicodeConfig"
