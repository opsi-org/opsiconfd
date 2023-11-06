# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
cleanup backend
"""

import pytest  # pylint: disable=unused-import
from opsicommon.objects import BoolConfig, UnicodeConfig

from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.backend.mysql.cleanup import convert_config_objects
from opsiconfd.backend.rpc.main import UnprotectedBackend
from tests.utils import backend  # pylint: disable=unused-import


def test_convert_config_objects(backend: UnprotectedBackend) -> None:  # pylint: disable=redefined-outer-name
	configs: list[BoolConfig | UnicodeConfig] = []
	for i in range(0, 50):
		configs.append(BoolConfig(id=f"test-convert-boolconfig-{i}"))

	configs.append(BoolConfig(id=f"test-convert-boolconfig-{111}"))

	configs.append(
		UnicodeConfig(
			id=f"test-convert-unicodeconfig-{1}", possibleValues=["bla", "blub"], defaultValues=["bla"], multiValue=False, editable=False
		)
	)
	configs.append(
		UnicodeConfig(
			id=f"test-convert-unicodeconfig-{2}", possibleValues=["bla", "blub"], defaultValues=["bla"], multiValue=True, editable=False
		)
	)
	configs.append(
		UnicodeConfig(
			id=f"test-convert-unicodeconfig-{3}", possibleValues=["bla", "blub"], defaultValues=["bla"], multiValue=True, editable=True
		)
	)

	backend.config_updateObjects(configs)

	# Set invalid type "Config"
	mysql = MySQLConnection()  # pylint: disable=invalid-name
	with mysql.connection():
		with mysql.session() as session:
			session.execute(
				"""
					UPDATE CONFIG as c
					SET c.`type` = "Config"
					WHERE c.configId LIKE "test-convert-%";
				"""
			)

	for obj in backend.config_getObjects(configId="test-convert-boolconfig*"):
		assert obj.getType() == "Config"

	for obj in backend.config_getObjects(configId="test-convert-unicodeconfig*"):
		assert obj.getType() == "Config"

	with mysql.connection():
		with mysql.session() as session:
			convert_config_objects(session)

	for obj in backend.config_getObjects(configId="test-convert-*"):
		assert obj.getType() in ("BoolConfig", "UnicodeConfig")

	for obj in backend.config_getObjects(configId="test-convert-boolconfig*"):
		assert obj.getType() == "BoolConfig"

	for obj in backend.config_getObjects(configId="test-convert-unicodeconfig*"):
		assert obj.getType() == "UnicodeConfig"
