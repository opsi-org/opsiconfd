# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
cleanup backend
"""

from opsicommon.objects import BoolConfig, UnicodeConfig

from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.backend.mysql.cleanup import convert_config_objects, remove_orphans_clientconfig_depot_id
from opsiconfd.backend.rpc.main import UnprotectedBackend
from tests.utils import backend  # noqa: F401


def test_convert_config_objects(backend: UnprotectedBackend) -> None:  # noqa: F811
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
	mysql = MySQLConnection()
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


def test_cleanup_clientconfig_depot_id(backend: UnprotectedBackend) -> None:  # noqa: F811
	depot_id = "test-clientconfig-depot.uib.gmbh"
	client_id = "test-clientconfig-client.uib.gmbh"
	backend.host_createOpsiDepotserver(id=depot_id)
	backend.host_createOpsiClient(id=client_id)
	backend.configState_create(configId="clientconfig.depot.id", objectId=client_id, values=[depot_id])

	config_states = backend.configState_getObjects(configId="clientconfig.depot.id", objectId=client_id)
	assert len(config_states) == 1
	assert config_states[0].getValues() == [depot_id]

	mysql = MySQLConnection()
	mysql.connect()
	with mysql.session() as session:
		remove_orphans_clientconfig_depot_id(session)

	config_states = backend.configState_getObjects(configId="clientconfig.depot.id", objectId=client_id)
	assert len(config_states) == 1
	assert config_states[0].getValues() == [depot_id]

	backend.host_delete(id=depot_id)
	mysql = MySQLConnection()
	mysql.connect()
	with mysql.session() as session:
		remove_orphans_clientconfig_depot_id(session)

	config_states = backend.configState_getObjects(configId="clientconfig.depot.id", objectId=client_id)
	assert len(config_states) == 0

	backend.host_delete(id=client_id)
