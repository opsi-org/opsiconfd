# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test backup
"""
import asyncio
from copy import deepcopy
from os.path import abspath
from pathlib import Path
from threading import Event, Thread
from unittest.mock import patch

import pytest

from opsiconfd.application import NormalState, app
from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.backup import create_backup, restore_backup
from opsiconfd.main.backup import backup_main

from .test_application import (  # noqa: F401
	AppStateReaderThread,
	app_state_reader,
)
from .utils import Config, clean_redis, config, get_config  # noqa: F401


@pytest.mark.parametrize(
	"cmdline_config, expexted_kwargs",
	[
		(
			{
				"backup_target": "/tmp/test.json",
				"quiet": False,
				"password": False,
				"overwrite": True,
				"no_maintenance": True,
				"no_config_files": True,
				"no_redis_data": True,
			},
			{
				"config_files": False,
				"redis_data": False,
				"backup_file": Path("/tmp/test.json"),
				"file_encoding": "json",
				"file_compression": None,
				"password": False,
				"maintenance": False,
			},
		),
		(
			{
				"backup_target": "/tmp/test.json.gz",
				"quiet": True,
				"password": False,
				"overwrite": True,
				"no_maintenance": False,
				"no_config_files": False,
				"no_redis_data": False,
			},
			{
				"config_files": True,
				"redis_data": True,
				"backup_file": Path("/tmp/test.json.gz"),
				"file_encoding": "json",
				"file_compression": "gz",
				"password": False,
				"maintenance": True,
			},
		),
		(
			{
				"backup_target": "/tmp/test_2023.05.03_01:01:01.msgpack",
			},
			{
				"backup_file": Path("/tmp/test_2023.05.03_01:01:01.msgpack"),
				"file_encoding": "msgpack",
				"file_compression": None,
				"password": False,
			},
		),
		(
			{
				"backup_target": "/tmp/test_2023.05.03_01:01:01.msgpack.lz4",
			},
			{
				"backup_file": Path("/tmp/test_2023.05.03_01:01:01.msgpack.lz4"),
				"file_encoding": "msgpack",
				"file_compression": "lz4",
				"password": False,
			},
		),
		(
			{
				"backup_target": "/tmp/test_2023.05.03_01:01:01.msgpack.lz4.aes",
				"password": "secret",
			},
			{
				"backup_file": Path("/tmp/test_2023.05.03_01:01:01.msgpack.lz4.aes"),
				"file_encoding": "msgpack",
				"file_compression": "lz4",
				"password": "secret",
			},
		),
	],
)
def test_backup_main(cmdline_config: dict[str, str | bool], expexted_kwargs: dict[str, str]) -> None:
	conf = {
		"backup_target": "",
		"quiet": False,
		"password": False,
		"overwrite": True,
		"no_maintenance": False,
		"no_config_files": False,
		"no_redis_data": False,
	}
	conf.update(cmdline_config)
	kwargs = {}

	def mock_create_backup(**kws: str | bool) -> None:
		nonlocal kwargs
		kwargs = kws

	with patch("opsiconfd.main.backup.create_backup", mock_create_backup):
		with get_config(conf):
			with pytest.raises(SystemExit, match="0"):
				backup_main()

			for key, val in expexted_kwargs.items():
				assert kwargs[key] == val


def test_create_backup(
	config: Config,  # noqa: F811
	app_state_reader: AppStateReaderThread,  # noqa: F811
) -> None:
	initalized_event = Event()
	thread = Thread(
		target=asyncio.run,
		args=[app.app_state_manager_task(manager_mode=True, init_app_state=NormalState(), initalized_event=initalized_event)],
		daemon=True,
	)
	thread.start()
	try:
		print("initalized_event =", initalized_event.wait(10))

		backup = create_backup()
		assert backup["meta"]["version"] == "1"
		assert len(backup["objects"]["Host"]) > 0
		assert backup["config_files"]["opsiconfd_conf"]["path"] == abspath(config.config_file)
		assert backup["config_files"]["opsiconfd_conf"]["content"]

		backup = create_backup(config_files=False)
		assert not backup["config_files"]
	finally:
		app.set_app_state(NormalState())
		app.stop_app_state_manager_task()
		thread.join(5)


def test_restore_backup(app_state_reader: AppStateReaderThread) -> None:  # noqa: F811
	initalized_event = Event()
	thread = Thread(
		target=asyncio.run,
		args=[app.app_state_manager_task(manager_mode=True, init_app_state=NormalState(), initalized_event=initalized_event)],
		daemon=True,
	)
	thread.start()
	try:
		print("initalized_event =", initalized_event.wait(10))

		database = "opsitestbackup"
		mysql = MySQLConnection()
		mysql.connect()
		with mysql.session() as session:
			session.execute(f"DROP DATABASE IF EXISTS {database}")

		mysql.database = database
		mysql.connect()

		restore_backup(Path("tests/data/backup/opsiconfd-backup.msgpack.lz4"), server_id="local", config_files=False, redis_data=False)
		with mysql.session() as session:
			databases = [row[0] for row in session.execute("SHOW DATABASES").fetchall()]
			assert database in databases

		backup = create_backup(config_files=False, redis_data=False)

		with mysql.session() as session:
			session.execute(f"DROP DATABASE {database}")

		restore_backup(deepcopy(backup))
		backup2 = create_backup(config_files=False, redis_data=False)

		assert sorted(list(backup["objects"])) == sorted(list(backup["objects"]))
		for object_type in backup["objects"]:
			assert backup["objects"][object_type] == backup2["objects"][object_type]

		# Test truncate
		for host in backup2["objects"]["Host"]:
			# Max 256
			host["description"] = "x" * 1000

		restore_backup(backup2)

	finally:
		app.set_app_state(NormalState())
		app.stop_app_state_manager_task()
		thread.join(5)
