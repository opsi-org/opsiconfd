# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test backup
"""
import asyncio
import time
from os.path import abspath
from threading import Thread

from opsiconfd.application import MaintenanceState, NormalState, ShutdownState, app
from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.backup import create_backup, restore_backup

from .utils import Config, clean_redis, config  # pylint: disable=unused-import


def test_create_backup(config: Config) -> None:  # pylint: disable=redefined-outer-name
	thread = Thread(target=asyncio.run, args=[app.app_state_manager_task(init_app_state=NormalState())], daemon=True)
	thread.start()
	app.app_state_initialized.wait(5)

	backup = create_backup()
	assert backup["meta"]["version"] == "1"
	assert len(backup["objects"]["Host"]) > 0
	assert backup["config_files"]["opsiconfd_conf"]["path"] == abspath(config.config_file)
	assert backup["config_files"]["opsiconfd_conf"]["content"]

	backup = create_backup(config_files=False)
	assert not backup["config_files"]

	app.set_app_state(ShutdownState())
	thread.join()


def test_restore_backup() -> None:
	thread = Thread(target=asyncio.run, args=[app.app_state_manager_task(init_app_state=MaintenanceState())], daemon=True)
	thread.start()
	app.app_state_initialized.wait(5)

	backup = create_backup(config_files=False)

	database = "opsitestbackup"
	mysql = MySQLConnection()
	mysql.connect()
	with mysql.session() as session:
		session.execute(f"DROP DATABASE IF EXISTS {database}")

	mysql._database = database  # pylint: disable=protected-access
	mysql.connect()
	restore_backup(backup)
	with mysql.session() as session:
		databases = [row[0] for row in session.execute("SHOW DATABASES").fetchall()]
		assert database in databases

	backup2 = create_backup(config_files=False)

	with mysql.session() as session:
		session.execute(f"DROP DATABASE IF EXISTS {database}")

	assert backup["objects"] == backup2["objects"]

	app.set_app_state(ShutdownState())
	thread.join()
