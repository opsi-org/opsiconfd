# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test backup
"""
import asyncio
from copy import deepcopy
from os.path import abspath
from threading import Thread

from opsiconfd.application import MaintenanceState, NormalState, ShutdownState, app
from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.backup import create_backup, restore_backup

from .test_application import (  # pylint: disable=unused-import
	AppStateReaderThread,
	app_state_reader,
)
from .utils import Config, clean_redis, config  # pylint: disable=unused-import


def test_create_backup(
	config: Config, app_state_reader: AppStateReaderThread  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	thread = Thread(target=asyncio.run, args=[app.app_state_manager_task(manager_mode=True, init_app_state=NormalState())], daemon=True)
	thread.start()
	try:
		app.app_state_updated.wait(5)

		backup = create_backup()
		assert backup["meta"]["version"] == "1"
		assert len(backup["objects"]["Host"]) > 0
		assert backup["config_files"]["opsiconfd_conf"]["path"] == abspath(config.config_file)
		assert backup["config_files"]["opsiconfd_conf"]["content"]

		backup = create_backup(config_files=False)
		assert not backup["config_files"]
	finally:
		app.set_app_state(ShutdownState())
		thread.join(5)


def test_restore_backup(app_state_reader: AppStateReaderThread) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	thread = Thread(
		target=asyncio.run, args=[app.app_state_manager_task(manager_mode=True, init_app_state=MaintenanceState())], daemon=True
	)
	thread.start()
	try:
		app.app_state_updated.wait(5)

		backup = create_backup(config_files=False)

		database = "opsitestbackup"
		mysql = MySQLConnection()
		mysql.connect()
		with mysql.session() as session:
			session.execute(f"DROP DATABASE IF EXISTS {database}")

		mysql._database = database  # pylint: disable=protected-access
		mysql.connect()

		restore_backup(deepcopy(backup))
		with mysql.session() as session:
			databases = [row[0] for row in session.execute("SHOW DATABASES").fetchall()]
			assert database in databases

		backup2 = create_backup(config_files=False)

		with mysql.session() as session:
			session.execute(f"DROP DATABASE IF EXISTS {database}")

		assert backup["objects"] == backup2["objects"]
	finally:
		app.set_app_state(ShutdownState())
		thread.join(5)
