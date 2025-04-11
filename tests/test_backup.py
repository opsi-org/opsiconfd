# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test backup
"""

import asyncio
import base64
import json
import pprint
from copy import deepcopy
from os.path import abspath
from pathlib import Path
from threading import Event, Thread
from unittest.mock import patch

import pytest

from opsiconfd.application import NormalState, app
from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.backup import create_backup, get_config_files, restore_backup
from opsiconfd.main.backup import backup_extract_main, backup_main

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

		with get_config({"add_config_files": []}):
			backup = create_backup()
		assert backup["meta"]["version"] == "1"
		assert len(backup["objects"]["Host"]) > 0
		assert backup["config_files"]["opsiconfd_conf"]["path"] == abspath(config.config_file)
		assert backup["config_files"]["opsiconfd_conf"]["content"]

		with get_config({"add_config_files": []}):
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

		try:
			restore_backup(Path("tests/data/backup/opsiconfd-backup.msgpack.lz4"), server_id="local", config_files=False, redis_data=False)
		except Exception:
			pprint.pprint(mysql.get_process_list())
			raise

		with mysql.session() as session:
			databases = [row[0] for row in session.execute("SHOW DATABASES").fetchall()]
			assert database in databases

		with get_config({"add_config_files": []}):
			backup = create_backup(config_files=False, redis_data=False)

		with mysql.session() as session:
			session.execute(f"DROP DATABASE {database}")

		restore_backup(deepcopy(backup))
		with get_config({"add_config_files": []}):
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


def test_backup_extract(
	config: Config,  # noqa: F811
	app_state_reader: AppStateReaderThread,  # noqa: F811
	tmp_path: Path,
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

		# Create a test backup
		backup_file = tmp_path / "test_backup.msgpack.lz4"
		with get_config({"add_config_files": []}):
			backup = create_backup(backup_file=backup_file)

		# Test extraction
		extract_dir = tmp_path / "extracted"
		with get_config(
			{"backup_file": str(backup_file), "extract_dir": str(extract_dir), "overwrite": True, "quiet": True, "password": False}
		):
			with pytest.raises(SystemExit, match="0"):
				backup_extract_main()

		# Verify extracted files
		assert (extract_dir / "meta.json").exists()
		assert (extract_dir / "objects").exists()
		assert (extract_dir / "config_files").exists()
		assert (extract_dir / "redis").exists()

		# Verify meta data
		meta_data = json.loads((extract_dir / "meta.json").read_text(encoding="utf-8"))
		assert meta_data["type"] == "opsiconfd_backup"
		assert meta_data["version"] == "1"

		# Verify database objects
		objects_dir = extract_dir / "objects"
		assert (objects_dir / "Host.json").exists()
		host_objects = json.loads((objects_dir / "Host.json").read_text(encoding="utf-8"))
		assert len(host_objects) > 0

		# Verify config files
		config_dir = extract_dir / "config_files"
		assert (config_dir / "workspace/tests/data/default-opsiconfd.conf").exists()
		config_content = (config_dir / "workspace/tests/data/default-opsiconfd.conf").read_text(encoding="utf-8")
		assert config_content == backup["config_files"]["opsiconfd_conf"]["content"]

		# Verify Redis data
		redis_dir = extract_dir / "redis"
		assert (redis_dir / "dumped_keys.json").exists()
		redis_data = json.loads((redis_dir / "dumped_keys.json").read_text(encoding="utf-8"))
		assert len(redis_data) > 0
		for key_data in redis_data:
			assert key_data["name"]
			assert key_data["value"]
			assert "expires" in key_data
			assert base64.b64decode(key_data["value"])

	finally:
		app.set_app_state(NormalState())
		app.stop_app_state_manager_task()
		thread.join(5)


@pytest.mark.parametrize(
	"add_config_files",
	(
		["extra_configs"],
		["extra_configs/config1.conf"],
		["extra_configs", "extra_configs2"],
		[],
		None,
	),
)
def test_get_config_files(config: Config, tmp_path: Path, add_config_files: list[str] | None) -> None:  # noqa: F811
	add_config_files_path = add_config_files
	if add_config_files_path:
		add_config_files_path = [str(tmp_path / name) for name in add_config_files_path]

	extra_config_dir = tmp_path / "extra_configs"
	extra_config_subdir = extra_config_dir / "subdir"
	extra_config_dir2 = tmp_path / "extra_configs2"

	extra_config_subdir.mkdir(parents=True)
	extra_config_dir2.mkdir(parents=True)

	extra_file1 = extra_config_dir / "config1.conf"
	extra_file1.write_text("config1 content")
	extra_file2 = extra_config_subdir / ".config2"
	extra_file2.write_text("config2 content")
	extra_file3 = extra_config_dir2 / "config3.txt"
	extra_file3.write_text("config3 content")

	with get_config({"add_config_files": add_config_files_path}):
		config_files = get_config_files()

		if not add_config_files:
			for name in config_files:
				assert not name.startswith("additional_")
			return

		if add_config_files == ["extra_configs/config1.conf"]:
			assert config_files["additional_config1.conf"] == extra_file1
			assert "additional_.config2" not in config_files
			assert "additional_config3.txt" not in config_files
			return

		if "extra_configs" in add_config_files:
			assert config_files["additional_config1.conf"] == extra_file1
			assert config_files["additional_.config2"] == extra_file2

		if "extra_configs2" in add_config_files:
			assert config_files["additional_config3.txt"] == extra_file3
		else:
			assert "additional_config3.txt" not in config_files
