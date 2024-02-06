# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test addon.manager
"""

import os
import pathlib
import shutil
from typing import Generator

import pytest
from _pytest.fixtures import FixtureFunction

from opsiconfd.addon import AddonManager

from .utils import (  # noqa: F401
	Config,
	OpsiconfdTestClient,
	clean_redis,
	config,
	test_client,
)


@pytest.fixture()
def cleanup() -> Generator[None, None, None]:
	def _cleanup() -> None:
		AddonManager().unload_addons()
		opsiconfd_test_addon = pathlib.Path("/var/lib/opsi/opsiconfd_test_addon")
		if opsiconfd_test_addon.exists():
			try:
				shutil.rmtree(opsiconfd_test_addon)
			except PermissionError:
				pass

	_cleanup()
	yield
	_cleanup()


def test_load_addon(config: Config, cleanup: FixtureFunction) -> None:  # noqa: F811
	config.addon_dirs = [os.path.abspath("tests/data/addons")]
	marker_file = "/var/lib/opsi/opsiconfd_test_addon/test1_on_load"

	addon_manager = AddonManager()
	addon_manager.load_addons()

	assert os.path.exists(marker_file)
	assert len(addon_manager.addons) == 2
	for addon in addon_manager.addons:
		assert addon.id in ("test1", "test2")
		if addon.id == "test1":
			assert addon.name == "Test-Addon #1"
			assert addon.version == "1.0"
			assert addon.path == os.path.join(config.addon_dirs[0], "test1")
		if addon.id == "test2":
			assert addon.name == "Test-Addon #2"
			assert addon.version == "1.1"
			assert addon.path == os.path.join(config.addon_dirs[0], "test2")
		assert addon_manager.get_addon_by_path(addon.router_prefix) == addon


def test_unload_addon(config: Config, cleanup: FixtureFunction) -> None:  # noqa: F811
	config.addon_dirs = [os.path.abspath("tests/data/addons")]
	marker_file = marker_file = "/var/lib/opsi/opsiconfd_test_addon/test1_on_unload"

	addon_manager = AddonManager()
	addon_manager.load_addons()

	assert len(addon_manager.addons) == 2
	addon_manager.unload_addon("test2")
	assert len(addon_manager.addons) == 1

	assert addon_manager.addons[0].id == "test1"
	addon_manager.unload_addon("test1")
	assert len(addon_manager.addons) == 0

	assert os.path.exists(marker_file)
	os.remove(marker_file)


def test_reload_addon(
	config: Config,  # noqa: F811
	cleanup: FixtureFunction,  # noqa: F811
	tmpdir: str,
) -> None:
	addon_dir = os.path.join(tmpdir, "test1")
	shutil.copytree(os.path.abspath("tests/data/addons/test1"), addon_dir)
	config.addon_dirs = [tmpdir]

	addon_manager = AddonManager()
	addon_manager.load_addons()
	assert len(addon_manager.addons) == 1
	assert addon_manager.addons[0].name == "Test-Addon #1"
	with open(os.path.join(addon_dir, "python", "const.py"), mode="r+", encoding="utf-8") as file:
		data = file.read()
		data = data.replace(addon_manager.addons[0].name, "NEW NAME")
		file.seek(0)
		file.truncate()
		file.write(data)

	with open(os.path.join(addon_dir, "python", "rest.py"), mode="r+", encoding="utf-8") as file:
		data = file.read()
		data = data.replace("TEST1", "TEST1 NEW")
		file.seek(0)
		file.truncate()
		file.write(data)

	addon_manager.reload_addon("test1")
	assert len(addon_manager.addons) == 1
	assert addon_manager.addons[0].name == "NEW NAME"
	response = addon_manager.addons[0].api_router.routes[0].endpoint()  # type: ignore[attr-defined]
	assert response.body.decode() == '"TEST1 NEW"'

	with pytest.raises(ValueError):
		addon_manager.reload_addon("notloaded")

	addon_manager.reload_addons()
	assert len(addon_manager.addons) == 1


def test_addon_static_dir(
	test_client: OpsiconfdTestClient,  # noqa: F811
	cleanup: FixtureFunction,  # noqa: F811
) -> None:
	AddonManager().load_addons()
	res = test_client.get("/addons/test1/static/index.html")
	assert res.status_code == 200


def test_addon_public_path(
	test_client: OpsiconfdTestClient,  # noqa: F811
	cleanup: FixtureFunction,  # noqa: F811
) -> None:
	AddonManager().load_addons()
	res = test_client.get("/addons/test1")
	assert res.status_code == 401

	res = test_client.get("/addons/test1/public")
	assert res.status_code == 200


def test_addon_auth(
	test_client: OpsiconfdTestClient,  # noqa: F811
	cleanup: FixtureFunction,  # noqa: F811
) -> None:
	AddonManager().load_addons()
	res = test_client.get("/addons/test1")
	assert res.status_code == 401

	res = test_client.get("/addons/test1/login")
	assert res.status_code == 200

	res = test_client.get("/addons/test1")
	assert res.status_code == 200

	res = test_client.get("/addons/test1/logout")
	assert res.status_code == 200

	res = test_client.get("/addons/test1")
	assert res.status_code == 401


def test_addon_exception_handling(
	test_client: OpsiconfdTestClient,  # noqa: F811
	cleanup: FixtureFunction,  # noqa: F811
) -> None:
	AddonManager().load_addons()
	res = test_client.get("/addons/test1")
	assert res.status_code == 401
	assert res.text == "addon_test1_error"
	assert res.headers.get("x-addon") == "test1"
