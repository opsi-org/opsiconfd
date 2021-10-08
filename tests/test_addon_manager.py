# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test addon.manager
"""

import os
import shutil
import tempfile
import pytest

from opsiconfd.addon import AddonManager

from .utils import config  # pylint: disable=unused-import

@pytest.fixture(autouse=True)
def cleanup():
	def _cleanup():
		AddonManager().unload_addons()
		for name in ("opsiconfd_test_addon_test1_on_load", "opsiconfd_test_addon_test1_on_unload"):
			name = os.path.join(tempfile.gettempdir(), name)
			if os.path.exists(name):
				os.remove(name)
	_cleanup()
	yield
	_cleanup()


def test_load_addon(config):  # pylint: disable=redefined-outer-name
	config.addon_dirs = [os.path.abspath("tests/data/addons")]
	marker_file = os.path.join(tempfile.gettempdir(), "opsiconfd_test_addon_test1_on_load")

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


def test_unload_addon(config):  # pylint: disable=redefined-outer-name
	config.addon_dirs = [os.path.abspath("tests/data/addons")]
	marker_file = os.path.join(tempfile.gettempdir(), "opsiconfd_test_addon_test1_on_unload")

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

def test_reload_addon(config, tmpdir):  # pylint: disable=redefined-outer-name
	addon_dir = os.path.join(tmpdir, "test1")
	shutil.copytree(os.path.abspath("tests/data/addons/test1"), addon_dir)
	config.addon_dirs = [tmpdir]

	addon_manager = AddonManager()
	addon_manager.load_addons()
	assert len(addon_manager.addons) == 1
	assert addon_manager.addons[0].name == "Test-Addon #1"
	with open(os.path.join(addon_dir, "__init__.py"), mode="r+", encoding="utf-8") as file:
		data = file.read()
		data = data.replace(addon_manager.addons[0].name, "NEW NAME")
		file.seek(0)
		file.truncate()
		file.write(data)

	addon_manager.reload_addon("test1")
	assert len(addon_manager.addons) == 1
	assert addon_manager.addons[0].name == "NEW NAME"
