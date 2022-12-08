# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test backup
"""
from os.path import abspath

from opsiconfd.backup import create_backup, restore_backup

from .utils import Config, config  # pylint: disable=unused-import


def test_create_backup(config: Config) -> None:  # pylint: disable=redefined-outer-name
	backup = create_backup()
	assert backup["meta"]["version"] == "1"
	assert len(backup["objects"]["Host"]) > 0
	assert backup["config_files"]["opsiconfd_conf"]["path"] == abspath(config.config_file)
	assert backup["config_files"]["opsiconfd_conf"]["content"]

	backup = create_backup(config_files=False)
	assert not backup["config_files"]


def test_restore_backup() -> None:
	backup = create_backup(config_files=False)
	restore_backup(backup, config_files=False)
