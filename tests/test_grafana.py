# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
grafana tests
"""

import shutil
import time
from configparser import RawConfigParser
from pathlib import Path
from unittest.mock import patch

import pytest

from opsiconfd.grafana import set_grafana_root_url


@pytest.mark.parametrize("filename", ("tests/data/grafana/faulty.ini", "tests/data/grafana/defaults.ini", "tests/data/grafana/sample.ini"))
def test_set_grafana_root_url(tmp_path: Path, filename: str) -> None:
	grafana_ini = tmp_path / "grafana.ini"
	grafana_ini_orig = Path(filename)
	shutil.copy(grafana_ini_orig, grafana_ini)
	with patch("opsiconfd.grafana.GRAFANA_INI", str(grafana_ini)):
		time.sleep(1)
		mtime = grafana_ini.stat().st_mtime
		set_grafana_root_url()
		assert abs(grafana_ini.stat().st_size - grafana_ini_orig.stat().st_size) < 60
		assert mtime != grafana_ini.stat().st_mtime

		# Call again, no changes needed
		mtime = grafana_ini.stat().st_mtime
		set_grafana_root_url()
		assert mtime == grafana_ini.stat().st_mtime

	new = grafana_ini.read_text(encoding="utf-8")
	new_config = RawConfigParser()
	new_config.read_string("[DEFAULT]\n" + new)
	assert new_config["server"]["root_url"] == r"%(protocol)s://%(domain)s:%(http_port)s/grafana"
	for section in new_config:
		if section == "server":
			continue
		assert "root_url" not in new_config[section]
