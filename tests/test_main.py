# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test main
"""

from unittest.mock import patch

from OPSI import __version__ as python_opsi_version  # type: ignore[import]

from opsiconfd import __version__
from opsiconfd.main import main

from .utils import get_config


def test_version(capsys):
	with get_config({"version": True}):
		main()
	captured = capsys.readouterr()
	assert captured.out == f"{__version__} [python-opsi={python_opsi_version}]\n"


def test_setup():
	with patch("opsiconfd.main.setup") as mock_setup:
		with get_config({"action": "setup"}):
			main()
			mock_setup.assert_called_once_with(full=True)
