# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
setup tests
"""

from unittest.mock import PropertyMock, patch

from opsiconfd.setup.configs import _get_windows_domain


def test_get_windows_domain() -> None:
	class Proc:  # pylint: disable=too-few-public-methods
		stdout = ""

	with patch("opsiconfd.setup.configs.run", PropertyMock(return_value=Proc())):
		Proc.stdout = (
			"SID for local machine MACHINE is: S-1-5-21-3621911554-2635998167-701618891\n"
			"SID for domain DOMAIN is: S-1-5-21-3621911554-701618891-2635998167\n"
		)
		assert _get_windows_domain() == "DOMAIN"

		Proc.stdout = "SID for local machine MACHINE is: S-1-5-21-3621911554-2635998167-701618891\nCould not fetch domain SID\n"
		assert _get_windows_domain() == "MACHINE"
