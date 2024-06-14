# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd config.main
"""

import json

from opsiconfd.config import config


def get_config_main() -> None:
	print(json.dumps(config.items(), indent=2))
