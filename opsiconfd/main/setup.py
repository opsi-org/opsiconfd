# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd setup.main
"""

from opsiconfd.config import config
from opsiconfd.logging import init_logging
from opsiconfd.redis import delete_locks
from opsiconfd.setup import setup
from opsiconfd.utils import log_config


def setup_main() -> None:
	init_logging(log_mode="local")
	log_config()
	if config.delete_locks:
		delete_locks()
	setup(explicit=True)
