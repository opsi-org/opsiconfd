# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
utils licence
"""

from functools import lru_cache

from opsiconfd.backend import get_protected_backend
from opsiconfd.logging import logger


@lru_cache()
def check_module(module: str) -> bool:
	try:
		get_protected_backend()._check_module(module)
		return True
	except Exception as err:
		logger.debug(err)
	return False
