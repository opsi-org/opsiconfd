# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd log_viewer.main
"""

import asyncio
import sys

from opsicommon.logging import set_filter_from_string

from opsiconfd.config import config
from opsiconfd.logging import AsyncRedisLogAdapter

_log_viewer_should_stop = asyncio.Event()


def stop_log_viewer() -> None:
	_log_viewer_should_stop.set()


async def log_viewer() -> None:
	_log_viewer_should_stop.clear()
	set_filter_from_string(config.log_filter)
	log_adapter = AsyncRedisLogAdapter(stderr_file=sys.stdout)
	while not _log_viewer_should_stop.is_set():
		await asyncio.sleep(1)
	await log_adapter.stop()


def log_viewer_main() -> None:
	try:
		asyncio.run(log_viewer())
	except KeyboardInterrupt:
		sys.exit(0)
