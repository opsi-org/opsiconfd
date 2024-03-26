# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.messagebus.filetransfer
"""

from __future__ import annotations

from opsicommon.messagebus.file_transfer import stop_running_file_transfers


async def async_file_transfer_shutdown() -> None:
	await stop_running_file_transfers()
