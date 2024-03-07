# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd main
"""

from opsicommon import __version__ as python_opsi_common_version

from opsiconfd import __version__
from opsiconfd.config import config


def main() -> None:
	if config.version:
		print(f"{__version__} [python-opsi-common={python_opsi_common_version}]")
		return None

	if config.action == "get-config":
		from opsiconfd.main.config import get_config_main

		return get_config_main()

	if config.action == "setup":
		from opsiconfd.main.setup import setup_main

		return setup_main()

	if config.action == "log-viewer":
		from opsiconfd.main.log_viewer import log_viewer_main

		return log_viewer_main()

	if config.action == "health-check":
		from opsiconfd.main.diagnostic import health_check_main

		return health_check_main()

	if config.action == "diagnostic-data":
		from opsiconfd.main.diagnostic import diagnostic_data_main

		return diagnostic_data_main()

	if config.action == "backup":
		from opsiconfd.main.backup import backup_main

		return backup_main()

	if config.action == "backup-info":
		from opsiconfd.main.backup import backup_info_main

		return backup_info_main()

	if config.action == "restore":
		from opsiconfd.main.backup import restore_main

		return restore_main()

	from opsiconfd.main.opsiconfd import opsiconfd_main

	return opsiconfd_main()
