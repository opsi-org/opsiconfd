# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check
"""

from typing import Iterator

# import opsiconfd.check.backend  # noqa: F401
# import opsiconfd.check.backup  # noqa: F401
# import opsiconfd.check.ssl  # noqa: F401
from opsiconfd.check.common import CheckResult, check_manager

# __all__ = []

# check_manager.register(
# 	backup_check,
# 	failed_addons_check,
# 	depotserver_check,
# 	run_as_user_check,
# 	opsiconfd_config_check,
# 	opsi_config_check,
# 	deprecated_calls_check,
# 	ldap_connection_check,
# 	mysql_connection_check,
# 	unique_hardware_addresses_check,
# 	opsi_licenses_check,
# 	products_on_clients_check,
# 	products_on_depots_check,
# 	redis_check,
# 	ssl_check,
# 	opsi_users_check,
# 	distro_eol_check,
# 	system_packages_check,
# 	system_repositories_check,
# 	disk_usage_check,
# )


def health_check(use_cache: bool = True) -> Iterator[CheckResult]:
	from opsiconfd.check.register import register_checks

	register_checks()
	print("health check:", id(check_manager))
	for check in check_manager:
		yield check.run(use_cache)
