# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""

from typing import Iterator

from opsiconfd.check.backend import check_depotservers
from opsiconfd.check.common import CheckResult
from opsiconfd.check.config import check_opsi_config, check_opsiconfd_config, check_run_as_user
from opsiconfd.check.jsonrpc import check_deprecated_calls
from opsiconfd.check.ldap import check_ldap_connection
from opsiconfd.check.mysql import check_mysql
from opsiconfd.check.opsilicense import check_opsi_licenses
from opsiconfd.check.opsipackages import check_product_on_clients, check_product_on_depots
from opsiconfd.check.redis import check_redis
from opsiconfd.check.ssl import check_ssl
from opsiconfd.check.system import check_disk_usage, check_distro_eol, check_system_packages
from opsiconfd.config import config

CHECKS = {
	"opsi_config": check_opsi_config,
	"opsiconfd_config": check_opsiconfd_config,
	"ssl": check_ssl,
	"redis": check_redis,
	"mysql": check_mysql,
	"run_as_user": check_run_as_user,
	"opsi_licenses": check_opsi_licenses,
	"distro_eol": check_distro_eol,
	"system_packages": check_system_packages,
	"disk_usage": check_disk_usage,
	"depotservers": check_depotservers,
	"product_on_depots": check_product_on_depots,
	"product_on_clients": check_product_on_clients,
	"deprecated_calls": check_deprecated_calls,
	"ldap_connection": check_ldap_connection,
}


def health_check() -> Iterator[CheckResult]:
	print(config.checks)
	print(config.skip_checks)
	for check_id, check in CHECKS.items():
		print(check_id)
		if config.checks and check_id not in config.checks:
			continue
		if config.skip_checks and check_id in config.skip_checks:
			continue
		yield check()
