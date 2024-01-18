# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""

from typing import Iterator

from rich.console import Console
from rich.markdown import Markdown

from opsiconfd.check.backend import check_depotservers
from opsiconfd.check.common import CheckResult
from opsiconfd.check.config import check_opsi_config, check_opsiconfd_config, check_run_as_user
from opsiconfd.check.const import CHECKS
from opsiconfd.check.jsonrpc import check_deprecated_calls
from opsiconfd.check.ldap import check_ldap_connection
from opsiconfd.check.mysql import check_mysql
from opsiconfd.check.opsilicense import check_opsi_licenses
from opsiconfd.check.opsipackages import check_product_on_clients, check_product_on_depots
from opsiconfd.check.redis import check_redis
from opsiconfd.check.ssl import check_ssl
from opsiconfd.check.system import check_disk_usage, check_distro_eol, check_system_packages
from opsiconfd.config import config

__all__ = [
	"check_depotservers",
	"check_opsi_config",
	"check_opsiconfd_config",
	"check_run_as_user",
	"check_mysql",
	"check_redis",
	"check_ssl",
	"check_system_packages",
	"check_disk_usage",
	"check_distro_eol",
	"check_opsi_licenses",
	"check_ldap_connection",
	"check_deprecated_calls",
	"check_product_on_clients",
	"check_product_on_depots",
	"CHECKS",
]


def health_check() -> Iterator[CheckResult]:
	for check_id in CHECKS:
		check = globals()[f"check_{check_id}"]
		if config.checks and check_id not in config.checks:
			continue
		if config.skip_checks and check_id in config.skip_checks:
			continue
		yield check()
