# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check registry
"""

from opsiconfd.check.common import CheckManager
from opsiconfd.check.backup import backup_check
from opsiconfd.check.addon import failed_addons_check
from opsiconfd.check.backend import depotserver_check
from opsiconfd.check.config import run_as_user_check, opsiconfd_config_check, opsi_config_check
from opsiconfd.check.jsonrpc import deprecated_calls_check
from opsiconfd.check.ldap import ldap_connection_check
from opsiconfd.check.mysql import mysql_connection_check, unique_hardware_addresses_check
from opsiconfd.check.opsilicense import opsi_licenses_check
from opsiconfd.check.opsipackages import products_on_clients_check, products_on_depots_check
from opsiconfd.check.redis import redis_check
from opsiconfd.check.ssl import ssl_check
from opsiconfd.check.users import opsi_users_check
from opsiconfd.check.system import distro_eol_check, system_packages_check,system_repositories_check, disk_usage_check

check_manager = CheckManager()
check_manager.register(
	backup_check,
	failed_addons_check,
	depotserver_check,
	run_as_user_check,
	opsiconfd_config_check,
	opsi_config_check,
	deprecated_calls_check,
	ldap_connection_check,
	mysql_connection_check,
	unique_hardware_addresses_check,
	opsi_licenses_check,
	products_on_clients_check,
	products_on_depots_check,
	redis_check,
	ssl_check,
	opsi_users_check,
	distro_eol_check,
	system_packages_check,
	system_repositories_check,
	disk_usage_check
)