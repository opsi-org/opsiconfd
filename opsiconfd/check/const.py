# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health constants
"""

CHECKS = [
	"opsi_config",
	"opsiconfd_config",
	"ssl",
	"redis",
	"mysql",
	"run_as_user",
	"opsi_licenses",
	"distro_eol",
	"system_packages",
	"disk_usage",
	"depotservers",
	"product_on_depots",
	"product_on_clients",
	"deprecated_calls",
	"ldap_connection",
	"opsi_users",
	"system_repos",
	"opsi_failed_addons",
	"opsi_backup",
	"unique_hardware_addresses",
]

DEPOTSERVER_CHECKS = [
	"opsi_config",
	"opsiconfd_config",
	"ssl",
	"redis",
	"run_as_user",
	"distro_eol",
	"system_packages",
	"disk_usage",
	"deprecated_calls",
	"opsi_users",
	"system_repos",
	"opsi_failed_addons",
]
