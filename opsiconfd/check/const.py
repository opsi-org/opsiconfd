# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
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
]
