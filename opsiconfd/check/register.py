# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

__all__ = ["register_checks"]


def register_checks() -> None:
	import opsiconfd.check.addon
	import opsiconfd.check.backend
	import opsiconfd.check.backup
	import opsiconfd.check.clients
	import opsiconfd.check.config
	import opsiconfd.check.grafana
	import opsiconfd.check.jsonrpc
	import opsiconfd.check.ldap
	import opsiconfd.check.mysql
	import opsiconfd.check.opsilicense
	import opsiconfd.check.opsipackages
	import opsiconfd.check.redis
	import opsiconfd.check.ssl
	import opsiconfd.check.system
	import opsiconfd.check.users
	import opsiconfd.check.worker  # noqa: F401
