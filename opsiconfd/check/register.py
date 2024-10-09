# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# health check
# """

__all__ = ["register_checks"]


def register_checks() -> None:
	import opsiconfd.check.addon  # noqa: F401
	import opsiconfd.check.backend  # noqa: F401
	import opsiconfd.check.backup  # noqa: F401
	import opsiconfd.check.config  # noqa: F401
	import opsiconfd.check.jsonrpc  # noqa: F401
	import opsiconfd.check.ldap  # noqa: F401
	import opsiconfd.check.mysql  # noqa: F401
	import opsiconfd.check.opsilicense  # noqa: F401
	import opsiconfd.check.opsipackages  # noqa: F401
	import opsiconfd.check.redis  # noqa: F401
	import opsiconfd.check.ssl  # noqa: F401
	import opsiconfd.check.system  # noqa: F401
	import opsiconfd.check.users  # noqa: F401
