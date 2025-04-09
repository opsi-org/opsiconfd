# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
utils licence
"""

from opsiconfd.backend import get_protected_backend


def module_available(module: str) -> bool:
	return get_protected_backend()._module_available(module)
