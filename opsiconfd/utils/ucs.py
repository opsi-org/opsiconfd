# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
ucs utils
"""


from functools import lru_cache
import subprocess
from typing import Tuple
from rich import print as rich_print
from rich.prompt import Prompt

from opsiconfd.config import config
from opsiconfd.logging import logger, secret_filter


@lru_cache(maxsize=1)
def get_root_dn() -> str:
	"""
	Get the root dn of the UCS domain.

	Returns:
		str: The root dn of the UCS domain.
	"""
	try:
		return subprocess.check_output(["ucr", "get", "ldap/base"], encoding="utf-8", timeout=10).strip()
	except subprocess.CalledProcessError as err:
		logger.error("Failed to get root dn: %s", err)
		raise err


@lru_cache(maxsize=1)
def get_server_role() -> str:
	"""
	Get the server role of the UCS system.

	Returns:
		str: The server role of the UCS system.
	"""
	try:
		return subprocess.check_output(["ucr", "get", "server/role"], encoding="utf-8", timeout=10).strip()
	except subprocess.CalledProcessError as err:
		logger.error("Failed to get server role: %s", err)
		raise err

def get_ucs_admin_user(interactive: bool = False) -> Tuple[str | None, str | None]:
	"""
	Get the UCS Administrator user and password.
	"""
	if get_server_role() == "domaincontroller_prim":
		return None, None

	if not interactive and not config.admin_user:
		logger.notice("Not running on primary domain controller and no UCS Administrator given.")
		return None, None

	if interactive and not config.admin_user:
		rich_print("To configure samba we need an UCS Administrator:")
		ucs_username = Prompt.ask("Enter UCS admin username", default="Administrator", show_default=True)
		ucs_password = Prompt.ask("Enter UCS admin password", password=True)
		secret_filter.add_secrets(ucs_password)
		ucs_admin_dn = f"uid={ucs_username},cn=users,{get_root_dn()}"
		config.admin_user = ucs_username
		config.admin_password = ucs_password
	else:
		ucs_admin_dn = f"uid={config.admin_user},cn=users,{get_root_dn()}"
		logger.info("Using UCS Administrator %s", ucs_admin_dn)
		ucs_password = config.admin_password

	return ucs_admin_dn, ucs_password