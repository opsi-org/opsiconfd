# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
ucs utils
"""

from functools import lru_cache

from opsi.process import ProcessError, run_command
from rich import print as rich_print
from rich.prompt import Prompt


@lru_cache(maxsize=1)
def get_root_dn() -> str:
	"""
	Get the root dn of the UCS domain.

	Returns:
		str: The root dn of the UCS domain.
	"""
	from opsiconfd.logging import logger

	try:
		return run_command(["ucr", "get", "ldap/base"], timeout=10).get_stdout_text().strip()
	except ProcessError as err:
		logger.error("Failed to get root dn: %s", err)
		raise


@lru_cache(maxsize=1)
def get_server_role() -> str:
	"""
	Get the server role of the UCS system.

	Returns:
		str: The server role of the UCS system.
	"""
	from opsiconfd.logging import logger

	try:
		return run_command(["ucr", "get", "server/role"], timeout=10).get_stdout_text().strip()
	except ProcessError as err:
		logger.error("Failed to get server role: %s", err)
		raise


def get_ucs_admin_user(interactive: bool = False) -> tuple[str | None, str | None]:
	"""
	Get the UCS Administrator user and password.
	"""
	from opsiconfd.config import config
	from opsiconfd.logging import logger, secret_filter

	if get_server_role() in ("domaincontroller_prim", "domaincontroller_master"):
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
