# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd test.main
"""

import sys

from rich import print
from rich.prompt import Prompt

from opsiconfd.auth._pam import PAMAuthentication
from opsiconfd.auth.ldap import LDAPAuthentication
from opsiconfd.config import config
from opsiconfd.logging import init_logging, logger


def test_pam_auth() -> None:
	print("Testing PAM authentication")
	pam_auth = PAMAuthentication()
	username = Prompt.ask("Enter username")
	password = Prompt.ask("Enter password", password=True)
	try:
		pam_auth.authenticate(username, password)
	except Exception as err:
		logger.error(err, exc_info=True)
		print("[b][red]PAM authentication failed")
		sys.exit(1)
	print("[b][green]PAM authentication successful")


def test_ldap_auth() -> None:
	print("Testing LDAP authentication")
	ldap_url = Prompt.ask("Enter LDAP URL")
	bind_user: str | None = Prompt.ask("Enter bind user") or None
	username = Prompt.ask("Enter username")
	password = Prompt.ask("Enter password", password=True)
	try:
		ldap_auth = LDAPAuthentication(ldap_url, bind_user)
		ldap_auth.authenticate(username, password)
	except Exception as err:
		logger.error(err, exc_info=True)
		print("[b][red]LDAP authentication failed")
		sys.exit(1)
	print("[b][green]LDAP authentication successful")


def test_main() -> None:
	init_logging(log_mode="local")
	if config.test_function == "pam_auth":
		return test_pam_auth()
	elif config.test_function == "ldap_auth":
		return test_ldap_auth()
	raise ValueError(f"Invalid test function '{config.test_function}'")
