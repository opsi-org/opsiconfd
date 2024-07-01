# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd test.main
"""

import sys
import ldap3
from rich.console import Console
from rich.prompt import Prompt

from opsiconfd.auth._pam import PAMAuthentication
from opsiconfd.auth.ldap import LDAPAuthentication
from opsiconfd.config import config, opsi_config
from opsiconfd.logging import init_logging, logger


def test_pam_auth() -> None:
	console = Console()
	error: Exception | None = None
	while True:
		console.print("[b]Testing PAM authentication")
		pam_auth = PAMAuthentication()
		username = (Prompt.ask("Enter username", console=console) or "").strip()
		password = (Prompt.ask("Enter password", console=console, password=True) or "").strip()
		error = None
		try:
			pam_auth.authenticate(username, password)
			groups = pam_auth.get_groupnames(username)
			console.print(f"[b][green]PAM authentication successful (groups: {', '.join(groups)})")
		except Exception as err:
			error = err
			logger.error(err, exc_info=True)
			console.print(f"[b][red]PAM authentication failed: {err}")

		if not (Prompt.ask("Test again?", console=console, choices=["y", "n"]) or "").strip() == "y":
			break
	if error:
		sys.exit(1)


def test_ldap_auth() -> None:
	console = Console()
	error: Exception | None = None
	ldap_conf = opsi_config.get("ldap_auth")
	ldap_url = ldap_conf.get("ldap_url") or ""
	bind_user = ldap_conf.get("bind_user") or ""

	while True:
		console.print("[b]Testing LDAP authentication")
		console.print(
			"[b]- LDAP URL[/b]\n"
			"  Examples:\n"
			"    Active Directory / Samba 4\n"
			"      ldaps://ad.company.de/dc=company,dc=de\n"
			"    OpenLDAP\n"
			"      ldap://ldap.company.de:7389/dc=company,dc=de\n"
			"      ldaps://10.10.1.2/dc=org,dc=tld",
			highlight=False,
		)
		if ldap_url:
			console.print(f"  LDAP URL from opsi.conf:\n  {ldap_url}", highlight=False)
		input = (Prompt.ask("  Enter LDAP URL", default=ldap_url or None) or "").strip()
		try:
			uri = ldap3.utils.uri.parse_uri(input)  # type: ignore[no-untyped-call]
			if not uri:
				raise ValueError("Parse error")
			ldap_url = input
			if not uri["base"]:
				console.print(f"[b][yellow]Warning: Base DN missing in LDAP URL '{ldap_url}'")
		except Exception as err:
			console.print(f"[b][red]Invalid LDAP URL: {err}")
			continue

		console.print(
			"[b]- Bind user (template)[/b]\n" "  [cyan]{base}[/cyan] will be replaced with the base DN from the LDAP URL.\n",
			" [cyan]{username}[/cyan] will be replaced with the username to authenticate.\n",
			"  Examples:\n"
			"    Active Directory / Samba 4\n"
			"      {username}@company.de\n"
			"    OpenLDAP\n"
			"      uid={username},ou=Users,dc=org,dc=tld\n"
			"      uid={username},cn=Users,{base}",
			highlight=False,
		)
		if bind_user:
			console.print(f"  LDAP bind user template from opsi.conf:\n  {bind_user}", highlight=False)
		bind_user = (Prompt.ask("  Enter bind user template", default=bind_user or None) or "").strip()

		username = (Prompt.ask("[b]- Enter username") or "").strip()
		password = (Prompt.ask("[b]- Enter password", password=True) or "").strip()
		try:
			ldap_auth = LDAPAuthentication(ldap_url, bind_user)
			ldap_auth.authenticate(username, password)
			groups = ldap_auth.get_groupnames(username)
			console.print(f"[b][green]PAM authentication successful (groups: {', '.join(groups)})")
		except Exception as err:
			error = err
			logger.error(err, exc_info=True)
			console.print(f"[b][red]LDAP authentication failed: {err}")
		else:
			if (Prompt.ask("Write values to opsi.conf?", console=console, choices=["y", "n"]) or "").strip() == "y":
				opsi_config.set("ldap_auth", "ldap_url", ldap_url or "")
				opsi_config.set("ldap_auth", "bind_user", bind_user or "")
				opsi_config.write_config_file()

		if not (Prompt.ask("Test again?", console=console, choices=["y", "n"]) or "") == "y":
			break
	if error:
		sys.exit(1)


def test_main() -> None:
	init_logging(log_mode="local")
	try:
		if config.test_function == "pam_auth":
			return test_pam_auth()
		elif config.test_function == "ldap_auth":
			return test_ldap_auth()
	except KeyboardInterrupt:
		sys.exit(1)
	raise ValueError(f"Invalid test function '{config.test_function}'")
