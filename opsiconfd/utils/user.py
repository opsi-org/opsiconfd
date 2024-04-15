# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
utils user
"""
import pwd
import re
from subprocess import run

from opsicommon.exceptions import BackendMissingDataError
from opsicommon.logging import secret_filter
from opsicommon.server.rights import set_rights

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.logging import logger
from opsiconfd.utils import get_opsi_config, is_local_user, lock_file
from opsiconfd.utils.cryptography import blowfish_encrypt

OPSI_PASSWD_FILE = None
PASSWD_LINE_REGEX = re.compile(r"^\s*([^:]+)\s*:\s*(\S+)\s*$")


def get_passwd_file() -> str:
	global OPSI_PASSWD_FILE
	if not OPSI_PASSWD_FILE:
		from opsiconfd.config import OPSI_PASSWD_FILE  # type: ignore[assignment]
	return OPSI_PASSWD_FILE  # type: ignore[return-value]


def user_set_credentials(username: str, password: str) -> None:
	"""
	Set the password of an opsi user.
	The information is stored in ``/etc/opsi/passwd``.
	The password will be encrypted with the opsi host key of the depot where the method is executed.
	"""
	username = str(username).lower()
	password = str(password)
	secret_filter.add_secrets(password)

	backend = get_unprotected_backend()

	if '"' in password:
		raise ValueError("Character '\"' not allowed in password")

	try:
		depot = backend.host_getObjects(id=backend._depot_id)[0]
		logger.debug(f"We are on depot: {depot}")
	except IndexError as err:
		raise BackendMissingDataError(f"Depot {backend._depot_id} not found in backend") from err

	encoded_password = blowfish_encrypt(depot.opsiHostKey, password)

	with open(get_passwd_file(), "a+", encoding="utf-8") as file:
		with lock_file(file):
			file.seek(0)
			lines = []
			add_line = f"{username}:{encoded_password}"
			for line in file.readlines():
				line = line.strip()
				match = PASSWD_LINE_REGEX.search(line)
				if not match:
					continue
				if match.group(1) == username:
					line = add_line
					add_line = ""
				lines.append(line)
			if add_line:
				lines.append(add_line)
			file.seek(0)
			file.truncate()
			file.write("\n".join(lines) + "\n")

	set_rights(get_passwd_file())

	if username != get_opsi_config().get("depot_user", "username"):
		return

	univention_server_role = ""
	try:
		cmd = ["ucr", "get", "server/role"]
		logger.debug("Executing: %s", cmd)
		univention_server_role = run(
			cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=5
		).stdout.strip()
	except FileNotFoundError:
		logger.debug("Not running on univention")
	else:
		try:
			logger.debug("Running on univention %s", univention_server_role)
			if univention_server_role not in ("domaincontroller_master", "domaincontroller_backup"):
				logger.warning("Did not change the password for %r, please change it on the master server.", username)
				return

			logger.debug("Executing: %s", cmd)
			user_dn = ""
			cmd = ["univention-admin", "users/user", "list", "--filter", f"(uid={username})"]
			out = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=5).stdout
			logger.debug(out)
			for line in out.strip().splitlines():
				line = line.strip()
				if line.startswith("DN"):
					user_dn = line.split(" ")[1]
					break

			if not user_dn:
				raise RuntimeError(f"Failed to get DN for user {username}")

			escaped_password = password.replace("'", "\\'")
			cmd = [
				"univention-admin",
				"users/user",
				"modify",
				"--dn",
				user_dn,
				"--set",
				f"password={escaped_password}",
				"--set",
				"overridePWLength=1",
				"--set",
				"overridePWHistory=1",
			]
			logger.debug("Executing: %s", cmd)
			out = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10).stdout
			logger.debug(out)
		except Exception as err:
			logger.error(err)
		return

	try:
		pwd.getpwnam(username)
	except KeyError as err:
		raise RuntimeError(f"System user '{username}' not found") from err

	password_set = False
	try:
		# smbldap
		cmd = ["smbldap-passwd", username]
		logger.debug("Executing: %s", cmd)
		inp = f"{password}\n{password}\n"
		out = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10, input=inp).stdout
		logger.debug(out)
		password_set = True
	except Exception as err:
		logger.debug("Setting password using smbldap failed: %s", err)

	if not password_set:
		# unix
		if not is_local_user(username):
			logger.warning("The user '%s' is not a local user, please change password also in Active Directory", username)
			return

		try:
			cmd = ["chpasswd"]
			logger.debug("Executing: %s", cmd)
			inp = f"{username}:{password}\n"
			out = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10, input=inp).stdout
			logger.debug(out)
		except Exception as err:
			logger.debug("Setting password using chpasswd failed: %s", err)

		try:
			cmd = ["smbpasswd", "-a", "-s", username]
			logger.debug("Executing: %s", cmd)
			inp = f"{password}\n{password}\n"
			out = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10, input=inp).stdout
			logger.debug(out)
		except Exception as err:
			logger.debug("Setting password using smbpasswd failed: %s", err)
