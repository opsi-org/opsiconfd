# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
utils user
"""

from __future__ import annotations

import re
import string
from functools import lru_cache
from pathlib import Path

from opsicommon.exceptions import BackendMissingDataError
from opsicommon.objects import User

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.config import config, opsi_config
from opsiconfd.logging import logger
from opsiconfd.utils import get_opsi_config, get_random_string
from opsiconfd.utils.cryptography import HashingAlgorithm, blowfish_decrypt, create_password_hash, encrypt

PASSWD_LINE_REGEX = re.compile(r"^\s*([^:]+)\s*:\s*(\S+)\s*$")


@lru_cache
def get_passwd_file() -> Path:
	from opsiconfd.config import OPSI_PASSWD_FILE

	return Path(OPSI_PASSWD_FILE)


def ensure_depot_user_credentials() -> None:
	backend = get_unprotected_backend()
	username = opsi_config.get("depot_user", "username")
	try:
		backend.user_getCredentials(username)
	except Exception as err:
		logger.warning("Failed to get credentials for user %s: %s, setting new random password", username, err)
		backend.user_setCredentials(
			username, get_random_string(32, alphabet=string.ascii_letters + string.digits, mandatory_alphabet="/^@?-")
		)


def migrate_opsi_passwd_file() -> None:
	passwd_file = get_passwd_file()
	if not passwd_file.exists():
		return

	backend = get_unprotected_backend()
	user_ids = backend.user_getIdents()
	depot = backend.host_getObjects(id=backend._depot_id)
	if not depot:
		raise BackendMissingDataError(f"Depot '{backend._depot_id}' not found in backend")
	depot = depot[0]
	if not depot.opsiHostKey:
		raise BackendMissingDataError(f"Host key for depot '{backend._depot_id}' not found")

	depot_user = get_opsi_config().get("depot_user", "username")

	with open(passwd_file, "r", encoding="utf-8") as file:
		for line in file.readlines():
			match = PASSWD_LINE_REGEX.search(line)
			if not match:
				continue
			username = match.group(1)
			blowfish_encrypted_password = match.group(2)
			if username in user_ids and username != depot_user and username != "monitoring":
				continue

			logger.info("Migrating user %r to backend", username)

			groups = ["{readonly}"]
			password = None
			encrypted_password = None
			try:
				password = blowfish_decrypt(depot.opsiHostKey, blowfish_encrypted_password)
			except Exception as err:
				logger.warning("Failed to decrypt password for user %r (%s), creating new random password", username, err)
				password = get_random_string(32, alphabet=string.ascii_letters + string.digits, mandatory_alphabet="/^@?-")

			if username == depot_user:
				# Only store encrypted password for depot user, login not required
				encrypted_password = encrypt(password) if password else None
				password = None

			backend.user_insertObject(
				User(
					id=username,
					passwordHash=create_password_hash(password, algorithm=HashingAlgorithm(config.password_hashing_method))
					if password
					else None,
					encryptedPassword=encrypted_password,
					groups=groups,
				)
			)

	old_passwd_file = passwd_file.with_suffix(".old")
	old_passwd_file.unlink(missing_ok=True)
	passwd_file.rename(old_passwd_file)
