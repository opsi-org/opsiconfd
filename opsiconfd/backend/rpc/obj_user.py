# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.user
"""
from __future__ import annotations

import os
import pwd
import re
from io import StringIO
from pathlib import Path
from subprocess import run
from typing import TYPE_CHECKING, Any, Protocol

import pyotp
from opsicommon.exceptions import BackendMissingDataError
from opsicommon.logging import secret_filter
from opsicommon.objects import User
from opsicommon.server.rights import set_rights
from opsicommon.types import forceHostId, forceList
from qrcode import QRCode  # type: ignore[import]

from opsiconfd.config import OPSI_PASSWD_FILE, get_configserver_id, opsi_config
from opsiconfd.logging import logger
from opsiconfd.utils import blowfish_decrypt, blowfish_encrypt, lock_file

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType

PASSWD_LINE_REGEX = re.compile(r"^\s*([^:]+)\s*:\s*(\S+)\s*$")


def is_local_user(username: str) -> bool:
	for line in Path("/etc/passwd").read_text(encoding="utf-8").splitlines():
		if line.startswith(f"{username}:"):
			return True
	return False


class RPCUserMixin(Protocol):
	def user_bulkInsertObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		users: list[dict] | list[User],  # pylint: disable=invalid-name
	) -> None:
		self._mysql.bulk_insert_objects(table="USER", objs=users)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def user_insertObject(self: BackendProtocol, user: dict | User) -> None:  # pylint: disable=invalid-name  # pylint: disable=invalid-name
		ace = self._get_ace("user_insertObject")
		self._mysql.insert_object(table="USER", obj=user, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def user_updateObject(self: BackendProtocol, user: dict | User) -> None:  # pylint: disable=invalid-name  # pylint: disable=invalid-name
		ace = self._get_ace("user_updateObject")
		self._mysql.insert_object(table="USER", obj=user, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def user_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		users: list[dict] | list[User] | dict | User,  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("user_createObjects")
		with self._mysql.session() as session:
			for user in forceList(users):
				self._mysql.insert_object(table="USER", obj=user, ace=ace, create=True, set_null=True, session=session)

	@rpc_method(check_acl=False)
	def user_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		users: list[dict] | list[User] | dict | User,  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("user_updateObjects")
		with self._mysql.session() as session:
			for user in forceList(users):
				self._mysql.insert_object(table="USER", obj=user, ace=ace, create=True, set_null=False, session=session)

	@rpc_method(check_acl=False)
	def user_getObjects(  # pylint: disable=invalid-name,redefined-builtin
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[User]:
		ace = self._get_ace("user_getObjects")
		return self._mysql.get_objects(table="USER", ace=ace, object_type=User, attributes=attributes, filter=filter)

	@rpc_method(check_acl=False)
	def user_getIdents(  # pylint: disable=invalid-name,redefined-builtin
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("user_getObjects")
		return self._mysql.get_idents(table="USER", object_type=User, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def user_deleteObjects(self: BackendProtocol, users: list[dict] | list[User] | dict | User) -> None:  # pylint: disable=invalid-name
		if not users:
			return
		ace = self._get_ace("user_deleteObjects")
		self._mysql.delete_objects(table="USER", object_type=User, obj=users, ace=ace)

	@rpc_method(check_acl=False)
	def user_delete(self: BackendProtocol, id: list[str] | str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		idents = self.user_getIdents(returnType="dict", id=id)
		if idents:
			self.user_deleteObjects(idents)

	@rpc_method
	def user_updateMultiFactorAuth(  # pylint: disable=invalid-name,redefined-builtin
		self: BackendProtocol, userId: str, type: str = "totp", returnType: str = "uri"
	) -> str:
		"""
		Configure multi factor authentication for user `userId`.
		Currently the only supported `type` is `TOTP` (Time-based One-time Password).
		If TOTP MFA is already active, a new secret will be generated.
		Set `type` to `inactive` to deactivate multi factor auth.
		If `returnType` is `uri` the provisioning URI is returned as string.
		If `returnType` is `qrcode` the provisioning URI is returned as ascii based QR Code.
		"""
		type = type.lower()
		if type not in ("inactive", "totp"):
			raise ValueError(f"Invalid type {type!r}")
		returnType = returnType.lower()

		try:
			user = self.user_getObjects(id=userId)[0]
		except IndexError:
			raise BackendMissingDataError(f"User {userId!r} not found") from None
		if type == "totp":
			self._check_module("vpn")
			user.mfaState = "totp_active"
			user.otpSecret = pyotp.random_base32()
			uri = pyotp.TOTP(user.otpSecret).provisioning_uri(name=f"{userId}@{get_configserver_id()}", issuer_name="opsi")
		else:
			user.mfaState = "inactive"
			user.otpSecret = ""
			returnType = ""

		self.user_updateObject(user)

		if not returnType:
			return ""

		if returnType == "uri":
			return uri

		if returnType == "qrcode":
			qrcode = QRCode()
			qrcode.add_data(uri)
			qrcode_io = StringIO()
			qrcode.print_ascii(out=qrcode_io)
			qrcode_io.seek(0)
			return "\n".join(
				[
					line[4:-4] if line.startswith("\xa0\xa0\xa0\xa0") and line.endswith("\xa0\xa0\xa0\xa0") else line
					for line in qrcode_io.getvalue().split("\n")
					if line.strip()
				]
			)

		raise ValueError(f"Invalid returnType {returnType}")

	@rpc_method
	def user_getCredentials(  # pylint: disable=invalid-name
		self: BackendProtocol, username: str | None = None, hostId: str | None = None
	) -> dict[str, str]:
		"""
		Get the credentials of an opsi user.
		The information is stored in ``/etc/opsi/passwd``.

		:param hostId: Optional value that should be the calling host.
		:return: Dict with the keys *password* and *rsaPrivateKey*.
		If this is called with an valid hostId the data will be encrypted with the opsi host key.
		:rtype: dict
		"""
		username = username or opsi_config.get("depot_user", "username")
		if hostId:
			hostId = forceHostId(hostId)

		result = {"password": "", "rsaPrivateKey": ""}

		if os.path.exists(OPSI_PASSWD_FILE):
			with open(OPSI_PASSWD_FILE, "r", encoding="utf-8") as file:
				with lock_file(file):
					for line in file.readlines():
						match = PASSWD_LINE_REGEX.search(line)
						if match and match.group(1) == username:
							result["password"] = match.group(2)
							break

		if not result["password"]:
			raise BackendMissingDataError(f"Username '{username}' not found in '{OPSI_PASSWD_FILE}'")

		depot = self.host_getObjects(id=self._depot_id)
		if not depot:
			raise BackendMissingDataError(f"Depot '{self._depot_id}'' not found in backend")
		depot = depot[0]
		if not depot.opsiHostKey:
			raise BackendMissingDataError(f"Host key for depot '{self._depot_id}' not found")

		result["password"] = blowfish_decrypt(depot.opsiHostKey, result["password"])

		if username == "pcpatch":
			try:
				id_rsa = os.path.join(pwd.getpwnam(username)[5], ".ssh", "id_rsa")
				with open(id_rsa, encoding="utf-8") as file:
					result["rsaPrivateKey"] = file.read()
			except Exception as err:  # pylint: disable=broad-except
				logger.debug(err)

		if hostId:
			host = self.host_getObjects(id=hostId)
			try:
				host = host[0]
			except IndexError as err:
				raise BackendMissingDataError(f"Host '{hostId}' not found in backend") from err

			result["password"] = blowfish_encrypt(host.opsiHostKey, result["password"])
			if result["rsaPrivateKey"]:
				result["rsaPrivateKey"] = blowfish_encrypt(host.opsiHostKey, result["rsaPrivateKey"])

		return result

	@rpc_method
	def user_setCredentials(  # pylint: disable=invalid-name,too-many-locals,too-many-branches,too-many-statements
		self: BackendProtocol, username: str, password: str
	) -> None:
		"""
		Set the password of an opsi user.
		The information is stored in ``/etc/opsi/passwd``.
		The password will be encrypted with the opsi host key of the depot where the method is.
		"""
		username = str(username).lower()
		password = str(password)
		secret_filter.add_secrets(password)

		if '"' in password:
			raise ValueError("Character '\"' not allowed in password")

		try:
			depot = self.host_getObjects(id=self._depot_id)[0]
		except IndexError as err:
			raise BackendMissingDataError(f"Depot {self._depot_id} not found in backend") from err

		encoded_password = blowfish_encrypt(depot.opsiHostKey, password)

		with open(OPSI_PASSWD_FILE, "a+", encoding="utf-8") as file:
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

		set_rights(OPSI_PASSWD_FILE)

		if username != opsi_config.get("depot_user", "username"):
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
					logger.warning("Did not change the password for 'pcpatch', please change it on the master server.")
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
					"udm",
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
			except Exception as err:  # pylint: disable=broad-except
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
		except Exception as err:  # pylint: disable=broad-except
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
			except Exception as err:  # pylint: disable=broad-except
				logger.debug("Setting password using chpasswd failed: %s", err)

			try:
				cmd = ["smbpasswd", "-a", "-s", username]
				logger.debug("Executing: %s", cmd)
				inp = f"{password}\n{password}\n"
				out = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10, input=inp).stdout
				logger.debug(out)
			except Exception as err:  # pylint: disable=broad-except
				logger.debug("Setting password using smbpasswd failed: %s", err)
