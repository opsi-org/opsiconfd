# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc.user
"""
from __future__ import annotations

import os
import pwd
from io import StringIO
from typing import TYPE_CHECKING, Any, Protocol

import pyotp
from opsicommon.exceptions import BackendMissingDataError
from opsicommon.objects import User
from opsicommon.types import forceHostId, forceList
from qrcode import QRCode  # type: ignore[import]

from opsiconfd.config import OPSI_PASSWD_FILE, get_configserver_id, opsi_config
from opsiconfd.logging import logger
from opsiconfd.utils import lock_file
from opsiconfd.utils.cryptography import blowfish_decrypt, blowfish_encrypt
from opsiconfd.utils.user import PASSWD_LINE_REGEX, user_set_credentials

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCUserMixin(Protocol):
	def user_bulkInsertObjects(
		self: BackendProtocol,
		users: list[dict] | list[User],
	) -> None:
		self._mysql.bulk_insert_objects(table="USER", objs=users)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def user_insertObject(self: BackendProtocol, user: dict | User) -> None:
		ace = self._get_ace("user_insertObject")
		self._mysql.insert_object(table="USER", obj=user, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def user_updateObject(self: BackendProtocol, user: dict | User) -> None:
		ace = self._get_ace("user_updateObject")
		self._mysql.insert_object(table="USER", obj=user, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def user_createObjects(
		self: BackendProtocol,
		users: list[dict] | list[User] | dict | User,
	) -> None:
		ace = self._get_ace("user_createObjects")
		with self._mysql.session() as session:
			for user in forceList(users):
				self._mysql.insert_object(table="USER", obj=user, ace=ace, create=True, set_null=True, session=session)

	@rpc_method(check_acl=False)
	def user_updateObjects(
		self: BackendProtocol,
		users: list[dict] | list[User] | dict | User,
	) -> None:
		ace = self._get_ace("user_updateObjects")
		with self._mysql.session() as session:
			for user in forceList(users):
				self._mysql.insert_object(table="USER", obj=user, ace=ace, create=True, set_null=False, session=session)

	@rpc_method(check_acl=False)
	def user_getObjects(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[User]:
		ace = self._get_ace("user_getObjects")
		return self._mysql.get_objects(table="USER", ace=ace, object_type=User, attributes=attributes, filter=filter)

	@rpc_method(check_acl=False)
	def user_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("user_getObjects")
		return self._mysql.get_idents(table="USER", object_type=User, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def user_deleteObjects(self: BackendProtocol, users: list[dict] | list[User] | dict | User) -> None:
		if not users:
			return
		ace = self._get_ace("user_deleteObjects")
		self._mysql.delete_objects(table="USER", object_type=User, obj=users, ace=ace)

	@rpc_method(check_acl=False)
	def user_delete(self: BackendProtocol, id: list[str] | str) -> None:
		idents = self.user_getIdents(returnType="dict", id=id)
		if idents:
			self.user_deleteObjects(idents)

	@rpc_method
	def user_updateMultiFactorAuth(self: BackendProtocol, userId: str, type: str = "totp", returnType: str = "uri") -> str:
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
	def user_getCredentials(self: BackendProtocol, username: str | None = None, hostId: str | None = None) -> dict[str, str]:
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

		if username == opsi_config.get("depot_user", "username"):
			try:
				id_rsa = os.path.join(pwd.getpwnam(username)[5], ".ssh", "id_rsa")
				with open(id_rsa, encoding="utf-8") as file:
					result["rsaPrivateKey"] = file.read()
			except Exception as err:
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
	def user_setCredentials(self: BackendProtocol, username: str, password: str) -> None:
		"""
		Set the password of an opsi user.
		The information is stored in ``/etc/opsi/passwd``.
		The password will be encrypted with the opsi host key of the depot where the method is.
		"""
		user_set_credentials(username, password)
