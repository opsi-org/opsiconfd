# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.backend.rpc.user
"""

from __future__ import annotations

import pwd
import secrets
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

import pyotp
from opsicommon.exceptions import BackendMissingDataError
from opsicommon.logging import secret_filter
from opsicommon.objects import User
from opsicommon.types import forceHostId, forceList
from qrcode import QRCode  # type: ignore[import]

from opsiconfd.backend.auth import RPCACE
from opsiconfd.config import config, get_configserver_id
from opsiconfd.logging import logger
from opsiconfd.utils import get_opsi_config, set_system_user_password
from opsiconfd.utils.cryptography import HashingAlgorithm, blowfish_encrypt, create_password_hash, decrypt, encrypt

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


def create_auth_token() -> tuple[str, str]:
	"""
	Create a new authentication token and return the token and its hash.
	"""
	token = secrets.token_hex(32)
	secret_filter.add_secrets(token)
	token_hash = create_password_hash(token, algorithm=HashingAlgorithm.SHA512, rounds=1000)
	secret_filter.add_secrets(token_hash)
	return token, token_hash


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

	def _user_getObjects(
		self: BackendProtocol,
		ace: list[RPCACE] | None = None,
		attributes: list[str] | None = None,
		filter: dict[str, Any] | None = None,
	) -> list[User]:
		return self._mysql.get_objects(table="USER", ace=ace, object_type=User, attributes=attributes, filter=filter)

	@rpc_method(check_acl=False)
	def user_getObjects(
		self: BackendProtocol,
		attributes: list[str] | None = None,
		**filter: Any,
	) -> list[User]:
		ace = self._get_ace("user_getObjects")
		return self._user_getObjects(ace=ace, attributes=attributes, filter=filter)  # type: ignore[return-value]

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
			self._assert_module("2fa")
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
			qrcode_string = "\n".join(
				[
					line[4:-4] if line.startswith("\xa0\xa0\xa0\xa0") and line.endswith("\xa0\xa0\xa0\xa0") else line
					for line in qrcode_io.getvalue().split("\n")
					if line.strip()
				]
			)
			return qrcode_string + "\n" + user.otpSecret

		raise ValueError(f"Invalid returnType {returnType}")

	@rpc_method
	def user_getCredentials(self: BackendProtocol, username: str | None = None, hostId: str | None = None) -> dict[str, str]:
		"""
		Get the credentials of the depot user.

		:param hostId: Optional value that should be the calling host.
		:return: Dict with the keys *password* and *rsaPrivateKey*.
		If this is called with an valid hostId the data will be encrypted with the opsi host key.
		:rtype: dict
		"""
		depot_user = get_opsi_config().get("depot_user", "username")
		if not username or username == "pcpatch":
			username = depot_user

		if username != depot_user:
			raise ValueError(f"Invalid user: {username!r}")

		result = {"password": "", "rsaPrivateKey": ""}
		users = self._user_getObjects(ace=None, attributes=["encryptedPassword"], filter={"id": depot_user})
		if not users:
			raise BackendMissingDataError(f"User {depot_user!r} not found")

		if not users[0].encryptedPassword:
			raise BackendMissingDataError(f"User {depot_user!r} has no encrypted password")

		result["password"] = decrypt(users[0].encryptedPassword)
		secret_filter.add_secrets(result["password"])

		try:
			id_rsa = Path(pwd.getpwnam(username)[5]) / ".ssh" / "id_rsa"
			result["rsaPrivateKey"] = id_rsa.read_text(encoding="utf-8")
		except Exception as err:
			logger.debug(err)

		if hostId:
			hostId = forceHostId(hostId)
			host = self.host_getObjects(id=hostId, attributes=["opsiHostKey"])
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
		"""
		depot_user = get_opsi_config().get("depot_user", "username")
		if not username or username == "pcpatch":
			username = depot_user

		if username != depot_user:
			raise ValueError(f"Invalid user: {username!r}")

		if '"' in password:
			raise ValueError("Character '\"' not allowed in password")

		user = User(
			id=username,
			encryptedPassword=encrypt(password),
			passwordHash=create_password_hash(password, algorithm=HashingAlgorithm(config.database_password_hashing_method)),
		)
		self.user_updateObjects([user])

		set_system_user_password(username, password)
