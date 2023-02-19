# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.extender
"""

from __future__ import annotations

import glob
import os
import pwd
import re
import shutil
import socket
import time
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from subprocess import run
from typing import TYPE_CHECKING, Any, Generator, Protocol
from uuid import UUID

from opsicommon.exceptions import (  # type: ignore[import]
	BackendAuthenticationError,
	BackendBadValueError,
	BackendMissingDataError,
	BackendPermissionDeniedError,
)
from opsicommon.license import (  # type: ignore[import]
	OPSI_CLIENT_INACTIVE_AFTER,
	OPSI_LICENSE_CLIENT_NUMBER_UNLIMITED,
	OPSI_LICENSE_DATE_UNLIMITED,
	OPSI_LICENSE_STATE_VALID,
	OPSI_MODULE_IDS,
	OPSI_OBSOLETE_MODULE_IDS,
	OpsiModulesFile,
	get_default_opsi_license_pool,
)
from opsicommon.logging import secret_filter  # type: ignore[import]
from opsicommon.types import (  # type: ignore[import]
	forceBool,
	forceHostId,
	forceObjectId,
)

from opsiconfd import __version__, contextvar_client_address, contextvar_client_session
from opsiconfd.application import AppState
from opsiconfd.application.filetransfer import delete_file, prepare_file
from opsiconfd.backup import create_backup, restore_backup
from opsiconfd.check import CheckResult, health_check
from opsiconfd.config import (
	FILE_TRANSFER_STORAGE_DIR,
	FQDN,
	LOG_DIR,
	LOG_SIZE_HARD_LIMIT,
	OPSI_LICENSE_DIR,
	OPSI_MODULES_FILE,
	OPSI_PASSWD_FILE,
	config,
	opsi_config,
)
from opsiconfd.diagnostic import get_diagnostic_data
from opsiconfd.logging import logger
from opsiconfd.ssl import get_ca_cert_as_pem
from opsiconfd.utils import blowfish_decrypt, blowfish_encrypt, lock_file

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol

LOG_TYPES = {  # key = logtype, value = requires objectId for read
	"bootimage": True,
	"clientconnect": True,
	"instlog": True,
	"opsiconfd": False,
	"userlogin": True,
	"winpe": True,
}
PASSWD_LINE_REGEX = re.compile(r"^\s*([^:]+)\s*:\s*(\S+)\s*$")


def truncate_log_data(data: str, max_size: int) -> str:
	"""
	Truncating `data` to not be longer than `max_size` chars.
	"""
	data_length = len(data)
	if data_length > max_size:
		start = data.find("\n", data_length - max_size)
		if start == -1:
			start = data_length - max_size
		return data[start:].lstrip()
	return data


class RPCGeneralMixin(Protocol):  # pylint: disable=too-many-public-methods
	opsi_modules_file: str = OPSI_MODULES_FILE
	opsi_license_path: str = OPSI_LICENSE_DIR

	@rpc_method
	def backend_createBase(self) -> None:  # pylint: disable=invalid-name
		return None

	@rpc_method
	def backend_deleteBase(self) -> None:  # pylint: disable=invalid-name
		return None

	@rpc_method
	def backend_getInterface(self: BackendProtocol) -> list[dict[str, Any]]:  # pylint: disable=invalid-name
		return self.get_interface()

	@rpc_method
	def backend_exit(self: BackendProtocol) -> None:
		session = contextvar_client_session.get()
		if session:
			session.sync_delete()

	@rpc_method(deprecated=True)
	def backend_setOptions(self: BackendProtocol, options: dict) -> None:  # pylint: disable=invalid-name
		return None

	@rpc_method(deprecated=True)
	def backend_getOptions(self: BackendProtocol) -> dict:  # pylint: disable=invalid-name
		return {}

	@rpc_method(check_acl=False)
	def backend_getSystemConfiguration(self: BackendProtocol) -> dict:  # pylint: disable=invalid-name
		"""
		Returns current system configuration.

		This holds information about server-side settings that may be relevant for clients.

		Under the key `log` information about log settings will be returned in form of a dict.
		In it under `size_limit` you will find the amount of bytes currently allowed as maximum log size.
		Under `types` you will find a list with currently supported log types.

		:rtype: dict
		"""
		return {"log": {"size_limit": config.max_log_size, "keep_rotated": config.keep_rotated_logs, "types": list(LOG_TYPES)}}

	@rpc_method(check_acl=False)
	def accessControl_authenticated(self: BackendProtocol) -> bool:  # pylint: disable=invalid-name
		session = contextvar_client_session.get()
		if not session or not session.authenticated:
			raise BackendAuthenticationError("Not authenticated")
		return True

	@rpc_method(check_acl=False)
	def accessControl_userIsAdmin(self: BackendProtocol) -> bool:  # pylint: disable=invalid-name
		session = contextvar_client_session.get()
		if not session:
			raise BackendPermissionDeniedError("Access denied")
		return session.is_admin

	@rpc_method(check_acl=False)
	def accessControl_userIsReadOnlyUser(self: BackendProtocol) -> bool:  # pylint: disable=invalid-name
		session = contextvar_client_session.get()
		if not session:
			raise BackendPermissionDeniedError("Access denied")
		return session.is_read_only

	@rpc_method(check_acl=False)
	def accessControl_getUserGroups(self: BackendProtocol) -> list[str]:  # pylint: disable=invalid-name
		session = contextvar_client_session.get()
		if not session:
			raise BackendPermissionDeniedError("Access denied")
		return list(session.user_groups)

	@rpc_method
	def service_checkHealth(self: BackendProtocol) -> list[CheckResult]:  # pylint: disable=invalid-name
		self._check_role("admin")
		return list(health_check())

	@rpc_method
	def service_getDiagnosticData(self: BackendProtocol) -> dict[str, Any]:  # pylint: disable=invalid-name
		self._check_role("admin")
		return get_diagnostic_data()

	@rpc_method
	def service_createBackup(  # pylint: disable=invalid-name
		self: BackendProtocol,
		config_files: bool = True,
		maintenance_mode: bool = True,
		password: str | None = None,
		return_type: str = "file_id",
	) -> dict[str, dict[str, Any]] | str:
		self._check_role("admin")
		session = contextvar_client_session.get()
		if not session:
			raise BackendPermissionDeniedError("Access denied")

		file_id = None
		file_encoding = "msgpack"
		file_compression = "lz4"
		backup_file = None
		if return_type == "file_id":
			now = datetime.now().strftime("%Y%m%d-%H%M%S")
			file_id, backup_file = prepare_file(
				filename=f"opsiconfd-backup-{now}.{file_encoding}.{file_compression}{'.aes' if password else ''}",
				content_type="binary/octet-stream",
			)

		data = create_backup(
			config_files=config_files,
			backup_file=backup_file,
			file_encoding=file_encoding,  # type: ignore[arg-type]
			file_compression=file_compression,  # type: ignore[arg-type]
			password=password,
			maintenance=maintenance_mode,
			maintenance_address_exceptions=["::1/128", "127.0.0.1/32", session.client_addr],
		)
		if file_id:
			return file_id
		return data

	@rpc_method
	def service_restoreBackup(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		data_or_file_id: dict[str, dict[str, Any]] | str,
		config_files: bool = False,
		server_id: str = "backup",
		password: str | None = None,
		batch: bool = True,
	) -> None:
		self._check_role("admin")
		session = contextvar_client_session.get()
		if not session:
			raise BackendPermissionDeniedError("Access denied")

		data_or_file: dict[str, dict[str, Any]] | Path = {}
		file_id = None
		if isinstance(data_or_file_id, str):
			file_id = UUID(data_or_file_id)
			data_or_file = Path(FILE_TRANSFER_STORAGE_DIR) / str(file_id)
			if not data_or_file.exists():
				raise ValueError("Invalid file ID")
		else:
			data_or_file = data_or_file_id

		restore_backup(
			data_or_file=data_or_file,
			config_files=config_files,
			server_id=server_id,
			password=password,
			batch=batch,
			maintenance_address_exceptions=["::1/128", "127.0.0.1/32", session.client_addr],
		)
		if file_id:
			delete_file(file_id)

	@rpc_method
	def service_setAppState(  # pylint: disable=invalid-name
		self: BackendProtocol, app_state: dict[str, Any], wait_accomplished: float = 30.0
	) -> dict[str, Any]:
		self._check_role("admin")
		self._app.set_app_state(AppState.from_dict(app_state), wait_accomplished=wait_accomplished)
		return self._app.app_state.to_dict()

	@rpc_method
	def getDomain(self: BackendProtocol) -> str:  # pylint: disable=invalid-name
		try:
			client_address = contextvar_client_address.get()
			if not client_address:
				raise ValueError("Failed to get client address")
			if client_address not in ("127.0.0.1", "::1"):
				names = socket.gethostbyaddr(client_address)
				if names[0] and names[0].count(".") >= 2:
					return ".".join(names[0].split(".")[1:])
		except Exception as err:  # pylint: disable=broad-except
			logger.debug("Failed to get domain by client address: %s", err)

		return ".".join(FQDN.split(".")[1:])

	@rpc_method
	def getOpsiCACert(self: BackendProtocol) -> str:  # pylint: disable=invalid-name
		return get_ca_cert_as_pem()

	# @rpc_method
	def getData(self: BackendProtocol, query: str) -> Generator[Any, None, None]:  # pylint: disable=invalid-name
		if not query.lower().strip().startswith(("select", "show", "pragma")):
			raise ValueError("Only queries to SELECT/SHOW/PRAGMA data are allowed.")

		with self._mysql.session() as session:
			for row in session.execute(query).fetchall():
				yield {k: v.strftime("%Y-%m-%d %H:%M:%S") if isinstance(v, datetime) else v for k, v in dict(row).items()}

	# @rpc_method
	def getRawData(self: BackendProtocol, query: str) -> Generator[Any, None, None]:  # pylint: disable=invalid-name
		if not query.lower().strip().startswith(("select", "show", "pragma")):
			raise ValueError("Only queries to SELECT/SHOW/PRAGMA data are allowed.")

		with self._mysql.session() as session:
			for row in session.execute(query).fetchall():
				yield {v.strftime("%Y-%m-%d %H:%M:%S") if isinstance(v, datetime) else v for v in list(row)}

	def _get_client_info(self: BackendProtocol) -> dict[str, int]:
		logger.info("%s fetching client info", self)
		now = datetime.now()
		inactive = 0
		client_ids = []
		for host in self.host_getObjects(attributes=["id", "lastSeen"], type="OpsiClient"):
			if host.lastSeen and (now - datetime.fromisoformat(host.lastSeen)).days < OPSI_CLIENT_INACTIVE_AFTER:
				client_ids.append(host.id)
			else:
				inactive += 1
		macos = 0
		linux = 0
		if client_ids:
			macos = len(
				self.productOnClient_getObjects(
					attributes=["clientId"], installationStatus="installed", productId="opsi-mac-client-agent", clientId=client_ids
				)
			)
			linux = len(
				self.productOnClient_getObjects(
					attributes=["clientId"], installationStatus="installed", productId="opsi-linux-client-agent", clientId=client_ids
				)
			)
		return {"macos": macos, "linux": linux, "windows": len(client_ids) - macos - linux, "inactive": inactive}

	@lru_cache(maxsize=10)
	def _get_licensing_info(
		self: BackendProtocol, licenses: bool = False, legacy_modules: bool = False, dates: bool = False, ttl_hash: int = 0
	) -> dict[str, Any]:
		"""
		Returns opsi licensing information.
		"""
		del ttl_hash  # ttl_hash is only used to invalidate the cache after a ttl
		pool = get_default_opsi_license_pool(
			license_file_path=self.opsi_license_path, modules_file_path=self.opsi_modules_file, client_info=self._get_client_info
		)

		for config_id in ("client_limit_warning_percent", "client_limit_warning_absolute"):
			try:
				setattr(pool, config_id, int(self.config_getObjects(id=f"licensing.{config_id}")[0].getDefaultValues()[0]))
			except Exception as err:  # pylint: disable=broad-except
				logger.debug(err)

		try:
			disable_warning_for_modules = [
				m for m in self.config_getObjects(id="licensing.disable_warning_for_modules")[0].getDefaultValues() if m in OPSI_MODULE_IDS
			]
		except Exception as err:  # pylint: disable=broad-except
			logger.debug(err)
			disable_warning_for_modules = []

		try:
			client_limit_warning_days = int(self.config_getObjects(id="licensing.client_limit_warning_days")[0].getDefaultValues()[0])
		except Exception as err:  # pylint: disable=broad-except
			logger.debug(err)
			client_limit_warning_days = 30

		modules = pool.get_modules()
		info: dict[str, Any] = {
			"client_numbers": pool.client_numbers,
			"known_modules": OPSI_MODULE_IDS,
			"obsolete_modules": OPSI_OBSOLETE_MODULE_IDS,
			"available_modules": [module_id for module_id, info in modules.items() if info["available"]],
			"modules": modules,
			"licenses_checksum": pool.get_licenses_checksum(),
			"config": {
				"client_limit_warning_percent": pool.client_limit_warning_percent,
				"client_limit_warning_absolute": pool.client_limit_warning_absolute,
				"client_limit_warning_days": client_limit_warning_days,
				"disable_warning_for_modules": disable_warning_for_modules,
			},
		}
		if licenses:
			info["licenses"] = [lic.to_dict(serializable=True, with_state=True) for lic in pool.get_licenses()]
		if legacy_modules:
			info["legacy_modules"] = pool.get_legacy_modules()
		if dates:
			info["dates"] = {}
			for at_date in pool.get_relevant_dates():
				info["dates"][str(at_date)] = {"modules": pool.get_modules(at_date=at_date)}
		return info

	def get_licensing_info(  # pylint: disable=invalid-name
		self: BackendProtocol, licenses: bool = False, legacy_modules: bool = False, dates: bool = False, allow_cache: bool = True
	) -> dict[str, Any]:
		pool = get_default_opsi_license_pool(
			license_file_path=self.opsi_license_path, modules_file_path=self.opsi_modules_file, client_info=self._get_client_info
		)
		if not allow_cache or pool.modified():
			self._get_licensing_info.cache_clear()
		if pool.modified():
			pool.load()

		def get_ttl_hash(seconds: int = 3600) -> int:
			"""Return the same value withing `seconds` time period"""
			return round(time.time() / seconds)

		return self._get_licensing_info(licenses=licenses, legacy_modules=legacy_modules, dates=dates, ttl_hash=get_ttl_hash())

	@rpc_method
	def backend_getLicensingInfo(  # pylint: disable=invalid-name
		self: BackendProtocol, licenses: bool = False, legacy_modules: bool = False, dates: bool = False, allow_cache: bool = True
	) -> dict[str, Any]:
		return self.get_licensing_info(licenses=licenses, legacy_modules=legacy_modules, dates=dates, allow_cache=allow_cache)

	@rpc_method
	def backend_info(self: BackendProtocol) -> dict[str, Any]:  # pylint: disable=too-many-branches,too-many-statements
		"""
		Get info about the used opsi version and the licensed modules.

		:rtype: dict
		"""
		modules: dict[str, str | bool] = {"valid": False}
		realmodules: dict[str, str] = {}

		if os.path.exists(self.opsi_modules_file):
			omf = OpsiModulesFile(self.opsi_modules_file)
			omf.read()
			for lic in omf.licenses:
				modules["valid"] = modules[lic.module_id] = lic.get_state() == OPSI_LICENSE_STATE_VALID
				modules["customer"] = lic.customer_name
				modules["expires"] = "never" if lic.valid_until == OPSI_LICENSE_DATE_UNLIMITED else str(lic.valid_until)
				modules["signature"] = lic.signature.hex()
				if lic.client_number > 0 and lic.client_number < OPSI_LICENSE_CLIENT_NUMBER_UNLIMITED:
					realmodules[lic.module_id] = str(lic.client_number if lic.is_signature_valid() else 0)

		return {"opsiVersion": __version__, "modules": modules, "realmodules": realmodules}

	@rpc_method
	def log_write(  # pylint: disable=invalid-name,too-many-branches
		self: BackendProtocol, logType: str, data: str, objectId: str | None = None, append: bool = False
	) -> None:
		"""
		Write log data into the corresponding log file.

		:param logType: Type of log. Currently supported: *bootimage*, *clientconnect*, *instlog*, *opsiconfd* or *userlogin*.
		:param data: Log content
		:type data: Unicode
		:param objectId: Specialising of ``logType``
		:param append: Changes the behaviour to either append or overwrite the log.
		:type append: bool
		"""
		logType = str(logType)
		if logType not in LOG_TYPES:
			raise BackendBadValueError(f"Unknown log type '{logType}'")

		if not objectId:
			raise BackendBadValueError(f"Writing {logType} log requires an objectId")
		objectId = forceObjectId(objectId)

		append = forceBool(append)

		bdata = data.encode("utf-8", "replace")
		if len(bdata) > LOG_SIZE_HARD_LIMIT:
			bdata = bdata[-1 * LOG_SIZE_HARD_LIMIT :]
			idx = bdata.find(b"\n")
			if idx > 0:
				bdata = bdata[idx + 1 :]

		log_file = os.path.join(LOG_DIR, logType, f"{objectId}.log")

		if not os.path.exists(os.path.dirname(log_file)):
			os.mkdir(os.path.dirname(log_file), 0o2770)

		try:
			if not append or (append and os.path.exists(log_file) and os.path.getsize(log_file) + len(bdata) > config.max_log_size):
				logger.info("Rotating file '%s'", log_file)
				if config.keep_rotated_logs <= 0:
					os.remove(log_file)
				else:
					for num in range(config.keep_rotated_logs, 0, -1):
						src_file_path = log_file
						if num > 1:
							src_file_path = f"{log_file}.{num-1}"
						if not os.path.exists(src_file_path):
							continue
						dst_file_path = f"{log_file}.{num}"
						os.rename(src_file_path, dst_file_path)
						try:
							shutil.chown(dst_file_path, -1, opsi_config.get("groups", "admingroup"))
							os.chmod(dst_file_path, 0o644)
						except Exception as err:  # pylint: disable=broad-except
							logger.error("Failed to set file permissions on '%s': %s", dst_file_path, err)

			for filename in glob.glob(f"{log_file}.*"):
				try:
					if int(filename.split(".")[-1]) > config.keep_rotated_logs:
						os.remove(filename)
				except ValueError:
					os.remove(filename)
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Failed to rotate log files: %s", err)

		with open(log_file, mode="ab" if append else "wb") as file:
			file.write(bdata)

		try:
			shutil.chown(log_file, group=opsi_config.get("groups", "admingroup"))
			os.chmod(log_file, 0o640)
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Failed to set file permissions on '%s': %s", log_file, err)

	@rpc_method
	def log_read(self: BackendProtocol, logType: str, objectId: str | None = None, maxSize: int = 0) -> str:  # pylint: disable=invalid-name
		"""
		Return the content of a log.

		:param logType: Type of log. Currently supported: *bootimage*, *clientconnect*, *instlog*, *opsiconfd* or *userlogin*.
		:type data: Unicode
		:param objectId: Specialising of ``logType``
		:param maxSize: Limit for the size of returned characters in bytes. Setting this to `0` disables limiting.
		"""
		log_type = str(logType)
		max_size = int(maxSize)

		if log_type not in LOG_TYPES:
			raise BackendBadValueError(f"Unknown log type '{log_type}'")

		if objectId:
			objectId = forceObjectId(objectId)
			log_file = os.path.join(LOG_DIR, log_type, f"{objectId}.log")
		else:
			if LOG_TYPES[log_type]:
				raise BackendBadValueError(f"Log type '{log_type}' requires objectId")
			log_file = os.path.join(LOG_DIR, log_type, "opsiconfd.log")

		if not os.path.exists(log_file):
			return ""
		with open(log_file, encoding="utf-8", errors="replace") as log:
			data = log.read()

		if len(data) > max_size > 0:
			return truncate_log_data(data, max_size)

		return data

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
					"univention-admin",
					"users/user",
					"modify",
					"--dn",
					user_dn,
					"--set",
					f"password='{escaped_password}'",
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
			inp = f"{password}\n{password}\n".encode("utf8")
			out = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10, input=inp).stdout
			logger.debug(out)
		except Exception as err:  # pylint: disable=broad-except
			logger.debug("Setting password using smbldap failed: %s", err)

		if not password_set:
			# unix
			is_local_user = False
			for line in Path("/etc/passwd").read_text(encoding="utf-8").splitlines():
				if line.startswith(f"{username}:"):
					is_local_user = True
					break
			if not is_local_user:
				logger.warning("The user '%s' is not a local user, please change password also in Active Directory", username)
				return

			try:
				cmd = ["chpasswd"]
				logger.debug("Executing: %s", cmd)
				inp = f"{username}:{password}\n".encode("utf8")
				out = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10, input=inp).stdout
				logger.debug(out)
			except Exception as err:  # pylint: disable=broad-except
				logger.debug("Setting password using chpasswd failed: %s", err)

			try:
				cmd = ["smbpasswd", "-a", "-s", username]
				logger.debug("Executing: %s", cmd)
				inp = f"{password}\n{password}\n".encode("utf8")
				out = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10, input=inp).stdout
				logger.debug(out)
			except Exception as err:  # pylint: disable=broad-except
				logger.debug("Setting password using smbpasswd failed: %s", err)
