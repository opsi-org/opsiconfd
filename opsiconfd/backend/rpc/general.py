# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.extender
"""

from __future__ import annotations

import os
import shutil
import socket
import time
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

from opsicommon.exceptions import (
	BackendAuthenticationError,
	BackendBadValueError,
	BackendPermissionDeniedError,
)
from opsicommon.license import (
	OPSI_CLIENT_INACTIVE_AFTER,
	OPSI_LICENSE_CLIENT_NUMBER_UNLIMITED,
	OPSI_LICENSE_DATE_UNLIMITED,
	OPSI_LICENSE_STATE_VALID,
	OPSI_MODULE_IDS,
	OPSI_OBSOLETE_MODULE_IDS,
	OpsiLicensePool,
	OpsiModulesFile,
	get_default_opsi_license_pool,
)
from opsicommon.types import forceBool, forceObjectId

from opsiconfd import __version__, contextvar_client_address, contextvar_client_session
from opsiconfd.application import AppState
from opsiconfd.application.filetransfer import delete_file, prepare_file
from opsiconfd.backup import create_backup, restore_backup
from opsiconfd.check.main import CheckResult, health_check
from opsiconfd.config import (
	FILE_TRANSFER_STORAGE_DIR,
	FQDN,
	LOG_DIR,
	LOG_SIZE_HARD_LIMIT,
	OPSI_LICENSE_DIR,
	OPSI_MODULES_FILE,
	config,
	opsi_config,
)
from opsiconfd.diagnostic import get_diagnostic_data
from opsiconfd.logging import logger
from opsiconfd.ssl import get_ca_cert_as_pem

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


def truncate_log_data(data: str, max_size: int) -> str:
	"""
	Truncating `data` to not be longer than `max_size` chars.
	"""
	if len(data) <= max_size:
		return data

	data = data[:max_size]
	idx = data.rfind("\n")
	if idx > 0:
		data = data[: idx + 1]
	return data


class RPCGeneralMixin(Protocol):  # pylint: disable=too-many-public-methods
	opsi_modules_file: str = OPSI_MODULES_FILE
	opsi_license_path: str = OPSI_LICENSE_DIR

	@rpc_method()
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
	def service_healthCheck(self: BackendProtocol) -> list[CheckResult]:  # pylint: disable=invalid-name
		self._check_role("admin")
		return list(health_check())

	@rpc_method
	def service_getDiagnosticData(self: BackendProtocol) -> dict[str, Any]:  # pylint: disable=invalid-name
		self._check_role("admin")
		return get_diagnostic_data()

	@rpc_method
	def service_createBackup(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		config_files: bool = True,
		redis_data: bool = True,
		maintenance_mode: bool = True,
		password: str | None = None,
		return_type: str = "file_id",
	) -> dict[str, dict[str, Any]] | str:
		"""
		Create a backup

		config_files: Backup config files?
		redis_data: Backup redis data?
		maintenance_mode: Run backup in maintenance mode?
		password: Password for backup encryption (optional).
		return_type: file_id or data.
		"""
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
			redis_data=redis_data,
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
		redis_data: bool = False,
		server_id: str = "backup",
		password: str | None = None,
		batch: bool = True,
	) -> None:
		"""
		Restore a backup

		data_or_file_id: file_id or raw data.
		config_files: Restore config files?
		redis_data: Restore redis data?
		server_id: The server ID to set ("local", "backup" or "<server-id>").
		password: Password for backup decryption (optional).
		batch: Batch mode or restore objects one by one.
		"""
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
			redis_data=redis_data,
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

	@rpc_method(check_acl=False)
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

	@rpc_method(check_acl=False)
	def getOpsiCACert(self: BackendProtocol) -> str:  # pylint: disable=invalid-name
		return get_ca_cert_as_pem()

	def _get_client_info(self: BackendProtocol) -> dict[str, int]:
		logger.info("%s fetching client info", self)

		result = {"macos": 0, "linux": 0, "windows": 0, "inactive": 0}
		with self._mysql.session() as session:
			res = session.execute(
				"""
				SELECT
					SUM(NOT c.`active`) AS `inactive`,
					SUM(c.`active` AND c.macos) AS macos,
					SUM(c.`active` AND c.linux) AS linux,
					SUM(c.`active` AND NOT c.macos AND NOT c.linux) AS windows
				FROM (
					SELECT
						IFNULL(DATEDIFF(NOW(), h.lastSeen) < :inactive_after, 0) AS `active`,
						(m.productId IS NOT NULL) AS macos,
						(l.productId IS NOT NULL) AS linux
					FROM HOST AS h
					LEFT JOIN PRODUCT_ON_CLIENT AS m
					ON m.clientId = h.hostId AND m.productId = "opsi-mac-client-agent" AND m.installationStatus = "installed"
					LEFT JOIN PRODUCT_ON_CLIENT AS l
					ON l.clientId = h.hostId AND l.productId = "opsi-linux-client-agent" AND l.installationStatus = "installed"
				) AS c
			""",
				params={"inactive_after": OPSI_CLIENT_INACTIVE_AFTER},
			).fetchone()
			if res:
				result.update({k: int(v or 0) for k, v in dict(res).items()})
		return result

	@lru_cache(maxsize=10)
	def _get_licensing_info(
		self: BackendProtocol,
		pool: OpsiLicensePool,
		licenses: bool = False,
		legacy_modules: bool = False,
		dates: bool = False,
		ttl_hash: int = 0,
	) -> dict[str, Any]:
		"""
		Returns opsi licensing information.
		"""
		del ttl_hash  # ttl_hash is only used to invalidate the cache after a ttl
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

	@rpc_method
	def backend_getLicensingInfo(  # pylint: disable=invalid-name
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

		return self._get_licensing_info(pool=pool, licenses=licenses, legacy_modules=legacy_modules, dates=dates, ttl_hash=get_ttl_hash())

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
	def log_write(  # pylint: disable=invalid-name,too-many-branches,too-many-locals
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
		log_type = str(logType)
		if log_type not in LOG_TYPES:
			raise BackendBadValueError(f"Unknown log type '{log_type}'")

		if not objectId:
			raise BackendBadValueError(f"Writing {log_type} log requires an objectId")

		object_id = forceObjectId(objectId)
		append = forceBool(append)

		bdata = data.encode("utf-8", "replace")
		if len(bdata) > LOG_SIZE_HARD_LIMIT:
			bdata = bdata[:LOG_SIZE_HARD_LIMIT]
			idx = bdata.rfind(b"\n")
			if idx > 0:
				bdata = bdata[: idx + 1]

		log_file = Path(LOG_DIR) / log_type / f"{object_id}.log"
		log_file.parent.mkdir(mode=0o2770, parents=True, exist_ok=True)

		try:
			if not append or (append and log_file.exists() and os.path.getsize(log_file) + len(bdata) > config.max_log_size * 1_000_000):
				logger.info("Rotating file '%s'", log_file)
				if config.keep_rotated_logs <= 0:
					log_file.unlink()
				else:
					for num in range(config.keep_rotated_logs, 0, -1):
						src_file_path = log_file
						if num > 1:
							src_file_path = log_file.with_name(f"{log_file.name}.{num-1}")
						if not src_file_path.exists():
							continue
						dst_file_path = log_file.with_name(f"{log_file.name}.{num}")
						src_file_path.rename(dst_file_path)
						try:
							shutil.chown(dst_file_path, -1, opsi_config.get("groups", "admingroup"))
							dst_file_path.chmod(0o644)
						except Exception as err:  # pylint: disable=broad-except
							logger.error("Failed to set file permissions on '%s': %s", dst_file_path, err)

			for lfile in log_file.parent.glob(f"{log_file.name}.*"):
				try:
					if int(lfile.suffix[1:]) > config.keep_rotated_logs:
						lfile.unlink()
				except ValueError:
					lfile.unlink()
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Failed to rotate log files: %s", err)

		with open(log_file, mode="ab" if append else "wb") as file:
			file.write(bdata)

		try:
			shutil.chown(log_file, group=opsi_config.get("groups", "admingroup"))
			log_file.chmod(0o644)
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Failed to set file permissions on '%s': %s", log_file, err)

		self._send_messagebus_event("log_updated", data={"type": logType, "object_id": objectId})

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
