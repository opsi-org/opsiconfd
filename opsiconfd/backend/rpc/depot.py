# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.depot
"""
# pylint: disable=too-many-lines

from __future__ import annotations

import base64
import grp
import os
import random
import re
import shutil
import subprocess
import uuid
from contextlib import closing, contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from socket import AF_INET, IPPROTO_UDP, SO_BROADCAST, SOCK_DGRAM, SOL_SOCKET, socket
from typing import TYPE_CHECKING, Any, Generator, Literal, Protocol

from opsicommon.exceptions import (
	BackendBadValueError,
	BackendError,
	BackendIOError,
	BackendPermissionDeniedError,
	BackendReferentialIntegrityError,
	BackendTemporaryError,
	BackendUnaccomplishableError,
)
from opsicommon.logging import log_context
from opsicommon.objects import (
	Product,
	ProductOnDepot,
	ProductProperty,
	ProductPropertyState,
)
from opsicommon.package import OpsiPackage
from opsicommon.package.associated_files import (
	create_package_content_file,
	create_package_md5_file,
	create_package_zsync_file,
)
from opsicommon.server.rights import set_rights
from opsicommon.types import (
	forceBool,
	forceDict,
	forceFilename,
	forceHostId,
	forceUnicodeLower,
)
from opsicommon.types import forceProductId as typeForceProductId
from opsicommon.utils import compare_versions, make_temp_dir

from opsiconfd import __version__, contextvar_client_session
from opsiconfd.config import (
	BOOT_DIR,
	DEPOT_DIR,
	PACKAGE_SCRIPT_TIMEOUT,
	WORKBENCH_DIR,
	config,
	opsi_config,
)
from opsiconfd.logging import logger
from opsiconfd.redis import decode_redis_result, redis_client
from opsiconfd.utils import get_disk_usage, get_file_md5sum

# deprecated can be used in extension config files
from . import rpc_method  # pylint: disable=unused-import

if TYPE_CHECKING:
	from .protocol import BackendProtocol
ALLOWED_SERVER_DATA = (
	Path("/tmp"),
	Path("/var/lib/opsi"),
	Path(BOOT_DIR),
)


class TransferSlotType(StrEnum):
	OPSICLIENTD_PRODUCT_SYNC = "opsiclientd_product_sync"
	OPSI_PACKAGE_UPDATER = "opsi_package_updater"


TRANSFER_SLOT_CONFIGS = {
	TransferSlotType.OPSI_PACKAGE_UPDATER: "opsiconfd.transfer.slots_opsi_package_updater",
	TransferSlotType.OPSICLIENTD_PRODUCT_SYNC: "opsiconfd.transfer.slots_opsiclientd_product_sync"
}
# Possibility to make retention time configurable if necessary
# TRANSFER_SLOT_RETENTION_CONFIGS = {
# 	TransferSlotType.OPSI_PACKAGE_UPDATER: "opsiconfd.transfer.retention_opsi_package_updater",
# 	TransferSlotType.OPSICLIENTD_PRODUCT_SYNC: "opsiconfd.transfer.retention_opsiclientd_product_sync"
# }
TRANSFER_SLOT_MAX = 1000
TRANSFER_SLOT_RETENTION_TIME = 60


def run_package_script(opsi_package: OpsiPackage, script_path: Path, client_data_dir: Path, env: dict[str, str] | None = None) -> list[str]:
	env = env or {}
	logger.info("Attempt to run package script %s", script_path.name)
	try:
		if not script_path.exists():
			logger.info("Package script '%s' not found", script_path)
			return []

		with open(script_path, "rb") as file:
			data = file.read()
		if data.startswith(b"#!"):
			new_data = re.sub(rb"(^|\s|/)python3?(\s+)", rb"\g<1>opsi-python\g<2>", data)  # pylint: disable=anomalous-backslash-in-string
			if b"\r\n" in data:
				logger.info("Replacing dos line breaks in %s", script_path.name)
				new_data = new_data.replace(b"\r\n", b"\n")
			if data != new_data:
				with open(script_path, "wb") as file:
					file.write(new_data)

		logger.notice("Running package script '%s'", script_path.name)
		os.chmod(str(script_path), 0o700)

		sp_env = {
			"PRODUCT_ID": opsi_package.product.getId(),
			"PRODUCT_TYPE": opsi_package.product.getType(),
			"PRODUCT_VERSION": opsi_package.product.getProductVersion(),
			"PACKAGE_VERSION": opsi_package.product.getPackageVersion(),
			"CLIENT_DATA_DIR": str(client_data_dir),
			"OPSI_SERVER_VERSION": __version__,
		}
		sp_env.update(env)
		logger.debug("Package script env: %s", sp_env)
		out = subprocess.run(
			str(script_path),
			shell=True,
			check=True,
			timeout=PACKAGE_SCRIPT_TIMEOUT,
			env=sp_env,
			encoding="utf-8",
			stdout=subprocess.PIPE,
			stderr=subprocess.STDOUT,
		).stdout
		logger.debug("Package script %r of package %r output: %s", script_path.name, opsi_package.product.getId(), out)
		return out.splitlines()
	except Exception as err:
		str_err = str(err)
		if isinstance(err, subprocess.CalledProcessError):
			str_err = f"{err} - {err.stdout}"
		logger.error(str_err, exc_info=True)
		raise RuntimeError(
			f"Failed to execute package script {script_path.name!r} of package {opsi_package.product.getId()!r}: {str_err}"
		) from err
	finally:
		logger.debug("Finished running package script %s", script_path.name)


@dataclass()
class TransferSlot:
	depot_id: str | None = None
	host_id: str | None = None
	slot_id: uuid.UUID | str | None = None
	slot_type: TransferSlotType = TransferSlotType.OPSICLIENTD_PRODUCT_SYNC
	retry_after: int | None = None
	retention: int = TRANSFER_SLOT_RETENTION_TIME

	def __post_init__(self) -> None:
		if isinstance(self.slot_id, str):
			self.slot_id = uuid.UUID("urn:uuid:" + self.slot_id)
		if not self.slot_id and not self.retry_after:
			self.slot_id = uuid.uuid4()
		if not self.slot_id and not self.retry_after:
			self.retry_after = TRANSFER_SLOT_RETENTION_TIME
		if self.slot_id:
			self.depot_id = forceHostId(self.depot_id)
			self.host_id = forceHostId(self.host_id)
			self.retry_after = None

	@property
	def redis_key(self) -> str:
		return f"{config.redis_key('slot')}:{self.depot_id}:{self.slot_type}:{self.host_id}:{self.slot_id}"

	@classmethod
	def from_redis_key(cls, key: str) -> TransferSlot | None:
		key_values = key.split(":")
		try:
			slot_id = key_values[-1]
			host_id = key_values[-2]
			slot_type = key_values[-3]
			depot_id = key_values[-4]
		except IndexError as err:
			logger.error("Cloud not parse redis key %s", key)
			logger.debug(err)
			return None
		return cls(depot_id=depot_id, host_id=host_id, slot_id=slot_id, slot_type=TransferSlotType(slot_type))


class RPCDepotserverMixin(Protocol):  # pylint: disable=too-few-public-methods
	ssh_rsa_public_key_file: str = "/etc/ssh/ssh_host_rsa_key.pub"
	_package_manager: DepotserverPackageManager | None

	def __init__(self: BackendProtocol) -> None:
		if self.host_getIdents(id=self._depot_id):  # pylint: disable=maybe-no-member
			self._package_manager = DepotserverPackageManager(self, self._depot_id)
		else:
			logger.info("Depot %r not found in backend", self._depot_id)
			self._package_manager = None  # type: ignore[assignment]

	@rpc_method
	def depot_getHostRSAPublicKey(self: BackendProtocol) -> str:  # pylint: disable=invalid-name
		return Path(self.ssh_rsa_public_key_file).read_text(encoding="utf-8")

	@rpc_method
	def depot_getMD5Sum(self: BackendProtocol, filename: str, forceCalculation: bool = False) -> str:  # pylint: disable=invalid-name
		"""
		This method calculates the md5-sum of a file.
		:param filename: File to compute checksum for.
		:param forceCalculation: if this is True, always calculate, otherwise use <filename>.md5 if available.
		"""
		md5_sum = None
		try:
			if not forceCalculation:
				hash_file = filename + ".md5"
				try:
					with open(hash_file, encoding="utf-8") as file:
						md5_sum = file.read()
					logger.info("Using pre-calculated MD5sum from '%s'.", hash_file)
				except (OSError, IOError):
					pass

			if not md5_sum:
				md5_sum = get_file_md5sum(filename)
			if not md5_sum:
				raise ValueError("Failed to get get_file_md5sum")
			logger.info("MD5sum of file '%s' is '%s'", filename, md5_sum)
			return md5_sum
		except Exception as err:
			raise BackendIOError(f"Failed to get get_file_md5sum: {err}") from err

	@rpc_method
	def depot_librsyncSignature(self: BackendProtocol, filename: str) -> str:  # pylint: disable=invalid-name
		try:
			# pylint: disable=import-outside-toplevel
			from opsicommon.utils.rsync import librsync_signature

			return librsync_signature(filename)
		except Exception as err:  # pylint: disable=broad-except
			raise BackendIOError(f"Failed to get librsync signature: {err}") from err

	@rpc_method
	def depot_librsyncPatchFile(self: BackendProtocol, oldfile: str, deltafile: str, newfile: str) -> None:  # pylint: disable=invalid-name
		try:
			# pylint: disable=import-outside-toplevel
			from opsicommon.utils.rsync import librsync_patch_file

			return librsync_patch_file(oldfile, deltafile, newfile)
		except Exception as err:
			raise BackendIOError(f"Failed to patch file: {err}") from err

	@rpc_method
	def depot_librsyncDeltaFile(  # pylint: disable=invalid-name
		self: BackendProtocol, filename: str, signature: str, deltafile: str
	) -> None:
		try:
			# pylint: disable=import-outside-toplevel
			from opsicommon.utils.rsync import librsync_delta_file

			# json serialisation cannot handle bytes, expecting base64 encoded string here
			signature_bytes = base64.b64decode(signature)
			librsync_delta_file(filename, signature_bytes, deltafile)
		except Exception as err:
			raise BackendIOError(f"Failed to create librsync delta file: {err}") from err

	@rpc_method
	def depot_getDiskSpaceUsage(self: BackendProtocol, path: str) -> dict[str, float]:  # pylint: disable=invalid-name
		try:
			return get_disk_usage(path).as_dict()
		except Exception as err:
			raise BackendIOError("Failed to get disk space usage: {err}") from err

	@rpc_method
	def depot_installPackage(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		filename: str,
		force: bool = False,
		propertyDefaultValues: dict[str, Any] | None = None,
		tempDir: str | None = None,
		forceProductId: str | None = None,
		suppressPackageContentFileGeneration: bool = False,
	) -> None:
		"""
		Installing a package on the depot corresponding to this Backend.
		"""
		if not self._package_manager:
			raise RuntimeError("Not a depotserver")

		with log_context({"instance": "package_install"}):
			self._package_manager.install_package(
				filename,
				force=force,
				property_default_values=propertyDefaultValues or {},
				temp_dir=Path(tempDir) if tempDir else None,
				force_product_id=forceProductId,
				suppress_package_content_file_generation=suppressPackageContentFileGeneration,
			)

	@rpc_method
	def depot_uninstallPackage(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str, force: bool = False, deleteFiles: bool = True
	) -> None:
		if not self._package_manager:
			raise RuntimeError("Not a depotserver")

		self._package_manager.uninstall_package(productId, force, deleteFiles)

	@rpc_method
	def depot_createPackageContentFile(self: BackendProtocol, productId: str) -> None:  # pylint: disable=invalid-name
		"""
		Create a package content file in the products depot directory.
		An existing file will be overriden.
		"""
		product_path = Path(DEPOT_DIR) / productId
		if not product_path.is_dir():
			raise BackendIOError(f"Product dir '{product_path}' not found")

		logger.notice("Creating package content file '%s'", product_path / f"{productId}.files")
		package_content_path = create_package_content_file(Path(product_path))
		if os.name == "posix":
			os.chown(package_content_path, -1, grp.getgrnam(opsi_config.get("groups", "fileadmingroup"))[2])
			os.chmod(package_content_path, 0o660)

	@rpc_method
	def depot_createMd5SumFile(self: BackendProtocol, filename: str, get_file_md5sumFilename: str) -> None:  # pylint: disable=invalid-name
		if not os.path.exists(filename):
			raise BackendIOError(f"File not found: {filename}")
		logger.info("Creating get_file_md5sum file '%s'", get_file_md5sumFilename)
		create_package_md5_file(Path(filename), Path(get_file_md5sumFilename))
		if os.name == "posix":
			os.chown(get_file_md5sumFilename, -1, grp.getgrnam(opsi_config.get("groups", "fileadmingroup"))[2])
			os.chmod(get_file_md5sumFilename, 0o660)

	@rpc_method
	def depot_createZsyncFile(self: BackendProtocol, filename: str, zsyncFilename: str) -> None:  # pylint: disable=invalid-name
		if not os.path.exists(filename):
			raise BackendIOError(f"File not found: {filename}")
		logger.info("Creating zsync file '%s'", zsyncFilename)
		create_package_zsync_file(Path(filename), Path(zsyncFilename))
		if os.name == "posix":
			os.chown(zsyncFilename, -1, grp.getgrnam(opsi_config.get("groups", "fileadmingroup"))[2])
			os.chmod(zsyncFilename, 0o660)

	@rpc_method(check_acl=False)
	def depot_acquireTransferSlot(  # pylint: disable=invalid-name
		self: BackendProtocol,
		depot: str,
		host: str,
		slot_id: str | None = None,
		slot_type: TransferSlotType = TransferSlotType.OPSICLIENTD_PRODUCT_SYNC,
	) -> TransferSlot:
		"""
		Acquires a transfer slot for the specified depot and slot ID.

		Args:
		        self (BackendProtocol): The backend protocol object.
		        depot (str): The depot for which to acquire the transfer slot.
		        host (str): The host for which to acquire the transfer slot
		        slot_id (str | None, optional): The ID of the slot to acquire. Defaults to None.
		        slot_type (TransferSlotType, optional): The type of slot to acquire. Defaults to "opsiclientd_product_sync".

		Returns:
		        TransferSlot: The acquired transfer slot.

		Raises:
		        BackendPermissionDeniedError: If access is denied.
		"""
		session = contextvar_client_session.get()
		if not session:
			raise BackendPermissionDeniedError("Access denied")

		slot = TransferSlot(depot_id=depot, host_id=host, slot_id=slot_id, slot_type=slot_type, retry_after=None)
		if slot_id:
			redis = redis_client()
			res = decode_redis_result(redis.get(slot.redis_key))
			if res:
				redis.set(slot.redis_key, host, ex=TRANSFER_SLOT_RETENTION_TIME)
				return slot

		max_slots = TRANSFER_SLOT_MAX
		slot_config_name = TRANSFER_SLOT_CONFIGS[slot_type]
		slot_config = self.configState_getValues(slot_config_name, depot).get(depot, {}).get(slot_config_name)
		if slot_config:
			try:
				max_slots = int(slot_config[0])
			except ValueError:
				logger.warning(
					"Invalid transfer slot max slots. Set config '%s' with an integer value. Using default: %s",
					slot_config_name,
					TRANSFER_SLOT_MAX,
				)

		redis = redis_client()
		depot_slots = len(list(decode_redis_result(redis.scan_iter(match=f"{config.redis_key('slot')}:{depot}:{slot_type}:*"))))
		if depot_slots >= max_slots:
			retry_after = random.randint(TRANSFER_SLOT_RETENTION_TIME, TRANSFER_SLOT_RETENTION_TIME * 2)
			return TransferSlot(retry_after=retry_after)

		redis.set(slot.redis_key, host, ex=TRANSFER_SLOT_RETENTION_TIME)
		return slot

	@rpc_method(check_acl=False)
	def depot_releaseTransferSlot(  # pylint: disable=invalid-name
		self: BackendProtocol,
		depot: str,
		host: str,
		slot_id: str,
		slot_type: TransferSlotType = TransferSlotType.OPSICLIENTD_PRODUCT_SYNC,
	) -> None:
		"""
		Release a transfer slot for the specified depot, client and slot ID.

		Args:
		        self (BackendProtocol): The backend protocol object.
		        depot (str): The depot for which to release the transfer slot.
		        host (str): The host for which to release the transfer slot.
		        slot_id (str): The ID of the slot to release.
		        slot_type (TransferSlotType, optional): The type of slot to acquire. Defaults to "opsiclientd_product_sync".

		Returns:
		        None

		Raises:
		        BackendPermissionDeniedError: If access is denied.
		"""

		session = contextvar_client_session.get()
		if not session:
			raise BackendPermissionDeniedError("Access denied")

		redis_client().unlink(TransferSlot(depot_id=depot, host_id=host, slot_id=slot_id, slot_type=slot_type).redis_key)

	@rpc_method
	def depot_listTransferSlot(self: BackendProtocol, depot: str) -> list[TransferSlot]:  # pylint: disable=invalid-name
		"""
		List all reserved TransferSlots of depot.

		Args:
		        self (BackendProtocol): The backend protocol object.
		        depot (str): The depot for which to release the transfer slot.
		Returns:
		        list[TransferSlot]
		"""

		slots = []

		slot_keys = redis_client().scan_iter(f"{config.redis_key('slot')}:{depot}:*")
		for slot_key in slot_keys:
			slot = TransferSlot.from_redis_key(slot_key.decode())
			if slot:
				slots.append(slot)

		return slots

	@rpc_method
	def workbench_buildPackage(self: BackendProtocol, package_dir: str) -> str:  # pylint: disable=invalid-name
		"""
		Creates an opsi package from an opsi package source directory.
		The function creates an opsi, md5 and zsync file in the source directory.
		The full path to the created opsi package is returned.
		"""
		package_path = Path(package_dir)
		workbench_path = Path(WORKBENCH_DIR)
		if not package_path.is_absolute():
			package_path = workbench_path / package_path
		package_path = package_path.resolve()
		if not package_path.is_relative_to(workbench_path):
			raise ValueError(f"Invalid package dir '{package_path}'")
		if not package_path.is_dir():
			raise BackendIOError(f"Package source dir '{package_path}' does not exist")
		opsi_package = OpsiPackage()
		opsi_package.find_and_parse_control_file(package_path)
		compression: Literal["zstd", "gz", "bz2"] = "zstd"
		if Path("/etc/opsi/makepackage_marker_use_gz").exists():
			logger.warning("Overriding compression to use 'gz' because of marker '/etc/opsi/makepackage_marker_use_gz'")
			compression = "gz"
		package_file = opsi_package.create_package_archive(package_path, destination=package_path, compression=compression)
		self.depot_createMd5SumFile(str(package_file), f"{package_file}.md5")
		self.depot_createZsyncFile(str(package_file), f"{package_file}.zsync")
		if os.name == "posix":
			for file in (str(package_file), f"{package_file}.md5", f"{package_file}.zsync"):
				try:
					os.chown(file, -1, grp.getgrnam(opsi_config.get("groups", "fileadmingroup"))[2])
					os.chmod(file, 0o660)
				except Exception as err:  # pylint: disable=broad-except
					logger.warning(err)
		return str(package_file)

	@rpc_method
	def workbench_installPackage(self: BackendProtocol, package_file_or_dir: str) -> None:  # pylint: disable=invalid-name
		"""
		Install an opsi package into the repository.
		If the path points to an opsi source directory,
		an opsi package is automatically created and then installed.
		"""
		package_path = Path(package_file_or_dir)
		workbench_path = Path(WORKBENCH_DIR)
		if not package_path.is_absolute():
			package_path = workbench_path / package_path
		package_path = package_path.resolve()
		if not package_path.is_relative_to(workbench_path):
			raise ValueError(f"Invalid package file '{package_path}'")
		if package_path.is_dir():
			package_path = Path(self.workbench_buildPackage(str(package_path)))
		self.depot_installPackage(str(package_path))

	@rpc_method
	def network_sendBroadcast(  # pylint: disable=invalid-name
		self: BackendProtocol, broadcast_address: str, ports: list[int], data: str
	) -> None:
		logger.debug("Sending data to network broadcast %s %s [%s]", broadcast_address, ports, data)
		payload = base64.b64decode(data)
		for port in ports:
			logger.debug("Broadcasting to port %s", port)
			with closing(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) as sock:
				sock.setsockopt(SOL_SOCKET, SO_BROADCAST, True)
				sock.sendto(payload, (broadcast_address, port))


class DepotserverPackageManager:
	"""
	PackageManager handling opsi Depotservers
	"""

	def __init__(self, backend: BackendProtocol, depot_id: str) -> None:
		self.backend = backend
		self._depot_id = depot_id

	def install_package(  # pylint: disable=too-many-arguments,too-many-locals,too-many-branches,too-many-statements
		self,
		filename: str,
		force: bool = False,
		property_default_values: dict[str, Any] | None = None,
		temp_dir: Path | None = None,
		force_product_id: str | None = None,
		suppress_package_content_file_generation: bool = False,
	) -> None:
		property_default_values = property_default_values or {}

		@contextmanager
		def get_opsi_package(
			filename: str, temp_dir: Path | None, new_product_id: str | None = None
		) -> Generator[tuple[OpsiPackage, Path], None, None]:
			opsi_package = OpsiPackage(Path(filename), temp_dir=temp_dir)
			with make_temp_dir(temp_dir) as temp_unpack_dir:
				if new_product_id:
					logger.info("Forcing product id '%s'", new_product_id)
				opsi_package.extract_package_archive(Path(filename), temp_unpack_dir, new_product_id=new_product_id)
				yield opsi_package, temp_unpack_dir

		@contextmanager
		def lock_product(product: Product, depot_id: str, force_installation: bool) -> Generator[ProductOnDepot, None, None]:
			product_id = product.getId()
			logger.debug("Checking for locked product '%s' on depot '%s'", product_id, depot_id)
			product_on_depots = self.backend.productOnDepot_getObjects(depotId=depot_id, productId=product_id)
			try:
				if product_on_depots[0].getLocked():
					logger.notice("Product '%s' currently locked on depot '%s'", product_id, depot_id)
					if not force_installation:
						raise BackendTemporaryError(
							f"Product '{product_id}' currently locked on depot '{depot_id}', use argument 'force' to ignore"
						)
					logger.warning("Installation of locked product forced")
			except IndexError:
				pass

			logger.notice("Locking product '%s' on depot '%s'", product_id, depot_id)
			product_on_depot = ProductOnDepot(
				productId=product_id,
				productType=product.getType(),
				productVersion=product.getProductVersion(),
				packageVersion=product.getPackageVersion(),
				depotId=depot_id,
				locked=True,
			)
			logger.info("Creating product on depot %s", product_on_depot)
			self.backend.productOnDepot_createObjects(product_on_depot)

			try:
				yield product_on_depot
			except Exception as err:
				logger.warning("Installation error. Not unlocking product '%s' on depot '%s'.", product_id, depot_id)
				raise err

			logger.notice(
				"Unlocking product '%s' %s-%s on depot '%s'",
				product_on_depot.getProductId(),
				product_on_depot.getProductVersion(),
				product_on_depot.getPackageVersion(),
				depot_id,
			)
			product_on_depot.setLocked(False)
			self.backend.productOnDepot_updateObject(product_on_depot)

		@contextmanager
		def run_package_scripts(
			opsi_package: OpsiPackage, unpack_dir: Path, client_data_dir: Path, env: dict[str, Any] | None = None
		) -> Generator[None, None, None]:
			logger.info("Running preinst script")
			for line in run_package_script(opsi_package, unpack_dir / "OPSI" / "preinst", client_data_dir, env=env or {}):
				logger.info("[preinst] %s", line)

			yield

			logger.info("Running postinst script")
			for line in run_package_script(opsi_package, unpack_dir / "OPSI" / "postinst", client_data_dir, env=env or {}):
				logger.info("[postinst] %s", line)

		def clean_up_products(product_id: str) -> None:
			product_idents = set()
			for product_on_depot in self.backend.productOnDepot_getObjects(productId=product_id):
				product_ident = f"{product_on_depot.productId};{product_on_depot.productVersion};{product_on_depot.packageVersion}"
				product_idents.add(product_ident)

			delete_products = set(
				product
				for product in self.backend.product_getObjects(id=product_id)
				if product.getIdent(returnType="unicode") not in product_idents
			)

			if delete_products:
				self.backend.product_deleteObjects(delete_products)

		def clean_up_product_property_states(  # pylint: disable=too-many-locals
			product_properties: list[ProductProperty], depot_id: str, product_on_depot: ProductOnDepot
		) -> None:
			product_properties_to_cleanup = {}
			for product_property in product_properties:
				if product_property.editable or not product_property.possibleValues:
					continue
				product_properties_to_cleanup[product_property.propertyId] = product_property

			if product_properties_to_cleanup:  # pylint: disable=too-many-nested-blocks
				client_ids = set(
					client_to_depot["clientId"] for client_to_depot in self.backend.configState_getClientToDepotserver(depotIds=depot_id)
				)

				if client_ids:
					delete_product_property_states = []
					update_product_property_states = []
					states = self.backend.productPropertyState_getObjects(
						objectId=client_ids,
						productId=product_on_depot.getProductId(),
						propertyId=list(product_properties_to_cleanup.keys()),
					)

					for product_property_state in states:
						changed = False
						new_values = []
						for value in product_property_state.values:
							product_property = product_properties_to_cleanup[product_property_state.propertyId]
							if value in (product_property.possibleValues or []):
								new_values.append(value)
								continue

							if product_property.getType() == "BoolProductProperty" and forceBool(value) in (
								product_property.possibleValues or []
							):
								new_values.append(forceBool(value))
								changed = True
								continue

							if product_property.getType() == "UnicodeProductProperty":
								new_value = None
								for possible_value in product_property.possibleValues or []:
									if forceUnicodeLower(possible_value) == forceUnicodeLower(value):
										new_value = possible_value
										break

								if new_value is not None:
									new_values.append(new_value)
									changed = True
									continue

							changed = True

						if changed:
							if not new_values:
								logger.debug("Properties changed: marking productPropertyState %s for deletion", product_property_state)
								delete_product_property_states.append(product_property_state)
							else:
								product_property_state.setValues(new_values)
								logger.debug("Properties changed: marking productPropertyState %s for update", product_property_state)
								update_product_property_states.append(product_property_state)

					if delete_product_property_states:
						self.backend.productPropertyState_deleteObjects(delete_product_property_states)
					if update_product_property_states:
						self.backend.productPropertyState_updateObjects(update_product_property_states)

		def copy_server_data(server_data: Path) -> None:
			prohibited_files = []
			for source in (server_data).rglob("*"):
				if source.is_dir():
					continue
				# Copy .../SERVER_DATA/tmp/foo/bar to /tmp/foo/bar
				destination = Path("/") / source.relative_to(server_data)
				if destination.parents[0] in (Path("/tftpboot"), Path("/$BOOT_DIR")):
					destination = Path(BOOT_DIR) / destination.relative_to(destination.parents[0])

				allowed = False
				for allowed_dir in ALLOWED_SERVER_DATA:
					if destination.is_relative_to(allowed_dir):
						allowed = True
						destination.parent.mkdir(exist_ok=True, parents=True)
						logger.debug("Copying %s to %s", source, destination)
						shutil.copy(source, destination)
						break
				if not allowed:
					prohibited_files.append(str(destination))
			if prohibited_files:
				logger.warning(
					"Package SERVER_DATA contains prohibited files: %s, allowed destinations are: %s",
					", ".join(prohibited_files),
					", ".join([str(a) for a in ALLOWED_SERVER_DATA]),
				)

		logger.info("=================================================================================================")
		if force_product_id:
			force_product_id = typeForceProductId(force_product_id)
			logger.notice("Installing package file '%s' as '%s' on depot '%s'", filename, force_product_id, self._depot_id)
		else:
			logger.notice("Installing package file '%s' on depot '%s'", filename, self._depot_id)

		try:
			filename = forceFilename(filename)
			force = forceBool(force)
			property_default_values = forceDict(property_default_values) or {}
			for property_id in property_default_values:
				if property_default_values[property_id] is None:
					property_default_values[property_id] = []

			if not os.path.isfile(filename):
				raise BackendIOError(f"Package file '{filename}' does not exist or can not be accessed.")
			if not os.access(filename, os.R_OK):
				raise BackendIOError(f"Read access denied for package file '{filename}'")

			try:
				with get_opsi_package(filename, temp_dir, force_product_id) as (opsi_package, tmp_unpack_dir):
					product = opsi_package.product
					product_id = product.getId()
					if not product_id:
						raise BackendIOError(f"Cannot extract product from {filename}")
					old_product_version = ""
					old_package_version = ""
					try:
						product_on_depot = self.backend.productOnDepot_getObjects(depotId=self._depot_id, productId=product_id)[0]
						old_product_version = product_on_depot.getProductVersion()
						old_package_version = product_on_depot.getPackageVersion()
					except Exception as err:  # pylint: disable=broad-except
						logger.debug(err)

					logger.info("Creating product in backend")
					self.backend.product_createObjects(product)
					product_path = Path(DEPOT_DIR) / product_id

					with lock_product(product, self._depot_id, force) as product_on_depot:
						logger.info("Checking package dependencies")
						self.check_dependencies(opsi_package)

						env = {
							"DEPOT_ID": self._depot_id,
							"OLD_PRODUCT_VERSION": old_product_version,
							"OLD_PACKAGE_VERSION": old_package_version,
							"BOOT_DIR": BOOT_DIR,
						}
						with run_package_scripts(opsi_package, tmp_unpack_dir, product_path, env=env):
							logger.info("Deleting old client-data dir")
							if (product_path).exists():
								shutil.rmtree(product_path)

							logger.info("Unpacking package files")
							shutil.move(tmp_unpack_dir / "CLIENT_DATA", product_path)

							if (tmp_unpack_dir / "SERVER_DATA").exists():
								logger.info("Unpacking SERVER_DATA")
								copy_server_data(tmp_unpack_dir / "SERVER_DATA")

							logger.info("Updating product dependencies of product %s", product)
							current_product_dependencies = {}
							for product_dependency in self.backend.productDependency_getObjects(
								productId=product_id, productVersion=product.getProductVersion(), packageVersion=product.getPackageVersion()
							):
								ident = product_dependency.getIdent(returnType="unicode")
								current_product_dependencies[ident] = product_dependency

							product_dependencies = []
							for product_dependency in opsi_package.product_dependencies:
								if force_product_id:
									product_dependency.productId = product_id

								ident = product_dependency.getIdent(returnType="unicode")
								if ident in current_product_dependencies:
									del current_product_dependencies[ident]
								product_dependencies.append(product_dependency)

							self.backend.productDependency_createObjects(product_dependencies)
							if current_product_dependencies:
								self.backend.productDependency_deleteObjects(list(current_product_dependencies.values()))

							logger.info("Updating product properties of product %s", product)
							current_product_properties = {}
							product_properties = []
							for product_property in self.backend.productProperty_getObjects(
								productId=product_id, productVersion=product.getProductVersion(), packageVersion=product.getPackageVersion()
							):
								ident = product_property.getIdent(returnType="unicode")
								current_product_properties[ident] = product_property

							for product_property in opsi_package.product_properties:
								if force_product_id:
									product_property.productId = product_id

								ident = product_property.getIdent(returnType="unicode")
								if ident in current_product_properties:
									del current_product_properties[ident]
								product_properties.append(product_property)
							self.backend.productProperty_createObjects(product_properties)

							for product_property in product_properties:
								# Adjust property default values
								if product_property.editable or not product_property.possibleValues:
									continue

								new_values = [
									value
									for value in property_default_values.get(product_property.propertyId, [])
									if value in product_property.possibleValues
								]
								if not new_values and product_property.defaultValues:
									new_values = product_property.defaultValues
								property_default_values[product_property.propertyId] = new_values

							if current_product_properties:
								self.backend.productProperty_deleteObjects(list(current_product_properties.values()))

							logger.info("Deleting product property states of product %s on depot '%s'", product_id, self._depot_id)
							pp_states = self.backend.productPropertyState_getObjects(productId=product_id, objectId=self._depot_id)
							if pp_states:
								self.backend.productPropertyState_deleteObjects(pp_states)

							logger.info("Deleting not needed property states of product %s", product_id)
							product_property_states = self.backend.productPropertyState_getObjects(productId=product_id)
							base_properties = self.backend.productProperty_getObjects(productId=product_id)

							product_property_ids = None
							product_property_states_to_delete = None
							product_property_ids = [product_property.propertyId for product_property in base_properties]
							product_property_states_to_delete = [
								pp_state for pp_state in product_property_states if pp_state.propertyId not in product_property_ids
							]
							logger.debug("Following productPropertyStates are marked to delete: '%s'", product_property_states_to_delete)
							if product_property_states_to_delete:
								self.backend.productPropertyState_deleteObjects(product_property_states_to_delete)

							logger.info("Setting product property states in backend")
							product_property_states = [
								ProductPropertyState(
									productId=product_id,
									propertyId=productProperty.propertyId,
									objectId=self._depot_id,
									values=productProperty.defaultValues,
								)
								for productProperty in product_properties
							]

							for product_property_state in product_property_states:
								if product_property_state.propertyId in property_default_values:
									try:
										product_property_state.setValues(property_default_values[product_property_state.propertyId])
									except Exception as err:  # pylint: disable=broad-except
										logger.error(
											"Failed to set default values to %s for productPropertyState %s: %s",
											property_default_values[product_property_state.propertyId],
											product_property_state,
											err,
										)
							self.backend.productPropertyState_createObjects(product_property_states)

						if not suppress_package_content_file_generation:
							create_package_content_file(product_path)
						else:
							logger.debug("Suppressed generation of package content file")
						set_rights(product_path)

				clean_up_products(product_on_depot.productId)
				clean_up_product_property_states(product_properties, self._depot_id, product_on_depot)
			except Exception as err:
				logger.debug("Failed to install the package %s", filename)
				logger.debug(err, exc_info=True)
				raise err
		except Exception as err:
			logger.error(err, exc_info=True)
			raise BackendError(f"Failed to install package '{filename}' on depot '{self._depot_id}': {err}") from err

	def uninstall_package(  # pylint: disable=too-many-branches,too-many-locals,too-many-statements
		self, product_id: str, force: bool = False, delete_files: bool = True
	) -> None:
		logger.info("=================================================================================================")
		logger.notice("Uninstalling product '%s' on depot '%s'", product_id, self._depot_id)
		try:  # pylint: disable=too-many-nested-blocks
			product_id = typeForceProductId(product_id)
			force = forceBool(force)
			delete_files = forceBool(delete_files)
			depot = self.backend.host_getObjects(type="OpsiDepotserver", id=self._depot_id)[0]
			allow_remove_used = True
			try:
				allow_remove_used = forceBool(
					self.backend.config_getObjects(id="allow_to_remove_package_in_use")[0].getDefaultValues()[0]  # pylint: disable=maybe-no-member
				)
			except IndexError:
				pass

			client_ids = [
				clientToDepot["clientId"] for clientToDepot in self.backend.configState_getClientToDepotserver(depotIds=[self._depot_id])
			]
			if client_ids:
				product_on_clients = self.backend.productOnClient_getObjects(productId=product_id, clientId=client_ids)
				if product_on_clients:
					update_product_on_clients = []
					installed = 0
					action_requests = 0
					for poc in product_on_clients:
						if poc.installationStatus == "installed":
							installed += 1
						if poc.actionRequest and poc.actionRequest != "none":
							action_requests += 1
							if allow_remove_used:
								poc.setActionRequest("none")
								update_product_on_clients.append(poc)

					if update_product_on_clients:
						self.backend.productOnClient_updateObjects(update_product_on_clients)

					if not allow_remove_used and (installed > 0 or action_requests > 0):
						logger.notice(
							"Product '%s' currently installed on %d clients, action requests set on %d clients",
							product_id,
							installed,
							action_requests,
						)
						if not force:
							raise BackendReferentialIntegrityError(
								f"Product '{product_id}' currently installed on {installed} clients "
								f"action requests set on {action_requests} clients, use argument 'force' to ignore"
							)
						logger.warning(
							"Uninstall of product '%s' forced which is installed on %d clients, action requests set on %d clients",
							product_id,
							installed,
							action_requests,
						)

			product_on_depots = self.backend.productOnDepot_getObjects(depotId=self._depot_id, productId=product_id)
			try:
				product_on_depot = product_on_depots[0]
			except IndexError as err:
				raise BackendBadValueError(f"Product '{product_id}' is not installed on depot '{self._depot_id}'") from err

			if product_on_depot.getLocked():
				logger.notice("Product '%s' currently locked on depot '%s'", product_id, self._depot_id)
				if not force:
					raise BackendTemporaryError(
						f"Product '{product_id}' currently locked on depot '{self._depot_id}', use argument 'force' to ignore"
					)
				logger.warning("Uninstall of locked product '%s' forced", product_id)

			logger.notice("Locking product '%s' on depot '%s'", product_id, self._depot_id)
			product_on_depot.setLocked(True)
			self.backend.productOnDepot_updateObject(product_on_depot)

			logger.debug("Deleting product '%s'", product_id)

			if delete_files:
				if not depot.depotLocalUrl.startswith("file:///"):
					raise BackendBadValueError(
						f"Value '{depot.depotLocalUrl}' not allowed for depot local url (has to start with 'file:///')"
					)

				for element in os.listdir(depot.depotLocalUrl[7:]):
					if element.lower() == product_id.lower():
						client_data_dir = os.path.join(depot.depotLocalUrl[7:], element)
						logger.info("Deleting client data dir '%s'", client_data_dir)
						shutil.rmtree(client_data_dir)

			self.backend.productOnDepot_deleteObjects(product_on_depot)
		except Exception as err:
			logger.error(err, exc_info=True)
			raise BackendError(f"Failed to uninstall product '{product_id}' on depot '{self._depot_id}': {err}") from err

	def check_dependencies(self, opsi_package: OpsiPackage) -> None:
		for dependency in opsi_package.package_dependencies:
			product_on_depots = self.backend.productOnDepot_getObjects(
				depotId=self._depot_id,
				productId=dependency.package,  # pylint: disable=protected-access
			)
			if not product_on_depots:
				raise BackendUnaccomplishableError(f"Dependent package '{dependency.package}' not installed")

			if not dependency.version:
				logger.info("Fulfilled product dependency '%s'", dependency)
				continue

			product_on_depot = product_on_depots[0]
			available_version = product_on_depot.getProductVersion() + "-" + product_on_depot.getPackageVersion()

			if compare_versions(available_version, dependency.condition or "==", dependency.version):  # type: ignore[arg-type]
				logger.info("Fulfilled package dependency %s (available version: %s)", dependency, available_version)
			else:
				raise BackendUnaccomplishableError(f"Unfulfilled package dependency {dependency} (available version: {available_version})")
