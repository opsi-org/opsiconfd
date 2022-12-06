# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.extender
"""

from __future__ import annotations

import grp
import os
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Generator, List, Protocol

from OPSI.System import getDiskSpaceUsage  # type: ignore[import]
from OPSI.Util import (  # type: ignore[import]
	compareVersions,
	findFiles,
	md5sum,
	removeDirectory,
)
from OPSI.Util.File import ZsyncFile  # type: ignore[import]
from OPSI.Util.Product import (  # type: ignore[import]
	PackageContentFile,
	ProductPackageFile,
	ProductPackageSource,
)
from OPSI.Util.Sync import (  # type: ignore[import]
	librsyncDeltaFile,
	librsyncPatchFile,
	librsyncSignature,
)
from opsicommon.exceptions import (  # type: ignore[import]
	BackendBadValueError,
	BackendError,
	BackendIOError,
	BackendMissingDataError,
	BackendReferentialIntegrityError,
	BackendTemporaryError,
	BackendUnaccomplishableError,
)
from opsicommon.logging import log_context  # type: ignore[import]
from opsicommon.objects import (  # type: ignore[import]
	Product,
	ProductOnDepot,
	ProductProperty,
	ProductPropertyState,
)
from opsicommon.types import forceUnicodeLower  # type: ignore[import]
from opsicommon.types import forceBool, forceDict, forceFilename  # type: ignore[import]
from opsicommon.types import (
	forceProductId as typeForceProductId,  # type: ignore[import]
)

from opsiconfd.config import opsi_config
from opsiconfd.logging import logger

# deprecated can be used in extension config files
from . import rpc_method  # pylint: disable=unused-import

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RPCDepotserverMixin(Protocol):  # pylint: disable=too-few-public-methods
	ssh_rsa_public_key_file: str = "/etc/ssh/ssh_host_rsa_key.pub"
	_package_manager: DepotserverPackageManager

	def __init__(self: BackendProtocol) -> None:
		if not self.host_getIdents(id=self._depot_id):  # pylint: disable=maybe-no-member
			logger.error("Depot %r not found in backend", self._depot_id)
			# Mark methods as not available
			for val in RPCDepotserverMixin.__dict__.values():
				if callable(val) and hasattr(val, "rpc_method"):
					delattr(val, "rpc_method")
		else:
			self._package_manager = DepotserverPackageManager(self, self._depot_id)

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
				md5_sum = md5sum(filename)
			if not md5_sum:
				raise ValueError("Failed to get md5sum")
			logger.info("MD5sum of file '%s' is '%s'", filename, md5_sum)
			return md5_sum
		except Exception as err:
			raise BackendIOError(f"Failed to get md5sum: {err}") from err

	@rpc_method
	def depot_librsyncSignature(self: BackendProtocol, filename: str) -> str:  # pylint: disable=invalid-name
		try:
			return librsyncSignature(filename)
		except Exception as err:  # pylint: disable=broad-except
			raise BackendIOError(f"Failed to get librsync signature: {err}") from err

	@rpc_method
	def depot_librsyncPatchFile(self: BackendProtocol, oldfile: str, deltafile: str, newfile: str) -> None:  # pylint: disable=invalid-name
		try:
			return librsyncPatchFile(oldfile, deltafile, newfile)
		except Exception as err:
			raise BackendIOError(f"Failed to patch file: {err}") from err

	@rpc_method
	def depot_librsyncDeltaFile(  # pylint: disable=invalid-name
		self: BackendProtocol, filename: str, signature: str, deltafile: str
	) -> None:
		try:
			librsyncDeltaFile(filename, signature, deltafile)
		except Exception as err:
			raise BackendIOError(f"Failed to create librsync delta file: {err}") from err

	@rpc_method
	def depot_getDiskSpaceUsage(self: BackendProtocol, path: str) -> Dict[str, Any]:  # pylint: disable=invalid-name
		if os.name != "posix":
			raise NotImplementedError("Not implemented for non-posix os")
		try:
			return getDiskSpaceUsage(path)
		except Exception as err:
			raise BackendIOError("Failed to get disk space usage: {err}") from err

	@rpc_method
	def depot_installPackage(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		filename: str,
		force: bool = False,
		propertyDefaultValues: Dict[str, Any] = None,
		tempDir: str = None,
		forceProductId: str = None,
		suppressPackageContentFileGeneration: bool = False,
	) -> None:
		"""
		Installing a package on the depot corresponding to this Backend.
		"""
		with log_context({"instance": "package_install"}):
			self._package_manager.install_package(
				filename,
				force=force,
				property_default_values=propertyDefaultValues or {},
				temp_dir=tempDir,
				force_product_id=forceProductId,
				suppress_package_content_file_generation=suppressPackageContentFileGeneration,
			)

	@rpc_method
	def depot_uninstallPackage(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str, force: bool = False, deleteFiles: bool = True
	) -> None:
		self._package_manager.uninstall_package(productId, force, deleteFiles)

	@rpc_method
	def depot_createPackageContentFile(self: BackendProtocol, productId: str) -> None:  # pylint: disable=invalid-name
		"""
		Create a package content file in the products depot directory.
		An existing file will be overriden.
		"""
		client_data_path = Path(
			self.host_getObjects(id=self._depot_id)[0].getDepotLocalUrl().replace("file://", "")
		)  # pylint: disable=protected-access
		product_path = client_data_path / productId
		if not product_path.is_dir():
			raise BackendIOError(f"Product dir '{product_path}' not found")

		package_content_path = product_path / f"{productId}.files"
		logger.notice("Creating package content file '%s'", package_content_path)

		if package_content_path.exists():
			package_content_path.unlink()

		package_content_file = PackageContentFile(str(package_content_path))
		package_content_file.setProductClientDataDir(str(product_path))
		client_data_files = findFiles(str(product_path))
		package_content_file.setClientDataFiles(client_data_files)
		package_content_file.generate()
		if os.name == "posix":
			os.chown(package_content_path, -1, grp.getgrnam(opsi_config.get("groups", "fileadmingroup"))[2])
			os.chmod(package_content_path, 0o660)

	@rpc_method
	def depot_createMd5SumFile(self: BackendProtocol, filename: str, md5sumFilename: str) -> None:  # pylint: disable=invalid-name
		if not os.path.exists(filename):
			raise BackendIOError(f"File not found: {filename}")
		logger.info("Creating md5sum file '%s'", md5sumFilename)
		md5 = md5sum(filename)
		with open(md5sumFilename, "w", encoding="utf-8") as md5file:
			md5file.write(md5)
		if os.name == "posix":
			os.chown(md5sumFilename, -1, grp.getgrnam(opsi_config.get("groups", "fileadmingroup"))[2])
			os.chmod(md5sumFilename, 0o660)

	@rpc_method
	def depot_createZsyncFile(self: BackendProtocol, filename: str, zsyncFilename: str) -> None:  # pylint: disable=invalid-name
		if not os.path.exists(filename):
			raise BackendIOError(f"File not found: {filename}")
		logger.info("Creating zsync file '%s'", zsyncFilename)
		zsync_file = ZsyncFile(zsyncFilename)
		zsync_file.generate(filename)
		if os.name == "posix":
			os.chown(zsyncFilename, -1, grp.getgrnam(opsi_config.get("groups", "fileadmingroup"))[2])
			os.chmod(zsyncFilename, 0o660)

	@rpc_method
	def workbench_buildPackage(self: BackendProtocol, package_dir: str) -> str:  # pylint: disable=invalid-name
		"""
		Creates an opsi package from an opsi package source directory.
		The function creates an opsi, md5 and zsync file in the source directory.
		The full path to the created opsi package is returned.
		"""
		package_path = Path(package_dir)
		workbench_path = Path(self.host_getObjects(id=self._depot_id)[0].getWorkbenchLocalUrl().replace("file://", ""))
		if not package_path.is_absolute():
			package_path = workbench_path / package_path
		package_path = package_path.resolve()
		if not package_path.is_relative_to(workbench_path):
			raise ValueError(f"Invalid package dir '{package_path}'")
		if not package_path.is_dir():
			raise BackendIOError(f"Package source dir '{package_path}' does not exist")
		pps = ProductPackageSource(
			packageSourceDir=str(package_path), packageFileDestDir=str(package_path), format="tar", compression="gzip", dereference=False
		)
		package_file = pps.pack()
		self.depot_createMd5SumFile(package_file, f"{package_file}.md5")
		self.depot_createZsyncFile(package_file, f"{package_file}.zsync")
		if os.name == "posix":
			for file in (package_file, f"{package_file}.md5", f"{package_file}.zsync"):
				try:  # pylint: disable=loop-try-except-usage
					os.chown(  # pylint: disable=dotted-import-in-loop
						file, -1, grp.getgrnam(opsi_config.get("groups", "fileadmingroup"))[2]  # pylint: disable=dotted-import-in-loop
					)
					os.chmod(file, 0o660)  # pylint: disable=dotted-import-in-loop
				except Exception as err:  # pylint: disable=broad-except
					logger.warning(err)
		return package_file

	@rpc_method
	def workbench_installPackage(self: BackendProtocol, package_file_or_dir: str) -> None:  # pylint: disable=invalid-name
		"""
		Install an opsi package into the repository.
		If the path points to an opsi source directory,
		an opsi package is automatically created and then installed.
		"""
		package_path = Path(package_file_or_dir)
		workbench_path = Path(self.host_getObjects(id=self._depot_id)[0].getWorkbenchLocalUrl().replace("file://", ""))
		if not package_path.is_absolute():
			package_path = workbench_path / package_path
		package_path = package_path.resolve()
		if not package_path.is_relative_to(workbench_path):
			raise ValueError(f"Invalid package file '{package_path}'")
		if package_path.is_dir():
			package_path = Path(self.workbench_buildPackage(str(package_path)))
		self.depot_installPackage(str(package_path))


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
		property_default_values: Dict[str, Any] = None,
		temp_dir: str = None,
		force_product_id: str = None,
		suppress_package_content_file_generation: bool = False,
	) -> None:
		property_default_values = property_default_values or {}

		@contextmanager
		def product_package_file(filename: str, temp_dir: str | None, depot_id: str) -> Generator[ProductPackageFile, None, None]:
			try:
				depots = self.backend.host_getObjects(id=depot_id)  # pylint: disable=protected-access
				depot = depots[0]
				del depots
			except IndexError as err:
				raise BackendMissingDataError(f"Depot '{depot_id}' not found in backend") from err

			depot_local_url = depot.getDepotLocalUrl()
			if not depot_local_url or not depot_local_url.startswith("file:///"):
				raise BackendBadValueError(f"Value '{depot_local_url}' not allowed for depot local url (has to start with 'file:///')")
			client_data_dir = depot_local_url[7:]

			ppf = ProductPackageFile(filename, tempDir=temp_dir)
			ppf.setClientDataDir(client_data_dir)
			ppf.getMetaData()

			try:
				yield ppf
				ppf.setAccessRights()
			finally:
				try:
					ppf.cleanup()
				except Exception as err:  # pylint: disable=broad-except
					logger.error("Cleanup failed: %s", err)

		@contextmanager
		def lock_product(product: Product, depot_id: str, force_installation: bool) -> ProductOnDepot:
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
		def run_package_scripts(product_package_file: ProductPackageFile, env: Dict[str, Any] = None) -> Generator[None, None, None]:
			logger.info("Running preinst script")
			for line in product_package_file.runPreinst(env=env or {}):
				logger.info("[preinst] %s", line)

			yield

			logger.info("Running postinst script")
			for line in product_package_file.runPostinst(env=env or {}):
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
			product_properties: List[ProductProperty], depot_id: str, product_on_depot: ProductOnDepot
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
							product_property = product_properties_to_cleanup[  # pylint: disable=loop-invariant-statement
								product_property_state.propertyId
							]  # pylint: disable=loop-invariant-statement
							if value in product_property.possibleValues:
								new_values.append(value)
								continue

							if product_property.getType() == "BoolProductProperty" and forceBool(value) in product_property.possibleValues:
								new_values.append(forceBool(value))
								changed = True
								continue

							if product_property.getType() == "UnicodeProductProperty":
								new_value = None
								for possible_value in product_property.possibleValues:
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

			if temp_dir:
				temp_dir = forceFilename(temp_dir)
			else:
				temp_dir = None

			if not os.path.isfile(filename):
				raise BackendIOError(f"Package file '{filename}' does not exist or can not be accessed.")
			if not os.access(filename, os.R_OK):
				raise BackendIOError(f"Read access denied for package file '{filename}'")

			try:
				with product_package_file(filename, temp_dir, self._depot_id) as ppf:
					product = ppf.packageControlFile.getProduct()
					if force_product_id:
						logger.info("Forcing product id '%s'", force_product_id)
						product.setId(force_product_id)
						ppf.packageControlFile.setProduct(product)

					product_id = product.getId()
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

					with lock_product(product, self._depot_id, force) as product_on_depot:
						logger.info("Checking package dependencies")
						self.check_dependencies(ppf)

						env = {
							"DEPOT_ID": self._depot_id,
							"OLD_PRODUCT_VERSION": old_product_version,
							"OLD_PACKAGE_VERSION": old_package_version,
						}
						with run_package_scripts(ppf, env):
							logger.info("Deleting old client-data dir")
							ppf.deleteProductClientDataDir()

							logger.info("Unpacking package files")
							ppf.extractData()

							logger.info("Updating product dependencies of product %s", product)
							current_product_dependencies = {}
							for product_dependency in self.backend.productDependency_getObjects(
								productId=product_id, productVersion=product.getProductVersion(), packageVersion=product.getPackageVersion()
							):
								ident = product_dependency.getIdent(returnType="unicode")
								current_product_dependencies[ident] = product_dependency

							product_dependencies = []
							for product_dependency in ppf.packageControlFile.getProductDependencies():
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

							for product_property in ppf.packageControlFile.getProductProperties():
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
							self.backend.productPropertyState_deleteObjects(
								self.backend.productPropertyState_getObjects(productId=product_id, objectId=self._depot_id)
							)

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
									try:  # pylint: disable=loop-try-except-usage
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
							ppf.createPackageContentFile()
						else:
							logger.debug("Suppressed generation of package content file")

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
					self.backend.config_getObjects(id="allow_to_remove_package_in_use")[0].getDefaultValues()[
						0
					]  # pylint: disable=maybe-no-member
				)
			except IndexError:
				pass

			if not allow_remove_used:
				client_ids = [
					clientToDepot["clientId"]
					for clientToDepot in self.backend.configState_getClientToDepotserver(depotIds=[self._depot_id])
				]
				if client_ids:
					product_on_clients = self.backend.productOnClient_getObjects(productId=product_id, clientId=client_ids)
					if product_on_clients:
						installed = 0
						action_requests = 0
						for poc in product_on_clients:
							if poc.installationStatus == "installed":
								installed += 1
							if poc.actionRequest and poc.actionRequest != "none":
								action_requests += 1
						if installed > 0 or action_requests > 0:
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

				for element in os.listdir(depot.depotLocalUrl[7:]):  # pylint: disable=loop-invariant-statement,dotted-import-in-loop
					if element.lower() == product_id.lower():
						client_data_dir = os.path.join(  # pylint: disable=dotted-import-in-loop
							depot.depotLocalUrl[7:], element  # pylint: disable=loop-invariant-statement
						)
						logger.info("Deleting client data dir '%s'", client_data_dir)
						removeDirectory(client_data_dir)

			self.backend.productOnDepot_deleteObjects(product_on_depot)
		except Exception as err:
			logger.error(err, exc_info=True)
			raise BackendError(f"Failed to uninstall product '{product_id}' on depot '{self._depot_id}': {err}") from err

	def check_dependencies(self, product_package_file: ProductPackageFile) -> None:
		for dependency in product_package_file.packageControlFile.getPackageDependencies():
			product_on_depots = self.backend.productOnDepot_getObjects(  # pylint: disable=protected-access
				depotId=self._depot_id, productId=dependency["package"]  # pylint: disable=protected-access
			)
			if not product_on_depots:
				raise BackendUnaccomplishableError(f"Dependent package '{dependency['package']}' not installed")

			if not dependency["version"]:
				logger.info("Fulfilled product dependency '%s'", dependency)
				continue

			product_on_depot = product_on_depots[0]
			available_version = product_on_depot.getProductVersion() + "-" + product_on_depot.getPackageVersion()

			if compareVersions(available_version, dependency["condition"], dependency["version"]):
				logger.info("Fulfilled package dependency %s (available version: %s)", dependency, available_version)
			else:
				raise BackendUnaccomplishableError(f"Unfulfilled package dependency {dependency} (available version: {available_version})")
