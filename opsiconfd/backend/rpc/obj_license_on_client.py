# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.license_on_client
"""
from __future__ import annotations

import random
from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.exceptions import (  # type: ignore[import]
	LicenseConfigurationError,
	LicenseMissingError,
)
from opsicommon.objects import LicenseOnClient  # type: ignore[import]
from opsicommon.types import (  # type: ignore[import]
	forceHostId,
	forceLicensePoolId,
	forceList,
	forceProductId,
	forceUnicode,
)

from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCLicenseOnClientMixin(Protocol):
	def licenseOnClient_bulkInsertObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseOnClients: list[dict] | list[LicenseOnClient]
	) -> None:
		self._mysql.bulk_insert_objects(table="LICENSE_ON_CLIENT", objs=licenseOnClients)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def licenseOnClient_insertObject(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseOnClient: dict | LicenseOnClient
	) -> None:
		ace = self._get_ace("licenseOnClient_insertObject")
		self._mysql.insert_object(table="LICENSE_ON_CLIENT", obj=licenseOnClient, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def licenseOnClient_updateObject(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseOnClient: dict | LicenseOnClient
	) -> None:
		ace = self._get_ace("licenseOnClient_updateObject")
		self._mysql.insert_object(table="LICENSE_ON_CLIENT", obj=licenseOnClient, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def licenseOnClient_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseOnClients: list[dict] | list[LicenseOnClient] | dict | LicenseOnClient
	) -> None:
		ace = self._get_ace("licenseOnClient_createObjects")
		with self._mysql.session() as session:
			for licenseOnClient in forceList(licenseOnClients):
				self._mysql.insert_object(
					table="LICENSE_ON_CLIENT", obj=licenseOnClient, ace=ace, create=True, set_null=True, session=session
				)

	@rpc_method(check_acl=False)
	def licenseOnClient_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseOnClients: list[dict] | list[LicenseOnClient] | dict | LicenseOnClient
	) -> None:
		ace = self._get_ace("licenseOnClient_updateObjects")
		with self._mysql.session() as session:
			for licenseOnClient in forceList(licenseOnClients):
				self._mysql.insert_object(
					table="LICENSE_ON_CLIENT", obj=licenseOnClient, ace=ace, create=True, set_null=False, session=session
				)

	@rpc_method(check_acl=False)
	def licenseOnClient_getObjects(  # pylint: disable=redefined-builtin,invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any
	) -> list[LicenseOnClient]:
		ace = self._get_ace("licenseOnClient_getObjects")
		return self._mysql.get_objects(
			table="LICENSE_ON_CLIENT", ace=ace, object_type=LicenseOnClient, attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def licenseOnClient_getHashes(  # pylint: disable=redefined-builtin,invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any
	) -> list[dict]:
		ace = self._get_ace("licenseOnClient_getObjects")
		return self._mysql.get_objects(
			table="LICENSE_ON_CLIENT", object_type=LicenseOnClient, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def licenseOnClient_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("licenseOnClient_getObjects")
		return self._mysql.get_idents(table="LICENSE_ON_CLIENT", object_type=LicenseOnClient, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def licenseOnClient_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licenseOnClients: list[dict] | list[LicenseOnClient] | dict | LicenseOnClient
	) -> None:
		ace = self._get_ace("licenseOnClient_deleteObjects")
		self._mysql.delete_objects(table="LICENSE_ON_CLIENT", object_type=LicenseOnClient, obj=licenseOnClients, ace=ace)

	@rpc_method(check_acl=False)
	def licenseOnClient_create(  # pylint: disable=too-many-arguments,invalid-name
		self: BackendProtocol,
		softwareLicenseId: str,
		licensePoolId: str,
		clientId: str,
		licenseKey: str | None = None,
		notes: str | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.licenseOnClient_createObjects(LicenseOnClient.fromHash(_hash))

	@rpc_method(check_acl=False)
	def licenseOnClient_delete(  # pylint: disable=invalid-name
		self: BackendProtocol, softwareLicenseId: str, licensePoolId: str, clientId: str
	) -> None:
		self.licenseOnClient_deleteObjects(
			self.licenseOnClient_getIdents(
				returnType="dict", softwareLicenseId=softwareLicenseId, licensePoolId=licensePoolId, clientId=clientId
			)
		)

	@rpc_method(check_acl=False)
	def licenseOnClient_getOrCreateObject(  # pylint: disable=invalid-name,too-many-branches
		self: BackendProtocol,
		clientId: str,
		licensePoolId: str | None = None,
		productId: str | None = None,
		windowsSoftwareId: str | None = None,
	) -> LicenseOnClient:
		clientId = forceHostId(clientId)
		if licensePoolId:
			licensePoolId = forceLicensePoolId(licensePoolId)
		elif productId or windowsSoftwareId:
			license_pool_ids = []
			if productId:
				productId = forceProductId(productId)
				license_pool_ids = self.licensePool_getIdents(productIds=productId, returnType="unicode")
			elif windowsSoftwareId:
				license_pool_ids = []
				windowsSoftwareId = forceUnicode(windowsSoftwareId)

				audit_softwares = self.auditSoftware_getObjects(windowsSoftwareId=windowsSoftwareId)  # pylint: disable=no-member
				for auditSoftware in audit_softwares:
					audit_software_to_license_pools = self.auditSoftwareToLicensePool_getObjects(  # pylint: disable=no-member
						name=auditSoftware.name,
						version=auditSoftware.version,
						subVersion=auditSoftware.subVersion,
						language=auditSoftware.language,
						architecture=auditSoftware.architecture,
					)
					if audit_software_to_license_pools:
						license_pool_ids.append(audit_software_to_license_pools[0].licensePoolId)

			if len(license_pool_ids) < 1:
				raise LicenseConfigurationError(
					f"No license pool for product id '{productId}', windowsSoftwareId '{windowsSoftwareId}' found"
				)
			if len(license_pool_ids) > 1:
				raise LicenseConfigurationError(
					f"Multiple license pools for product id '{productId}', windowsSoftwareId '{windowsSoftwareId}' found: {license_pool_ids}"
				)
			licensePoolId = license_pool_ids[0]
		else:
			raise ValueError("You have to specify one of: licensePoolId, productId, windowsSoftwareId")

		if not self.licensePool_getIdents(id=licensePoolId):
			raise LicenseConfigurationError(f"License pool '{licensePoolId}' not found")

		# Test if a license is already used by the host
		license_on_client = None
		license_on_clients = self.licenseOnClient_getObjects(licensePoolId=licensePoolId, clientId=clientId)
		if license_on_clients:
			logger.info(
				"Using already assigned license '%s' for client '%s', license pool '%s'",
				license_on_clients[0].getSoftwareLicenseId(),
				clientId,
				licensePoolId,
			)
			license_on_client = license_on_clients[0]
		else:
			(software_license_id, license_key) = self._get_usable_software_license(clientId, licensePoolId)  # type: ignore[arg-type]
			if not license_key:
				logger.info("License available but no license key found")

			logger.info(
				"Using software license id '%s', license key '%s' for host '%s' and license pool '%s'",
				software_license_id,
				license_key,
				clientId,
				licensePoolId,
			)

			assert licensePoolId

			license_on_client = LicenseOnClient(
				softwareLicenseId=software_license_id, licensePoolId=licensePoolId, clientId=clientId, licenseKey=license_key, notes=None
			)
			self.licenseOnClient_createObjects(license_on_client)
		return license_on_client

	def _get_usable_software_license(  # pylint: disable=too-many-branches
		self: BackendProtocol, client_id: str, license_pool_id: str
	) -> tuple[str, str]:
		software_license_id = ""
		license_key = ""

		license_on_clients = self.licenseOnClient_getObjects(licensePoolId=license_pool_id, clientId=client_id)
		if license_on_clients:
			# Already registered
			return (license_on_clients[0].getSoftwareLicenseId(), license_on_clients[0].getLicenseKey())

		software_license_to_license_pools = self.softwareLicenseToLicensePool_getObjects(licensePoolId=license_pool_id)
		if not software_license_to_license_pools:
			raise LicenseMissingError(f"No licenses in pool '{license_pool_id}'")

		software_license_ids = [
			softwareLicenseToLicensePool.softwareLicenseId for softwareLicenseToLicensePool in software_license_to_license_pools
		]

		software_licenses_bound_to_host = self.softwareLicense_getObjects(id=software_license_ids, boundToHost=client_id)
		if software_licenses_bound_to_host:
			logger.info("Using license bound to host: %s", software_licenses_bound_to_host[0])
			software_license_id = software_licenses_bound_to_host[0].getId()
		else:
			# Search an available license
			for software_license in self.softwareLicense_getObjects(id=software_license_ids, boundToHost=[None, ""]):
				logger.debug("Checking license '%s', maxInstallations %d", software_license.getId(), software_license.getMaxInstallations())
				if software_license.getMaxInstallations() == 0:
					# 0 = infinite
					software_license_id = software_license.getId()
					break
				installations = len(self.licenseOnClient_getIdents(softwareLicenseId=software_license.getId()))
				logger.debug("Installations registered: %d", installations)
				if installations < software_license.getMaxInstallations():
					software_license_id = software_license.getId()
					break

			if software_license_id:
				logger.info("Found available license for pool '%s' and client '%s': %s", license_pool_id, client_id, software_license_id)

		if not software_license_id:
			raise LicenseMissingError(
				f"No license available for pool '{license_pool_id}' and client '{client_id}', or all remaining licenses are bound to a different host."
			)

		license_keys = []
		for software_license_to_license_pool in software_license_to_license_pools:
			if software_license_to_license_pool.getLicenseKey():
				if software_license_to_license_pool.getSoftwareLicenseId() == software_license_id:
					license_key = software_license_to_license_pool.getLicenseKey()
					break
				logger.debug("Found license key: %s", license_key)
				license_keys.append(software_license_to_license_pool.getLicenseKey())

		if not license_key and license_keys:
			license_key = random.choice(license_keys)
			logger.info("Randomly choosing license key")

		logger.debug("Using license '%s', license key: %s", software_license_id, license_key)
		return (software_license_id, license_key)
