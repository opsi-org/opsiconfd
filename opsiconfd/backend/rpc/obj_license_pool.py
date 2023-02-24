# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.license_pool
"""
from __future__ import annotations

from contextlib import nullcontext
from typing import TYPE_CHECKING, Any, Literal, Protocol

from opsicommon.objects import LicensePool  # type: ignore[import]
from opsicommon.types import forceList, forceObjectClass  # type: ignore[import]

from ..auth import RPCACE
from . import rpc_method

if TYPE_CHECKING:
	from ..mysql import Session
	from .protocol import BackendProtocol, IdentType


class RPCLicensePoolMixin(Protocol):
	def _license_pool_insert_object(  # pylint: disable=too-many-arguments
		self: BackendProtocol,
		license_pool: LicensePool | dict,
		ace: list[RPCACE],
		create: bool = True,
		set_null: bool = True,
		session: Session | None = None,
		lock: bool = True,
	) -> None:
		query, data = self._mysql.insert_query(table="LICENSE_POOL", obj=license_pool, ace=ace, create=create, set_null=set_null)
		with self._mysql.session(session) as session:  # pylint: disable=redefined-argument-from-local
			with self._mysql.table_lock(
				session, {"LICENSE_POOL": "WRITE", "PRODUCT_ID_TO_LICENSE_POOL": "WRITE"}
			) if lock else nullcontext():
				session.execute(
					"DELETE FROM `PRODUCT_ID_TO_LICENSE_POOL` WHERE licensePoolId = :id",
					params=data,
				)
				if session.execute(query, params=data).rowcount > 0:
					for value in data["productIds"] or []:
						session.execute(
							"""
							INSERT INTO `PRODUCT_ID_TO_LICENSE_POOL`
								(licensePoolId, productId)
							VALUES
								(:licensePoolId, :productId)
							""",
							params={"licensePoolId": data["id"], "productId": value},
						)

	@rpc_method(check_acl=False)
	def licensePool_insertObject(self: BackendProtocol, licensePool: dict | LicensePool) -> None:  # pylint: disable=invalid-name
		self._check_module("license_management")
		ace = self._get_ace("licensePool_insertObject")
		licensePool = forceObjectClass(licensePool, LicensePool)
		self._license_pool_insert_object(license_pool=licensePool, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def licensePool_updateObject(self: BackendProtocol, licensePool: dict | LicensePool) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("licensePool_updateObject")
		self._license_pool_insert_object(license_pool=licensePool, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def licensePool_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licensePools: list[dict] | list[LicensePool] | dict | LicensePool
	) -> None:
		self._check_module("license_management")
		ace = self._get_ace("licensePool_createObjects")
		with self._mysql.session() as session:
			with self._mysql.table_lock(session, {"LICENSE_POOL": "WRITE", "PRODUCT_ID_TO_LICENSE_POOL": "WRITE"}):
				for license_pool in forceList(licensePools):
					license_pool = forceObjectClass(license_pool, LicensePool)
					self._license_pool_insert_object(
						license_pool=license_pool, ace=ace, create=True, set_null=True, session=session, lock=False
					)

	@rpc_method(check_acl=False)
	def licensePool_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licensePools: list[dict] | list[LicensePool] | dict | LicensePool
	) -> None:
		ace = self._get_ace("licensePool_updateObjects")
		with self._mysql.session() as session:
			with self._mysql.table_lock(session, {"LICENSE_POOL": "WRITE", "PRODUCT_ID_TO_LICENSE_POOL": "WRITE"}):
				for license_pool in forceList(licensePools):
					license_pool = forceObjectClass(license_pool, LicensePool)
					self._license_pool_insert_object(
						license_pool=license_pool, ace=ace, create=True, set_null=False, session=session, lock=False
					)

	def _license_pool_get(  # pylint: disable=too-many-arguments,too-many-locals
		self: BackendProtocol,
		ace: list[RPCACE] | None = None,
		return_type: Literal["object", "dict"] = "object",
		attributes: list[str] | tuple[str, ...] | None = None,
		filter: dict[str, Any] | None = None,  # pylint: disable=redefined-builtin
	) -> list[dict] | list[LicensePool]:
		if filter and "productIds" in filter:
			filter["productId"] = filter.pop("productIds")

		aggregates = {
			"productIds": f'GROUP_CONCAT(`productId` SEPARATOR "{self._mysql.record_separator}")',
		}
		return self._mysql.get_objects(
			table=(
				"`LICENSE_POOL` LEFT JOIN `PRODUCT_ID_TO_LICENSE_POOL` ON "
				"`LICENSE_POOL`.`licensePoolId` = `LICENSE_POOL`.`licensePoolId`"
			),
			object_type=LicensePool,
			aggregates=aggregates,
			ace=ace,
			return_type=return_type,
			attributes=attributes,
			filter=filter,
		)

	@rpc_method(check_acl=False)
	def licensePool_getObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[LicensePool]:
		ace = self._get_ace("licensePool_getObjects")
		return self._license_pool_get(ace=ace, return_type="object", attributes=attributes, filter=filter)  # type: ignore[return-value]

	@rpc_method(check_acl=False)
	def licensePool_getHashes(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[dict]:
		ace = self._get_ace("licensePool_getObjects")
		return self._license_pool_get(ace=ace, return_type="dict", attributes=attributes, filter=filter)  # type: ignore[return-value]

	@rpc_method(check_acl=False)
	def licensePool_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("licensePool_getObjects")
		return self._mysql.get_idents("LICENSE_POOL", LicensePool, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def licensePool_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, licensePools: list[dict] | list[LicensePool] | dict | LicensePool  # pylint: disable=invalid-name
	) -> None:
		if not licensePools:
			return
		ace = self._get_ace("licensePool_deleteObjects")
		self._mysql.delete_objects(table="LICENSE_POOL", object_type=LicensePool, obj=licensePools, ace=ace)

	@rpc_method(check_acl=False)
	def licensePool_create(  # pylint: disable=invalid-name
		self: BackendProtocol,
		id: str,  # pylint: disable=redefined-builtin
		description: str | None = None,
		productIds: list[str] | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.licensePool_createObjects(LicensePool.fromHash(_hash))

	@rpc_method(check_acl=False)
	def licensePool_delete(self: BackendProtocol, id: list[str] | str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		idents = self.licensePool_getIdents(returnType="dict", id=id)
		if idents:
			self.licensePool_deleteObjects(idents)
