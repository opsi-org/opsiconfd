# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.software_license_to_license_pool
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Protocol

from opsicommon.objects import SoftwareLicenseToLicensePool  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCSoftwareLicenseToLicensePoolMixin(Protocol):
	@rpc_method
	def softwareLicenseToLicensePool_insertObject(  # pylint: disable=invalid-name
		self: BackendProtocol, softwareLicenseToLicensePool: dict | SoftwareLicenseToLicensePool  # pylint: disable=invalid-name
	) -> None:
		ace = self._get_ace("softwareLicenseToLicensePool_insertObject")
		self._mysql.insert_object(table="SOFTWARE_LICENSE_TO_LICENSE_POOL", obj=softwareLicenseToLicensePool, ace=ace, create=True, set_null=True)

	@rpc_method
	def softwareLicenseToLicensePool_updateObject(  # pylint: disable=invalid-name
		self: BackendProtocol, softwareLicenseToLicensePool: dict | SoftwareLicenseToLicensePool
	) -> None:
		ace = self._get_ace("softwareLicenseToLicensePool_updateObject")
		self._mysql.insert_object(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL", obj=softwareLicenseToLicensePool, ace=ace, create=False, set_null=False
		)

	@rpc_method
	def softwareLicenseToLicensePool_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		softwareLicenseToLicensePools: List[dict] | List[SoftwareLicenseToLicensePool] | dict | SoftwareLicenseToLicensePool
	) -> None:
		ace = self._get_ace("softwareLicenseToLicensePool_createObjects")
		for softwareLicenseToLicensePool in forceList(softwareLicenseToLicensePools):
			self._mysql.insert_object(
				table="SOFTWARE_LICENSE_TO_LICENSE_POOL", obj=softwareLicenseToLicensePool, ace=ace, create=True, set_null=True
			)

	@rpc_method
	def softwareLicenseToLicensePool_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		softwareLicenseToLicensePools: List[dict] | List[SoftwareLicenseToLicensePool] | dict | SoftwareLicenseToLicensePool
	) -> None:
		ace = self._get_ace("softwareLicenseToLicensePool_updateObjects")
		for softwareLicenseToLicensePool in forceList(softwareLicenseToLicensePools):
			self._mysql.insert_object(
				table="SOFTWARE_LICENSE_TO_LICENSE_POOL", obj=softwareLicenseToLicensePool, ace=ace, create=True, set_null=False
			)

	@rpc_method
	def softwareLicenseToLicensePool_getObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: List[str] = None, **filter: Any  # pylint: disable=redefined-builtin,invalid-name
	) -> List[SoftwareLicenseToLicensePool]:
		ace = self._get_ace("softwareLicenseToLicensePool_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL", ace=ace, object_type=SoftwareLicenseToLicensePool, attributes=attributes, filter=filter
		)

	@rpc_method
	def softwareLicenseToLicensePool_getHashes(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("softwareLicenseToLicensePool_getObjects")
		return self._mysql.get_objects(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL",
			object_type=SoftwareLicenseToLicensePool,
			ace=ace,
			return_type="dict",
			attributes=attributes,
			filter=filter
		)

	@rpc_method
	def softwareLicenseToLicensePool_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("softwareLicenseToLicensePool_getObjects")
		return self._mysql.get_idents(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL", object_type=SoftwareLicenseToLicensePool, ace=ace, ident_type=returnType, filter=filter
		)

	@rpc_method
	def softwareLicenseToLicensePool_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol,
		softwareLicenseToLicensePools: List[dict] | List[SoftwareLicenseToLicensePool] | dict | SoftwareLicenseToLicensePool
	) -> None:
		ace = self._get_ace("softwareLicenseToLicensePool_deleteObjects")
		self._mysql.delete_objects(
			table="SOFTWARE_LICENSE_TO_LICENSE_POOL", object_type=SoftwareLicenseToLicensePool, obj=softwareLicenseToLicensePools, ace=ace
		)

	@rpc_method
	def softwareLicenseToLicensePool_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.softwareLicenseToLicensePool_deleteObjects([{"id": id}])
