# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.group
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Protocol

from opsicommon.objects import Group, HostGroup  # type: ignore[import]
from opsicommon.types import forceList  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCGroupMixin(Protocol):
	@rpc_method
	def group_insertObject(self: BackendProtocol, group: dict | Group) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("group_insertObject")
		self._mysql.insert_object(table="GROUP", obj=group, ace=ace, create=True, set_null=True)

	@rpc_method
	def group_updateObject(self: BackendProtocol, group: dict | Group) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("group_updateObject")
		self._mysql.insert_object(table="GROUP", obj=group, ace=ace, create=False, set_null=False)

	@rpc_method
	def group_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, groups: List[dict] | List[Group] | dict | Group
	) -> None:
		ace = self._get_ace("group_createObjects")
		for group in forceList(groups):
			self._mysql.insert_object(table="GROUP", obj=group, ace=ace, create=True, set_null=True)

	@rpc_method
	def group_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, groups: List[dict] | List[Group] | dict | Group
	) -> None:
		ace = self._get_ace("group_updateObjects")
		for group in forceList(groups):
			self._mysql.insert_object(table="GROUP", obj=group, ace=ace, create=True, set_null=False)

	@rpc_method
	def group_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[Group]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("group_getObjects")
		return self._mysql.get_objects(
			table="GROUP", ace=ace, object_type=Group, attributes=attributes, filter=filter
		)

	@rpc_method
	def group_getHashes(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("group_getObjects")
		return self._mysql.get_objects(
			table="GROUP", object_type=Group, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method
	def group_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("group_getObjects")
		return self._mysql.get_idents(table="GROUP", object_type=Group, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method
	def group_deleteObjects(self: BackendProtocol, groups: List[dict] | List[Group] | dict | Group) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("group_deleteObjects")
		self._mysql.delete_objects(table="GROUP", object_type=Group, obj=groups, ace=ace)

	@rpc_method
	def group_createHostGroup(  # pylint: disable=invalid-name
		self: BackendProtocol, id: str, description: str = None, notes: str = None, parentGroupId: str = None  # pylint: disable=redefined-builtin,unused-argument
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.group_createObjects(HostGroup.fromHash(_hash))

	@rpc_method
	def group_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.group_deleteObjects([{"id": id}])