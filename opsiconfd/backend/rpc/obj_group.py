# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.group
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import Group, HostGroup  # type: ignore[import]
from opsicommon.types import forceList, forceObjectClass  # type: ignore[import]

from ..mysql.cleanup import remove_orphans_object_to_group_host
from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCGroupMixin(Protocol):
	def group_bulkInsertObjects(self: BackendProtocol, groups: list[dict] | list[Group]) -> None:  # pylint: disable=invalid-name
		self._mysql.bulk_insert_objects(table="GROUP", objs=groups)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def group_insertObject(self: BackendProtocol, group: dict | Group) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("group_insertObject")
		group = forceObjectClass(group, Group)
		self._mysql.insert_object(table="GROUP", obj=group, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def group_updateObject(self: BackendProtocol, group: dict | Group) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("group_updateObject")
		group = forceObjectClass(group, Group)
		self._mysql.insert_object(table="GROUP", obj=group, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def group_createObjects(self: BackendProtocol, groups: list[dict] | list[Group] | dict | Group) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("group_createObjects")
		with self._mysql.session() as session:
			for group in forceList(groups):
				group = forceObjectClass(group, Group)
				self._mysql.insert_object(table="GROUP", obj=group, ace=ace, create=True, set_null=True, session=session)

	@rpc_method(check_acl=False)
	def group_updateObjects(self: BackendProtocol, groups: list[dict] | list[Group] | dict | Group) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("group_updateObjects")
		with self._mysql.session() as session:
			for group in forceList(groups):
				group = forceObjectClass(group, Group)
				self._mysql.insert_object(table="GROUP", obj=group, ace=ace, create=True, set_null=False, session=session)

	@rpc_method(check_acl=False)
	def group_getObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[Group]:
		ace = self._get_ace("group_getObjects")
		return self._mysql.get_objects(table="GROUP", ace=ace, object_type=Group, attributes=attributes, filter=filter)

	@rpc_method(check_acl=False)
	def group_getHashes(  # pylint: disable=invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any  # pylint: disable=redefined-builtin
	) -> list[dict]:
		ace = self._get_ace("group_getObjects")
		return self._mysql.get_objects(table="GROUP", object_type=Group, ace=ace, return_type="dict", attributes=attributes, filter=filter)

	@rpc_method(check_acl=False)
	def group_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("group_getObjects")
		return self._mysql.get_idents(table="GROUP", object_type=Group, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def group_deleteObjects(self: BackendProtocol, groups: list[dict] | list[Group] | dict | Group) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("group_deleteObjects")
		self._mysql.delete_objects(table="GROUP", object_type=Group, obj=groups, ace=ace)
		with self._mysql.session() as session:
			remove_orphans_object_to_group_host(session)

	@rpc_method(check_acl=False)
	def group_createHostGroup(  # pylint: disable=invalid-name
		self: BackendProtocol,
		id: str,  # pylint: disable=redefined-builtin
		description: str | None = None,
		notes: str | None = None,
		parentGroupId: str | None = None,
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.group_createObjects(HostGroup.fromHash(_hash))

	@rpc_method(check_acl=False)
	def group_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.group_deleteObjects(self.group_getIdents(returnType="dict", id=id))
