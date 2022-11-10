# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
backend.obj_host
"""

from typing import Any, List

from opsicommon.objects import Host  # type: ignore[import]

from ..mysql import BackendProtocol, IdentType
from . import rpc_method


class RPCHostMixin:
	@rpc_method
	def host_insertObject(self: BackendProtocol, host: dict | Host) -> None:  # pylint: disable=invalid-name
		"""
		Creates a new Host object in the backend.
		If the Host object already exists, it will be completely overwritten with the new values.
		Attributes that are not passed (or passed with the value 'null') will be set to 'null' in the backend.
		"""
		# {"id":"testx1.uib.local","type":"OpsiClient"}
		self._mysql.insert_object(table="HOST", obj=host, ace=self._get_ace("host_insertObject"), create=True, set_null=True)

	@rpc_method
	def host_updateObject(self: BackendProtocol, host: dict | Host) -> None:  # pylint: disable=invalid-name
		"""
		Updates an Host object in the backend.
		Attributes that are not passed (or passed with the value 'null'), will not be changed in the backend.
		If the object does not exist, no change takes place, no object is created.
		"""
		# {"id":"testx1.uib.local","type":"OpsiClient"}
		self._mysql.insert_object(table="HOST", obj=host, ace=self._get_ace("host_updateObject"), create=False, set_null=False)

	@rpc_method
	def host_createObjects(self: BackendProtocol, hosts: List[dict] | List[Host]) -> None:  # pylint: disable=invalid-name
		"""
		An object or a list of objects can be passed. Each object is passed internally to 'insertObject'.
		"""
		for host in hosts:
			self._mysql.insert_object(table="HOST", obj=host, ace=self._get_ace("host_createObjects"), create=True, set_null=True)

	@rpc_method
	def host_updateObjects(self: BackendProtocol, hosts: List[dict] | List[Host]) -> None:  # pylint: disable=invalid-name
		"""
		An object or a list of objects can be passed.
		Each object will be updated if it exists or created if it does not exist yet.
		"""
		for host in hosts:
			self._mysql.insert_object(table="HOST", obj=host, ace=self._get_ace("host_updateObjects"), create=True, set_null=False)

	@rpc_method
	def host_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		return self._mysql.get_idents(table="HOST", object_type=Host, ace=self._get_ace("host_getIdents"), ident_type=returnType, filter=filter)

	@rpc_method
	def host_getHashes(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		return self._mysql.get_objects(
			table="HOST", ace=self._get_ace("host_getObjects"), return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method
	def host_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[Host]:  # pylint: disable=redefined-builtin,invalid-name
		return self._mysql.get_objects(
			table="HOST", ace=self._get_ace("host_getObjects"), return_type="object", attributes=attributes, filter=filter
		)
