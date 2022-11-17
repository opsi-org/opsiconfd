# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.config
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Protocol

from opsicommon.objects import OBJECT_CLASSES, Config  # type: ignore[import]

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RPCConfigMixin(Protocol):
	@rpc_method
	def config_insertObject(self: BackendProtocol, config: dict | Config) -> None:  # pylint: disable=invalid-name
		"""
		Creates a new Config object in the backend.
		If the Config object already exists, it will be completely overwritten with the new values.
		Attributes that are not passed (or passed with the value 'null') will be set to 'null' in the backend.
		"""
		ace = self._get_ace("config_insertObject")
		query, data = self._mysql.insert_query(table="CONFIG", obj=config, ace=ace, create=True, set_null=True)
		with self._mysql.session() as session:
			session.execute("DELETE FROM `CONFIG_VALUE` WHERE configId = :id", params=data)
			session.execute(query, params=data)
			for value in data["possibleValues"] or []:
				session.execute(
					"INSERT INTO `CONFIG_VALUE` (configId, value, isDefault) VALUES (:configId, :value, :isDefault)",
					params={"configId": data["id"], "value": value, "isDefault": value in (data["defaultValues"] or [])}  # pylint: disable=loop-invariant-statement
				)

	@rpc_method
	def config_updateObject(self: BackendProtocol, config: dict | Config) -> None:  # pylint: disable=invalid-name
		"""
		Updates an Config object in the backend.
		Attributes that are not passed (or passed with the value 'null'), will not be changed in the backend.
		If the object does not exist, no change takes place, no object is created.
		"""
		ace = self._get_ace("config_insertObject")
		query, data = self._mysql.insert_query(table="CONFIG", obj=config, ace=ace, create=False, set_null=False)
		with self._mysql.session() as session:
			session.execute("DELETE FROM `CONFIG_VALUE` WHERE configId = :id", params=data)
			if session.execute(query, params=data).rowcount > 0:
				for value in data["possibleValues"] or []:
					session.execute(
						"INSERT INTO `CONFIG_VALUE` (configId, value, isDefault) VALUES (:configId, :value, :isDefault)",
						params={"configId": data["id"], "value": value, "isDefault": value in (data["defaultValues"] or [])}  # pylint: disable=loop-invariant-statement
					)

	@rpc_method
	def config_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[Config]:  # pylint: disable=redefined-builtin,invalid-name
		aggregates = {
			"possibleValues": f'GROUP_CONCAT(`value` SEPARATOR "{self._mysql.record_separator}")',
			"defaultValues": f'GROUP_CONCAT(IF(`isDefault`, `value`, NULL) SEPARATOR "{self._mysql.record_separator}")'
		}
		return self._mysql.get_objects(
			table="CONFIG LEFT JOIN CONFIG_VALUE ON CONFIG.configId = CONFIG_VALUE.configId",
			object_type=Config,
			aggregates=aggregates,
			ace=self._get_ace("config_getObjects"), attributes=attributes, filter=filter
		)
