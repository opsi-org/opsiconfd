# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.config
"""

from typing import Any, List

from opsicommon.objects import OBJECT_CLASSES, Config  # type: ignore[import]

from ..mysql import BackendProtocol
from . import rpc_method


class RPCConfigMixin:
	@rpc_method
	def config_insertObject(self: BackendProtocol, config: dict | Config) -> None:  # pylint: disable=invalid-name
		"""
		Creates a new Host object in the backend.
		If the Host object already exists, it will be completely overwritten with the new values.
		Attributes that are not passed (or passed with the value 'null') will be set to 'null' in the backend.
		"""
		# {"id": "test123", "type": "UnicodeConfig", "description": "desc",
		# "possibleValues": ["1","2"], "defaultValues": ["1","2"], "editable": true, "multiValue": true }

		if not isinstance(config, Config):
			config = OBJECT_CLASSES[config["type"]].fromHash(config)
		config.setDefaults()
		data = config.to_hash()

		with self._mysql.session() as session:
			session.execute("DELETE FROM `CONFIG_VALUE` WHERE configId = :id", params=data)
			session.execute(
				"""
				REPLACE INTO `CONFIG` (configId ,type, description, multiValue, editable)
				VALUES (:id, :type, :description, :multiValue, :editable)
				""",
				params=data
			)
			for value in data["possibleValues"] or []:
				session.execute(
					"""
					INSERT INTO `CONFIG_VALUE` (configId, value, isDefault)
					VALUES (:configId, :value, :isDefault)
					""",
					params={"configId": data["id"], "value": value, "isDefault": value in (data["defaultValues"] or [])}  # pylint: disable=loop-invariant-statement
				)
		# {"id":"testx1.uib.local","type":"OpsiClient"}
		# self._mysql.insert_object(tables=["CONFIG", "CONFIG_VALUE"], obj=config, ace=self._get_ace("config_insertObject"))

	@rpc_method
	def config_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
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
