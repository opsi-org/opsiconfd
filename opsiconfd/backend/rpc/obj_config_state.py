# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.config_state
"""
from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any, List, Protocol

from opsicommon.objects import ConfigState, ProductOnDepot  # type: ignore[import]
from opsicommon.types import (  # type: ignore[import]
	forceBool,
	forceHostIdList,
	forceList,
	forceObjectIdList,
	forceProductIdList,
	forceUnicodeList,
)

from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCConfigStateMixin(Protocol):
	@rpc_method
	def configState_getValues(  # pylint: disable=invalid-name
		self: BackendProtocol, config_ids: List[str] | str, object_ids: List[str] | str, with_defaults: bool = True
	) -> dict[str, dict[str, list[Any]]]:
		config_ids = forceUnicodeList(config_ids)
		object_ids = forceObjectIdList(object_ids)
		res: dict[str, dict[str, list[Any]]] = {}
		if with_defaults:
			defaults = {config.id: config.defaultValues if with_defaults else None for config in self.config_getObjects(id=config_ids)}
			res = {host_id: defaults.copy() for host_id in self.host_getIdents(returnType="str", id=object_ids)}
		for config_state in self.configState_getObjects(configId=config_ids, objectId=object_ids):
			if config_state.objectId not in res:
				res[config_state.objectId] = {}
			res[config_state.objectId][config_state.configId] = config_state.values
		return res

	@rpc_method
	def configState_insertObject(self: BackendProtocol, configState: dict | ConfigState) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("configState_insertObject")
		self._mysql.insert_object(table="CONFIG_STATE", obj=configState, ace=ace, create=True, set_null=True)

	@rpc_method
	def configState_updateObject(self: BackendProtocol, configState: dict | ConfigState) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("configState_updateObject")
		self._mysql.insert_object(table="CONFIG_STATE", obj=configState, ace=ace, create=False, set_null=False)

	@rpc_method
	def configState_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, configStates: List[dict] | List[ConfigState] | dict | ConfigState
	) -> None:
		ace = self._get_ace("configState_createObjects")
		for config_state in forceList(configStates):
			self._mysql.insert_object(table="CONFIG_STATE", obj=config_state, ace=ace, create=True, set_null=True)

	@rpc_method
	def configState_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, configStates: List[dict] | List[ConfigState] | dict | ConfigState
	) -> None:
		ace = self._get_ace("configState_updateObjects")
		for config_state in forceList(configStates):
			self._mysql.insert_object(table="CONFIG_STATE", obj=config_state, ace=ace, create=True, set_null=False)

	@rpc_method
	def configState_getObjects(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[ConfigState]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("configState_getObjects")
		return self._mysql.get_objects(
			table="CONFIG_STATE", ace=ace, object_type=ConfigState, attributes=attributes, filter=filter
		)

	@rpc_method
	def configState_getHashes(self: BackendProtocol, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		ace = self._get_ace("configState_getObjects")
		return self._mysql.get_objects(
			table="CONFIG_STATE", object_type=ConfigState, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method
	def configState_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> List[str] | List[dict] | List[list] | List[tuple]:
		ace = self._get_ace("configState_getObjects")
		return self._mysql.get_idents(table="CONFIG_STATE", object_type=ConfigState, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method
	def configState_deleteObjects(self: BackendProtocol, configStates: List[dict] | List[ConfigState] | dict | ConfigState) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("configState_deleteObjects")
		self._mysql.delete_objects(table="CONFIG_STATE", object_type=ConfigState, obj=configStates, ace=ace)

	@rpc_method
	def configState_create(self: BackendProtocol, configId: str, objectId: str, values: List[Any] = None) -> None:  # pylint: disable=invalid-name,unused-argument
		_hash = locals()
		del _hash["self"]
		self.configState_createObjects(ConfigState.fromHash(_hash))

	@rpc_method
	def configState_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.config_deleteObjects([{"id": id}])

	@rpc_method
	def configState_getClientToDepotserver(  # pylint: disable=invalid-name,too-many-locals,too-many-branches
		self: BackendProtocol,
		depotIds: list[str] = None,  # pylint: disable=invalid-name
		clientIds: list[str] = None,  # pylint: disable=invalid-name
		masterOnly: bool = True,  # pylint: disable=invalid-name
		productIds: list[str] = None  # pylint: disable=invalid-name
	) -> list[dict[str, Any]]:
		"""
		Get a mapping of client and depots.

		:param depotIds: Limit the search to the specified depot ids.
		If nothing is given all depots are taken into account.
		:type depotIds: [str, ]
		:param clientIds: Limit the search to the specified client ids.
		If nothing is given all depots are taken into account.
		:type clientIds: [str, ]
		:param masterOnly: If this is set to `True` only master depots are taken into account.
		:type masterOnly: bool
		:param productIds: Limit the data to the specified products if
		alternative depots are to be taken into account.
		:type productIds: [str,]
		:return: A list of dicts containing the keys `depotId` and
		`clientId` that belong to each other. If alternative depots are taken into the IDs of
		these depots are to be found in the list behind `alternativeDepotIds`.
		The key does always exist but may be empty.
		:rtype: [{"depotId": str, "alternativeDepotIds": [str, ], "clientId": str},]
		"""
		depotIds = depotIds or []
		clientIds = clientIds or []
		productIds = productIds or []

		depotIds = forceHostIdList(depotIds)
		productIds = forceProductIdList(productIds)

		depotIds = self.host_getIdents(type="OpsiDepotserver", id=depotIds)
		if not depotIds:
			return []
		depotIds = set(depotIds)  # type: ignore[assignment]

		clientIds = forceHostIdList(clientIds)
		clientIds = self.host_getIdents(type="OpsiClient", id=clientIds)
		if not clientIds:
			return []

		used_depot_ids = set()
		result = []

		for client_id, configs in self.configState_getValues(config_ids=["clientconfig.depot.id"], object_ids=clientIds).items():
			try:  # pylint: disable=loop-try-except-usage
				depotId = configs["clientconfig.depot.id"][0]
				if not depotId:
					raise IndexError("Missing value")  # pylint: disable=loop-invariant-statement
			except (KeyError, IndexError):
				logger.error("No depot server configured for client %s", client_id)
				continue

			if depotId not in depotIds:
				continue
			used_depot_ids.add(depotId)

			result.append({"depotId": depotId, "clientId": client_id, "alternativeDepotIds": []})

		if forceBool(masterOnly):
			return result

		po_depots_by_depot_id_and_product_id: dict[str, dict[str, ProductOnDepot]] = {}
		for pod in self.productOnDepot_getObjects(productId=productIds):  # pylint: disable=no-member
			try:  # pylint: disable=loop-try-except-usage
				po_depots_by_depot_id_and_product_id[pod.depotId][pod.productId] = pod
			except KeyError:
				po_depots_by_depot_id_and_product_id[pod.depotId] = {pod.productId: pod}

		p_hash = {}
		for (depotId, productOnDepotsByProductId) in po_depots_by_depot_id_and_product_id.items():
			product_string = [
				f"|{productId};{productOnDepotsByProductId[productId].productVersion};{productOnDepotsByProductId[productId].packageVersion}"
				for productId in sorted(productOnDepotsByProductId.keys())
			]

			p_hash[depotId] = "".join(product_string)

		for used_depot_id in used_depot_ids:
			p_string = p_hash.get(used_depot_id, "")
			alternative_depot_ids = [depotId for (depotId, ps) in p_hash.items() if depotId != used_depot_id and p_string == ps]

			for i, element in enumerate(result):
				if element["depotId"] == used_depot_id:
					result[i]["alternativeDepotIds"] = alternative_depot_ids

		return result
