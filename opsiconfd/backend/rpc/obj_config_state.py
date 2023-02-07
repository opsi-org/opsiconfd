# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.config_state
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.objects import ConfigState, ProductOnDepot  # type: ignore[import]
from opsicommon.types import (  # type: ignore[import]
	forceBool,
	forceHostIdList,
	forceList,
	forceObjectClass,
	forceObjectIdList,
	forceProductIdList,
	forceUnicodeList,
)

from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCConfigStateMixin(Protocol):
	@rpc_method(check_acl=False)
	def configState_getValues(  # pylint: disable=invalid-name
		self: BackendProtocol,
		config_ids: list[str] | str | None = None,
		object_ids: list[str] | str | None = None,
		with_defaults: bool = True,
	) -> dict[str, dict[str, list[Any]]]:
		config_ids = forceUnicodeList(config_ids or [])
		object_ids = forceObjectIdList(object_ids or [])
		res: dict[str, dict[str, list[Any]]] = {}
		if with_defaults:
			defaults = {c.id: c.defaultValues for c in self.config_getObjects(id=config_ids)}
			res = {h: defaults.copy() for h in self.host_getIdents(returnType="str", id=object_ids)}
		for config_state in self.configState_getObjects(configId=config_ids, objectId=object_ids):
			if config_state.objectId not in res:
				res[config_state.objectId] = {}
			res[config_state.objectId][config_state.configId] = config_state.values
		return res

	def configState_bulkInsertObjects(# pylint: disable=invalid-name
		self: BackendProtocol, configStates: list[dict] | list[ConfigState]
	) -> None:
		self._mysql.bulk_insert_objects(table="CONFIG_STATE", objs=configStates)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def configState_insertObject(self: BackendProtocol, configState: dict | ConfigState) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("configState_insertObject")
		configState = forceObjectClass(configState, ConfigState)
		self._mysql.insert_object(table="CONFIG_STATE", obj=configState, ace=ace, create=True, set_null=True)
		self.opsipxeconfd_config_states_updated(configState)
		self.dhcpd_control_config_states_updated(configState)

	@rpc_method(check_acl=False)
	def configState_updateObject(self: BackendProtocol, configState: dict | ConfigState) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("configState_updateObject")
		configState = forceObjectClass(configState, ConfigState)
		self._mysql.insert_object(table="CONFIG_STATE", obj=configState, ace=ace, create=False, set_null=False)
		self.opsipxeconfd_config_states_updated(configState)
		self.dhcpd_control_config_states_updated(configState)

	@rpc_method(check_acl=False)
	def configState_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, configStates: list[dict] | list[ConfigState] | dict | ConfigState
	) -> None:
		ace = self._get_ace("configState_createObjects")
		with self._mysql.session() as session:
			for config_state in forceList(configStates):
				config_state = forceObjectClass(config_state, ConfigState)
				self._mysql.insert_object(table="CONFIG_STATE", obj=config_state, ace=ace, create=True, set_null=True, session=session)
		self.opsipxeconfd_config_states_updated(configStates)
		self.dhcpd_control_config_states_updated(configStates)

	@rpc_method(check_acl=False)
	def configState_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, configStates: list[dict] | list[ConfigState] | dict | ConfigState
	) -> None:
		ace = self._get_ace("configState_updateObjects")
		with self._mysql.session() as session:
			for config_state in forceList(configStates):
				config_state = forceObjectClass(config_state, ConfigState)
				self._mysql.insert_object(table="CONFIG_STATE", obj=config_state, ace=ace, create=True, set_null=False, session=session)
		self.opsipxeconfd_config_states_updated(configStates)
		self.dhcpd_control_config_states_updated(configStates)

	@rpc_method(check_acl=False)
	def configState_getObjects(  # pylint: disable=redefined-builtin,invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any
	) -> list[ConfigState]:
		ace = self._get_ace("configState_getObjects")
		return self._mysql.get_objects(table="CONFIG_STATE", ace=ace, object_type=ConfigState, attributes=attributes, filter=filter)

	@rpc_method(check_acl=False)
	def configState_getHashes(  # pylint: disable=redefined-builtin,invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any
	) -> list[dict]:
		ace = self._get_ace("configState_getObjects")
		return self._mysql.get_objects(
			table="CONFIG_STATE", object_type=ConfigState, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def configState_getIdents(  # pylint: disable=invalid-name
		self: BackendProtocol, returnType: IdentType = "str", **filter: Any  # pylint: disable=redefined-builtin
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("configState_getObjects")
		return self._mysql.get_idents(table="CONFIG_STATE", object_type=ConfigState, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def configState_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, configStates: list[dict] | list[ConfigState] | dict | ConfigState
	) -> None:
		ace = self._get_ace("configState_deleteObjects")
		self._mysql.delete_objects(table="CONFIG_STATE", object_type=ConfigState, obj=configStates, ace=ace)
		self.opsipxeconfd_config_states_deleted(configStates)

	@rpc_method(check_acl=False)
	def configState_create(  # pylint: disable=invalid-name,unused-argument
		self: BackendProtocol, configId: str, objectId: str, values: list[Any] | None = None
	) -> None:
		_hash = locals()
		del _hash["self"]
		self.configState_createObjects(ConfigState.fromHash(_hash))

	@rpc_method(check_acl=False)
	def configState_delete(self: BackendProtocol, id: str) -> None:  # pylint: disable=redefined-builtin,invalid-name
		self.configState_deleteObjects(self.configState_getIdents(returnType="dict", id=id))

	@rpc_method(check_acl=False)
	def configState_getClientToDepotserver(  # pylint: disable=invalid-name,too-many-locals,too-many-branches
		self: BackendProtocol,
		depotIds: list[str] | None = None,  # pylint: disable=invalid-name
		clientIds: list[str] | None = None,  # pylint: disable=invalid-name
		masterOnly: bool = True,  # pylint: disable=invalid-name
		productIds: list[str] | None = None,  # pylint: disable=invalid-name
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

		config_server_id = self.host_getIdents(type="OpsiConfigserver")[0]

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

		for client_id, configs in self.configState_getValues(config_ids=["clientconfig.depot.id"], object_ids=list(clientIds)).items():
			try:
				depotId = configs["clientconfig.depot.id"][0]
				if not depotId:
					raise IndexError("Missing value")
			except (KeyError, IndexError):
				logger.error("No depot server configured for client %s", client_id)
				continue

			if depotId not in depotIds:
				continue
			used_depot_ids.add(depotId)

			result.append({"depotId": depotId, "clientId": client_id, "alternativeDepotIds": []})
			clientIds.remove(client_id)

		if clientIds:
			used_depot_ids.add(config_server_id)
			result += [{"depotId": config_server_id, "clientId": client_id, "alternativeDepotIds": []} for client_id in clientIds]

		if forceBool(masterOnly):
			return result

		po_depots_by_depot_id_and_product_id: dict[str, dict[str, ProductOnDepot]] = {}
		for pod in self.productOnDepot_getObjects(productId=productIds):  # pylint: disable=no-member
			try:
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
