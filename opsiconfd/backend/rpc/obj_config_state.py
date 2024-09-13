# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.backend.rpc.config_state
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any, Protocol

from opsicommon.exceptions import BackendPermissionDeniedError
from opsicommon.objects import ConfigState, ProductOnDepot
from opsicommon.types import (
	forceBool,
	forceHostIdList,
	forceObjectClass,
	forceObjectClassList,
	forceObjectIdList,
	forceProductIdList,
	forceUnicodeList,
)

from opsiconfd import contextvar_client_session
from opsiconfd.backend.auth import RPCACE
from opsiconfd.config import get_configserver_id
from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


class RPCConfigStateMixin(Protocol):
	@rpc_method(check_acl=False)
	def configState_getValues(
		self: BackendProtocol,
		config_ids: list[str] | str | None = None,
		object_ids: list[str] | str | None = None,
		with_defaults: bool = True,
	) -> dict[str, dict[str, list[Any]]]:
		config_ids = forceUnicodeList(config_ids or [])
		object_ids = forceObjectIdList(object_ids or [])
		session = contextvar_client_session.get()
		if not session:
			raise BackendPermissionDeniedError("Access denied")
		if session.host_type == "OpsiClient":
			if not session.host_id:
				raise BackendPermissionDeniedError("Access denied")
			object_ids = [session.host_id]

		res: dict[str, dict[str, list[Any]]] = {}
		if with_defaults:
			configserver_id = get_configserver_id()
			defaults = {c.id: c.defaultValues for c in self.config_getObjects(id=config_ids)}
			res = {h: defaults.copy() for h in self.host_getIdents(returnType="str", id=object_ids)}
			client_id_to_depot_id = {
				ctd.objectId: (ctd.values or [None])[0]
				for ctd in self._configState_getObjects(objectId=object_ids, configId="clientconfig.depot.id")
			}
			depot_values: dict[str, dict[str, list[Any]]] = defaultdict(lambda: defaultdict(list))
			depot_ids = list(set(client_id_to_depot_id.values()))
			depot_ids.append(configserver_id)
			if depot_ids:
				for config_state in self._configState_getObjects(configId=config_ids, objectId=depot_ids):
					depot_values[config_state.objectId][config_state.configId] = config_state.values or []
			for host_id in self.host_getIdents(returnType="str", id=object_ids):
				depot_id = client_id_to_depot_id.get(host_id)
				if depot_id and depot_id in depot_values:
					for cid, value in depot_values[depot_id].items():
						res[host_id][cid] = value
				elif not depot_id and configserver_id in depot_values:
					for cid, value in depot_values[configserver_id].items():
						res[host_id][cid] = value
		for config_state in self._configState_getObjects(configId=config_ids, objectId=object_ids):
			if config_state.objectId not in res:
				res[config_state.objectId] = {}
			res[config_state.objectId][config_state.configId] = config_state.values or []
		return res

	def configState_bulkInsertObjects(self: BackendProtocol, configStates: list[dict] | list[ConfigState]) -> None:
		self._mysql.bulk_insert_objects(table="CONFIG_STATE", objs=configStates)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def configState_insertObject(self: BackendProtocol, configState: dict | ConfigState) -> None:
		ace = self._get_ace("configState_insertObject")
		configState = forceObjectClass(configState, ConfigState)
		self._mysql.insert_object(table="CONFIG_STATE", obj=configState, ace=ace, create=True, set_null=True)
		if not self.events_enabled:
			return
		self._send_messagebus_event("configState_created", data=configState.getIdent("dict"))  # type: ignore[arg-type]
		self.opsipxeconfd_config_states_updated(configState)
		self.dhcpd_control_config_states_updated(configState)

	@rpc_method(check_acl=False)
	def configState_updateObject(self: BackendProtocol, configState: dict | ConfigState) -> None:
		ace = self._get_ace("configState_updateObject")
		configState = forceObjectClass(configState, ConfigState)
		self._mysql.insert_object(table="CONFIG_STATE", obj=configState, ace=ace, create=False, set_null=False)
		if not self.events_enabled:
			return
		self._send_messagebus_event("configState_updated", data=configState.getIdent("dict"))  # type: ignore[arg-type]
		self.opsipxeconfd_config_states_updated(configState)
		self.dhcpd_control_config_states_updated(configState)

	@rpc_method(check_acl=False)
	def configState_createObjects(self: BackendProtocol, configStates: list[dict] | list[ConfigState] | dict | ConfigState) -> None:
		ace = self._get_ace("configState_createObjects")
		configStates = forceObjectClassList(configStates, ConfigState)
		with self._mysql.session() as session:
			for config_state in configStates:
				config_state = forceObjectClass(config_state, ConfigState)
				self._mysql.insert_object(table="CONFIG_STATE", obj=config_state, ace=ace, create=True, set_null=True, session=session)
		if not self.events_enabled:
			return
		for configState in configStates:
			self._send_messagebus_event("configState_created", data=configState.getIdent("dict"))  # type: ignore[arg-type]
		self.opsipxeconfd_config_states_updated(configStates)
		self.dhcpd_control_config_states_updated(configStates)

	@rpc_method(check_acl=False)
	def configState_updateObjects(self: BackendProtocol, configStates: list[dict] | list[ConfigState] | dict | ConfigState) -> None:
		ace = self._get_ace("configState_updateObjects")
		configStates = forceObjectClassList(configStates, ConfigState)
		with self._mysql.session() as session:
			for config_state in configStates:
				config_state = forceObjectClass(config_state, ConfigState)
				self._mysql.insert_object(table="CONFIG_STATE", obj=config_state, ace=ace, create=True, set_null=False, session=session)
		if not self.events_enabled:
			return
		for configState in configStates:
			self._send_messagebus_event("configState_updated", data=configState.getIdent("dict"))  # type: ignore[arg-type]
		self.opsipxeconfd_config_states_updated(configStates)
		self.dhcpd_control_config_states_updated(configStates)

	def _configState_getObjects(
		self: BackendProtocol, ace: list[RPCACE] | None = None, attributes: list[str] | None = None, **filter: Any
	) -> list[ConfigState]:
		return self._mysql.get_objects(table="CONFIG_STATE", ace=ace or [], object_type=ConfigState, attributes=attributes, **filter)

	@rpc_method(check_acl=False)
	def configState_getObjects(self: BackendProtocol, attributes: list[str] | None = None, **filter: Any) -> list[ConfigState]:
		return self._configState_getObjects(ace=self._get_ace("configState_getObjects"), attributes=attributes, filter=filter)

	@rpc_method(deprecated=True, alternative_method="configState_getObjects", check_acl=False)
	def configState_getHashes(self: BackendProtocol, attributes: list[str] | None = None, **filter: Any) -> list[dict]:
		ace = self._get_ace("configState_getObjects")
		return self._mysql.get_objects(
			table="CONFIG_STATE", object_type=ConfigState, ace=ace, return_type="dict", attributes=attributes, filter=filter
		)

	@rpc_method(check_acl=False)
	def configState_getIdents(
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("configState_getObjects")
		return self._mysql.get_idents(table="CONFIG_STATE", object_type=ConfigState, ace=ace, ident_type=returnType, filter=filter)

	@rpc_method(check_acl=False)
	def configState_deleteObjects(self: BackendProtocol, configStates: list[dict] | list[ConfigState] | dict | ConfigState) -> None:
		if not configStates:
			return
		ace = self._get_ace("configState_deleteObjects")
		self._mysql.delete_objects(table="CONFIG_STATE", object_type=ConfigState, obj=configStates, ace=ace)
		if not self.events_enabled:
			return
		configStates = forceObjectClassList(configStates, ConfigState)
		for configState in configStates:
			self._send_messagebus_event("configState_deleted", data=configState.getIdent("dict"))  # type: ignore[arg-type]
		self.opsipxeconfd_config_states_deleted(configStates)

	@rpc_method(check_acl=False)
	def configState_create(self: BackendProtocol, configId: str, objectId: str, values: list[Any] | None = None) -> None:
		_hash = locals()
		del _hash["self"]
		self.configState_createObjects(ConfigState.fromHash(_hash))

	@rpc_method(check_acl=False)
	def configState_delete(self: BackendProtocol, configId: list[str] | str, objectId: list[str] | str) -> None:
		idents = self.configState_getIdents(returnType="dict", configId=configId, objectId=objectId)
		if idents:
			self.configState_deleteObjects(idents)

	@rpc_method(check_acl=False)
	def configState_getClientToDepotserver(
		self: BackendProtocol,
		depotIds: list[str] | None = None,
		clientIds: list[str] | None = None,
		masterOnly: bool = True,
		productIds: list[str] | None = None,
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

			clientIds.remove(client_id)
			if depotId not in depotIds:
				continue

			used_depot_ids.add(depotId)
			result.append({"depotId": depotId, "clientId": client_id, "alternativeDepotIds": []})

		if clientIds and (not depotIds or config_server_id in depotIds):
			used_depot_ids.add(config_server_id)
			result += [{"depotId": config_server_id, "clientId": client_id, "alternativeDepotIds": []} for client_id in clientIds]

		if forceBool(masterOnly):
			return result

		po_depots_by_depot_id_and_product_id: dict[str, dict[str, ProductOnDepot]] = {}
		for pod in self.productOnDepot_getObjects(productId=productIds):
			try:
				po_depots_by_depot_id_and_product_id[pod.depotId][pod.productId] = pod
			except KeyError:
				po_depots_by_depot_id_and_product_id[pod.depotId] = {pod.productId: pod}

		p_hash = {}
		for depotId, productOnDepotsByProductId in po_depots_by_depot_id_and_product_id.items():
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
