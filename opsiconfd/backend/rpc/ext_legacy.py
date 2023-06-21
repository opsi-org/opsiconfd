# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
rpc methods legacy
"""
# pylint: disable=too-many-lines

from __future__ import annotations

import re
import socket
import time
from collections import defaultdict
from typing import TYPE_CHECKING, Any, Generator, Protocol

from opsicommon.exceptions import (  # type: ignore[import]
	BackendAuthenticationError,
	BackendBadValueError,
	BackendConfigurationError,
	BackendMissingDataError,
	BackendUnaccomplishableError,
	LicenseConfigurationError,
)
from opsicommon.objects import (  # type: ignore[import]
	AuditHardwareOnHost,
	AuditSoftware,
	AuditSoftwareOnClient,
	AuditSoftwareToLicensePool,
	BoolConfig,
	BoolProductProperty,
	ConcurrentSoftwareLicense,
	ConfigState,
	ObjectToGroup,
	OEMSoftwareLicense,
	OpsiDepotserver,
	Product,
	ProductOnClient,
	ProductOnDepot,
	ProductPropertyState,
	RetailSoftwareLicense,
	UnicodeConfig,
	UnicodeProductProperty,
	VolumeSoftwareLicense,
)
from opsicommon.types import (  # type: ignore[import]
	forceBool,
	forceDomain,
	forceFqdn,
	forceHardwareAddress,
	forceHostId,
	forceHostname,
	forceObjectId,
	forceProductId,
	forceProductPropertyId,
	forceUnicodeList,
)

from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RPCExtLegacyMixin(Protocol):  # pylint: disable=too-many-public-methods
	def _hash_values_none_to_empty_string(self: BackendProtocol, _hash: dict) -> dict:
		for key, value in _hash.items():
			if value is None:
				_hash[key] = ""
		return _hash

	def _product_to_hash(self: BackendProtocol, product: Product) -> dict[str, Any]:
		result = product.toHash()
		result["productId"] = result["id"]
		del result["id"]
		if result["type"] == "LocalbootProduct":
			result["productType"] = "localboot"
		elif result["type"] == "NetbootProduct":
			result["productType"] = "netboot"
		else:
			raise BackendBadValueError(f"Unknown product type {result['type']}")
		del result["type"]
		return self._hash_values_none_to_empty_string(result)

	def _get_product_states_hash(
		self: BackendProtocol, client_ids: list[str] | None = None, product_type: str | None = None
	) -> dict[str, list]:
		client_ids = client_ids or []
		product_type = product_type or None

		result = defaultdict(list)

		modificationtime_regex = re.compile(r"^(\d\d\d\d)-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)$")
		for product_on_client in self.productOnClient_getObjects(clientId=client_ids, productType=product_type):
			last_state_change = product_on_client.modificationTime or ""

			match = modificationtime_regex.search(last_state_change)
			if match:
				last_state_change = f"{match.group(1)}{match.group(2)}{match.group(3)}{match.group(4)}{match.group(5)}{match.group(6)}"

			installation_status = product_on_client.installationStatus
			if product_on_client.actionResult == "failed":
				installation_status = "failed"
			elif installation_status == "unknown":
				installation_status = "not_installed"

			result[product_on_client.clientId].append(
				{
					"lastStateChange": last_state_change,
					"productVersion": product_on_client.productVersion or "",
					"packageVersion": product_on_client.packageVersion or "",
					"installationStatus": installation_status,
					"actionRequest": product_on_client.actionRequest,
					"productActionProgress": product_on_client.actionProgress or "",
					"productId": product_on_client.productId,
				}
			)

		return result

	@rpc_method(deprecated=True, alternative_method="backend_exit", check_acl=False)
	def exit(self: BackendProtocol) -> None:
		self.backend_exit()

	@rpc_method(deprecated=True, alternative_method="log_write", check_acl=False)
	def writeLog(  # pylint: disable=invalid-name
		self: BackendProtocol, type: str, data: str, objectId: str | None = None, append: bool = True  # pylint: disable=redefined-builtin
	) -> None:
		self.log_write(logType=type, data=data, objectId=objectId, append=append)

	@rpc_method(deprecated=True, alternative_method="log_read", check_acl=False)
	def readLog(  # pylint: disable=invalid-name
		self: BackendProtocol, type: str, objectId: str | None = None, maxSize: int = 0  # pylint: disable=redefined-builtin
	) -> str:
		return self.log_read(logType=type, objectId=objectId, maxSize=maxSize)

	@rpc_method(deprecated=True, alternative_method="backend_info", check_acl=False)
	def getOpsiInformation_hash(self: BackendProtocol) -> dict:  # pylint: disable=invalid-name
		return self.backend_info()

	@rpc_method(deprecated=True, alternative_method="dispatcher_getConfig", check_acl=False)
	def getBackendInfos_listOfHashes(self: BackendProtocol) -> list[dict]:  # pylint: disable=invalid-name
		return [{}]

	@rpc_method(deprecated=True, alternative_method="backend_getInterface", check_acl=False)
	def getPossibleMethods_listOfHashes(self: BackendProtocol) -> list[dict]:  # pylint: disable=invalid-name
		possible_methods = []
		for method in self.backend_getInterface():
			compatible = True
			for param in method["params"]:
				if param.startswith("**"):
					compatible = False
					break
			if compatible:
				possible_methods.append({"name": method["name"], "params": method["params"]})
		return possible_methods

	@rpc_method(deprecated=True, alternative_method="accessControl_authenticated", check_acl=False)
	def authenticated(self: BackendProtocol) -> bool:
		if self.accessControl_authenticated():
			return True
		raise BackendAuthenticationError("Not authenticated")

	@rpc_method(deprecated=True, alternative_method="configState_getObjects", check_acl=False)
	def getGeneralConfig_hash(self: BackendProtocol, objectId: str | None = None) -> dict[str, str]:  # pylint: disable=invalid-name
		if objectId:
			objectId = forceFqdn(objectId)
			if objectId in self.host_getIdents(type="OpsiDepotserver", returnType="unicode"):
				objectId = None

		if objectId:
			return {
				config_id: ",".join([str(v) for v in values])
				for config_id, values in self.configState_getValues(config_ids=[], object_ids=[objectId])[objectId].items()
			}
		return {config.id: ",".join([str(v) for v in config.defaultValues]) for config in self.config_getObjects()}

	@rpc_method(deprecated=True, alternative_method="configState_getObjects", check_acl=False)
	def getGeneralConfigValue(self: BackendProtocol, key: str, objectId: str | None = None) -> str:  # pylint: disable=invalid-name
		return self.getGeneralConfig_hash(objectId=objectId).get(key)

	@rpc_method(deprecated=True, alternative_method="configState_create", check_acl=False)
	def setGeneralConfig(  # pylint: disable=invalid-name
		self: BackendProtocol, config: dict[str, str], objectId: str | None = None
	) -> None:
		if objectId:
			objectId = forceFqdn(objectId)
			if objectId in self.host_getIdents(type="OpsiDepotserver", returnType="unicode"):
				objectId = None
			elif objectId not in self.host_getIdents(type="OpsiClient", returnType="unicode"):
				raise BackendMissingDataError(f"Object {objectId!r} not found in Backend")
		else:
			objectId = None

		known_config_ids = frozenset(self.config_getIdents(returnType="unicode"))
		for config_id in known_config_ids:
			if config_id not in config:
				self.config_delete(id=config_id)

		bool_values = frozenset(["yes", "no", "on", "off", "1", "0", "true", "false"])

		def get_new_configs() -> Generator[BoolConfig | UnicodeConfig, None, None]:
			has_no_object_id = bool(objectId is None)
			for config_id, value in config.items():
				if has_no_object_id or config_id not in known_config_ids:
					if value.lower() in bool_values:
						yield BoolConfig(id=config_id, defaultValues=[forceBool(value)])
					else:
						yield UnicodeConfig(id=config_id, defaultValues=[value], possibleValues=[value], editable=True, multiValue=False)

		def get_new_config_states() -> Generator[ConfigState, None, None]:
			if objectId is not None:
				for config_id, value in config.items():
					if value.lower() in bool_values:
						yield ConfigState(configId=config_id, objectId=objectId, values=[forceBool(value)])
					else:
						yield ConfigState(configId=config_id, objectId=objectId, values=[value])

		self.config_createObjects(get_new_configs())
		self.configState_createObjects(get_new_config_states())

	@rpc_method(deprecated=True, alternative_method="configState_create", check_acl=False)
	def setGeneralConfigValue(  # pylint: disable=invalid-name
		self: BackendProtocol, key: str, value: str, objectId: str | None = None
	) -> None:
		general_config = self.getGeneralConfig_hash(objectId=objectId)
		general_config[key] = value
		return self.setGeneralConfig(general_config, objectId=objectId)

	@rpc_method(deprecated=True, alternative_method="configState_delete", check_acl=False)
	def deleteGeneralConfig(self: BackendProtocol, objectId: str) -> None:  # pylint: disable=invalid-name
		return self.configState_delete(configId=[], objectId=forceObjectId(objectId))

	@rpc_method(deprecated=True, alternative_method="configState_create", check_acl=False)
	def setNetworkConfig(  # pylint: disable=invalid-name
		self: BackendProtocol, config: dict[str, str], objectId: str | None = None
	) -> None:
		if objectId and "depotId" in config:
			return self.setGeneralConfigValue("clientconfig.depot.id", config["depotId"], objectId)
		raise NotImplementedError("Please use general config to change values")

	@rpc_method(deprecated=True, check_acl=False)
	def getNetworkConfig_hash(self: BackendProtocol, objectId: str | None = None) -> dict[str, str]:  # pylint: disable=invalid-name
		config_server_idents = self.host_getIdents(type="OpsiConfigserver", returnType="unicode")
		if not config_server_idents:
			raise BackendMissingDataError("No configserver found")

		depot_id = self.getGeneralConfigValue("clientconfig.depot.id", objectId=objectId)

		depots = self.host_getObjects(type="OpsiDepotserver", id=depot_id)
		if not depots:
			raise BackendMissingDataError(f"Depotserver '{depot_id}' not found")

		depot_drive = self.getGeneralConfigValue("clientconfig.depot.drive", objectId=objectId)
		depot_url = depots[0].getDepotRemoteUrl()

		return {
			"opsiServer": config_server_idents[0],
			"nextBootServiceURL": self.getGeneralConfigValue("clientconfig.configserver.url", objectId=objectId),
			"nextBootServerType": "service",
			"depotId": depot_id,
			"depotUrl": depot_url,
			"depotDrive": depot_drive,
			"configUrl": depot_url.replace("/install", "/pcpatch"),
			"configDrive": depot_drive,
			"utilsUrl": depot_url.replace("/install", "/utils"),
			"utilsDrive": depot_drive,
			"winDomain": self.getGeneralConfigValue("clientconfig.windows.domain", objectId=objectId),
		}

	@rpc_method(deprecated=True, check_acl=False)
	def getNetworkConfigValue(self: BackendProtocol, key: str, objectId: str | None = None) -> str:  # pylint: disable=invalid-name
		return self.getNetworkConfig_hash(objectId).get(key)

	@rpc_method(deprecated=True, alternative_method="group_getIdents", check_acl=False)
	def getGroupIds_list(self: BackendProtocol) -> list[str]:  # pylint: disable=invalid-name
		return self.group_getIdents(returnType="unicode")

	@rpc_method(deprecated=True, check_acl=False)
	def getHostGroupTree_hash(self: BackendProtocol) -> dict:  # pylint: disable=invalid-name
		groups: dict[str, dict] = {}
		childs: dict[str, dict] = {}
		for group in self.group_getObjects(attributes=["id", "parentGroupId"]):
			if group.getParentGroupId():
				if group.getParentGroupId() not in childs:
					childs[group.getParentGroupId()] = {}
				childs[group.getParentGroupId()][group.getId()] = {}
			else:
				groups[group.getId()] = {}

		def insert_group(_group_id: str, _group: dict, _groups: dict) -> bool:
			if _group_id in _groups:
				_groups[_group_id] = _group
				return True
			for _gid in list(_groups):
				if insert_group(_group_id, _group, _groups[_gid]):
					return True
			return False

		while list(childs):
			left = len(childs)
			for group_id in list(childs):
				if insert_group(group_id, childs[group_id], groups):
					del childs[group_id]
			if left == len(childs):
				raise BackendUnaccomplishableError("Error in host groups")
		return groups

	@rpc_method(deprecated=True, alternative_method="group_create", check_acl=False)
	def createGroup(  # pylint: disable=invalid-name
		self: BackendProtocol, groupId: str, members: list[str] | None = None, description: str = "", parentGroupId: str = ""
	) -> None:
		members = members or []
		self.group_createHostGroup(id=groupId, description=description, notes="", parentGroupId=parentGroupId or None)
		objects = [ObjectToGroup(groupType="HostGroup", groupId=groupId, objectId=member) for member in members]
		self.objectToGroup_createObjects(objects)

	@rpc_method(deprecated=True, check_acl=False)
	def getHostId(self: BackendProtocol, hostname: str) -> str:  # pylint: disable=invalid-name
		if not hostname:
			raise ValueError("Hostname required")
		return f"{hostname}.{self.getDomain()}"

	@rpc_method(deprecated=True, alternative_method="hostControl_start", check_acl=False)
	def powerOnHost(self: BackendProtocol, hostId: str) -> dict[str, Any]:  # pylint: disable=invalid-name
		return self.hostControl_start(hostId)

	@rpc_method(deprecated=True, alternative_method="host_getObjects", check_acl=False)
	def getIpAddress(self: BackendProtocol, hostId: str) -> str:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		hosts = self.host_getObjects(attributes=["ipAddress"], id=hostId)
		if not hosts:
			raise BackendMissingDataError(f"Host {hostId!r} not found")
		return hosts[0].getIpAddress() or ""

	@rpc_method(deprecated=True, alternative_method="host_createOpsiClient", check_acl=False)
	def createClient(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		clientName: str,
		domain: str,
		description: str | None = None,
		notes: str | None = None,
		ipAddress: str | None = None,
		hardwareAddress: str | None = None,
	) -> str:
		ipAddress = ipAddress or None
		hardwareAddress = hardwareAddress or None

		client_id = forceHostId(f"{forceHostname(clientName)}.{forceDomain(domain)}")
		self.host_createOpsiClient(id=client_id, description=description, notes=notes, ipAddress=ipAddress, hardwareAddress=hardwareAddress)
		return client_id

	@rpc_method(deprecated=True, alternative_method="host_updateObject", check_acl=False)
	def setHostDescription(self: BackendProtocol, hostId: str, description: str) -> None:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		hosts = self.host_getObjects(id=hostId)
		if not hosts:
			raise BackendMissingDataError(f"Host '{hostId}' not found")
		hosts[0].setDescription(description)
		self.host_updateObject(hosts[0])

	@rpc_method(deprecated=True, alternative_method="host_updateObject", check_acl=False)
	def setHostNotes(self: BackendProtocol, hostId: str, notes: str) -> None:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		hosts = self.host_getObjects(id=hostId)
		if not hosts:
			raise BackendMissingDataError(f"Host '{hostId}' not found")
		hosts[0].setNotes(notes)
		self.host_updateObject(hosts[0])

	@rpc_method(deprecated=True, alternative_method="auditSoftwareOnClient_getObjects", check_acl=False)
	def getSoftwareInformation_hash(self: BackendProtocol, hostId: str) -> dict:  # pylint: disable=invalid-name
		audit_softwares: dict[str, dict[str, dict[str, dict[str, dict[str, AuditSoftware]]]]] = defaultdict(
			lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))
		)
		for aus in self.auditSoftware_getObjects():
			audit_softwares[aus.name][aus.version][aus.subVersion][aus.language][aus.architecture] = aus

		keys_to_remove = ("clientId", "name", "version", "subVersion", "language", "architecture", "state", "firstseen", "lastseen")
		result = {}
		scantime = time.strptime("2000-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")

		for audit_software_on_client in self.auditSoftwareOnClient_getObjects(clientId=hostId):
			lastseen = time.strptime(audit_software_on_client.getLastseen(), "%Y-%m-%d %H:%M:%S")
			scantime = max(lastseen, scantime)
			try:
				aus = audit_softwares[audit_software_on_client.name][audit_software_on_client.version][audit_software_on_client.subVersion][
					audit_software_on_client.language
				][audit_software_on_client.architecture]
			except KeyError:
				logger.error(
					"No auditSoftwares found with filter: "
					'{"name": %s, "version": %s, "subVersion": %s, "language": %s, "architecture": %s}',
					audit_software_on_client.getName(),
					audit_software_on_client.getVersion(),
					audit_software_on_client.getSubVersion(),
					audit_software_on_client.getLanguage(),
					audit_software_on_client.getArchitecture(),
				)
				continue

			_hash = audit_software_on_client.toHash()
			_hash["softwareId"] = aus.getWindowsSoftwareId()
			_hash["displayName"] = aus.getWindowsDisplayName()
			_hash["displayVersion"] = aus.getWindowsDisplayVersion()
			_hash["installSize"] = aus.getInstallSize()

			for key_to_remove in keys_to_remove:
				del _hash[key_to_remove]

			if aus.getWindowsSoftwareId():
				result[aus.getWindowsSoftwareId()] = self._hash_values_none_to_empty_string(_hash)

		result["SCANPROPERTIES"] = {"scantime": time.strftime("%Y-%m-%d %H:%M:%S", scantime)}
		return result

	@rpc_method(deprecated=True, alternative_method="auditSoftwareOnClient_getObjects", check_acl=False)
	def getSoftwareInformation_listOfHashes(self: BackendProtocol) -> list[dict]:  # pylint: disable=invalid-name
		result = []
		for audit_software in self.auditSoftware_getObjects():
			_hash = audit_software.toHash()
			_hash["displayName"] = _hash["windowsDisplayName"]
			_hash["displayVersion"] = _hash["windowsDisplayVersion"]

			for key in ("windowsDisplayName", "windowsDisplayVersion", "type", "name", "architecture", "language", "version", "subVersion"):
				del _hash[key]

			_hash["installSize"] = _hash["installSize"] or 0
			_hash["uninstallString"] = ""
			_hash["binaryName"] = ""
			_hash["installedOn"] = []
			for audit_software_on_client in self.auditSoftwareOnClient_getObjects(
				name=audit_software.getName(),
				version=audit_software.getVersion(),
				subVersion=audit_software.getSubVersion(),
				language=audit_software.getLanguage(),
				architecture=audit_software.getArchitecture(),
			):
				if audit_software_on_client.getUninstallString():
					_hash["uninstallString"] = audit_software_on_client.getUninstallString()
				if audit_software_on_client.getBinaryName():
					_hash["binaryName"] = audit_software_on_client.getBinaryName()
				_hash["installedOn"].append(audit_software_on_client.getClientId())
			_hash["installationCount"] = len(_hash["installedOn"])
			result.append(_hash)
		return result

	@rpc_method(deprecated=True, alternative_method="auditSoftwareOnClient_updateObjects", check_acl=False)
	def setSoftwareInformation(self: BackendProtocol, hostId: str, info: dict) -> None:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		self.auditSoftwareOnClient_delete(name=[], version=[], subVersion=[], language=[], architecture=[], clientId=hostId)

		for windows_software_id, value in info.items():
			if windows_software_id == "SCANPROPERTIES":
				continue

			audit_software = {
				"name": "",
				"version": "",
				"subVersion": "",
				"language": "",
				"architecture": "x86",
				"windowsSoftwareId": windows_software_id,
				"windowsDisplayName": "",
				"windowsDisplayVersion": "",
				"installSize": -1,
			}
			audit_software_on_client = {
				"clientId": hostId,
				"uninstallString": "",
				"binaryName": "",
				"usageFrequency": -1,
				"lastUsed": None,
			}
			for key, val in value.items():
				if key.lower() == "displayname":
					audit_software["name"] = audit_software["windowsDisplayName"] = val
				elif key.lower() == "displayversion":
					audit_software["version"] = audit_software["windowsDisplayVersion"] = val
				elif key.lower() == "installsize":
					audit_software["installSize"] = val
				else:
					for akey in list(audit_software_on_client):
						if key.lower() == akey.lower():
							audit_software_on_client[key] = val
							break

			audit_software["name"] = audit_software["name"] or audit_software["windowsSoftwareId"]
			audit_software_on_client["name"] = audit_software["name"]
			audit_software_on_client["version"] = audit_software["version"]
			audit_software_on_client["subVersion"] = audit_software["subVersion"]
			audit_software_on_client["language"] = audit_software["language"]
			audit_software_on_client["architecture"] = audit_software["architecture"]

			self.auditSoftware_createObjects(AuditSoftware.fromHash(audit_software))
			self.auditSoftwareOnClient_createObjects(AuditSoftwareOnClient.fromHash(audit_software_on_client))

	@rpc_method(deprecated=True, alternative_method="auditSoftwareOnClient_delete", check_acl=False)
	def deleteSoftwareInformation(self: BackendProtocol, hostId: str) -> None:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		self.auditSoftwareOnClient_delete(clientId=hostId, name=[], version=[], subVersion=[], language=[], architecture=[])

	@rpc_method(deprecated=True, alternative_method="auditHardware_getConfig", check_acl=False)
	def getOpsiHWAuditConf(self: BackendProtocol, locale: str | None = None) -> list:  # pylint: disable=invalid-name
		return self.auditHardware_getConfig(locale)

	@rpc_method(deprecated=True, alternative_method="auditHardwareOnHost_getObjects", check_acl=False)
	def getHardwareInformation_hash(self: BackendProtocol, hostId: str) -> dict:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		info: dict[str, list[dict[str, Any]]] = {}
		scantime = time.strptime("2000-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
		for audit_hardware_on_host in self.auditHardwareOnHost_getObjects(hostId=hostId, state=1):
			hardware_class = audit_hardware_on_host.getHardwareClass()
			if hardware_class not in info:
				info[hardware_class] = []
			data = audit_hardware_on_host.toHash()
			lastseen = time.strptime(str(data["lastseen"]), "%Y-%m-%d %H:%M:%S")
			scantime = max(scantime, lastseen)
			for key in ("hardwareClass", "hostId", "firstseen", "state", "lastseen"):
				del data[key]
			info[hardware_class].append(data)

		info["SCANPROPERTIES"] = [{"scantime": time.strftime("%Y-%m-%d %H:%M:%S", scantime)}]
		return info

	@rpc_method(deprecated=True, alternative_method="auditHardwareOnHost_updateObjects", check_acl=False)
	def setHardwareInformation(self: BackendProtocol, hostId: str, info: dict) -> None:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		self.auditHardwareOnHost_setObsolete(hostId)
		audit_hardware_on_hosts = []
		for hardware_class, devices in info.items():
			if hardware_class == "SCANPROPERTIES":
				continue

			for device in devices:
				data = {str(attribute): value for attribute, value in device.items()}
				data["hardwareClass"] = hardware_class
				data["hostId"] = hostId
				audit_hardware_on_hosts.append(AuditHardwareOnHost.fromHash(data))
		self.auditHardwareOnHost_updateObjects(audit_hardware_on_hosts)

	@rpc_method(deprecated=True, alternative_method="auditHardwareOnHost_delete", check_acl=False)
	def deleteHardwareInformation(self: BackendProtocol, hostId: str) -> None:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		self.auditHardwareOnHost_delete(hostId=hostId, hardwareClass=[])

	@rpc_method(deprecated=True, alternative_method="host_getObject", check_acl=False)
	def getHost_hash(self: BackendProtocol, hostId: str) -> dict:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		hosts = self.host_getObjects(id=hostId)
		if not hosts:
			raise BackendMissingDataError(f"Host {hostId!r} not found")
		_hash = hosts[0].toHash()
		_hash["hostId"] = _hash["id"]

		timestamp_regex = re.compile(r"^(\d\d\d\d)-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)$")
		match = timestamp_regex.search(_hash.get("created", ""))
		if match:
			_hash["created"] = f"{match.group(1)}{match.group(2)}{match.group(3)}{match.group(4)}{match.group(5)}{match.group(6)}"
		match = timestamp_regex.search(_hash.get("lastSeen", ""))
		if match:
			_hash["lastSeen"] = f"{match.group(1)}{match.group(2)}{match.group(3)}{match.group(4)}{match.group(5)}{match.group(6)}"
		del _hash["type"]
		del _hash["id"]
		return self._hash_values_none_to_empty_string(_hash)

	@rpc_method(deprecated=True, alternative_method="host_getIdents", check_acl=False)
	def getClientIdByMac(self: BackendProtocol, mac: str) -> str:  # pylint: disable=invalid-name
		hosts = self.host_getObjects(attributes=["id"], type="OpsiClient", hardwareAddress=forceHardwareAddress(mac))
		if not hosts:
			return ""
		return hosts[0].id

	@rpc_method(deprecated=True, alternative_method="host_getIdents", check_acl=False)
	def getServerIds_list(self: BackendProtocol) -> list[str]:  # pylint: disable=invalid-name
		return self.host_getIdents(type="OpsiConfigserver")

	@rpc_method(deprecated=True, alternative_method="host_getIdents", check_acl=False)
	def getServerId(self: BackendProtocol, clientId: str) -> str:  # pylint: disable=invalid-name
		return self.host_getIdents(type="OpsiConfigserver")[0]

	@rpc_method(deprecated=True, alternative_method="host_createOpsiDepotserver", check_acl=False)
	def createDepot(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		depotName: str,
		domain: str,
		depotLocalUrl: str,
		depotRemoteUrl: str,
		repositoryLocalUrl: str,
		repositoryRemoteUrl: str,
		network: str,
		description: str | None = None,
		notes: str | None = None,
		maxBandwidth: int = 0,
	) -> str:
		depot_id = forceHostId(forceHostname(depotName) + "." + forceDomain(domain))
		self.host_createOpsiDepotserver(
			id=depot_id,
			depotLocalUrl=depotLocalUrl,
			depotRemoteUrl=depotRemoteUrl,
			repositoryLocalUrl=repositoryLocalUrl,
			repositoryRemoteUrl=repositoryRemoteUrl,
			description=description,
			notes=notes,
			hardwareAddress=None,
			ipAddress=None,
			networkAddress=network,
			maxBandwidth=maxBandwidth,
		)
		return depot_id

	@rpc_method(deprecated=True, alternative_method="host_getIdents", check_acl=False)
	def getDepotIds_list(self: BackendProtocol) -> list[str]:  # pylint: disable=invalid-name
		return self.host_getIdents(type="OpsiDepotserver", isMasterDepot=True)

	@rpc_method(deprecated=True, alternative_method="host_getObjects", check_acl=False)
	def getDepot_hash(self: BackendProtocol, depotId: str) -> dict:  # pylint: disable=invalid-name
		depotId = forceHostId(depotId)
		depots = self.host_getObjects(id=depotId)
		if not depots:
			raise BackendMissingDataError(f"Depot {depotId!r} not found")
		_hash = depots[0].toHash()
		del _hash["type"]
		if not _hash["ipAddress"]:
			try:
				_hash["ipAddress"] = socket.gethostbyname(depotId)
			except Exception as err:  # pylint: disable=broad-except
				logger.debug("Failed to get host by name (%s): %s", depotId, err)
		_hash["ip"] = _hash["ipAddress"]
		return self._hash_values_none_to_empty_string(_hash)

	@rpc_method(deprecated=False, alternative_method="configState_getClientToDepotserver", check_acl=False)
	def getDepotId(self: BackendProtocol, clientId: str) -> str:  # pylint: disable=invalid-name
		clientId = forceHostId(clientId)

		for client_to_depotserver in self.configState_getClientToDepotserver(clientIds=clientId):
			if client_to_depotserver["clientId"] == clientId:
				return client_to_depotserver["depotId"]
		raise BackendConfigurationError(f"Failed to get depot server for client {clientId!r}")

	@rpc_method(deprecated=True, alternative_method="host_getObject", check_acl=False)
	def getOpsiHostKey(self: BackendProtocol, hostId: str) -> str:  # pylint: disable=invalid-name
		if not hostId:
			raise ValueError("No host id given")
		hostId = forceHostId(hostId)
		hosts = self.host_getObjects(attributes=["opsiHostKey"], id=hostId)
		if not hosts:
			raise BackendMissingDataError(f"Host {hostId!r} not found")
		return hosts[0].opsiHostKey

	@rpc_method(deprecated=True, alternative_method="host_updateObject", check_acl=False)
	def setOpsiHostKey(self: BackendProtocol, hostId: str, opsiHostKey: str) -> None:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		hosts = self.host_getObjects(id=hostId)
		if not hosts:
			raise BackendMissingDataError(f"Host {hostId!r} not found")
		hosts[0].setOpsiHostKey(opsiHostKey)
		self.host_updateObject(hosts[0])

	@rpc_method(deprecated=True, alternative_method="host_getObject", check_acl=False)
	def getMacAddresses_list(self: BackendProtocol, hostId: str) -> list[str]:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		hosts = self.host_getObjects(id=hostId)
		if not hosts:
			raise BackendMissingDataError(f"Host {hostId!r} not found")
		if not hosts[0].hardwareAddress:
			return [""]
		return [hosts[0].hardwareAddress]

	@rpc_method(deprecated=True, alternative_method="host_updateObject", check_acl=False)
	def setMacAddresses(self: BackendProtocol, hostId: str, macs: list[str]) -> None:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		hosts = self.host_getObjects(id=hostId)
		if not hosts:
			raise BackendMissingDataError(f"Host {hostId!r} not found")
		hosts[0].setHardwareAddress(macs[0])
		self.host_updateObject(hosts[0])

	@rpc_method(deprecated=True, alternative_method="host_getObject", check_acl=False)
	def getMacAddress(self: BackendProtocol, hostId: str) -> str:  # pylint: disable=invalid-name
		return self.getMacAddresses_list(hostId)[0]

	@rpc_method(deprecated=True, alternative_method="host_updateObject", check_acl=False)
	def setMacAddress(self: BackendProtocol, hostId: str, mac: str) -> None:  # pylint: disable=invalid-name
		self.setMacAddresses(hostId, macs=[mac])

	@rpc_method(deprecated=True, alternative_method="productOnDepot_updateObjects", check_acl=False)
	def lockProduct(self: BackendProtocol, productId: str, depotIds: list[str] | None = None) -> None:  # pylint: disable=invalid-name
		depotIds = depotIds or []
		product_on_depots = self.productOnDepot_getObjects(productId=productId, depotId=depotIds)
		if not product_on_depots:
			raise BackendMissingDataError(f"Product {productId!r} not found on given depots")
		for product_on_depot in product_on_depots:
			product_on_depot.setLocked(True)
		self.productOnDepot_updateObjects(product_on_depots)

	@rpc_method(deprecated=True, alternative_method="productOnDepot_updateObjects", check_acl=False)
	def unlockProduct(self: BackendProtocol, productId: str, depotIds: list[str] | None = None) -> None:  # pylint: disable=invalid-name
		depotIds = depotIds or []
		product_on_depots = self.productOnDepot_getObjects(productId=productId, depotId=depotIds)
		if not product_on_depots:
			raise BackendMissingDataError(f"Product {productId!r} not found on given depots")
		for product_on_depot in product_on_depots:
			product_on_depot.setLocked(False)
		self.productOnDepot_updateObjects(product_on_depots)

	@rpc_method(deprecated=True, alternative_method="productOnDepot_getObjects", check_acl=False)
	def getProductLocks_hash(  # pylint: disable=invalid-name
		self: BackendProtocol, depotIds: list[str] | None = None  # pylint: disable=invalid-name
	) -> dict[str, list[str]]:
		result: dict[str, list[str]] = {}
		for product_on_depot in self.productOnDepot_getObjects(depotId=depotIds, locked=True):
			if product_on_depot.productId not in result:
				result[product_on_depot.productId] = []
			result[product_on_depot.productId].append(product_on_depot.depotId)
		return result

	@rpc_method(deprecated=True, alternative_method="product_insertObject", check_acl=False)
	def createProduct(  # pylint: disable=invalid-name,too-many-arguments,too-many-locals
		self: BackendProtocol,
		productType: str,
		productId: str,
		name: str,
		productVersion: str,
		packageVersion: str,
		licenseRequired: bool = False,
		setupScript: str = "",
		uninstallScript: str = "",
		updateScript: str = "",
		alwaysScript: str = "",
		onceScript: str = "",
		priority: int = 0,
		description: str = "",
		advice: str = "",
		productClassNames: list[str] | None = None,
		pxeConfigTemplate: str = "",
		windowsSoftwareIds: list[str] | None = None,
		depotIds: list[str] | None = None,
	) -> None:
		product_dict = locals()
		del product_dict["productType"]
		del product_dict["depotIds"]
		del product_dict["self"]
		product_dict["id"] = product_dict["productId"]
		del product_dict["productId"]

		product = Product.fromHash(product_dict)
		self.product_createObjects(product_dict)

		depotIds = depotIds or self.host_getIdents(type="OpsiDepotserver")
		product_on_depots = [
			ProductOnDepot(
				productId=product.id,
				productType=product.getType(),
				productVersion=product.productVersion,
				packageVersion=product.packageVersion,
				depotId=depot_id,
			)
			for depot_id in depotIds
		]
		self.productOnDepot_createObjects(product_on_depots)

	@rpc_method(deprecated=True, alternative_method="product_insertObject", check_acl=False)
	def createLocalBootProduct(  # pylint: disable=invalid-name,too-many-arguments,too-many-locals
		self: BackendProtocol,
		productId: str,
		name: str,
		productVersion: str,
		packageVersion: str,
		licenseRequired: bool = False,
		setupScript: str = "",
		uninstallScript: str = "",
		updateScript: str = "",
		alwaysScript: str = "",
		onceScript: str = "",
		priority: int = 0,
		description: str = "",
		advice: str = "",
		productClassNames: list[str] | None = None,
		windowsSoftwareIds: list[str] | None = None,
		depotIds: list[str] | None = None,
	) -> None:
		self.createProduct(
			"localboot",
			productId,
			name,
			productVersion,
			packageVersion,
			licenseRequired,
			setupScript,
			uninstallScript,
			updateScript,
			alwaysScript,
			onceScript,
			priority,
			description,
			advice,
			productClassNames,
			"",
			windowsSoftwareIds,
			depotIds,
		)

	@rpc_method(deprecated=True, alternative_method="product_insertObject", check_acl=False)
	def createNetBootProduct(  # pylint: disable=invalid-name,too-many-arguments,too-many-locals
		self: BackendProtocol,
		productId: str,
		name: str,
		productVersion: str,
		packageVersion: str,
		licenseRequired: bool = False,
		setupScript: str = "",
		uninstallScript: str = "",
		updateScript: str = "",
		alwaysScript: str = "",
		onceScript: str = "",
		priority: int = 0,
		description: str = "",
		advice: str = "",
		productClassNames: list[str] | None = None,
		pxeConfigTemplate: str = "",
		windowsSoftwareIds: list[str] | None = None,
		depotIds: list[str] | None = None,
	) -> None:
		self.createProduct(
			"netboot",
			productId,
			name,
			productVersion,
			packageVersion,
			licenseRequired,
			setupScript,
			uninstallScript,
			updateScript,
			alwaysScript,
			onceScript,
			priority,
			description,
			advice,
			productClassNames,
			pxeConfigTemplate,
			windowsSoftwareIds,
			depotIds,
		)

	@rpc_method(deprecated=True, alternative_method="product_getObjects", check_acl=False)
	def getProduct_hash(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str, depotId: str | None = None  # pylint: disable=invalid-name
	) -> dict[str, Any]:
		if not depotId:
			products = self.product_getObjects(id=productId)
			if not products:
				raise BackendMissingDataError(f"No product with id {productId!r} found")
			return self._product_to_hash(products[0])

		product_on_depot = self.productOnDepot_getObjects(productId=productId, depotId=depotId)
		if not product_on_depot:
			raise BackendMissingDataError(f"No product with id {productId!r} on depot {depotId!r} found")
		product_on_depot = product_on_depot[0]
		products = self.product_getObjects(
			id=product_on_depot.productId, productVersion=product_on_depot.productVersion, packageVersion=product_on_depot.packageVersion
		)
		if not products:
			raise BackendMissingDataError(
				f"Product with id {product_on_depot.productId!r}, "
				f"productVersion {product_on_depot.productVersion!r}, "
				f"packageVersion {product_on_depot.packageVersion!r} not found"
			)
		return self._product_to_hash(products[0])

	@rpc_method(deprecated=True, alternative_method="product_getObjects", check_acl=False)
	def getProducts_hash(  # pylint: disable=invalid-name
		self: BackendProtocol, depotIds: list[str] | None = None
	) -> dict[str, dict[str, dict[str, Any]]]:
		depotIds = depotIds or self.getDepotIds_list()
		none_product = Product(id="", productVersion="", packageVersion="")
		products: dict[str, dict[str, dict[str, Product]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: none_product)))
		for product in self.product_getObjects():
			products[product.id][product.productVersion][product.packageVersion] = product

		result: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
		for product_on_depot in self.productOnDepot_getObjects(depotId=depotIds):
			product = products[product_on_depot.productId][product_on_depot.productVersion][product_on_depot.packageVersion]

			if not product:
				raise BackendMissingDataError(
					f"Product with id {product_on_depot.productId!r}, "
					f"productVersion {product_on_depot.productVersion!r}, "
					f"packageVersion {product_on_depot.packageVersion!r} not found"
				)
			result[product_on_depot.depotId][product_on_depot.productId] = self._product_to_hash(product)

		return result

	@rpc_method(deprecated=True, alternative_method="product_getObjects", check_acl=False)
	def getProducts_listOfHashes(self: BackendProtocol, depotId: str | None = None) -> list[dict[str, Any]]:  # pylint: disable=invalid-name
		if not depotId:
			return [self._product_to_hash(product) for product in self.product_getObjects()]

		result = []
		for products in self.getProducts_hash(depotIds=[depotId]).values():
			for product_hash in products.values():
				result.append(product_hash)
		return result

	@rpc_method(deprecated=True, alternative_method="product_getIdents", check_acl=False)
	def getProductIds_list(  # pylint: disable=invalid-name
		self: BackendProtocol, productType: str | None = None, objectId: str | None = None, installationStatus: str | None = None
	) -> list[str]:
		productType = productType or None
		objectId = objectId or None
		installationStatus = installationStatus or None

		product_type = None
		if productType == "localboot":
			product_type = "LocalbootProduct"
		elif productType == "netboot":
			product_type = "NetbootProduct"

		if objectId:
			objectId = forceHostId(objectId)
			hosts = self.host_getObjects(id=objectId)
			if not hosts:
				raise BackendMissingDataError(f"Host {objectId!r} not found")

			if isinstance(hosts[0], OpsiDepotserver):
				return [
					ident["productId"]
					for ident in self.productOnDepot_getIdents(productType=product_type, depotId=hosts[0].getId(), returnType="dict")
				]

			return [
				ident["productId"]
				for ident in self.productOnClient_getIdents(
					productType=product_type, clientId=hosts[0].getId(), installationStatus=installationStatus or [], returnType="dict"
				)
			]

		return list({ident["id"] for ident in self.product_getIdents(type=product_type, returnType="dict")})

	@rpc_method(deprecated=True, alternative_method="product_getIdents", check_acl=False)
	def getLocalBootProductIds_list(  # pylint: disable=invalid-name
		self: BackendProtocol, objectId: str | None = None, installationStatus: str | None = None
	) -> list[str]:
		return self.getProductIds_list("localboot", objectId, installationStatus)

	@rpc_method(deprecated=True, alternative_method="product_getIdents", check_acl=False)
	def getNetBootProductIds_list(  # pylint: disable=invalid-name
		self: BackendProtocol, objectId: str | None = None, installationStatus: str | None = None
	) -> list[str]:
		return self.getProductIds_list("netboot", objectId, installationStatus)

	@rpc_method(deprecated=True, alternative_method="productOnDepot_getIdents", check_acl=False)
	def getInstallableProductIds_list(self: BackendProtocol, clientId: str) -> list[str]:  # pylint: disable=invalid-name
		depot_id = self.getDepotId(clientId=clientId)
		return [productOnDepot.productId for productOnDepot in self.productOnDepot_getObjects(depotId=depot_id)]

	@rpc_method(deprecated=True, alternative_method="productOnDepot_getIdents", check_acl=False)
	def getInstallableLocalBootProductIds_list(self: BackendProtocol, clientId: str) -> list[str]:  # pylint: disable=invalid-name
		depot_id = self.getDepotId(clientId=clientId)
		return [
			productOnDepot.productId for productOnDepot in self.productOnDepot_getObjects(depotId=depot_id, productType="LocalbootProduct")
		]

	@rpc_method(deprecated=True, alternative_method="productOnDepot_getIdents", check_acl=False)
	def getInstallableNetBootProductIds_list(self: BackendProtocol, clientId: str) -> list[str]:  # pylint: disable=invalid-name
		depot_id = self.getDepotId(clientId=clientId)
		return [
			productOnDepot.productId for productOnDepot in self.productOnDepot_getObjects(depotId=depot_id, productType="NetbootProduct")
		]

	@rpc_method(deprecated=True, alternative_method="productOnClient_getIdents", check_acl=False)
	def getInstalledProductIds_list(self: BackendProtocol, objectId: str) -> list[str]:  # pylint: disable=invalid-name
		return [
			productOnClient.productId
			for productOnClient in self.productOnClient_getObjects(
				attributes=["productId"], clientId=objectId, installationStatus="installed"
			)
		]

	@rpc_method(deprecated=True, alternative_method="productOnClient_getIdents", check_acl=False)
	def getInstalledLocalBootProductIds_list(self: BackendProtocol, objectId: str) -> list[str]:  # pylint: disable=invalid-name
		return [
			productOnClient.productId
			for productOnClient in self.productOnClient_getObjects(
				clientId=objectId, productType="LocalbootProduct", installationStatus="installed"
			)
		]

	@rpc_method(deprecated=True, alternative_method="productOnClient_getIdents", check_acl=False)
	def getInstalledNetBootProductIds_list(self: BackendProtocol, objectId: str) -> list[str]:  # pylint: disable=invalid-name
		return [
			productOnClient.productId
			for productOnClient in self.productOnClient_getObjects(
				clientId=objectId, productType="NetbootProduct", installationStatus="installed"
			)
		]

	@rpc_method(deprecated=True, alternative_method="productOnClient_getIdents", check_acl=False)
	def getProvidedLocalBootProductIds_list(self: BackendProtocol, depotId: str) -> list[str]:  # pylint: disable=invalid-name
		return [
			productOnDepot.productId for productOnDepot in self.productOnDepot_getObjects(depotId=depotId, productType="LocalbootProduct")
		]

	@rpc_method(deprecated=True, alternative_method="productOnDepot_getIdents", check_acl=False)
	def getProvidedNetBootProductIds_list(self: BackendProtocol, depotId: str) -> list[str]:  # pylint: disable=invalid-name
		return [
			productOnDepot.productId for productOnDepot in self.productOnDepot_getObjects(depotId=depotId, productType="NetbootProduct")
		]

	@rpc_method(deprecated=True, alternative_method="productOnClient_getObjects", check_acl=False)
	def getProductInstallationStatus_hash(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str, objectId: str
	) -> dict[str, Any]:
		productId = forceProductId(productId)
		product_on_clients = self.productOnClient_getObjects(productId=productId, clientId=objectId)
		if not product_on_clients:
			return {"installationStatus": "not_installed", "productId": productId}
		poc = product_on_clients[0].toHash()
		match = re.search(r"^(\d\d\d\d)-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)$", poc.get("modificationTime", ""))
		if match:
			poc["lastStateChange"] = f"{match.group(1)}{match.group(2)}{match.group(3)}{match.group(4)}{match.group(5)}{match.group(6)}"
		return poc

	@rpc_method(deprecated=True, alternative_method="productOnClient_getObjects", check_acl=False)
	def getProductInstallationStatus_listOfHashes(  # pylint: disable=invalid-name
		self: BackendProtocol, objectId: str
	) -> list[dict[str, Any]]:
		depot_id = self.getDepotId(clientId=objectId)
		products = {
			pod.productId: {
				"lastStateChange": "",
				"productVersion": pod.productVersion,
				"packageVersion": pod.packageVersion,
				"installationStatus": "not_installed",
				"productId": pod.productId,
			}
			for pod in self.productOnDepot_getObjects(depotId=depot_id)
		}

		modification_time_regex = re.compile(r"^(\d\d\d\d)-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)$")
		for product_on_client in self.productOnClient_getObjects(clientId=objectId):
			last_state_change = ""
			match = modification_time_regex.search(str(product_on_client.modificationTime))
			if match:
				last_state_change = f"{match.group(1)}{match.group(2)}{match.group(3)}{match.group(4)}{match.group(5)}{match.group(6)}"
			installation_status = product_on_client.installationStatus
			if product_on_client.actionResult == "failed":
				installation_status = "failed"
			elif installation_status == "unknown":
				installation_status = "not_installed"
			products[product_on_client.productId] = {
				"lastStateChange": last_state_change,
				"productVersion": product_on_client.productVersion,
				"packageVersion": product_on_client.packageVersion,
				"installationStatus": installation_status,
				"productId": product_on_client.productId,
			}
		return list(products.values())

	@rpc_method(deprecated=True, alternative_method="productOnClient_updateObjects", check_acl=False)
	def setProductState(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		productId: str,
		objectId: str,
		installationStatus: str | None = None,
		actionRequest: str | None = None,
		productVersion: str | None = None,
		packageVersion: str | None = None,
		lastStateChange: str | None = None,
		productActionProgress: str | None = None,
	) -> None:
		installationStatus = installationStatus or None
		actionRequest = actionRequest or None
		productVersion = productVersion or None
		packageVersion = packageVersion or None
		lastStateChange = lastStateChange or None
		productActionProgress = productActionProgress or None
		action_result = None

		depot_id = self.getDepotId(clientId=objectId)
		product_on_depots = self.productOnDepot_getObjects(depotId=depot_id, productId=productId)
		if not product_on_depots:
			raise BackendMissingDataError(f"Product {productId!r} not found on depot {depot_id!r}")

		if actionRequest:
			productActionProgress = ""
			if actionRequest != "none":
				action_result = "none"

		if installationStatus:
			productActionProgress = ""
			if installationStatus == "failed":
				action_result = "failed"
				installationStatus = None
			elif installationStatus == "installed":
				action_result = "successful"
			elif installationStatus == "installing":
				productActionProgress = installationStatus
				action_result = "none"
				installationStatus = "unknown"

		if (actionRequest and actionRequest != "none") or installationStatus:
			if not productVersion:
				productVersion = product_on_depots[0].productVersion
			if not packageVersion:
				packageVersion = product_on_depots[0].packageVersion

		self.productOnClient_updateObjects(
			ProductOnClient(
				productId=productId,
				productType=product_on_depots[0].productType,
				clientId=objectId,
				installationStatus=installationStatus,
				actionRequest=actionRequest,
				actionProgress=productActionProgress,
				actionResult=action_result,
				productVersion=productVersion,
				packageVersion=packageVersion,
				modificationTime=lastStateChange,
			)
		)

	@rpc_method(deprecated=False, alternative_method="productOnClient_updateObjects", check_acl=False)
	def setProductInstallationStatus(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str, objectId: str, installationStatus: str
	) -> None:
		self.setProductState(productId=productId, objectId=objectId, installationStatus=installationStatus)

	@rpc_method(deprecated=False, alternative_method="productOnClient_updateObjects", check_acl=False)
	def setProductActionProgress(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str, hostId: str, productActionProgress: dict
	) -> None:
		self.setProductState(productId=productId, objectId=hostId, productActionProgress=productActionProgress)

	@rpc_method(deprecated=True, alternative_method="product_getObjects", check_acl=False)
	def getPossibleProductActions_list(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str | None = None, depotId: str | None = None
	) -> list[str]:
		if not productId:
			return ["none", "setup", "uninstall", "update", "always", "once", "custom"]

		depotId = depotId or None
		result = ["none"]
		product = self.getProduct_hash(productId=productId, depotId=depotId)
		if product["setupScript"]:
			result.append("setup")
		if product["uninstallScript"]:
			result.append("uninstall")
		if product["updateScript"]:
			result.append("update")
		if product["alwaysScript"]:
			result.append("always")
		if product["onceScript"]:
			result.append("once")
		if product["customScript"]:
			result.append("custom")

		return result

	@rpc_method(deprecated=True, alternative_method="product_getObjects", check_acl=False)
	def getPossibleProductActions_hash(self: BackendProtocol, depotId: str | None = None) -> dict:  # pylint: disable=invalid-name
		result = {}
		if not depotId or depotId not in self.getDepotIds_list():
			depotId = None

		for product in self.getProducts_listOfHashes(depotId=depotId):
			result[product["productId"]] = ["none"]
			if product["setupScript"]:
				result[product["productId"]].append("setup")
			if product["uninstallScript"]:
				result[product["productId"]].append("uninstall")
			if product["updateScript"]:
				result[product["productId"]].append("update")
			if product["alwaysScript"]:
				result[product["productId"]].append("always")
			if product["onceScript"]:
				result[product["productId"]].append("once")
			if product["customScript"]:
				result[product["productId"]].append("custom")

		return result

	@rpc_method(deprecated=True, alternative_method="productOnClient_getObjects", check_acl=False)
	def getProductActionRequests_listOfHashes(  # pylint: disable=invalid-name
		self: BackendProtocol, clientId: str, options: dict | None = None
	) -> list[dict]:
		return [
			{"productId": productOnClient.productId, "actionRequest": productOnClient.actionRequest}
			for productOnClient in self.productOnClient_getObjects(clientId=clientId)
		]

	@rpc_method(deprecated=True, alternative_method="productOnClient_updateObjects", check_acl=False)
	def setProductActionRequest(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str, clientId: str, actionRequest: str
	) -> None:
		self.setProductState(productId=productId, objectId=clientId, actionRequest=actionRequest)

	@rpc_method(deprecated=True, alternative_method="productOnClient_updateObjects", check_acl=False)
	def unsetProductActionRequest(self: BackendProtocol, productId: str, clientId: str) -> None:  # pylint: disable=invalid-name
		self.setProductActionRequest(productId=productId, clientId=clientId, actionRequest="none")

	@rpc_method(deprecated=True, alternative_method="productOnClient_updateObjects", check_acl=False)
	def getLocalBootProductStates_hash(  # pylint: disable=invalid-name
		self: BackendProtocol, objectIds: list[str] | None = None, options: dict | None = None
	) -> dict[str, list]:
		return self._get_product_states_hash(client_ids=objectIds, product_type="LocalbootProduct")

	@rpc_method(deprecated=True, alternative_method="productOnClient_updateObjects", check_acl=False)
	def getNetBootProductStates_hash(  # pylint: disable=invalid-name
		self: BackendProtocol, objectIds: list[str] | None = None, options: dict | None = None
	) -> dict[str, list]:
		return self._get_product_states_hash(client_ids=objectIds, product_type="NetbootProduct")

	@rpc_method(deprecated=True, alternative_method="productOnClient_updateObjects", check_acl=False)
	def getProductStates_hash(  # pylint: disable=invalid-name
		self: BackendProtocol, objectIds: list[str] | None = None, options: dict | None = None
	) -> dict[str, list]:
		return self._get_product_states_hash(client_ids=objectIds)

	@rpc_method(deprecated=True, alternative_method="productProperty_getObjects", check_acl=False)
	def getProductPropertyDefinitions_hash(  # pylint: disable=invalid-name,too-many-branches
		self: BackendProtocol, depotId: str | None = None
	) -> dict[str, list[dict[str, Any]]]:
		depotId = depotId or None
		result: dict[str, list[dict[str, Any]]] = {}
		property_names: dict[str, dict[str, int]] = {}
		product_properties: dict[str, dict[str, dict[str, list]]] = {}

		for product_property in self.productProperty_getObjects():
			if product_property.productId not in product_properties:
				product_properties[product_property.productId] = {}
			if product_property.productVersion not in product_properties[product_property.productId]:
				product_properties[product_property.productId][product_property.productVersion] = {}
			if product_property.packageVersion not in product_properties[product_property.productId][product_property.productVersion]:
				product_properties[product_property.productId][product_property.productVersion][product_property.packageVersion] = []
			product_properties[product_property.productId][product_property.productVersion][product_property.packageVersion].append(
				product_property
			)

		depot_properties: dict[str, dict[str, list]] = {}
		if depotId:
			for product_property_state in self.productPropertyState_getObjects(objectId=depotId):
				if product_property_state.productId not in depot_properties:
					depot_properties[product_property_state.productId] = {}
				depot_properties[product_property_state.productId][product_property_state.propertyId] = product_property_state.values

		for product_on_depot in self.productOnDepot_getIdents(depotId=depotId, returnType="dict"):
			for product_property in (
				product_properties.get(product_on_depot["productId"], {})
				.get(product_on_depot["productVersion"], {})
				.get(product_on_depot["packageVersion"], [])
			):
				product_id = product_property.getProductId()
				if product_id not in result:
					result[product_id] = []
				if product_id not in property_names:
					property_names[product_id] = {}
				if product_property.getPropertyId() in property_names[product_id]:
					continue
				property_names[product_id][product_property.getPropertyId()] = 1

				defaults = product_property.getDefaultValues()
				if depotId:
					defaults = depot_properties.get(product_id, {}).get(product_property.getPropertyId(), defaults)

				values = []
				if not product_property.getEditable() or (
					product_property.getPossibleValues() and len(product_property.getPossibleValues()) > 1
				):
					values = forceUnicodeList(product_property.getPossibleValues())

				result[product_id].append(
					{
						"name": product_property.getPropertyId(),
						"description": product_property.getDescription(),
						"values": values,
						"default": ",".join(forceUnicodeList(defaults)),
					}
				)
		return result

	@rpc_method(deprecated=True, alternative_method="productProperty_getObjects", check_acl=False)
	def getProductPropertyDefinitions_listOfHashes(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str, depotId: str | None = None
	) -> list[dict]:
		result = []
		property_names = {}
		for product_on_depot in self.productOnDepot_getIdents(depotId=depotId, productId=productId, returnType="dict"):
			productProperties = self.productProperty_getObjects(
				productId=product_on_depot["productId"],
				productVersion=product_on_depot["productVersion"],
				packageVersion=product_on_depot["packageVersion"],
			)
			for productProperty in productProperties:
				if productProperty.getPropertyId() in property_names:
					continue
				property_names[productProperty.getPropertyId()] = 1

				defaults = productProperty.getDefaultValues()
				if depotId:
					productPropertyState = self.productPropertyState_getObjects(
						productId=productId, propertyId=productProperty.getPropertyId(), objectId=depotId
					)

					if productPropertyState:
						defaults = productPropertyState[0].values

				values = []
				if not productProperty.getEditable() or (
					productProperty.getPossibleValues() and len(productProperty.getPossibleValues()) > 1
				):
					values = forceUnicodeList(productProperty.getPossibleValues())

				result.append(
					{
						"name": productProperty.getPropertyId(),
						"description": productProperty.getDescription(),
						"values": values,
						"default": ",".join(forceUnicodeList(defaults)),
					}
				)

		return result

	@rpc_method(deprecated=True, alternative_method="productProperty_deleteObjects", check_acl=False)
	def deleteProductPropertyDefinition(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str, name: str, depotIds: list[str] | None = None
	) -> None:
		product_properties = []
		for productOnDepot in self.productOnDepot_getObjects(productId=productId, depotId=depotIds or []):
			product_properties.extend(
				self.productProperty_getObjects(
					productId=productOnDepot.productId,
					productVersion=productOnDepot.productVersion,
					packageVersion=productOnDepot.packageVersion,
					propertyId=name,
				)
			)

		if product_properties:
			self.productProperty_deleteObjects(product_properties)

	@rpc_method(deprecated=True, alternative_method="productProperty_deleteObjects", check_acl=False)
	def deleteProductPropertyDefinitions(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str, depotIds: list[str]
	) -> None:
		product_properties = []
		for productOnDepot in self.productOnDepot_getObjects(productId=productId, depotId=depotIds):
			product_properties.extend(
				self.productProperty_getObjects(
					productId=productOnDepot.productId,
					productVersion=productOnDepot.productVersion,
					packageVersion=productOnDepot.packageVersion,
				)
			)
		if product_properties:
			self.productProperty_deleteObjects(product_properties)

	@rpc_method(deprecated=True, alternative_method="productProperty_createObjects", check_acl=False)
	def createProductPropertyDefinition(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		productId: str,
		name: str,
		description: str | None = None,
		defaultValue: Any = None,
		possibleValues: list[Any] | None = None,
		depotIds: list[str] | None = None,
	) -> None:
		possibleValues = possibleValues or []
		depotIds = depotIds or []
		product_properties = []
		product_property_states = []
		created: dict[str, list[str]] = {}

		depotIds = self.host_getIdents(type="OpsiDepotserver", id=depotIds, returnType="unicode")
		if not depotIds:
			return
		for product_on_depot in self.productOnDepot_getObjects(productId=productId, depotId=depotIds):
			if product_on_depot.packageVersion in created.get(product_on_depot.productVersion, []):
				continue
			defaultValues: list[str] = []
			if defaultValue:
				defaultValues = [defaultValue]
			editable = True
			if possibleValues:
				editable = False
			product_properties.append(
				UnicodeProductProperty(
					productId=product_on_depot.productId,
					productVersion=product_on_depot.productVersion,
					packageVersion=product_on_depot.packageVersion,
					propertyId=name,
					description=description,
					possibleValues=possibleValues,
					defaultValues=defaultValues,
					editable=editable,
					multiValue=False,
				)
			)
			for depot_id in depotIds:
				product_property_states.append(
					ProductPropertyState(productId=product_on_depot.productId, propertyId=name, objectId=depot_id, values=defaultValues)
				)
			if product_on_depot.productVersion not in created:
				created[product_on_depot.productVersion] = []
			created[product_on_depot.productVersion].append(product_on_depot.packageVersion)
		if product_properties:
			self.productProperty_createObjects(product_properties)
		if product_property_states:
			self.productPropertyState_createObjects(product_property_states)

	@rpc_method(deprecated=True, check_acl=False)
	def getProductProperties_hash(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str, objectId: str | None = None
	) -> dict[str, Any]:
		if not objectId:
			return {ppd["name"]: ppd["default"] for ppd in self.getProductPropertyDefinitions_listOfHashes(productId=productId)}

		return {
			p: ",".join(forceUnicodeList(v))
			for p, v in self.productPropertyState_getValues(
				product_ids=[productId], property_ids=[], object_ids=[objectId], with_defaults=True
			)
			.get(objectId, {})
			.get(productId, {})
			.items()
		}

	@rpc_method(check_acl=False)
	def setProductProperties(  # pylint: disable=invalid-name,too-many-locals
		self: BackendProtocol, productId: str, properties: dict[str, str], objectId: str | None = None
	) -> None:
		"""
		Create or modify ProductPropertyStates.

		Product property states for the specified `objectId` will be created or modified.
		If `objectId` is `None`, ProductPropertyStates will be changed for all depots
		where ProductPropertyStates exist for the specified product.

		:param productId: The ID of the product.
		:param properties: <property-id> <value> pairs of properties to set.
		:param objectId: ID of the object to set the values for or `None`.
		"""
		property_ids = set(forceProductPropertyId(ppi) for ppi in properties)
		property_classes = {}
		property_multi_value = {}
		for prop in self.productProperty_getObjects(productId=productId, propertyId=property_ids):
			property_classes[prop.propertyId] = prop.__class__
			property_multi_value[prop.propertyId] = prop.getMultiValue()

		new_properties = {}
		for property_id, value in properties.items():
			property_type = property_classes.get(property_id)
			if not property_type:
				raise BackendMissingDataError(f"Property with id {property_id!r} not found for product {productId!r}!") from None

			if issubclass(property_type, UnicodeProductProperty):
				logger.debug("Property %s is unicode.", property_id)
				new_value = forceUnicodeList(value)

				logger.debug("New values for property %s: %s", property_id, new_value)
				if not property_multi_value[property_id] and len(new_value) > 1:
					raise ValueError(f"Property {property_id!r} is not multivalue but new values {new_value!r} are!")

				new_properties[forceProductPropertyId(property_id)] = new_value
			elif issubclass(property_type, BoolProductProperty):
				logger.debug("Property %s is bool.", property_id)
				new_properties[forceProductPropertyId(property_id)] = forceBool(value)  # type: ignore[assignment]
			else:
				raise ValueError(f"Property type of {property_type!r} currently unhandled")

		product_property_states = []
		if objectId:
			product_property_states = [
				ProductPropertyState(productId=productId, propertyId=property_id, objectId=objectId, values=value)
				for property_id, value in new_properties.items()
			]
		else:
			# Apply the changes to depots with an existing ProductPropertyState
			depot_ids = self.host_getIdents(type="OpsiDepotserver", returnType="unicode")
			for product_property_state in self.productPropertyState_getObjects(productId=productId, objectId=depot_ids):
				try:
					product_property_state.setValues(new_properties[product_property_state.propertyId])
					product_property_states.append(product_property_state)
				except KeyError:
					continue

		self.productPropertyState_createObjects(product_property_states)

	@rpc_method(check_acl=False)
	def setProductProperty(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str, propertyId: str, value: Any, objectId: str | None = None
	) -> None:
		"""
		Create or modify ProductPropertyState.

		The product property states for the specified `objectId` will be created or modified.
		If `objectId` is `None`, the ProductPropertyState will be changed for all depots
		where this ProductPropertyState exist for the specified product.

		:param productId: The ID of the product.
		:param propertyId: The ID of the productProperty.
		:param value: The value to set.
		:param objectId: ID of the object to set the values for or `None`.
		"""
		self.setProductProperties(productId, {propertyId: value}, objectId)

	@rpc_method(deprecated=True, alternative_method="productDependency_getObjects", check_acl=False)
	def getProductDependencies_listOfHashes(  # pylint: disable=invalid-name
		self: BackendProtocol, productId: str | None = None, depotId: str | None = None
	) -> list[dict]:
		productId = productId or None
		depotId = depotId or None
		result = []
		if depotId:
			product_dependencies: dict[str, dict[str, dict[str, list]]] = {}
			for product_dependency in self.productDependency_getObjects():
				if productId and product_dependency.productId != productId:
					continue
				if product_dependency.productId not in product_dependencies:
					product_dependencies[product_dependency.productId] = {}
				if product_dependency.productVersion not in product_dependencies[product_dependency.productId]:
					product_dependencies[product_dependency.productId][product_dependency.productVersion] = {}
				if (
					product_dependency.packageVersion
					not in product_dependencies[product_dependency.productId][product_dependency.productVersion]
				):
					product_dependencies[product_dependency.productId][product_dependency.productVersion][
						product_dependency.packageVersion
					] = []
				product_dependencies[product_dependency.productId][product_dependency.productVersion][
					product_dependency.packageVersion
				].append(
					product_dependency
				)

			for product_on_depot in self.productOnDepot_getIdents(depotId=depotId, returnType="dict"):
				for product_dependency in (
					product_dependencies.get(product_on_depot["productId"], {})
					.get(product_on_depot["productVersion"], {})
					.get(product_on_depot["packageVersion"], [])
				):
					result.append(
						{
							"productId": product_dependency.getProductId(),
							"action": product_dependency.getProductAction(),
							"requiredProductId": product_dependency.getRequiredProductId(),
							"requiredProductClassId": "",
							"requiredAction": product_dependency.getRequiredAction() or "",
							"requiredInstallationStatus": product_dependency.getRequiredInstallationStatus() or "",
							"requirementType": product_dependency.getRequirementType() or "",
						}
					)
		else:
			for product_dependency in self.productDependency_getObjects(productId=productId):
				result.append(
					{
						"productId": product_dependency.getProductId(),
						"action": product_dependency.getProductAction(),
						"requiredProductId": product_dependency.getRequiredProductId(),
						"requiredProductClassId": "",
						"requiredAction": product_dependency.getRequiredAction() or "",
						"requiredInstallationStatus": product_dependency.getRequiredInstallationStatus() or "",
						"requirementType": product_dependency.getRequirementType() or "",
					}
				)
		return result

	@rpc_method(deprecated=True, alternative_method="productDependency_create", check_acl=False)
	def createProductDependency(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		productId: str,
		action: str,
		requiredProductId: str = "",
		requiredProductClassId: str = "",
		requiredAction: str = "",
		requiredInstallationStatus: str = "",
		requirementType: str = "",
		depotIds: list[str] | None = None,
	) -> None:
		for product_on_depot in self.productOnDepot_getObjects(productId=productId, depotId=depotIds or []):
			self.productDependency_create(
				productId=product_on_depot.productId,
				productVersion=product_on_depot.productVersion,
				packageVersion=product_on_depot.packageVersion,
				productAction=action,
				requiredProductId=requiredProductId or None,
				requiredProductVersion=None,
				requiredPackageVersion=None,
				requiredAction=requiredAction or None,
				requiredInstallationStatus=requiredInstallationStatus or None,
				requirementType=requirementType or None,
			)

	@rpc_method(deprecated=True, alternative_method="licenseContract_create", check_acl=False)
	def createLicenseContract(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		licenseContractId: str = "",
		partner: str = "",
		conclusionDate: str = "",
		notificationDate: str = "",
		expirationDate: str = "",
		notes: str = "",
	) -> str:
		if not licenseContractId:
			# Generate license pool id
			known_license_contract_ids = self.licenseContract_getIdents(returnType="unicode")
			now = time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime())
			index = 0
			while True:
				licenseContractId = f"c_{now}_{index}"
				if licenseContractId not in known_license_contract_ids:
					break
				index += 1

		self.licenseContract_create(
			id=licenseContractId,
			description=None,
			notes=notes,
			partner=partner,
			conclusionDate=conclusionDate,
			notificationDate=notificationDate,
			expirationDate=expirationDate,
		)

		return self.licenseContract_getIdents(id=licenseContractId, returnType="unicode")[0]

	@rpc_method(deprecated=True, alternative_method="licenseContract_getIdents", check_acl=False)
	def getLicenseContractIds_list(self: BackendProtocol) -> list[str]:  # pylint: disable=invalid-name
		return self.licenseContract_getIdents(returnType="unicode")

	@rpc_method(deprecated=True, alternative_method="licenseContract_getObjects", check_acl=False)
	def getLicenseContract_hash(self: BackendProtocol, licenseContractId: str) -> dict:  # pylint: disable=invalid-name
		license_contracts = self.licenseContract_getObjects(id=licenseContractId)
		if not license_contracts:
			raise BackendMissingDataError(f"License contract {licenseContractId!r} does not exist")
		lc_hash = license_contracts[0].toHash()

		# Cut time part, date only
		if lc_hash["conclusionDate"]:
			lc_hash["conclusionDate"] = lc_hash["conclusionDate"].split(" ")[0]
		else:
			lc_hash["conclusionDate"] = ""

		if lc_hash["notificationDate"]:
			lc_hash["notificationDate"] = lc_hash["notificationDate"].split(" ")[0]
		else:
			lc_hash["notificationDate"] = ""

		if lc_hash["expirationDate"]:
			lc_hash["expirationDate"] = lc_hash["expirationDate"].split(" ")[0]
		else:
			lc_hash["expirationDate"] = ""

		lc_hash["licenseContractId"] = lc_hash["id"]
		del lc_hash["id"]
		del lc_hash["type"]
		return lc_hash

	@rpc_method(deprecated=True, alternative_method="licenseContract_getObjects", check_acl=False)
	def getLicenseContracts_listOfHashes(self: BackendProtocol) -> list[dict]:  # pylint: disable=invalid-name
		license_contracts = []
		for license_contract in self.licenseContract_getObjects():
			lc_hash = license_contract.toHash()
			# Cut time part, date only
			if lc_hash["conclusionDate"]:
				lc_hash["conclusionDate"] = lc_hash["conclusionDate"].split(" ")[0]
			else:
				lc_hash["conclusionDate"] = ""

			if lc_hash["notificationDate"]:
				lc_hash["notificationDate"] = lc_hash["notificationDate"].split(" ")[0]
			else:
				lc_hash["notificationDate"] = ""

			if lc_hash["expirationDate"]:
				lc_hash["expirationDate"] = lc_hash["expirationDate"].split(" ")[0]
			else:
				lc_hash["expirationDate"] = ""

			lc_hash["licenseContractId"] = lc_hash["id"]
			del lc_hash["id"]
			del lc_hash["type"]
			license_contracts.append(lc_hash)

		return license_contracts

	@rpc_method(deprecated=True, alternative_method="licenseContract_delete", check_acl=False)
	def deleteLicenseContract(self: BackendProtocol, licenseContractId: str) -> None:  # pylint: disable=invalid-name
		self.licenseContract_delete(id=licenseContractId)

	@rpc_method(deprecated=True, alternative_method="softwareLicense_create", check_acl=False)
	def createSoftwareLicense(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol,
		softwareLicenseId: str = "",
		licenseContractId: str = "",
		licenseType: str = "",
		maxInstallations: int | None = None,
		boundToHost: str | None = None,
		expirationDate: str | None = None,
	) -> str:
		boundToHost = boundToHost or None
		expirationDate = expirationDate or None
		licenseType = licenseType or "volume"

		if not softwareLicenseId:
			# Generate software license id
			known_software_license_ids = self.softwareLicense_getIdents(returnType="unicode")
			now = time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime())
			index = 0
			while True:
				softwareLicenseId = f"l_{now}_{index}"
				if softwareLicenseId not in known_software_license_ids:
					break
				index += 1

		if str(licenseType).lower() == "oem":
			method = self.softwareLicense_createOEM
		elif str(licenseType).lower() == "retail":
			method = self.softwareLicense_createRetail
		elif str(licenseType).lower() == "volume":
			method = self.softwareLicense_createVolume
		elif str(licenseType).lower() == "concurrent":
			method = self.softwareLicense_createConcurrent
		else:
			raise BackendBadValueError(f"Unknown license type {licenseType!r}")

		method(
			id=softwareLicenseId,
			licenseContractId=licenseContractId,
			maxInstallations=maxInstallations,
			boundToHost=boundToHost,
			expirationDate=expirationDate,
		)
		return self.softwareLicense_getIdents(id=softwareLicenseId, returnType="tuple")[0][0]

	@rpc_method(deprecated=True, alternative_method="softwareLicense_getIdents", check_acl=False)
	def getSoftwareLicenseIds_list(self: BackendProtocol) -> list[str]:  # pylint: disable=invalid-name
		return [ident[0] for ident in self.softwareLicense_getIdents(returnType="unicode")]

	@rpc_method(deprecated=True, alternative_method="softwareLicense_getObjects", check_acl=False)
	def getSoftwareLicense_hash(self: BackendProtocol, softwareLicenseId: str) -> dict:  # pylint: disable=invalid-name
		software_icenses = self.softwareLicense_getObjects(id=softwareLicenseId)
		if not software_icenses:
			raise BackendMissingDataError(f"Software license {softwareLicenseId!r} does not exist")

		sl_hash = software_icenses[0].toHash()
		if isinstance(software_icenses[0], OEMSoftwareLicense):
			sl_hash["licenseType"] = "OEM"
		elif isinstance(software_icenses[0], RetailSoftwareLicense):
			sl_hash["licenseType"] = "RETAIL"
		elif isinstance(software_icenses[0], VolumeSoftwareLicense):
			sl_hash["licenseType"] = "VOLUME"
		elif isinstance(software_icenses[0], ConcurrentSoftwareLicense):
			sl_hash["licenseType"] = "CONCURRENT"

		# Cut time part, date only
		if sl_hash["expirationDate"]:
			sl_hash["expirationDate"] = sl_hash["expirationDate"].split(" ")[0]
		else:
			sl_hash["expirationDate"] = ""

		sl_hash["boundToHost"] = sl_hash["boundToHost"] or ""
		sl_hash["softwareLicenseId"] = sl_hash["id"]
		del sl_hash["id"]
		del sl_hash["type"]

		sl_hash["licenseKeys"] = {}
		sl_hash["licensePoolIds"] = []
		for software_license_to_icense_pool in self.softwareLicenseToLicensePool_getObjects(softwareLicenseId=softwareLicenseId):
			sl_hash["licensePoolIds"].append(software_license_to_icense_pool.getLicensePoolId())
			if software_license_to_icense_pool.getLicenseKey():
				sl_hash["licenseKeys"][software_license_to_icense_pool.getLicensePoolId()] = software_license_to_icense_pool.getLicenseKey()
		return sl_hash

	@rpc_method(deprecated=True, alternative_method="softwareLicense_getObjects", check_acl=False)
	def getSoftwareLicenses_listOfHashes(self: BackendProtocol) -> list[dict]:  # pylint: disable=invalid-name
		software_licenses = []
		for software_license in self.softwareLicense_getObjects():
			sl_hash = software_license.toHash()
			if isinstance(software_license, OEMSoftwareLicense):
				sl_hash["licenseType"] = "OEM"
			elif isinstance(software_license, RetailSoftwareLicense):
				sl_hash["licenseType"] = "RETAIL"
			elif isinstance(software_license, VolumeSoftwareLicense):
				sl_hash["licenseType"] = "VOLUME"
			elif isinstance(software_license, ConcurrentSoftwareLicense):
				sl_hash["licenseType"] = "CONCURRENT"

			# Cut time part, date only
			if sl_hash["expirationDate"]:
				sl_hash["expirationDate"] = sl_hash["expirationDate"].split(" ")[0]
			else:
				sl_hash["expirationDate"] = ""

			sl_hash["boundToHost"] = sl_hash["boundToHost"] or ""
			sl_hash["softwareLicenseId"] = sl_hash["id"]
			del sl_hash["id"]
			del sl_hash["type"]

			sl_hash["licenseKeys"] = {}
			sl_hash["licensePoolIds"] = []
			for software_license_to_license_pool in self.softwareLicenseToLicensePool_getObjects(
				softwareLicenseId=software_license.getId()
			):
				sl_hash["licensePoolIds"].append(software_license_to_license_pool.getLicensePoolId())
				if software_license_to_license_pool.getLicenseKey():
					sl_hash["licenseKeys"][
						software_license_to_license_pool.getLicensePoolId()
					] = software_license_to_license_pool.getLicenseKey()

			software_licenses.append(sl_hash)
		return software_licenses

	@rpc_method(deprecated=True, alternative_method="softwareLicense_delete", check_acl=False)
	def deleteSoftwareLicense(  # pylint: disable=invalid-name
		self: BackendProtocol, softwareLicenseId: str, removeFromPools: bool = False
	) -> None:
		if removeFromPools:
			self.softwareLicenseToLicensePool_delete(softwareLicenseId=softwareLicenseId)
		self.softwareLicense_delete(id=softwareLicenseId)

	@rpc_method(deprecated=True, alternative_method="licensePool_create", check_acl=False)
	def createLicensePool(  # pylint: disable=invalid-name
		self: BackendProtocol,
		licensePoolId: str = "",
		description: str = "",
		productIds: list[str] | None = None,
		windowsSoftwareIds: list[str] | None = None,
	) -> str:
		if not licensePoolId:
			# Generate license pool id
			known_license_pool_ids = set(self.licensePool_getIdents(returnType="unicode"))
			now = time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime())
			index = 0
			licensePoolId = f"p_{now}_{index}"
			while licensePoolId in known_license_pool_ids:
				index += 1
				licensePoolId = f"p_{now}_{index}"

		self.licensePool_create(id=licensePoolId, description=description, productIds=productIds or [])

		if windowsSoftwareIds:
			audit_software_to_license_pools = [
				AuditSoftwareToLicensePool(
					name=aus.name,
					version=aus.version,
					subVersion=aus.subVersion,
					language=aus.language,
					architecture=aus.architecture,
					licensePoolId=licensePoolId,
				)
				for aus in self.auditSoftware_getObjects(windowsSoftwareId=forceUnicodeList(windowsSoftwareIds))
			]
			self.auditSoftwareToLicensePool_createObjects(audit_software_to_license_pools)

		pool_idents = self.licensePool_getIdents(id=licensePoolId, returnType="tuple")
		if not pool_idents:
			raise RuntimeError("Failed to create license pool")
		return pool_idents[0][0]

	@rpc_method(deprecated=True, alternative_method="licensePool_getIdents", check_acl=False)
	def getLicensePoolIds_list(self: BackendProtocol) -> list[str]:  # pylint: disable=invalid-name
		return self.licensePool_getIdents(returnType="unicode")

	@rpc_method(deprecated=True, alternative_method="licensePool_getObjects", check_acl=False)
	def getLicensePool_hash(self: BackendProtocol, licensePoolId: str) -> dict:  # pylint: disable=invalid-name
		license_pools = self.licensePool_getObjects(id=licensePoolId)
		if not license_pools:
			raise BackendMissingDataError(f"License pool {licensePoolId!r} does not exist")

		lp_hash = license_pools[0].toHash()
		lp_hash["licensePoolId"] = lp_hash["id"]
		del lp_hash["id"]
		del lp_hash["type"]
		lp_hash["windowsSoftwareIds"] = []
		for audit_software_to_license_pool in self.auditSoftwareToLicensePool_getObjects(licensePoolId=license_pools[0].id):
			audit_softwares = self.auditSoftware_getObjects(
				["windowsSoftwareId"],
				name=audit_software_to_license_pool.name,
				version=audit_software_to_license_pool.version,
				subVersion=audit_software_to_license_pool.subVersion,
				language=audit_software_to_license_pool.language,
				architecture=audit_software_to_license_pool.architecture,
			)
			if not audit_softwares:
				continue
			if not audit_softwares[0].windowsSoftwareId:
				continue
			lp_hash["windowsSoftwareIds"].append(audit_softwares[0].windowsSoftwareId)
		return lp_hash

	@rpc_method(deprecated=True, alternative_method="licensePool_getObjects", check_acl=False)
	def getLicensePools_listOfHashes(self: BackendProtocol) -> list[dict]:  # pylint: disable=invalid-name
		license_pools = []

		audit_software_to_license_pools_by_license_pool_id: dict[str, list[AuditSoftwareToLicensePool]] = {}
		for audit_software_to_license_pool in self.auditSoftwareToLicensePool_getObjects():
			if audit_software_to_license_pool.licensePoolId not in audit_software_to_license_pools_by_license_pool_id:
				audit_software_to_license_pools_by_license_pool_id[audit_software_to_license_pool.licensePoolId] = []
			audit_software_to_license_pools_by_license_pool_id[audit_software_to_license_pool.licensePoolId].append(
				audit_software_to_license_pool
			)

		for license_pool in self.licensePool_getObjects():
			lp_hash = license_pool.toHash()
			lp_hash["licensePoolId"] = lp_hash["id"]
			del lp_hash["id"]
			del lp_hash["type"]
			lp_hash["windowsSoftwareIds"] = []
			for audit_software_to_license_pool in audit_software_to_license_pools_by_license_pool_id.get(license_pool.id, []):
				audit_softwares = self.auditSoftware_getObjects(
					["windowsSoftwareId"],
					name=audit_software_to_license_pool.name,
					version=audit_software_to_license_pool.version,
					subVersion=audit_software_to_license_pool.subVersion,
					language=audit_software_to_license_pool.language,
					architecture=audit_software_to_license_pool.architecture,
				)
				if not audit_softwares:
					continue
				if not audit_softwares[0].windowsSoftwareId:
					continue
				lp_hash["windowsSoftwareIds"].append(audit_softwares[0].windowsSoftwareId)
			license_pools.append(lp_hash)
		return license_pools

	@rpc_method(deprecated=True, alternative_method="licensePool_delete", check_acl=False)
	def deleteLicensePool(self: BackendProtocol, licensePoolId: str, deleteLicenses: bool = False) -> None:  # pylint: disable=invalid-name
		if deleteLicenses:
			for ident in self.softwareLicenseToLicensePool_getIdents(licensePoolId=licensePoolId, returnType="dict"):
				self.licenseOnClient_delete(softwareLicenseId=ident["softwareLicenseId"], licensePoolId=licensePoolId, clientId=[])
				self.softwareLicense_delete(ident["softwareLicenseId"])
		self.licensePool_delete(id=licensePoolId)

	@rpc_method(deprecated=True, alternative_method="softwareLicenseToLicensePool_create", check_acl=False)
	def addSoftwareLicenseToLicensePool(  # pylint: disable=invalid-name
		self: BackendProtocol, softwareLicenseId: str, licensePoolId: str, licenseKey: str = ""
	) -> None:
		self.softwareLicenseToLicensePool_create(softwareLicenseId=softwareLicenseId, licensePoolId=licensePoolId, licenseKey=licenseKey)

	@rpc_method(deprecated=True, alternative_method="softwareLicenseToLicensePool_delete", check_acl=False)
	def removeSoftwareLicenseFromLicensePool(  # pylint: disable=invalid-name
		self: BackendProtocol, softwareLicenseId: str, licensePoolId: str
	) -> None:
		self.softwareLicenseToLicensePool_delete(softwareLicenseId=softwareLicenseId, licensePoolId=licensePoolId)

	@rpc_method(deprecated=True, alternative_method="licensePool_updateObject", check_acl=False)
	def addProductIdsToLicensePool(  # pylint: disable=invalid-name
		self: BackendProtocol, productIds: list[str], licensePoolId: str
	) -> None:
		productIds = forceUnicodeList(productIds)
		license_pools = self.licensePool_getObjects(id=licensePoolId)
		if not license_pools:
			raise BackendMissingDataError(f"License pool {licensePoolId!r} does not exist")
		productIds.extend(license_pools[0].getProductIds())
		license_pools[0].setProductIds(productIds)
		self.licensePool_updateObject(license_pools[0])

	@rpc_method(deprecated=True, alternative_method="licensePool_updateObject", check_acl=False)
	def removeProductIdsFromLicensePool(  # pylint: disable=invalid-name
		self: BackendProtocol, productIds: list[str], licensePoolId: str
	) -> None:
		productIds = forceUnicodeList(productIds)
		licensePools = self.licensePool_getObjects(id=licensePoolId)
		if not licensePools:
			raise BackendMissingDataError(f"License pool {licensePoolId!r} does not exist")
		new_product_ids = [p for p in licensePools[0].getProductIds() if p not in productIds]
		licensePools[0].setProductIds(new_product_ids)
		self.licensePool_updateObject(licensePools[0])

	@rpc_method(deprecated=True, alternative_method="auditSoftwareToLicensePool_createObjects", check_acl=False)
	def setWindowsSoftwareIdsToLicensePool(  # pylint: disable=invalid-name
		self: BackendProtocol, windowsSoftwareIds: list[str], licensePoolId: str
	) -> None:
		windowsSoftwareIds = forceUnicodeList(windowsSoftwareIds)
		license_pool_ids = self.licensePool_getIdents(id=licensePoolId, returnType="unicode")
		if not license_pool_ids:
			raise BackendMissingDataError(f"License pool {licensePoolId!r} does not exist")

		self.auditSoftwareToLicensePool_delete(
			name=[], version=[], subVersion=[], language=[], architecture=[], licensePoolId=license_pool_ids
		)

		audit_software_to_license_pools = [
			AuditSoftwareToLicensePool(
				name=auditSoftware.name,
				version=auditSoftware.version,
				subVersion=auditSoftware.subVersion,
				language=auditSoftware.language,
				architecture=auditSoftware.architecture,
				licensePoolId=licensePoolId,
			)
			for auditSoftware in self.auditSoftware_getObjects(windowsSoftwareId=forceUnicodeList(windowsSoftwareIds))
		]
		self.auditSoftwareToLicensePool_createObjects(audit_software_to_license_pools)

	@rpc_method(deprecated=True, alternative_method="licensePool_getIdents", check_acl=False)
	def getLicensePoolId(self: BackendProtocol, productId: str = "", windowsSoftwareId: str = "") -> str:  # pylint: disable=invalid-name
		if not productId and not windowsSoftwareId:
			raise BackendBadValueError("Neither product id nor windows software id given.")
		idents = []
		if productId:
			productId = forceProductId(productId)
			idents = self.licensePool_getIdents(productIds=productId, returnType="unicode")
		elif windowsSoftwareId:
			windowsSoftwareId = str(windowsSoftwareId)

			audit_softwares = self.auditSoftware_getObjects(windowsSoftwareId=windowsSoftwareId)
			for audit_software in audit_softwares:
				audit_software_to_license_pools = self.auditSoftwareToLicensePool_getObjects(
					name=audit_software.name,
					version=audit_software.version,
					subVersion=audit_software.subVersion,
					language=audit_software.language,
					architecture=audit_software.architecture,
				)
				if audit_software_to_license_pools:
					idents.append(audit_software_to_license_pools[0].licensePoolId)
		if len(idents) < 1:
			raise LicenseConfigurationError(f"No license pool for product id {productId!r}, windowsSoftwareId {windowsSoftwareId!r} found")
		if len(idents) > 1:
			raise LicenseConfigurationError(
				f"Multiple license pools for product id {productId!r}, windowsSoftwareId {windowsSoftwareId!r} found"
			)
		return idents[0]

	@rpc_method(deprecated=True, alternative_method="licenseOnClient_getOrCreateObject", check_acl=False)
	def getOrCreateSoftwareLicenseUsage_hash(  # pylint: disable=invalid-name
		self: BackendProtocol, hostId: str, licensePoolId: str = "", productId: str = "", windowsSoftwareId: str = ""
	) -> dict:
		license_on_client = self.licenseOnClient_getOrCreateObject(
			clientId=hostId, licensePoolId=licensePoolId, productId=productId, windowsSoftwareId=windowsSoftwareId
		)
		return license_on_client.toHash()

	@rpc_method(deprecated=True, alternative_method="licenseOnClient_getOrCreateObject", check_acl=False)
	def getAndAssignSoftwareLicenseKey(  # pylint: disable=invalid-name
		self: BackendProtocol, hostId: str, licensePoolId: str = "", productId: str = "", windowsSoftwareId: str = ""
	) -> str:
		license_key = ""
		try:
			licensePoolId = licensePoolId or self.getLicensePoolId(productId=productId, windowsSoftwareId=windowsSoftwareId)
			return self.getOrCreateSoftwareLicenseUsage_hash(hostId, licensePoolId, productId, windowsSoftwareId).get("licenseKey", "")
		except Exception as err:  # pylint: disable=broad-except
			logger.warning(
				"Failed to get license key from license management for host '%s', pool '%s', product '%s', softwareid '%s': %s",
				hostId,
				licensePoolId,
				productId,
				windowsSoftwareId,
				err,
			)

			# Trying the old way - product keys as product property
			if productId:
				properties = self.getProductProperties_hash(productId=productId, objectId=hostId)
				try:
					license_key = properties["productkey"]
				except KeyError:
					# No productkey found - we continue.
					pass

			if not license_key:
				raise err

		return license_key

	@rpc_method(deprecated=True, alternative_method="licenseOnClient_getOrCreateObject", check_acl=False)
	def getLicenseKey(self: BackendProtocol, productId: str, clientId: str) -> str:  # pylint: disable=invalid-name
		"""
		Returns an unused licensekey if available or
		the license key assigend to a specific client
		"""
		return self.getAndAssignSoftwareLicenseKey(hostId=clientId, productId=productId)

	@rpc_method(deprecated=True, alternative_method="licenseOnClient_getObjects", check_acl=False)
	def getSoftwareLicenseUsages_listOfHashes(  # pylint: disable=invalid-name
		self: BackendProtocol, hostIds: list[str] | None = None, licensePoolIds: list[str] | None = None
	) -> list[dict]:
		hostIds = hostIds or []
		licensePoolIds = licensePoolIds or []
		licenseOnClients = []
		for license_on_client in self.licenseOnClient_getObjects(licensePoolId=licensePoolIds, clientId=hostIds):
			loc_hash = license_on_client.toHash()
			loc_hash["licenseKey"] = loc_hash["licenseKey"] or ""
			loc_hash["notes"] = loc_hash["notes"] or ""
			loc_hash["hostId"] = loc_hash["clientId"]
			del loc_hash["clientId"]
			licenseOnClients.append(loc_hash)
		return licenseOnClients

	@rpc_method(deprecated=True, alternative_method="licenseOnClient_create", check_acl=False)
	def setSoftwareLicenseUsage(  # pylint: disable=invalid-name,too-many-arguments
		self: BackendProtocol, hostId: str, licensePoolId: str, softwareLicenseId: str, licenseKey: str = "", notes: str = ""
	) -> dict[str, str]:
		self.licenseOnClient_create(
			softwareLicenseId=softwareLicenseId, licensePoolId=licensePoolId, clientId=hostId, licenseKey=licenseKey, notes=notes
		)
		return {"hostId": hostId, "softwareLicenseId": softwareLicenseId, "licensePoolId": licensePoolId}

	@rpc_method(deprecated=True, alternative_method="licenseOnClient_delete", check_acl=False)
	def deleteAllSoftwareLicenseUsages(self: BackendProtocol, hostIds: list[str]) -> None:  # pylint: disable=invalid-name
		self.licenseOnClient_delete(clientId=hostIds)

	@rpc_method(deprecated=True, alternative_method="softwareLicenseToLicensePool_getObjects", check_acl=False)
	def getLicenseStatistics_hash(self: BackendProtocol) -> dict[str, Any]:  # pylint: disable=invalid-name
		result = {}
		for license_pool in self.licensePool_getObjects():
			pool_od = license_pool.getId()
			licenses = 0
			max_installations: int | str = 0
			remaining_installations: int | str = 0
			additional_license_pool_ids = set()

			for software_license_to_license_pool in self.softwareLicenseToLicensePool_getObjects(licensePoolId=pool_od):
				for software_license_to_license_pool_2 in self.softwareLicenseToLicensePool_getObjects(
					softwareLicenseId=software_license_to_license_pool.getSoftwareLicenseId()
				):
					if software_license_to_license_pool_2.getLicensePoolId() == pool_od:
						continue
					additional_license_pool_ids.add(software_license_to_license_pool_2.getLicensePoolId())

				licenses += 1
				allowed_installations = self.softwareLicense_getObjects(
					attributes=["maxInstallations"], id=software_license_to_license_pool.getSoftwareLicenseId()
				)[0].getMaxInstallations()
				if allowed_installations == 0:
					max_installations = "infinite"
				elif max_installations != "infinite":
					max_installations += allowed_installations

			used_by = [
				licenseOnClient.getClientId()
				for licenseOnClient in self.licenseOnClient_getObjects(attributes=["clientId"], licensePoolId=pool_od)
			]

			if max_installations == "infinite":
				remaining_installations = "infinite"
			else:
				remaining_installations = int(max_installations) - len(used_by)
				if additional_license_pool_ids:
					licenses_used_by_clients_in_additional_pools = self.licenseOnClient_getIdents(licensePoolId=additional_license_pool_ids)
					remaining_installations = remaining_installations - len(licenses_used_by_clients_in_additional_pools)

				if remaining_installations < 1:
					remaining_installations = 0

			result[pool_od] = {
				"licenses": licenses,
				"used_by": used_by,
				"usageCount": len(used_by),
				"maxInstallations": max_installations,
				"remainingInstallations": remaining_installations,
			}

		return result

	@rpc_method(deprecated=True, alternative_method="depot_getMD5Sum", check_acl=False)
	def getMD5Sum(self: BackendProtocol, filename: str) -> str:  # pylint: disable=invalid-name
		return self.depot_getMD5Sum(filename)

	@rpc_method(deprecated=True, alternative_method="depot_librsyncSignature", check_acl=False)
	def librsyncSignature(self: BackendProtocol, filename: str) -> str:  # pylint: disable=invalid-name
		return self.depot_librsyncSignature(filename)

	@rpc_method(deprecated=True, alternative_method="depot_getDiskSpaceUsage", check_acl=False)
	def getDiskSpaceUsage(self: BackendProtocol, path: str) -> dict[str, float]:  # pylint: disable=invalid-name
		return self.depot_getDiskSpaceUsage(path)

	@rpc_method(deprecated=True, alternative_method="depot_getHostRSAPublicKey", check_acl=False)
	def getHostRSAPublicKey(self: BackendProtocol) -> str:  # pylint: disable=invalid-name
		return self.depot_getHostRSAPublicKey()

	@rpc_method(deprecated=True, alternative_method="user_getCredentials", check_acl=False)
	def getPcpatchPassword(self: BackendProtocol, hostId: str) -> str:  # pylint: disable=invalid-name
		return self.user_getCredentials(username="pcpatch", hostId=hostId)["password"]

	@rpc_method(deprecated=True, alternative_method="accessControl_userIsAdmin", check_acl=False)
	def userIsAdmin(self: BackendProtocol) -> bool:  # pylint: disable=invalid-name
		if self.accessControl_userIsAdmin():
			return True
		raise BackendAuthenticationError("User is not an admin")

	@rpc_method(deprecated=True, alternative_method="productOnDepot_getIdents", check_acl=False)
	def areDepotsSynchronous(self: BackendProtocol, depotIds: list[str] | None = None) -> bool:  # pylint: disable=invalid-name
		depotIds = self.host_getIdents(type="OpsiDepotserver", id=depotIds, returnType="unicode")
		if not depotIds:
			raise BackendMissingDataError("No depots found")

		if len(depotIds) == 1:
			return True

		last_ident = ""
		for idx, current_depot in enumerate(depotIds):
			idents = [
				f"{ident['productId']};{ident['productVersion']};{ident['packageVersion']}"
				for ident in self.productOnDepot_getIdents(depotId=current_depot, returnType="dict")
			]
			idents.sort()
			ident = "|".join(idents)
			if (idx > 0) and (ident != last_ident):
				return False
			last_ident = ident
		return True

	@rpc_method(deprecated=True, alternative_method="host_updateObject", check_acl=False)
	def setHostInventoryNumber(self: BackendProtocol, hostId: str, inventoryNumber: str) -> None:  # pylint: disable=invalid-name
		hostId = forceHostId(hostId)
		hosts = self.host_getObjects(id=hostId)
		if not hosts:
			raise BackendMissingDataError(f"Host {hostId!r} not found")
		host = hosts[0]
		host.setInventoryNumber(inventoryNumber)
		self.host_updateObject(host)
