# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""Read data from the retired opsi file backend format."""

from __future__ import annotations

import configparser
import json
import re
from dataclasses import dataclass, fields
from pathlib import Path
from typing import TYPE_CHECKING, Any

from opsi.opsi.package import OpsiPackage
from opsi.opsi.service.model.object import (
	BoolConfig,
	Config,
	ConfigState,
	Group,
	Host,
	HostGroup,
	ObjectToGroup,
	OpsiClient,
	OpsiConfigserver,
	OpsiDepotserver,
	Product,
	ProductDependency,
	ProductGroup,
	ProductOnClient,
	ProductOnDepot,
	ProductProperty,
	ProductPropertyState,
	UnicodeConfig,
)
from opsi.opsi.service.model.type import to_bool

if TYPE_CHECKING:
	from collections.abc import Iterable


class CaseSensitiveConfigParser(configparser.RawConfigParser):
	"""Raw config parser preserving legacy opsi option name case."""

	def optionxform(self, optionstr: str) -> str:
		"""Return option names unchanged."""
		return optionstr


@dataclass
class LegacyFileBackendData:
	"""Objects read from a legacy file backend."""

	hosts: list[Host]
	products: list[Product]
	configs: list[Config]
	groups: list[Group]
	product_dependencies: list[ProductDependency]
	product_properties: list[ProductProperty]
	product_on_depots: list[ProductOnDepot]
	product_on_clients: list[ProductOnClient]
	product_property_states: list[ProductPropertyState]
	config_states: list[ConfigState]
	objects_to_groups: list[ObjectToGroup]

	def counts(self) -> dict[str, int]:
		"""Return the number of objects in each collection."""
		return {field.name: len(getattr(self, field.name)) for field in fields(self)}


class LegacyFileBackendReader:
	"""Read objects from a legacy opsi file backend without modifying it."""

	PRODUCT_FILENAME_REGEX = re.compile(r"^([a-zA-Z0-9_.-]+)_([\w.]+)-([\w.]+)\.(local|net)boot$")

	def __init__(
		self,
		base_dir: Path = Path("/var/lib/opsi/config"),
		host_key_file: Path = Path("/etc/opsi/pckeys"),
		config_server_id: str | None = None,
	) -> None:
		"""Initialize the reader.

		Args:
			base_dir: Legacy file backend data directory.
			host_key_file: Legacy host key file.
			config_server_id: Host ID identifying the configserver.
		"""
		self.base_dir = base_dir
		self.host_key_file = host_key_file
		self.config_server_id = config_server_id

	@staticmethod
	def unescape(value: str) -> str:
		"""Decode escaping used by the legacy INI files."""
		return value.replace("\\n", "\n").replace("\\;", ";").replace("\\#", "#").replace("%%", "%")

	def read_host_keys(self) -> dict[str, str]:
		"""Read host IDs and keys from the legacy pckeys file."""
		if not self.host_key_file.exists():
			return {}

		host_keys: dict[str, str] = {}
		for line in self.host_key_file.read_text(encoding="utf-8").splitlines():
			line = line.strip()
			if not line or line.startswith("#"):
				continue
			host_id, separator, host_key = line.partition(":")
			if separator and host_id.strip() and host_key.strip():
				host_keys[host_id.strip().lower()] = host_key.strip()
		return host_keys

	@staticmethod
	def _read_ini(path: Path) -> configparser.RawConfigParser:
		"""Read a legacy INI file while preserving option name case."""
		parser = CaseSensitiveConfigParser(interpolation=None, strict=False, empty_lines_in_values=True)
		if path.exists():
			with path.open("r", encoding="utf-8") as file:
				parser.read_file(file)
		return parser

	@staticmethod
	def _get(parser: configparser.RawConfigParser, section: str, option: str) -> str | None:
		"""Return an INI value using case-insensitive section and option matching."""
		matching_section = next((name for name in parser.sections() if name.lower() == section.lower()), None)
		if not matching_section:
			return None
		matching_option = next((name for name in parser.options(matching_section) if name.lower() == option.lower()), None)
		if not matching_option:
			return None
		return parser.get(matching_section, matching_option, raw=True)

	def _read_mapping(
		self,
		parser: configparser.RawConfigParser,
		mappings: dict[str, tuple[str, str, bool]],
	) -> dict[str, Any]:
		"""Read mapped attributes from a legacy INI parser."""
		result: dict[str, Any] = {}
		for attribute, (section, option, is_json) in mappings.items():
			value = self._get(parser, section, option)
			if value is None:
				continue
			result[attribute] = json.loads(value) if is_json else self.unescape(value)
		return result

	def read_hosts(self) -> list[Host]:
		"""Read configserver, depot, and client objects."""
		hosts: list[Host] = []
		host_keys = self.read_host_keys()
		depot_mappings = {
			"description": ("depotserver", "description", False),
			"notes": ("depotserver", "notes", False),
			"hardwareAddress": ("depotserver", "hardwareaddress", False),
			"ipAddress": ("depotserver", "ipaddress", False),
			"inventoryNumber": ("depotserver", "inventorynumber", False),
			"networkAddress": ("depotserver", "network", False),
			"isMasterDepot": ("depotserver", "ismasterdepot", True),
			"masterDepotId": ("depotserver", "masterdepotid", False),
			"depotRemoteUrl": ("depotshare", "remoteurl", False),
			"depotWebdavUrl": ("depotshare", "webdavurl", False),
			"depotLocalUrl": ("depotshare", "localurl", False),
			"repositoryRemoteUrl": ("repository", "remoteurl", False),
			"repositoryLocalUrl": ("repository", "localurl", False),
			"maxBandwidth": ("repository", "maxbandwidth", False),
			"workbenchLocalUrl": ("workbench", "localurl", False),
			"workbenchRemoteUrl": ("workbench", "remoteurl", False),
		}
		for path in sorted((self.base_dir / "depots").glob("*.ini")):
			host_id = path.stem.lower()
			data = {"id": host_id, "opsiHostKey": host_keys.get(host_id), **self._read_mapping(self._read_ini(path), depot_mappings)}
			object_type = OpsiConfigserver if host_id == self.config_server_id else OpsiDepotserver
			hosts.append(object_type.fromHash(data))

		client_mappings = {
			"oneTimePassword": ("info", "onetimepassword", False),
			"description": ("info", "description", False),
			"notes": ("info", "notes", False),
			"hardwareAddress": ("info", "hardwareaddress", False),
			"ipAddress": ("info", "ipaddress", False),
			"inventoryNumber": ("info", "inventorynumber", False),
			"created": ("info", "created", False),
			"lastSeen": ("info", "lastseen", False),
		}
		for path in sorted((self.base_dir / "clients").glob("*.ini")):
			host_id = path.stem.lower()
			data = {"id": host_id, "opsiHostKey": host_keys.get(host_id), **self._read_mapping(self._read_ini(path), client_mappings)}
			hosts.append(OpsiClient.fromHash(data))
		return hosts

	def read_configs(self) -> list[Config]:
		"""Read configuration definitions."""
		configs: list[Config] = []
		parser = self._read_ini(self.base_dir / "config.ini")
		for section in parser.sections():
			data: dict[str, Any] = {"id": section}
			for attribute, option, is_json in (
				("description", "description", False),
				("editable", "editable", True),
				("multiValue", "multivalue", True),
				("possibleValues", "possiblevalues", True),
				("defaultValues", "defaultvalues", True),
			):
				value = self._get(parser, section, option)
				if value is not None:
					data[attribute] = json.loads(value) if is_json else self.unescape(value)
			config_type = self._get(parser, section, "type")
			possible_values = data.get("possibleValues") or []
			if config_type == "BoolConfig" or (
				len(possible_values) == 2
				and True in possible_values
				and False in possible_values
				and not data.get("editable")
				and not data.get("multiValue")
			):
				object_type = BoolConfig
			else:
				object_type = UnicodeConfig
			configs.append(object_type.fromHash(data))
		return configs

	def read_product_data(self) -> tuple[list[Product], list[ProductProperty], list[ProductDependency]]:
		"""Read products, properties, and dependencies from control files."""
		products: list[Product] = []
		properties: list[ProductProperty] = []
		dependencies: list[ProductDependency] = []
		product_dir = self.base_dir / "products"
		if not product_dir.is_dir():
			return products, properties, dependencies

		for control_file in sorted(product_dir.iterdir()):
			if not self.PRODUCT_FILENAME_REGEX.match(control_file.name):
				continue
			package = OpsiPackage()
			package.parse_control_file_legacy(control_file)
			products.append(package.product)
			properties.extend(package.product_properties)
			dependencies.extend(package.product_dependencies)
		return products, properties, dependencies

	def _host_ini_files(self) -> Iterable[tuple[str, configparser.RawConfigParser, bool]]:
		"""Yield host IDs, parsers, and depot flags for legacy host files."""
		for directory, is_depot in (("depots", True), ("clients", False)):
			for path in sorted((self.base_dir / directory).glob("*.ini")):
				yield path.stem.lower(), self._read_ini(path), is_depot

	def read_states(self) -> tuple[list[ProductOnDepot], list[ProductOnClient], list[ProductPropertyState], list[ConfigState]]:
		"""Read product and configuration state objects."""
		product_on_depots: list[ProductOnDepot] = []
		product_on_clients: list[ProductOnClient] = []
		property_states: list[ProductPropertyState] = []
		config_states: list[ConfigState] = []
		for host_id, parser, is_depot in self._host_ini_files():
			for section in parser.sections():
				section_lower = section.lower()
				if section_lower == "generalconfig":
					for config_id, value in parser.items(section, raw=True):
						config_states.append(
							ConfigState.fromHash({"configId": config_id, "objectId": host_id, "values": json.loads(value)})
						)
					continue
				if section_lower.endswith("-install"):
					product_id = section[:-8]
					for property_id, value in parser.items(section, raw=True):
						property_states.append(
							ProductPropertyState.fromHash(
								{"productId": product_id, "propertyId": property_id, "objectId": host_id, "values": json.loads(value)}
							)
						)
					continue
				if not section_lower.endswith("-state"):
					continue
				product_id = section[:-6]
				product_type = self._get(parser, section, "producttype")
				if not product_type:
					raise ValueError(f"Missing producttype in section {section!r} for host {host_id!r}")
				data: dict[str, Any] = {"productId": product_id, "productType": product_type}
				if is_depot:
					data["depotId"] = host_id
					for attribute in ("productVersion", "packageVersion", "locked"):
						value = self._get(parser, section, attribute)
						if value is not None:
							data[attribute] = self.unescape(value)
					product_on_depots.append(ProductOnDepot.fromHash(data))
					continue

				data["clientId"] = host_id
				for attribute in (
					"actionProgress",
					"productVersion",
					"packageVersion",
					"modificationTime",
					"lastAction",
					"actionResult",
					"targetConfiguration",
				):
					value = self._get(parser, section, attribute)
					if value is not None:
						data[attribute] = self.unescape(value)
				summary_section = (
					product_type.replace("LocalbootProduct", "localboot").replace("NetbootProduct", "netboot") + "_product_states"
				)
				summary = self._get(parser, summary_section, product_id)
				if summary is None:
					summary = self._get(parser, f"{product_type}_product_states", product_id)
				if summary is None:
					data.update({"installationStatus": "not_installed", "actionRequest": "none"})
				elif ":" not in summary:
					raise ValueError(f"Invalid product state {summary!r} for product {product_id!r} on host {host_id!r}")
				else:
					data["installationStatus"], data["actionRequest"] = summary.split(":", 1)
				product_on_clients.append(ProductOnClient.fromHash(data))
		return product_on_depots, product_on_clients, property_states, config_states

	def read_groups(self) -> tuple[list[Group], list[ObjectToGroup]]:
		"""Read groups and their object assignments."""
		groups: list[Group] = []
		assignments: list[ObjectToGroup] = []
		for filename, group_type, object_type in (
			("clientgroups.ini", "HostGroup", HostGroup),
			("productgroups.ini", "ProductGroup", ProductGroup),
		):
			parser = self._read_ini(self.base_dir / filename)
			for section in parser.sections():
				data: dict[str, Any] = {"id": section}
				for attribute, option in (("description", "description"), ("parentGroupId", "parentgroupid"), ("notes", "notes")):
					value = self._get(parser, section, option)
					if value is not None:
						data[attribute] = self.unescape(value)
				groups.append(object_type.fromHash(data))
				for object_id, value in parser.items(section, raw=True):
					if object_id.lower() in {"description", "parentgroupid", "notes"}:
						continue
					if to_bool(value):
						assignments.append(ObjectToGroup.fromHash({"groupType": group_type, "groupId": section, "objectId": object_id}))
		return self._sort_groups(groups), assignments

	@staticmethod
	def _sort_groups(groups: list[Group]) -> list[Group]:
		"""Sort groups so parents are inserted before their children."""
		remaining = list(groups)
		sorted_groups: list[Group] = []
		known_ids: set[tuple[str, str]] = set()
		while remaining:
			ready = [group for group in remaining if not group.parentGroupId or (group.getType(), group.parentGroupId) in known_ids]
			if not ready:
				unresolved = ", ".join(f"{group.getType()}:{group.id}" for group in remaining)
				raise ValueError(f"Unresolvable legacy group hierarchy: {unresolved}")
			for group in ready:
				remaining.remove(group)
				sorted_groups.append(group)
				known_ids.add((group.getType(), group.id))
		return sorted_groups

	def read(self) -> LegacyFileBackendData:
		"""Read and validate the complete legacy backend into memory."""
		for directory in (self.base_dir / "clients", self.base_dir / "depots", self.base_dir / "products"):
			if not directory.is_dir():
				raise FileNotFoundError(f"Legacy file backend directory not found: {directory}")
		products, product_properties, product_dependencies = self.read_product_data()
		product_on_depots, product_on_clients, property_states, config_states = self.read_states()
		groups, assignments = self.read_groups()
		return LegacyFileBackendData(
			hosts=self.read_hosts(),
			products=products,
			configs=self.read_configs(),
			groups=groups,
			product_dependencies=product_dependencies,
			product_properties=product_properties,
			product_on_depots=product_on_depots,
			product_on_clients=product_on_clients,
			product_property_states=property_states,
			config_states=config_states,
			objects_to_groups=assignments,
		)


def import_legacy_file_backend(data: LegacyFileBackendData, backend: Any) -> None:
	"""Insert a legacy file backend snapshot into the current backend."""
	collections = (
		("host_insertObject", data.hosts),
		("product_insertObject", data.products),
		("config_insertObject", data.configs),
		("group_insertObject", data.groups),
		("productDependency_insertObject", data.product_dependencies),
		("productProperty_insertObject", data.product_properties),
		("productOnDepot_insertObject", data.product_on_depots),
		("productOnClient_insertObject", data.product_on_clients),
		("productPropertyState_insertObject", data.product_property_states),
		("configState_insertObject", data.config_states),
		("objectToGroup_insertObject", data.objects_to_groups),
	)
	for method_name, objects in collections:
		method = getattr(backend, method_name)
		for obj in objects:
			method(obj)
