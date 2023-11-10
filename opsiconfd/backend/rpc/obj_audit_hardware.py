# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.audit_hardware
"""
from __future__ import annotations

import re
from collections import defaultdict
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol

from opsicommon.objects import (
	AuditHardware,
	AuditHardwareOnHost,
)
from opsicommon.types import forceLanguageCode, forceList

from opsiconfd.config import AUDIT_HARDWARE_CONFIG_FILE, AUDIT_HARDWARE_CONFIG_LOCALES_DIR
from opsiconfd.logging import logger

from ..auth import RPCACE
from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol, IdentType


OPSI_HARDWARE_CLASSES: list[dict[str, Any]] = []


def inherit_from_super_classes(classes: list[dict[str, Any]], _class: dict[str, Any], scname: str | None = None) -> None:  # pylint: disable=unused-private-member
	if not scname:  # pylint: disable=too-many-nested-blocks
		for _scname in _class["Class"].get("Super", []):
			inherit_from_super_classes(classes, _class, _scname)
	else:
		if not classes:
			logger.error("Super class '%s' of class '%s' not found", scname, _class["Class"].get("Opsi"))
		for cls in classes:
			if cls["Class"].get("Opsi") == scname:
				clcopy = deepcopy(cls)
				inherit_from_super_classes(classes, clcopy)
				new_values = []
				for new_value in clcopy["Values"]:
					found_at = -1
					for idx, current_value in enumerate(_class["Values"]):
						if current_value["Opsi"] == new_value["Opsi"]:
							if not current_value.get("UI"):
								_class["Values"][idx]["UI"] = new_value.get("UI", "")
							found_at = idx
							break
					if found_at > -1:
						new_value = _class["Values"][found_at]
						del _class["Values"][found_at]
					new_values.append(new_value)
				new_values.extend(_class["Values"])
				_class["Values"] = new_values
				break


@lru_cache(maxsize=10)
# pylint: disable=invalid-name,too-many-locals,too-many-branches,too-many-statements
def get_audit_hardware_config(
	language: str | None = None,
) -> list[dict[str, dict[str, str] | list[dict[str, str]]]]:
	if not language:
		language = "en"
	language = forceLanguageCode(language).replace("-", "_")

	locale_path = Path(AUDIT_HARDWARE_CONFIG_LOCALES_DIR)
	locale_file = locale_path / f"hwaudit_{language}.properties"
	if not locale_file.exists():
		orig_language = language
		if "_" in language:
			language = language.split("_")[0]
		else:
			language = f"{language}_{language.upper()}"
		logger.debug("No translation file found for language %r, trying %r", orig_language, language)
		locale_file = locale_path / f"hwaudit_{language}.properties"
		if not locale_file.exists():
			logger.error("No translation file found for language %r, falling back to en", language)
			language = "en"
			locale_file = locale_path / f"hwaudit_{language}.properties"

	locale = {}
	try:
		for line in locale_file.read_text(encoding="utf-8").splitlines():
			line = line.strip()
			if not line or line.startswith((";", "#")):
				continue
			try:
				identifier, translation = line.split("=", 1)
				locale[identifier.strip()] = translation.strip()
			except ValueError as verr:
				logger.trace("Failed to read translation: %s", verr)
	except Exception as err:  # pylint: disable=broad-except
		logger.error("Failed to read translation file for language %s: %s", language, err)

	classes: list[dict[str, Any]] = []
	try:  # pylint: disable=too-many-nested-blocks
		with open(AUDIT_HARDWARE_CONFIG_FILE, encoding="utf-8") as hwc_file:
			exec(hwc_file.read())  # pylint: disable=exec-used

		for cls_idx, current_class_config in enumerate(OPSI_HARDWARE_CLASSES):
			opsi_class = current_class_config["Class"]["Opsi"]
			if current_class_config["Class"]["Type"] == "STRUCTURAL":
				if locale.get(opsi_class):
					OPSI_HARDWARE_CLASSES[cls_idx]["Class"]["UI"] = locale[opsi_class]
				else:
					logger.error("No translation for class '%s' found", opsi_class)
					OPSI_HARDWARE_CLASSES[cls_idx]["Class"]["UI"] = opsi_class

			for val_idx, current_value in enumerate(current_class_config["Values"]):
				opsi_property = current_value["Opsi"]
				try:
					OPSI_HARDWARE_CLASSES[cls_idx]["Values"][val_idx]["UI"] = locale[f"{opsi_class}.{opsi_property}"]
				except KeyError:
					pass

		for owc in OPSI_HARDWARE_CLASSES:
			try:
				if owc["Class"].get("Type") == "STRUCTURAL":
					logger.debug("Found STRUCTURAL hardware class '%s'", owc["Class"].get("Opsi"))
					ccopy = deepcopy(owc)
					if "Super" in ccopy["Class"]:
						inherit_from_super_classes(OPSI_HARDWARE_CLASSES, ccopy)
						del ccopy["Class"]["Super"]
					del ccopy["Class"]["Type"]

					# Fill up empty display names
					for val_idx, current_value in enumerate(ccopy.get("Values", [])):
						if not current_value.get("UI"):
							logger.warning(
								"No translation found for hardware audit configuration property '%s.%s' in %s",
								ccopy["Class"]["Opsi"],
								current_value["Opsi"],
								locale_file,
							)
							ccopy["Values"][val_idx]["UI"] = current_value["Opsi"]

					classes.append(ccopy)
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Error in config file '%s': %s", AUDIT_HARDWARE_CONFIG_FILE, err)

		AuditHardware.setHardwareConfig(classes)
		AuditHardwareOnHost.setHardwareConfig(classes)
	except Exception as err:  # pylint: disable=broad-except
		logger.warning("Failed to read audit hardware configuration from file '%s': %s", AUDIT_HARDWARE_CONFIG_FILE, err)

	return classes


def get_audit_hardware_database_config() -> dict[str, dict[str, dict[str, str]]]:
	audit_hardware_config: dict[str, dict[str, dict[str, str]]] = {}
	for conf in get_audit_hardware_config():
		hw_class = conf["Class"]["Opsi"]  # type: ignore
		audit_hardware_config[hw_class] = {}
		for value in conf["Values"]:
			audit_hardware_config[hw_class][value["Opsi"]] = {"Type": value["Type"], "Scope": value["Scope"]}  # type: ignore
	return audit_hardware_config


class RPCAuditHardwareMixin(Protocol):
	_audit_hardware_database_config: dict[str, dict[str, dict[str, str]]] = {}

	def __init__(self) -> None:
		self._audit_hardware_database_config = get_audit_hardware_database_config()

	def _audit_hardware_by_hardware_class(
		self: BackendProtocol, audit_hardwares: list[dict] | list[AuditHardware] | dict | AuditHardware
	) -> dict[str, list[AuditHardware]]:
		by_hardware_class = defaultdict(list)
		for ahoh in forceList(audit_hardwares):
			if not isinstance(ahoh, AuditHardware):
				ahoh = AuditHardware.fromHash(ahoh)
			by_hardware_class[ahoh.hardwareClass].append(ahoh)
		return by_hardware_class

	def auditHardware_deleteAll(self: BackendProtocol) -> None:  # pylint: disable=invalid-name
		with self._mysql.session() as session:
			for hardware_class in self._audit_hardware_database_config:
				session.execute(f"TRUNCATE TABLE `HARDWARE_CONFIG_{hardware_class}`")
				session.execute(f"TRUNCATE TABLE `HARDWARE_DEVICE_{hardware_class}`")

	@rpc_method(check_acl=False)
	def auditHardware_getConfig(  # pylint: disable=invalid-name
		self: BackendProtocol, language: str | None = None
	) -> list[dict[str, dict[str, str] | list[dict[str, str]]]]:
		self._get_ace("auditHardware_getConfig")

		return get_audit_hardware_config(language)

	def auditHardware_bulkInsertObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditHardwares: list[dict] | list[AuditHardware]
	) -> None:
		for hardware_class, auh in self._audit_hardware_by_hardware_class(auditHardwares).items():
			self._mysql.bulk_insert_objects(table=f"HARDWARE_DEVICE_{hardware_class}", objs=auh)  # type: ignore[arg-type]

	@rpc_method(check_acl=False)
	def auditHardware_insertObject(self: BackendProtocol, auditHardware: dict | AuditHardware) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("auditHardware_insertObject")
		for hardware_class, auh in self._audit_hardware_by_hardware_class(auditHardware).items():
			for obj in auh:
				self._mysql.insert_object(table=f"HARDWARE_DEVICE_{hardware_class}", obj=obj, ace=ace, create=True, set_null=True)

	@rpc_method(check_acl=False)
	def auditHardware_updateObject(self: BackendProtocol, auditHardware: dict | AuditHardware) -> None:  # pylint: disable=invalid-name
		ace = self._get_ace("auditHardware_updateObject")
		for hardware_class, auh in self._audit_hardware_by_hardware_class(auditHardware).items():
			for obj in auh:
				self._mysql.insert_object(table=f"HARDWARE_DEVICE_{hardware_class}", obj=obj, ace=ace, create=False, set_null=False)

	@rpc_method(check_acl=False)
	def auditHardware_createObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditHardwares: list[dict] | list[AuditHardware] | dict | AuditHardware
	) -> None:
		ace = self._get_ace("auditHardware_createObjects")
		with self._mysql.session() as session:
			for hardware_class, auh in self._audit_hardware_by_hardware_class(auditHardwares).items():
				for obj in auh:
					self._mysql.insert_object(
						table=f"HARDWARE_DEVICE_{hardware_class}", obj=obj, ace=ace, create=True, set_null=True, session=session
					)

	@rpc_method(check_acl=False)
	def auditHardware_updateObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditHardwares: list[dict] | list[AuditHardware] | dict | AuditHardware
	) -> None:
		ace = self._get_ace("auditHardware_updateObjects")
		with self._mysql.session() as session:
			for hardware_class, auh in self._audit_hardware_by_hardware_class(auditHardwares).items():
				for obj in auh:
					self._mysql.insert_object(
						table=f"HARDWARE_DEVICE_{hardware_class}", obj=obj, ace=ace, create=True, set_null=False, session=session
					)

	def _audit_hardware_get(  # pylint: disable=redefined-builtin,too-many-branches,too-many-locals,too-many-statements,too-many-arguments
		self: BackendProtocol,
		ace: list[RPCACE],
		return_hardware_ids: bool = False,
		return_type: Literal["object", "dict", "ident"] = "object",
		ident_type: IdentType = "str",
		attributes: list[str] | None = None,
		filter: dict[str, Any] | None = None,
	) -> list[dict[str, Any]]:
		attributes = attributes or []
		filter = filter or {}
		hardware_classes = set()
		hardware_class = filter.get("hardwareClass")
		if hardware_class not in ([], None):
			for hwc in forceList(hardware_class):
				regex = re.compile(f"^{hwc.replace('*', '.*')}$")
				for key in self._audit_hardware_database_config:
					if regex.search(key):
						hardware_classes.add(key)

			if not hardware_classes:
				return []

		if not hardware_classes:
			hardware_classes = set(self._audit_hardware_database_config)

		for unwanted_key in ("hardwareClass", "type"):
			try:
				del filter[unwanted_key]
			except KeyError:
				pass  # not there - everything okay.

		if return_hardware_ids and attributes and "hardware_id" not in attributes:
			attributes.append("hardware_id")

		results = []
		with self._mysql.session() as session:
			for hardware_class in hardware_classes:  # pylint: disable=too-many-nested-blocks
				class_filter = {}
				ident_attributes = []
				for attr, info in self._audit_hardware_database_config[hardware_class].items():
					if info.get("Scope") == "g":
						ident_attributes.append(attr)
						if attr in filter:
							class_filter[attr] = ["", None] if filter[attr] in ("", None) else filter[attr]
						if attributes and return_type != "dict" and attr not in attributes:
							attributes.append(attr)

				if attributes and return_hardware_ids and "hardware_id" not in attributes:
					attributes.append("hardware_id")

				if return_type == "ident":
					attributes = ident_attributes

				if not class_filter and filter:
					continue

				table = f"HARDWARE_DEVICE_{hardware_class}"
				columns = self._mysql.get_columns(tables=[table], ace=ace, attributes=attributes)
				if not return_hardware_ids and "hardware_id" in columns:
					del columns["hardware_id"]
				where, params = self._mysql.get_where(columns=columns, ace=ace, filter=class_filter)
				query = f"""SELECT {', '.join([f"{c.select} AS `{a}`" for a, c in columns.items() if c.select])} FROM `{table}` {where}"""
				for row in session.execute(query, params=params).fetchall():
					data = dict(row)
					if return_type == "object":
						results.append(AuditHardware(hardwareClass=hardware_class, **data))
					elif return_type == "ident":
						results.append(
							self._mysql.get_ident(  # type: ignore[arg-type]
								data=data, ident_attributes=ident_attributes, ident_type=ident_type
							)
						)
					else:
						results.append(data)  # type: ignore[arg-type]
		return results  # type: ignore[return-value]

	@rpc_method(check_acl=False)
	def auditHardware_getObjects(  # pylint: disable=redefined-builtin,invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any
	) -> list[AuditHardware]:
		ace = self._get_ace("auditHardware_getObjects")
		# type: ignore[return-value]
		return self._audit_hardware_get(ace=ace, return_hardware_ids=False, return_type="object", attributes=attributes, filter=filter)

	@rpc_method(deprecated=True, alternative_method="auditHardware_getObjects", check_acl=False)
	def auditHardware_getHashes(  # pylint: disable=redefined-builtin,invalid-name
		self: BackendProtocol, attributes: list[str] | None = None, **filter: Any
	) -> list[dict]:
		ace = self._get_ace("auditHardware_getObjects")
		return self._audit_hardware_get(ace=ace, return_hardware_ids=False, return_type="dict", attributes=attributes, filter=filter)

	@rpc_method(check_acl=False)
	def auditHardware_getIdents(  # pylint: disable=invalid-name,redefined-builtin
		self: BackendProtocol,
		returnType: IdentType = "str",
		**filter: Any,
	) -> list[str] | list[dict] | list[list] | list[tuple]:
		ace = self._get_ace("auditHardware_getObjects")
		return self._audit_hardware_get(ace=ace, return_hardware_ids=False, return_type="ident", ident_type=returnType, filter=filter)

	@rpc_method(check_acl=True)
	def auditHardware_deleteObjects(  # pylint: disable=invalid-name
		self: BackendProtocol, auditHardwares: list[dict] | list[AuditHardware] | dict | AuditHardware
	) -> None:
		if not auditHardwares:
			return

		# self._mysql.delete_objects(table="AUDIT_HARDWARE", object_type=AuditHardware, obj=auditHardwares, ace=ace)
		with self._mysql.session() as session:
			for hardware_class, audit_hardwares in self._audit_hardware_by_hardware_class(auditHardwares).items():
				audit_hardware_indent_attributes = set(AuditHardware.hardware_attributes[hardware_class])

				conditions = []
				params: dict[str, Any] = {}
				for audit_hardware in audit_hardwares:
					cond = []
					for attr in audit_hardware_indent_attributes:
						val = getattr(audit_hardware, attr)
						param = f"p{len(params) + 1}"
						params[param] = val
						cond.append(f"`{attr}` {'IS' if val is None else '='} :{param}")
					conditions.append(f"({' AND '.join(cond)})")

				query = f"DELETE FROM HARDWARE_DEVICE_{hardware_class} WHERE {' OR '.join(conditions)}"
				session.execute(query, params=params)

	@rpc_method(check_acl=False)
	def auditHardware_create(self, hardwareClass: str, **kwargs: Any) -> None:  # pylint: disable=unused-argument,invalid-name
		_hash = locals()
		del _hash["self"]
		return self.auditHardware_createObjects(AuditHardware.fromHash(_hash))

	@rpc_method(check_acl=False)
	def auditHardware_delete(self, hardwareClass: str, **kwargs: Any) -> None:  # pylint: disable=invalid-name
		_filter = {key: [] if val is None else val for key, val in kwargs.items()}
		_filter["hardwareClass"] = [] if hardwareClass is None else hardwareClass
		objs = self.auditHardware_getObjects(attributes=[], **_filter)
		if objs:
			self.auditHardware_deleteObjects(objs)
