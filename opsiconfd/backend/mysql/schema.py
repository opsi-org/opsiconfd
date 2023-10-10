# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.mysql.schema
"""
# pylint: disable=too-many-lines

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Literal

from sqlalchemy.exc import OperationalError  # type: ignore[import]

from opsiconfd.logging import logger

from .cleanup import (
	remove_orphans_config_value,
	remove_orphans_hardware_config,
	remove_orphans_license_on_client_to_host,
	remove_orphans_product_id_to_license_pool,
	remove_orphans_product_property_value,
	remove_orphans_product_on_depot,
)

if TYPE_CHECKING:
	from . import MySQLConnection, Session


CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS `CONFIG` (
	`configId` varchar(200) NOT NULL,
	`type` varchar(30) NOT NULL,
	`description` varchar(256) DEFAULT NULL,
	`multiValue` tinyint(1) NOT NULL DEFAULT '0',
	`editable` tinyint(1) NOT NULL DEFAULT '1',
	PRIMARY KEY (`configId`),
	KEY `index_config_type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `CONFIG_STATE` (
	`configId` varchar(200) NOT NULL,
	`objectId` varchar(255) NOT NULL,
	`values` text,
	PRIMARY KEY (`configId`,`objectId`),
	KEY `index_config_state_configId` (`configId`),
	KEY `index_config_state_objectId` (`objectId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `CONFIG_VALUE` (
	`config_value_id` int(11) NOT NULL AUTO_INCREMENT,
	`configId` varchar(200) NOT NULL,
	`value` text,
	`isDefault` tinyint(1) DEFAULT NULL,
	PRIMARY KEY (`config_value_id`),
	KEY `configId` (`configId`),
	FOREIGN KEY (`configId`)
		REFERENCES `CONFIG` (`configId`)
		ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `GROUP` (
	`type` varchar(30) NOT NULL,
	`groupId` varchar(255) NOT NULL,
	`parentGroupId` varchar(255) DEFAULT NULL,
	`description` varchar(100) DEFAULT NULL,
	`notes` varchar(500) DEFAULT NULL,
	PRIMARY KEY (`type`,`groupId`),
	KEY `index_group_parentGroupId` (`parentGroupId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `HOST` (
	`hostId` varchar(255) NOT NULL,
	`type` varchar(30) DEFAULT NULL,
	`description` varchar(100) DEFAULT NULL,
	`notes` varchar(500) DEFAULT NULL,
	`hardwareAddress` varchar(17) DEFAULT NULL,
	`ipAddress` varchar(255) DEFAULT NULL,
	`inventoryNumber` varchar(64) DEFAULT NULL,
	`created` timestamp NULL DEFAULT NULL,
	`lastSeen` timestamp NULL DEFAULT NULL,
	`opsiHostKey` varchar(32) DEFAULT NULL,
	`oneTimePassword` varchar(32) DEFAULT NULL,
	`systemUUID` varchar(36) DEFAULT NULL,
	`maxBandwidth` int(11) DEFAULT NULL,
	`depotLocalUrl` varchar(128) DEFAULT NULL,
	`depotRemoteUrl` varchar(255) DEFAULT NULL,
	`depotWebdavUrl` varchar(255) DEFAULT NULL,
	`repositoryLocalUrl` varchar(128) DEFAULT NULL,
	`repositoryRemoteUrl` varchar(255) DEFAULT NULL,
	`networkAddress` varchar(31) DEFAULT NULL,
	`isMasterDepot` tinyint(1) DEFAULT NULL,
	`masterDepotId` varchar(255) DEFAULT NULL,
	`workbenchLocalUrl` varchar(128) DEFAULT NULL,
	`workbenchRemoteUrl` varchar(255) DEFAULT NULL,
	PRIMARY KEY (`hostId`),
	UNIQUE KEY `systemUUID` (`systemUUID`),
	KEY `index_host_type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `LICENSE_CONTRACT` (
	`licenseContractId` varchar(100) NOT NULL,
	`type` varchar(30) NOT NULL,
	`description` varchar(100) DEFAULT NULL,
	`notes` varchar(1000) DEFAULT NULL,
	`partner` varchar(100) DEFAULT NULL,
	`conclusionDate` timestamp NULL DEFAULT NULL,
	`notificationDate` timestamp NULL DEFAULT NULL,
	`expirationDate` timestamp NULL DEFAULT NULL,
	PRIMARY KEY (`licenseContractId`),
	KEY `index_license_contract_type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `LICENSE_POOL` (
	`licensePoolId` varchar(100) NOT NULL,
	`type` varchar(30) NOT NULL,
	`description` varchar(200) DEFAULT NULL,
	PRIMARY KEY (`licensePoolId`),
	KEY `index_license_pool_type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `OBJECT_TO_GROUP` (
	`groupType` varchar(30) NOT NULL,
	`groupId` varchar(255) NOT NULL,
	`objectId` varchar(255) NOT NULL,
	PRIMARY KEY (`groupType`,`groupId`,`objectId`),
	KEY `groupType` (`groupType`,`groupId`),
	KEY `index_object_to_group_objectId` (`objectId`),
	FOREIGN KEY (`groupType`, `groupId`)
		REFERENCES `GROUP` (`type`, `groupId`)
		ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `OPSI_SCHEMA` (
	`version` int(11) NOT NULL,
	`updateStarted` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updateEnded` timestamp NULL DEFAULT NULL,
	PRIMARY KEY (`version`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `PRODUCT` (
	`productId` varchar(255) NOT NULL,
	`productVersion` varchar(32) NOT NULL,
	`packageVersion` varchar(16) NOT NULL,
	`type` varchar(32) NOT NULL,
	`name` varchar(128) NOT NULL DEFAULT '',
	`licenseRequired` tinyint(1) NOT NULL DEFAULT '0',
	`setupScript` varchar(50) DEFAULT NULL,
	`uninstallScript` varchar(50) DEFAULT NULL,
	`updateScript` varchar(50) DEFAULT NULL,
	`alwaysScript` varchar(50) DEFAULT NULL,
	`onceScript` varchar(50) DEFAULT NULL,
	`customScript` varchar(50) DEFAULT NULL,
	`userLoginScript` varchar(50) DEFAULT NULL,
	`priority` int(11) DEFAULT '0',
	`description` text,
	`advice` text,
	`pxeConfigTemplate` varchar(50) DEFAULT NULL,
	`changelog` text,
	PRIMARY KEY (`productId`,`productVersion`,`packageVersion`),
	KEY `index_product_type` (`type`),
	KEY `index_productId` (`productId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `PRODUCT_DEPENDENCY` (
	`productId` varchar(255) NOT NULL,
	`productVersion` varchar(32) NOT NULL,
	`packageVersion` varchar(16) NOT NULL,
	`productAction` varchar(16) NOT NULL,
	`requiredProductId` varchar(255) NOT NULL,
	`requiredProductVersion` varchar(32) DEFAULT NULL,
	`requiredPackageVersion` varchar(16) DEFAULT NULL,
	`requiredAction` varchar(16) DEFAULT NULL,
	`requiredInstallationStatus` varchar(16) DEFAULT NULL,
	`requirementType` varchar(16) DEFAULT NULL,
	PRIMARY KEY (`productId`,`productVersion`,`packageVersion`,`productAction`,`requiredProductId`),
	FOREIGN KEY (`productId`, `productVersion`, `packageVersion`)
		REFERENCES `PRODUCT` (`productId`, `productVersion`, `packageVersion`)
		ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `PRODUCT_ID_TO_LICENSE_POOL` (
	`licensePoolId` varchar(100) NOT NULL,
	`productId` varchar(255) NOT NULL,
	PRIMARY KEY (`licensePoolId`,`productId`),
	FOREIGN KEY (`licensePoolId`)
		REFERENCES `LICENSE_POOL` (`licensePoolId`)
		ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `PRODUCT_ON_CLIENT` (
	`productId` varchar(255) NOT NULL,
	`clientId` varchar(255) NOT NULL,
	`productType` varchar(16) NOT NULL,
	`targetConfiguration` varchar(16) DEFAULT NULL,
	`installationStatus` varchar(16) NOT NULL DEFAULT 'not_installed',
	`actionRequest` varchar(16) NOT NULL DEFAULT 'none',
	`actionProgress` varchar(255) DEFAULT NULL,
	`actionResult` varchar(16) DEFAULT NULL,
	`lastAction` varchar(16) DEFAULT NULL,
	`productVersion` varchar(32) DEFAULT NULL,
	`packageVersion` varchar(16) DEFAULT NULL,
	`modificationTime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (`productId`,`productType`,`clientId`),
	UNIQUE KEY `productId-clientId` (`productId`,`clientId`),
	KEY `FK_PRODUCT_ON_CLIENT_HOST` (`clientId`),
	FOREIGN KEY (`clientId`)
		REFERENCES `HOST` (`hostId`)
		ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `PRODUCT_ON_DEPOT` (
	`productId` varchar(255) NOT NULL,
	`productVersion` varchar(32) NOT NULL,
	`packageVersion` varchar(16) NOT NULL,
	`depotId` varchar(255) NOT NULL,
	`productType` varchar(16) NOT NULL,
	`locked` tinyint(1) NOT NULL DEFAULT '0',
	PRIMARY KEY (`productId`,`productType`,`productVersion`,`packageVersion`,`depotId`),
	UNIQUE KEY `productId-depotId` (`productId`,`depotId`),
	KEY `productId-productVersion-packageVersion` (`productId`,`productVersion`,`packageVersion`),
	KEY `depotId` (`depotId`),
	KEY `index_product_on_depot_productType` (`productType`),
	FOREIGN KEY (`depotId`)
		REFERENCES `HOST` (`hostId`)
		ON DELETE CASCADE ON UPDATE CASCADE,
	FOREIGN KEY (`productId`, `productVersion`, `packageVersion`)
		REFERENCES `PRODUCT` (`productId`, `productVersion`, `packageVersion`)
		ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `PRODUCT_PROPERTY` (
	`productId` varchar(255) NOT NULL,
	`productVersion` varchar(32) NOT NULL,
	`packageVersion` varchar(16) NOT NULL,
	`propertyId` varchar(200) NOT NULL,
	`type` varchar(30) NOT NULL,
	`description` text,
	`multiValue` tinyint(1) NOT NULL DEFAULT '0',
	`editable` tinyint(1) NOT NULL DEFAULT '1',
	PRIMARY KEY (`productId`,`productVersion`,`packageVersion`,`propertyId`),
	KEY `index_product_property_type` (`type`),
	FOREIGN KEY (`productId`, `productVersion`, `packageVersion`)
		REFERENCES `PRODUCT` (`productId`, `productVersion`, `packageVersion`)
		ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `PRODUCT_PROPERTY_STATE` (
	`productId` varchar(255) NOT NULL,
	`propertyId` varchar(200) NOT NULL,
	`objectId` varchar(255) NOT NULL,
	`values` text,
	PRIMARY KEY (`productId`,`propertyId`,`objectId`),
	KEY `index_product_property_state_objectId` (`objectId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `PRODUCT_PROPERTY_VALUE` (
	`product_property_id` int(11) NOT NULL AUTO_INCREMENT,
	`productId` varchar(255) NOT NULL,
	`productVersion` varchar(32) NOT NULL,
	`packageVersion` varchar(16) NOT NULL,
	`propertyId` varchar(200) NOT NULL,
	`value` text,
	`isDefault` tinyint(1) DEFAULT NULL,
	PRIMARY KEY (`product_property_id`),
	KEY `index_product_property_value` (`productId`,`productVersion`,`packageVersion`,`propertyId`),
	FOREIGN KEY (`productId`, `productVersion`, `packageVersion`, `propertyId`)
		REFERENCES `PRODUCT_PROPERTY` (`productId`, `productVersion`, `packageVersion`, `propertyId`)
		ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `SOFTWARE` (
	`name` varchar(100) NOT NULL,
	`version` varchar(100) NOT NULL,
	`subVersion` varchar(100) NOT NULL,
	`language` varchar(10) NOT NULL,
	`architecture` varchar(3) NOT NULL,
	`windowsSoftwareId` varchar(100) DEFAULT NULL,
	`windowsDisplayName` varchar(100) DEFAULT NULL,
	`windowsDisplayVersion` varchar(100) DEFAULT NULL,
	`type` varchar(30) NOT NULL,
	`installSize` bigint(20) DEFAULT NULL,
	PRIMARY KEY (`name`,`version`,`subVersion`,`language`,`architecture`),
	KEY `index_software_windowsSoftwareId` (`windowsSoftwareId`),
	KEY `index_software_type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `SOFTWARE_CONFIG` (
	`clientId` varchar(255) NOT NULL,
	`name` varchar(100) NOT NULL,
	`version` varchar(100) NOT NULL,
	`subVersion` varchar(100) NOT NULL,
	`language` varchar(10) NOT NULL,
	`architecture` varchar(3) NOT NULL,
	`uninstallString` varchar(200) DEFAULT NULL,
	`binaryName` varchar(100) DEFAULT NULL,
	`firstseen` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`lastseen` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`state` tinyint(4) NOT NULL,
	`usageFrequency` int(11) NOT NULL DEFAULT '-1',
	`lastUsed` timestamp NULL DEFAULT NULL,
	`licenseKey` varchar(1024) DEFAULT NULL,
	PRIMARY KEY (`clientId`,`name`,`version`,`subVersion`,`language`,`architecture`),
	KEY `index_software_config_clientId` (`clientId`),
	KEY `index_software_config_nvsla` (`name`,`version`,`subVersion`,`language`,`architecture`),
	FOREIGN KEY (`clientId`)
		REFERENCES `HOST` (`hostId`)
		ON DELETE CASCADE ON UPDATE CASCADE,
	FOREIGN KEY (`name`, `version`, `subVersion`, `language`, `architecture`)
		REFERENCES `SOFTWARE` (`name`, `version`, `subVersion`, `language`, `architecture`)
		ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `SOFTWARE_LICENSE` (
	`softwareLicenseId` varchar(100) NOT NULL,
	`licenseContractId` varchar(100) NOT NULL,
	`type` varchar(30) NOT NULL,
	`boundToHost` varchar(255) DEFAULT NULL,
	`maxInstallations` int(11) NOT NULL DEFAULT '1',
	`expirationDate` timestamp NULL DEFAULT NULL,
	PRIMARY KEY (`softwareLicenseId`),
	KEY `licenseContractId` (`licenseContractId`),
	KEY `index_software_license_type` (`type`),
	KEY `index_software_license_boundToHost` (`boundToHost`),
	FOREIGN KEY (`licenseContractId`)
		REFERENCES `LICENSE_CONTRACT` (`licenseContractId`),
	FOREIGN KEY (`boundToHost`)
		REFERENCES `HOST` (`hostId`)
		ON DELETE SET NULL ON UPDATE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `SOFTWARE_LICENSE_TO_LICENSE_POOL` (
	`softwareLicenseId` varchar(100) NOT NULL,
	`licensePoolId` varchar(100) NOT NULL,
	`licenseKey` varchar(1024) DEFAULT NULL,
	PRIMARY KEY (`softwareLicenseId`,`licensePoolId`),
	KEY `licensePoolId` (`licensePoolId`),
	FOREIGN KEY (`softwareLicenseId`)
		REFERENCES `SOFTWARE_LICENSE` (`softwareLicenseId`),
	FOREIGN KEY (`licensePoolId`)
		REFERENCES `LICENSE_POOL` (`licensePoolId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `USER` (
	`userId` varchar(200) NOT NULL,
	`created` timestamp NULL DEFAULT NULL,
	`lastLogin` timestamp NULL DEFAULT NULL,
	`mfaState` varchar(16) DEFAULT NULL,
	`otpSecret` varchar(32) DEFAULT NULL,
	PRIMARY KEY (`userId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `WINDOWS_SOFTWARE_ID_TO_PRODUCT` (
	`windowsSoftwareId` varchar(100) NOT NULL,
	`productId` varchar(255) NOT NULL,
	PRIMARY KEY (`windowsSoftwareId`,`productId`),
	KEY `index_productId` (`productId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `LICENSE_ON_CLIENT` (
	`softwareLicenseId` varchar(100) NOT NULL,
	`licensePoolId` varchar(100) NOT NULL,
	`clientId` varchar(255) NOT NULL,
	`licenseKey` varchar(1024) DEFAULT NULL,
	`notes` varchar(1024) DEFAULT NULL,
	PRIMARY KEY (`softwareLicenseId`,`licensePoolId`,`clientId`),
	KEY `softwareLicenseId` (`softwareLicenseId`,`licensePoolId`),
	KEY `index_license_on_client_clientId` (`clientId`),
	FOREIGN KEY (`softwareLicenseId`, `licensePoolId`)
		REFERENCES `SOFTWARE_LICENSE_TO_LICENSE_POOL` (`softwareLicenseId`, `licensePoolId`),
	FOREIGN KEY (`clientId`)
		REFERENCES `HOST` (`hostId`)
		ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `AUDIT_SOFTWARE_TO_LICENSE_POOL` (
	`licensePoolId` varchar(100) NOT NULL,
	`name` varchar(100) NOT NULL,
	`version` varchar(100) NOT NULL,
	`subVersion` varchar(100) NOT NULL,
	`language` varchar(10) NOT NULL,
	`architecture` varchar(3) NOT NULL,
	PRIMARY KEY (`licensePoolId`,`name`,`version`,`subVersion`,`language`,`architecture`),
	KEY `licensePoolId` (`licensePoolId`),
	FOREIGN KEY (`licensePoolId`)
		REFERENCES `LICENSE_POOL` (`licensePoolId`)
		ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""


def create_audit_hardware_tables(  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
	session: Session, tables: dict[str, dict[str, dict[str, str | bool | None]]]
) -> None:
	from opsiconfd.backend.rpc.obj_audit_hardware import (  # pylint: disable=import-outside-toplevel
		get_audit_hardware_database_config,
	)

	existing_tables = set(tables.keys())

	for hw_class, values in get_audit_hardware_database_config().items():  # pylint: disable=too-many-nested-blocks
		logger.debug("Processing hardware class '%s'", hw_class)
		hardware_device_table_name = f"HARDWARE_DEVICE_{hw_class}"
		hardware_config_table_name = f"HARDWARE_CONFIG_{hw_class}"

		hardware_device_table_exists = hardware_device_table_name in existing_tables
		hardware_config_table_exists = hardware_config_table_name in existing_tables

		if hardware_device_table_exists:
			hardware_device_table = f"ALTER TABLE `{hardware_device_table_name}`\n"
		else:
			hardware_device_table = f"CREATE TABLE `{hardware_device_table_name}` (\n`hardware_id` INTEGER NOT NULL AUTO_INCREMENT,\n"

		if hardware_config_table_exists:
			hardware_config_table = f"ALTER TABLE `{hardware_config_table_name}`\n"
		else:
			hardware_config_table = (
				f"CREATE TABLE `{hardware_config_table_name}` (\n"
				f"`config_id` INTEGER NOT NULL AUTO_INCREMENT,\n"
				"`hostId` varchar(255) NOT NULL,\n"
				"`hardware_id` INTEGER NOT NULL,\n"
				"`firstseen` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,\n"
				"`lastseen` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,\n"
				"`state` TINYINT NOT NULL DEFAULT 1,\n"
			)

		hardware_device_values_processed = 0
		hardware_config_values_processed = 0
		for value, value_info in values.items():
			logger.debug("  Processing value '%s'", value)
			if value_info["Scope"] == "g":
				if hardware_device_table_exists:
					if value in tables[hardware_device_table_name]:
						# Column exists => change
						hardware_device_table += f"CHANGE `{value}` `{value}` {value_info['Type']} NULL,\n"
					else:
						# Column does not exist => add
						hardware_device_table += f'ADD `{value}` {value_info["Type"]} NULL,\n'
				else:
					hardware_device_table += f'`{value}` {value_info["Type"]} NULL,\n'
				hardware_device_values_processed += 1
			elif value_info["Scope"] == "i":
				if hardware_config_table_exists:
					if value in tables[hardware_config_table_name]:
						# Column exists => change
						hardware_config_table += f'CHANGE `{value}` `{value}` {value_info["Type"]} NULL,\n'
					else:
						# Column does not exist => add
						hardware_config_table += f'ADD `{value}` {value_info["Type"]} NULL,\n'
				else:
					hardware_config_table += f'`{value}` {value_info["Type"]} NULL,\n'
				hardware_config_values_processed += 1

		if not hardware_device_table_exists:
			hardware_device_table += "PRIMARY KEY (`hardware_id`)\n"
		if not hardware_config_table_exists:
			hardware_config_table += "PRIMARY KEY (`config_id`),\n"
			hardware_config_table += f"FOREIGN KEY (`hardware_id`) REFERENCES `{hardware_device_table_name}` (`hardware_id`) "
			hardware_config_table += "ON DELETE CASCADE ON UPDATE CASCADE\n"

		# Remove leading and trailing whitespace
		hardware_device_table = hardware_device_table.strip()
		hardware_config_table = hardware_config_table.strip()

		# Remove trailing comma
		if hardware_device_table.endswith(","):
			hardware_device_table = hardware_device_table[:-1]
		if hardware_config_table.endswith(","):
			hardware_config_table = hardware_config_table[:-1]

		# Finish sql query
		if hardware_device_table_exists:
			hardware_device_table += " ;\n"
		else:
			hardware_device_table += "\n) ENGINE=InnoDB DEFAULT CHARSET=utf8;\n"

		if hardware_config_table_exists:
			hardware_config_table += " ;\n"
		else:
			hardware_config_table += "\n) ENGINE=InnoDB DEFAULT CHARSET=utf8;\n"

		# Execute sql query
		if hardware_device_values_processed or not hardware_device_table_exists:
			logger.debug(hardware_device_table)
			session.execute(hardware_device_table)
		if hardware_config_values_processed or not hardware_config_table_exists:
			logger.debug(hardware_config_table)
			session.execute(hardware_config_table)
	session.commit()


def read_schema_version(session: Session) -> int | None:
	"""
	Read the version of the schema from the database.
	"""
	try:
		# Remove migration markers for failed migrations
		session.execute("DELETE FROM `OPSI_SCHEMA` WHERE `updateEnded` IS NULL OR `updateEnded` = '0000-00-00 00:00:00'")
		row = session.execute("SELECT MAX(`version`) FROM `OPSI_SCHEMA`").fetchone()
		if row and row[0] is not None:
			return int(row[0])
	except Exception as err:  # pylint: disable=broad-except
		logger.warning("Reading database schema version failed: %s", err)
	return None


def get_indexes(session: Session, database: str, table: str) -> dict[str, list[str]]:
	indexes = {}
	for res in session.execute(
		"SELECT INDEX_NAME, GROUP_CONCAT(`COLUMN_NAME` ORDER BY `SEQ_IN_INDEX` ASC) FROM `INFORMATION_SCHEMA`.`STATISTICS`"
		" WHERE `TABLE_SCHEMA` = :database AND `TABLE_NAME` = :table GROUP BY `INDEX_NAME`",
		params={"database": database, "table": table},
	).fetchall():
		indexes[res[0]] = res[1].split(",")
	return indexes


def create_index(session: Session, database: str, table: str, index: str, columns: list[str]) -> None:  # pylint: disable=too-many-branches
	logger.debug("Create index: table=%r, index=%r, columns=%r", table, index, columns)
	correct_indexes = []
	wrong_indexes = []
	cur_indexes = get_indexes(session=session, database=database, table=table)
	logger.debug("Current indexes: %s", cur_indexes)
	for name, cols in cur_indexes.items():
		if cols == columns:
			# Same colums in correct order
			if index != "PRIMARY" or name == index:
				# Same index name or name irrelevant
				correct_indexes.append(name)
			else:
				wrong_indexes.append(name)
		elif sorted(cols) == sorted(columns):
			# Same colums in wrong order
			wrong_indexes.append(name)
		elif name == index:
			# Primary INDEX with wrong columns
			wrong_indexes.append(name)

	logger.debug("Correct indexes: %s", correct_indexes)
	logger.debug("Wrong indexes: %s", wrong_indexes)

	for wrong_index in wrong_indexes:
		try:
			logger.debug("Dropping index %r", wrong_index)
			session.execute(f"ALTER TABLE `{table}` DROP INDEX `{wrong_index}`")
		except OperationalError as err:
			logger.warning("Failed to drop index %r on %r: %s", wrong_index, table, err)

	if correct_indexes:
		logger.debug("Keeping index %r", correct_indexes[0])
		return

	key = ",".join([f"`{c}`" for c in columns])
	if index == "PRIMARY":
		logger.info("Setting new PRIMARY KEY on table %r %r", table, key)
		session.execute(f"ALTER TABLE `{table}` ADD PRIMARY KEY ({key})")
	elif index == "UNIQUE":
		logger.info("Setting new UNIQUE KEY on table %r %r", table, key)
		session.execute(f"ALTER TABLE `{table}` ADD UNIQUE KEY ({key})")
	else:
		logger.info("Setting new index %r on table %r %r", index, table, key)
		session.execute(f"CREATE INDEX `{index}` on `{table}` ({key})")


def remove_index(session: Session, database: str, table: str, index: str) -> None:
	indexes = get_indexes(session=session, database=database, table=table)
	if index in indexes:
		logger.info("Removing index %r on table %r", index, table)
		session.execute(f"ALTER TABLE `{table}` DROP INDEX `{index}`")


UpdateRules = Literal["RESTRICT", "CASCADE", "NO ACTION", "SET NULL"]


@dataclass
class OpsiForeignKey:
	table: str
	ref_table: str
	f_keys: list[str] = field(default_factory=list)
	ref_keys: list[str] = field(default_factory=list)
	update_rule: UpdateRules = "CASCADE"
	delete_rule: UpdateRules = "CASCADE"

	def __post_init__(self) -> None:
		possible_rules: tuple[UpdateRules, ...] = ("RESTRICT", "CASCADE", "NO ACTION", "SET NULL")
		if self.update_rule not in possible_rules:
			raise ValueError("update_rule is not a valid update rule.")
		if self.delete_rule not in possible_rules:
			raise ValueError("delete_rule is not a valid delete rule.")


def create_foreign_key(session: Session, database: str, foreign_key: OpsiForeignKey, cleanup_function: Callable | None = None) -> None:
	keys = ",".join([f"`{k}`" for k in foreign_key.f_keys])
	if foreign_key.ref_keys:
		refs = ",".join([f"`{k}`" for k in foreign_key.ref_keys])
	else:
		refs = keys
	res = session.execute(
		"""
		SELECT DISTINCT `t1`.`CONSTRAINT_NAME`, t2.UPDATE_RULE, t2.DELETE_RULE FROM `INFORMATION_SCHEMA`.`KEY_COLUMN_USAGE` AS `t1`
		INNER JOIN `INFORMATION_SCHEMA`.`REFERENTIAL_CONSTRAINTS` AS `t2`
		ON `t1`.`CONSTRAINT_SCHEMA` = `t2`.`CONSTRAINT_SCHEMA` AND `t1`.`CONSTRAINT_NAME` = `t2`.`CONSTRAINT_NAME`
		WHERE `t1`.`TABLE_SCHEMA` = :database AND `t1`.`TABLE_NAME` = :table
		AND `t1`.`REFERENCED_TABLE_NAME` = :ref_table
		""",
		params={"database": database, "table": foreign_key.table, "ref_table": foreign_key.ref_table},
	).fetchone()
	if not res or res[1] != foreign_key.update_rule or res[2] != foreign_key.delete_rule:
		if res:
			logger.info("Removing foreign key to %s on table %s", foreign_key.ref_table, foreign_key.table)
			session.execute(f"ALTER TABLE `{foreign_key.table}` DROP FOREIGN KEY {res[0]}")
		if cleanup_function:
			cleanup_function(session=session)
		logger.info(
			"Creating foreign key to %s on table %s with ON UPDATE %s and ON DELETE %s",
			foreign_key.ref_table,
			foreign_key.table,
			foreign_key.update_rule,
			foreign_key.delete_rule,
		)
		session.execute(
			f"""
			ALTER TABLE `{foreign_key.table}` ADD
			FOREIGN KEY ({keys})
			REFERENCES `{foreign_key.ref_table}` ({refs})
			ON UPDATE {foreign_key.update_rule} ON DELETE {foreign_key.delete_rule}
			"""
		)


def read_database_schema(mysql: MySQLConnection, with_audit_hardware: bool = False) -> str:
	sql = ""
	with mysql.session() as session:
		tables = sorted(mysql.tables)
		for table in ("LICENSE_ON_CLIENT", "AUDIT_SOFTWARE_TO_LICENSE_POOL"):
			# Move to end for foreign keys
			tables.remove(table)
			tables.append(table)

		for table in tables:
			if not with_audit_hardware and table.startswith(("HARDWARE_DEVICE_", "HARDWARE_CONFIG_")):
				continue
			create = session.execute(f"SHOW CREATE TABLE `{table}`").fetchone()[1]
			create = re.sub(r"CREATE TABLE `", "CREATE TABLE IF NOT EXISTS `", create)
			create = re.sub(r"CONSTRAINT `[^`]+` FOREIGN KEY", "FOREIGN KEY", create)
			# Remove AUTO_INCREMENT, ENGINE, CHARSET, ...
			create = re.sub(r"\)\s*ENGINE.*", ") ENGINE=InnoDB DEFAULT CHARSET=utf8;\n", create)
			lines = create.splitlines(keepends=True)
			for idx, line in enumerate(lines):
				if line.startswith("  "):
					lines[idx] = "\t" + line.lstrip()
			sql = f"{sql}{''.join(lines)}\n"
	return sql.rstrip("\n") + "\n"


def create_database(mysql: MySQLConnection) -> None:
	with mysql.session() as session:
		session.execute(f"CREATE DATABASE IF NOT EXISTS `{mysql.database}`")


def drop_database(mysql: MySQLConnection) -> None:
	with mysql.session() as session:
		session.execute(f"DROP DATABASE IF EXISTS `{mysql.database}`")


def update_database(mysql: MySQLConnection, force: bool = False) -> None:  # pylint: disable=too-many-branches,too-many-statements
	with mysql.session() as session:
		session.execute(CREATE_TABLES_SQL)
		session.commit()

		create_audit_hardware_tables(session, mysql.tables)
		mysql.read_tables()

		schema_version = read_schema_version(session)
		logger.info("Current database schema version is %r", schema_version)

		if not schema_version or schema_version < mysql.schema_version:
			logger.notice("Starting update to schema version %r", mysql.schema_version)
			session.execute("INSERT INTO `OPSI_SCHEMA` (`version`) VALUES (:version)", params={"version": mysql.schema_version})

		if schema_version and schema_version >= mysql.schema_version:
			if force:
				logger.info("Database schema is up-to-date but update is forced")
			else:
				logger.info("Database schema is up-to-date")
				return

		logger.info("Running opsi 4.1 updates")

		if "BOOT_CONFIGURATION" in mysql.tables:
			logger.info("Dropping table BOOT_CONFIGURATION")
			session.execute("DROP TABLE IF EXISTS `BOOT_CONFIGURATION`")

		if "workbenchLocalUrl" not in mysql.tables["HOST"]:
			logger.info("Adding column 'workbenchLocalUrl' on table HOST.")
			session.execute("ALTER TABLE `HOST` ADD `workbenchLocalUrl` varchar(128)")

		if "workbenchRemoteUrl" not in mysql.tables["HOST"]:
			logger.info("Adding column 'workbenchRemoteUrl' on table HOST.")
			session.execute("ALTER TABLE `HOST` ADD `workbenchRemoteUrl` varchar(255)")

		if mysql.tables["OBJECT_TO_GROUP"]["groupId"]["type"] != "varchar(255)":
			logger.info("Changing size of column 'groupId' on table OBJECT_TO_GROUP")
			session.execute("ALTER TABLE `OBJECT_TO_GROUP` MODIFY COLUMN `groupId` varchar(255) NOT NULL")

		if mysql.tables["HOST"]["inventoryNumber"]["type"] != "varchar(64)":
			logger.info("Changing size of column 'inventoryNumber' on table HOST")
			session.execute('ALTER TABLE `HOST` MODIFY COLUMN `inventoryNumber` varchar(64) NOT NULL DEFAULT ""')

		create_index(
			session=session,
			database=mysql.database,
			table="WINDOWS_SOFTWARE_ID_TO_PRODUCT",
			index="index_productId",
			columns=["productId"],
		)

		create_index(
			session=session,
			database=mysql.database,
			table="PRODUCT",
			index="index_productId",
			columns=["productId"],
		)

		logger.info("Running opsi 4.2 updates")

		if mysql.tables["HOST"]["ipAddress"]["type"] != "varchar(255)":
			logger.info("Changing size of column 'ipAddress' on table HOST")
			session.execute("ALTER TABLE `HOST` MODIFY COLUMN `ipAddress` varchar(255)")

		logger.info("Running opsi 4.3 updates")

		for row in session.execute(
			"SELECT `TABLE_NAME`, `ENGINE`, `TABLE_COLLATION` FROM	`INFORMATION_SCHEMA`.`TABLES` WHERE `TABLE_SCHEMA` = :database",
			params={"database": mysql.database},
		).fetchall():
			row_dict = dict(row)
			if row_dict["ENGINE"] != "InnoDB":
				logger.info("Changing table %s to InnoDB engine", row_dict["TABLE_NAME"])
				session.execute(f"ALTER TABLE `{row_dict['TABLE_NAME']}` ENGINE = InnoDB")
			if row_dict["TABLE_COLLATION"] not in ("utf8_general_ci", "utf8mb3_general_ci", "utf8mb4_general_ci"):
				logger.info("Changing table %s to utf8_general_ci collation", row_dict["TABLE_NAME"])
				session.execute(f"ALTER TABLE `{row_dict['TABLE_NAME']}` DEFAULT COLLATE utf8_general_ci")

		session.execute(
			"""ALTER TABLE `HOST`
			MODIFY COLUMN `created` timestamp NULL DEFAULT NULL,
			MODIFY COLUMN `lastSeen` timestamp NULL DEFAULT NULL
			"""
		)
		if "systemUUID" not in mysql.tables["HOST"]:
			logger.info("Creating column 'systemUUID' on table HOST")
			session.execute("ALTER TABLE `HOST` ADD `systemUUID` varchar(36) NULL DEFAULT NULL AFTER `oneTimePassword`")
		create_index(
			session=session,
			database=mysql.database,
			table="HOST",
			index="UNIQUE",
			columns=["systemUUID"],
		)

		session.execute(
			"""ALTER TABLE `CONFIG`
			MODIFY COLUMN `multiValue` tinyint(1) NOT NULL DEFAULT 0,
			MODIFY COLUMN `editable` tinyint(1) NOT NULL DEFAULT 1
			"""
		)

		session.execute(
			"""ALTER TABLE `PRODUCT`
			MODIFY COLUMN `name` varchar(128) NOT NULL DEFAULT "",
			MODIFY COLUMN `licenseRequired` tinyint(1) NOT NULL DEFAULT 0,
			MODIFY COLUMN `priority` int(11) DEFAULT 0
			"""
		)

		session.execute(
			"""ALTER TABLE `PRODUCT_PROPERTY`
			MODIFY COLUMN `multiValue` tinyint(1) NOT NULL DEFAULT 0,
			MODIFY COLUMN `editable` tinyint(1) NOT NULL DEFAULT 1
			"""
		)

		session.execute("UPDATE `PRODUCT_ON_DEPOT` SET `locked` = 0 WHERE `locked` IS NULL")
		session.execute(
			"""ALTER TABLE `PRODUCT_ON_DEPOT`
			MODIFY COLUMN `locked` tinyint(1) NOT NULL DEFAULT 0
			"""
		)

		session.execute("UPDATE `PRODUCT_ON_CLIENT` SET `installationStatus` = 'not_installed' WHERE `installationStatus` IS NULL")
		session.execute("UPDATE `PRODUCT_ON_CLIENT` SET `actionRequest` = 'none' WHERE `actionRequest` IS NULL")
		session.execute(
			"""ALTER TABLE `PRODUCT_ON_CLIENT`
			MODIFY COLUMN `installationStatus` varchar(16) NOT NULL DEFAULT "not_installed",
			MODIFY COLUMN `actionRequest` varchar(16) NOT NULL DEFAULT "none"
			"""
		)

		session.execute(
			"""ALTER TABLE `SOFTWARE_CONFIG`
			MODIFY COLUMN `lastUsed` timestamp NULL DEFAULT NULL
			"""
		)

		session.execute("UPDATE `SOFTWARE_LICENSE` SET `maxInstallations` = 1 WHERE `maxInstallations` IS NULL")
		session.execute(
			"""ALTER TABLE `SOFTWARE_LICENSE`
			MODIFY COLUMN `maxInstallations` int(11) NOT NULL DEFAULT 1
			"""
		)

		create_index(
			session=session,
			database=mysql.database,
			table="PRODUCT_ON_CLIENT",
			index="PRIMARY",
			columns=["productId", "productType", "clientId"],
		)
		create_index(
			session=session,
			database=mysql.database,
			table="PRODUCT_ON_CLIENT",
			index="UNIQUE",
			columns=["productId", "clientId"],
		)
		create_foreign_key(
			session=session,
			database=mysql.database,
			foreign_key=OpsiForeignKey(table="PRODUCT_ON_CLIENT", ref_table="HOST", f_keys=["clientId"], ref_keys=["hostId"]),
		)

		create_index(
			session=session,
			database=mysql.database,
			table="PRODUCT_ON_DEPOT",
			index="PRIMARY",
			columns=["productId", "productType", "productVersion", "packageVersion", "depotId"],
		)
		create_index(session=session, database=mysql.database, table="PRODUCT_ON_DEPOT", index="UNIQUE", columns=["productId", "depotId"])
		create_foreign_key(
			session=session,
			database=mysql.database,
			foreign_key=OpsiForeignKey(table="PRODUCT_ON_DEPOT", ref_table="HOST", f_keys=["depotId"], ref_keys=["hostId"]),
			cleanup_function=remove_orphans_product_on_depot,
		)

		create_index(
			session=session,
			database=mysql.database,
			table="PRODUCT_PROPERTY_VALUE",
			index="index_product_property_value",
			columns=["productId", "productVersion", "packageVersion", "propertyId"],
		)

		create_foreign_key(
			session=session,
			database=mysql.database,
			foreign_key=OpsiForeignKey(
				table="PRODUCT_PROPERTY_VALUE",
				ref_table="PRODUCT_PROPERTY",
				f_keys=["productId", "productVersion", "packageVersion", "propertyId"],
			),
			cleanup_function=remove_orphans_product_property_value,
		)

		create_foreign_key(
			session=session,
			database=mysql.database,
			foreign_key=OpsiForeignKey(
				table="CONFIG_VALUE",
				ref_table="CONFIG",
				f_keys=["configId"],
			),
			cleanup_function=remove_orphans_config_value,
		)

		create_index(
			session=session,
			database=mysql.database,
			table="AUDIT_SOFTWARE_TO_LICENSE_POOL",
			index="PRIMARY",
			columns=["licensePoolId", "name", "version", "subVersion", "language", "architecture"],
		)

		if "config_state_id" in mysql.tables["CONFIG_STATE"]:
			logger.info("Removing duplicates from table CONFIG_STATE")
			duplicates = []
			for row in session.execute(
				"""
				SELECT GROUP_CONCAT(`config_state_id`) AS ids, COUNT(*) AS num
				FROM `CONFIG_STATE` GROUP BY `configId`, `objectId` HAVING num > 1
				"""
			).fetchall():
				ids = dict(row)["ids"].split(",")
				duplicates.extend(ids[1:])
			if duplicates:
				logger.info("Deleting duplicate config_state_ids: %s", duplicates)
				session.execute("DELETE FROM `CONFIG_STATE` WHERE `config_state_id` IN :ids", params={"ids": duplicates})

			logger.info("Dropping column 'config_state_id' from table CONFIG_STATE")
			session.execute("ALTER TABLE `CONFIG_STATE` DROP COLUMN `config_state_id`")

		create_index(
			session=session,
			database=mysql.database,
			table="CONFIG_STATE",
			index="PRIMARY",
			columns=["configId", "objectId"],
		)

		if "license_on_client_id" in mysql.tables["LICENSE_ON_CLIENT"]:
			session.execute("DELETE FROM `LICENSE_ON_CLIENT` WHERE `clientId` IS NULL")
			session.execute("ALTER TABLE `LICENSE_ON_CLIENT` MODIFY COLUMN `clientId` varchar(255) NOT NULL")

			logger.info("Removing duplicates from table LICENSE_ON_CLIENT")
			duplicates = []
			for row in session.execute(
				"""
				SELECT GROUP_CONCAT(`license_on_client_id`) AS ids, COUNT(*) AS num
				FROM `LICENSE_ON_CLIENT` GROUP BY `softwareLicenseId`, `licensePoolId`, `clientId` HAVING num > 1
				"""
			).fetchall():
				ids = dict(row)["ids"].split(",")
				duplicates.extend(ids[1:])
			if duplicates:
				logger.info("Deleting duplicate license_on_client_ids: %s", duplicates)
				session.execute(
					"DELETE FROM `LICENSE_ON_CLIENT` WHERE `license_on_client_id` IN :ids",
					params={"ids": duplicates},
				)

			logger.info("Dropping column 'license_on_client_id' from table LICENSE_ON_CLIENT")
			session.execute("ALTER TABLE `LICENSE_ON_CLIENT` DROP COLUMN `license_on_client_id`")

		create_index(
			session=session,
			database=mysql.database,
			table="LICENSE_ON_CLIENT",
			index="PRIMARY",
			columns=["softwareLicenseId", "licensePoolId", "clientId"],
		)

		if "object_to_group_id" in mysql.tables["OBJECT_TO_GROUP"]:
			logger.info("Removing duplicates from table OBJECT_TO_GROUP")
			duplicates = []
			for row in session.execute(
				"""
				SELECT GROUP_CONCAT(`object_to_group_id`) AS ids, COUNT(*) AS num
				FROM `OBJECT_TO_GROUP` GROUP BY `groupType`, `groupId`, `objectId` HAVING num > 1
				"""
			).fetchall():
				ids = dict(row)["ids"].split(",")
				duplicates.extend(ids[1:])
			if duplicates:
				logger.info("Deleting duplicate object_to_group_ids: %s", duplicates)
				session.execute(
					"DELETE FROM `OBJECT_TO_GROUP` WHERE `object_to_group_id` IN :ids",
					params={"ids": duplicates},
				)

			logger.info("Dropping column 'object_to_group_id' from table OBJECT_TO_GROUP")
			session.execute("ALTER TABLE `OBJECT_TO_GROUP` DROP COLUMN `object_to_group_id`")

		create_index(
			session=session,
			database=mysql.database,
			table="OBJECT_TO_GROUP",
			index="PRIMARY",
			columns=["groupType", "groupId", "objectId"],
		)

		if "product_property_state_id" in mysql.tables["PRODUCT_PROPERTY_STATE"]:
			session.execute("DELETE FROM `PRODUCT_PROPERTY_STATE` WHERE `productId` IS NULL")
			session.execute("ALTER TABLE `PRODUCT_PROPERTY_STATE` MODIFY COLUMN `productId` varchar(255) NOT NULL")

			logger.info("Removing duplicates from table PRODUCT_PROPERTY_STATE")
			duplicates = []
			for row in session.execute(
				"""
				SELECT GROUP_CONCAT(`product_property_state_id`) AS ids, COUNT(*) AS num
				FROM `PRODUCT_PROPERTY_STATE` GROUP BY `productId`, `propertyId`, `objectId` HAVING num > 1
				"""
			).fetchall():
				ids = dict(row)["ids"].split(",")
				duplicates.extend(ids[1:])
			if duplicates:
				logger.info("Deleting duplicate product_property_state_ids: %s", duplicates)
				session.execute(
					"DELETE FROM `PRODUCT_PROPERTY_STATE` WHERE `product_property_state_id` IN :ids",
					params={"ids": duplicates},
				)

			logger.info("Dropping column 'product_property_state_id' from table PRODUCT_PROPERTY_STATE")
			session.execute("ALTER TABLE `PRODUCT_PROPERTY_STATE` DROP COLUMN `product_property_state_id`")

		create_index(
			session=session,
			database=mysql.database,
			table="PRODUCT_PROPERTY_STATE",
			index="PRIMARY",
			columns=["productId", "propertyId", "objectId"],
		)

		if "config_id" in mysql.tables["SOFTWARE_CONFIG"]:
			logger.info("Removing duplicates from table SOFTWARE_CONFIG")
			duplicates = []
			for row in session.execute(
				"""
				SELECT GROUP_CONCAT(`config_id`) AS ids, COUNT(*) AS num
				FROM `SOFTWARE_CONFIG` GROUP BY `clientId`, `name`, `version`, `subVersion`, `language`, `architecture` HAVING num > 1
				"""
			).fetchall():
				ids = dict(row)["ids"].split(",")
				duplicates.extend(ids[1:])
			if duplicates:
				logger.info("Deleting duplicate config_ids: %s", duplicates)
				session.execute(
					"DELETE FROM `SOFTWARE_CONFIG` WHERE `config_id` IN :ids",
					params={"ids": duplicates},
				)

			logger.info("Dropping column 'config_id' from table SOFTWARE_CONFIG")
			session.execute("ALTER TABLE `SOFTWARE_CONFIG` DROP COLUMN `config_id`")

		create_index(
			session=session,
			database=mysql.database,
			table="SOFTWARE_CONFIG",
			index="PRIMARY",
			columns=["clientId", "name", "version", "subVersion", "language", "architecture"],
		)

		def cleanup_software_config(session: Session) -> None:
			result = session.execute(
				"""
				SELECT c.name, c.version, c.subVersion, c.`language`, c.architecture
				FROM SOFTWARE_CONFIG AS c
				LEFT JOIN SOFTWARE AS s ON
					s.name = c.name AND s.version = c.version AND s.subVersion = c.subVersion AND
					s.`language` = c.`language` AND	s.architecture = c.architecture
				LEFT JOIN HOST AS h ON h.hostId = c.clientId
				WHERE s.name IS NULL OR h.hostId IS NULL
				"""
			).fetchall()
			if result:
				logger.info("Removing orphan entries from SOFTWARE_CONFIG")
				for row in result:
					session.execute(
						"""
						DELETE FROM SOFTWARE_CONFIG
						WHERE name = :name AND version = :version AND subVersion = :subVersion
							AND `language` = :language AND architecture = :architecture
						""",
						params=dict(row),
					)

		create_foreign_key(
			session=session,
			database=mysql.database,
			foreign_key=OpsiForeignKey(
				table="SOFTWARE_CONFIG",
				ref_table="SOFTWARE",
				f_keys=["name", "version", "subVersion", "language", "architecture"],
			),
			cleanup_function=cleanup_software_config,
		)

		create_foreign_key(
			session=session,
			database=mysql.database,
			foreign_key=OpsiForeignKey(
				table="SOFTWARE_CONFIG",
				f_keys=["clientId"],
				ref_table="HOST",
				ref_keys=["hostId"],
			),
			cleanup_function=cleanup_software_config,
		)

		create_foreign_key(
			session=session,
			database=mysql.database,
			foreign_key=OpsiForeignKey(
				table="PRODUCT_ON_DEPOT", ref_table="PRODUCT", f_keys=["productId", "productVersion", "packageVersion"]
			),
		)

		create_foreign_key(
			session=session,
			database=mysql.database,
			foreign_key=OpsiForeignKey(
				table="PRODUCT_PROPERTY", ref_table="PRODUCT", f_keys=["productId", "productVersion", "packageVersion"]
			),
		)

		create_foreign_key(
			session=session,
			database=mysql.database,
			foreign_key=OpsiForeignKey(
				table="PRODUCT_DEPENDENCY", ref_table="PRODUCT", f_keys=["productId", "productVersion", "packageVersion"]
			),
		)

		create_foreign_key(
			session=session,
			database=mysql.database,
			foreign_key=OpsiForeignKey(
				table="OBJECT_TO_GROUP", ref_table="GROUP", f_keys=["groupType", "groupId"], ref_keys=["type", "groupId"]
			),
		)

		create_foreign_key(
			session=session,
			database=mysql.database,
			foreign_key=OpsiForeignKey(table="AUDIT_SOFTWARE_TO_LICENSE_POOL", ref_table="LICENSE_POOL", f_keys=["licensePoolId"]),
		)

		create_foreign_key(
			session=session,
			database=mysql.database,
			foreign_key=OpsiForeignKey(table="LICENSE_ON_CLIENT", ref_table="HOST", f_keys=["clientId"], ref_keys=["hostId"]),
			cleanup_function=remove_orphans_license_on_client_to_host,
		)

		create_foreign_key(
			session=session,
			database=mysql.database,
			foreign_key=OpsiForeignKey(
				table="PRODUCT_ID_TO_LICENSE_POOL", ref_table="LICENSE_POOL", f_keys=["licensePoolId"], ref_keys=["licensePoolId"]
			),
			cleanup_function=remove_orphans_product_id_to_license_pool,
		)

		def software_license_set_missing_hosts_to_null(session: Session) -> None:
			session.execute(
				"""
				UPDATE `SOFTWARE_LICENSE` SET `boundToHost` = NULL
				WHERE boundToHost NOT IN (SELECT hostId FROM HOST)
				""",
				params={"version": mysql.schema_version},
			)

		create_foreign_key(
			session=session,
			database=mysql.database,
			foreign_key=OpsiForeignKey(
				table="SOFTWARE_LICENSE",
				ref_table="HOST",
				f_keys=["boundToHost"],
				ref_keys=["hostId"],
				update_rule="SET NULL",
				delete_rule="SET NULL",
			),
			cleanup_function=software_license_set_missing_hosts_to_null,
		)

		if "LOG_CONFIG_VALUE" in mysql.tables:
			logger.info("Dropping table LOG_CONFIG_VALUE")
			session.execute("DROP TABLE IF EXISTS `LOG_CONFIG_VALUE`")

		if "LOG_CONFIG" in mysql.tables:
			logger.info("Dropping table LOG_CONFIG")
			session.execute("DROP TABLE IF EXISTS `LOG_CONFIG`")

		if "CONFIG_STATE_LOG" in mysql.tables:
			logger.info("Dropping table CONFIG_STATE_LOG")
			session.execute("DROP TABLE IF EXISTS `CONFIG_STATE_LOG`")

		remove_orphans_hardware_config(mysql, session)
		for table in mysql.tables:
			if table.startswith("HARDWARE_CONFIG_"):
				# Set DEFAULT 1
				session.execute(f"ALTER TABLE `{table}` MODIFY COLUMN `state` TINYINT NOT NULL DEFAULT 1")
				session.execute(f"DELETE FROM `{table}` WHERE state != 1")
				ref_table = table.replace("HARDWARE_CONFIG_", "HARDWARE_DEVICE_")
				create_foreign_key(
					session=session,
					database=mysql.database,
					foreign_key=OpsiForeignKey(table=table, ref_table=ref_table, f_keys=["hardware_id"], ref_keys=["hardware_id"]),
				)

		logger.info("All updates completed")

		if not schema_version or schema_version < mysql.schema_version:
			logger.notice("Finished update to schema version %r", mysql.schema_version)
			session.execute(
				"UPDATE `OPSI_SCHEMA` SET `updateEnded` = CURRENT_TIMESTAMP WHERE version = :version",
				params={"version": mysql.schema_version},
			)
