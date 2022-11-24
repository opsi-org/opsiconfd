# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.mysql.schema
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from opsiconfd.logging import logger

from .cleanup import remove_orphans_config_value, remove_orphans_product_property_value

if TYPE_CHECKING:
	from . import MySQLConnection, Session


def read_schema_version(session: Session) -> int | None:
	"""
	Read the version of the schema from the database.
	"""
	try:
		# Remove migration markers for failed migrations
		session.execute("DELETE FROM `OPSI_SCHEMA` WHERE `updateEnded` IS NULL OR `updateEnded` = '0000-00-00 00:00:00'")
		row = session.execute("SELECT MAX(`version`) FROM `OPSI_SCHEMA`").fetchone()
		if row:
			return int(row[0])
	except Exception as err:  # pylint: disable=broad-except
		logger.warning("Reading database schema version failed: %s", err)
	return None


def get_index_columns(session: Session, database: str, table: str, index: str) -> list[str]:
	res = session.execute(
		"SELECT GROUP_CONCAT(`COLUMN_NAME` ORDER BY `SEQ_IN_INDEX` ASC) FROM `INFORMATION_SCHEMA`.`STATISTICS`"
		" WHERE `TABLE_SCHEMA` = :database AND `TABLE_NAME` = :table AND `INDEX_NAME` = :index",
		params={"database": database, "table": table, "index": index},
	).fetchone()
	if not res or not res[0]:
		return []
	return res[0].split(",")


def create_index(session: Session, database: str, table: str, index: str, columns: list[str]) -> None:
	index_columns = get_index_columns(session=session, database=database, table=table, index=index)
	if index_columns != columns:
		key = ",".join([f"`{c}`" for c in columns])
		if index == "PRIMARY":
			logger.notice("Setting new PRIMARY KEY on table %r", table)
			if index_columns:
				session.execute(f"ALTER TABLE `{table}` DROP PRIMARY KEY")
			session.execute(f"ALTER TABLE `{table}` ADD PRIMARY KEY ({key})")
		else:
			logger.notice("Setting new index %r on table %r", index, table)
			if index_columns:
				session.execute(f"ALTER TABLE `{table}` DROP INDEX `{index}`")
			session.execute(f"CREATE INDEX `{index}` on `{table}` ({key})")


def remove_index(session: Session, database: str, table: str, index: str) -> None:
	index_columns = get_index_columns(session=session, database=database, table=table, index=index)
	if index_columns:
		logger.notice("Removing index %r on table %r", index, table)
		session.execute(f"ALTER TABLE `{table}` DROP INDEX `{index}`")


def update_database(mysql: MySQLConnection) -> None:  # pylint: disable=too-many-branches,too-many-statements
	with mysql.session() as session:

		schema_version = read_schema_version(session)
		logger.info("Current database schema version is %r", schema_version)

		if not schema_version or schema_version < mysql.schema_version:
			logger.notice("Starting update to schema version %r", mysql.schema_version)
			session.execute("INSERT INTO `OPSI_SCHEMA` (`version`) VALUES (:version)", params={"version": mysql.schema_version})

		logger.info("Running opsi 4.1 updates")

		if "BOOT_CONFIGURATION" in mysql.tables:
			logger.notice("Dropping table BOOT_CONFIGURATION")
			session.execute("DROP TABLE IF EXISTS `BOOT_CONFIGURATION`")

		if "workbenchLocalUrl" not in mysql.tables["HOST"]:
			logger.notice("Adding column 'workbenchLocalUrl' on table HOST.")
			session.execute("ALTER TABLE `HOST` add `workbenchLocalUrl` varchar(128)")

		if "workbenchRemoteUrl" not in mysql.tables["HOST"]:
			logger.notice("Adding column 'workbenchRemoteUrl' on table HOST.")
			session.execute("ALTER TABLE `HOST` add `workbenchRemoteUrl` varchar(255)")

		if mysql.tables["OBJECT_TO_GROUP"]["groupId"]["type"] != "varchar(255)":
			logger.notice("Changing size of column 'groupId' on table OBJECT_TO_GROUP")
			session.execute("ALTER TABLE `OBJECT_TO_GROUP` MODIFY COLUMN `groupId` varchar(255) NOT NULL")

		if mysql.tables["HOST"]["inventoryNumber"]["type"] != "varchar(64)":
			logger.notice("Changing size of column 'inventoryNumber' on table HOST")
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
			logger.notice("Changing size of column 'ipAddress' on table HOST")
			session.execute("ALTER TABLE `HOST` MODIFY COLUMN `ipAddress` varchar(255)")

		logger.info("Running opsi 4.3 updates")

		for row in session.execute(
			"SELECT `TABLE_NAME`, `ENGINE`, `TABLE_COLLATION` FROM  `INFORMATION_SCHEMA`.`TABLES` WHERE `TABLE_SCHEMA` = :database",
			params={"database": mysql.database},
		).fetchall():
			row_dict = dict(row)
			if row_dict["ENGINE"] != "InnoDB":
				logger.notice("Changing table %s to InnoDB engine", row_dict["TABLE_NAME"])
				session.execute(f"ALTER TABLE `{row_dict['TABLE_NAME']}` ENGINE = InnoDB")
			if row_dict["TABLE_COLLATION"] != "utf8_general_ci":
				logger.notice("Changing table %s to utf8_general_ci collation", row_dict["TABLE_NAME"])
				session.execute(f"ALTER TABLE `{row_dict['TABLE_NAME']}` DEFAULT COLLATE utf8_general_ci")

		create_index(
			session=session,
			database=mysql.database,
			table="PRODUCT_PROPERTY_VALUE",
			index="index_product_property_value",
			columns=["productId", "propertyId", "productVersion", "packageVersion"],
		)

		res = session.execute(
			"""
			SELECT DISTINCT `t1`.`CONSTRAINT_NAME`, t2.DELETE_RULE FROM `INFORMATION_SCHEMA`.`KEY_COLUMN_USAGE` AS `t1`
			INNER JOIN `INFORMATION_SCHEMA`.`REFERENTIAL_CONSTRAINTS` AS `t2` ON `t1`.`CONSTRAINT_NAME` = `t2`.`CONSTRAINT_NAME`
			WHERE `t1`.`REFERENCED_TABLE_SCHEMA` = :database AND `t1`.`TABLE_NAME` = 'PRODUCT_PROPERTY_VALUE'
			AND `t1`.`REFERENCED_TABLE_NAME` = 'PRODUCT_PROPERTY'
			""",
			params={"database": mysql.database},
		).fetchone()
		if not res or res[1] == "RESTRICT":
			if res:
				logger.notice("Removing FK to PRODUCT_PROPERTY on table PRODUCT_PROPERTY_VALUE with RESTRICT")
				session.execute(f"ALTER TABLE `PRODUCT_PROPERTY_VALUE` DROP FOREIGN KEY `{res[0]}`")

			remove_orphans_product_property_value(session=session, dry_run=False)
			logger.notice("Creating FK to PRODUCT_PROPERTY on table PRODUCT_PROPERTY_VALUE with CASCADE")
			session.execute(
				"""
				ALTER TABLE `PRODUCT_PROPERTY_VALUE` ADD CONSTRAINT `FK_PRODUCT_PROPERTY`
				FOREIGN KEY (`productId`, `productVersion`, `packageVersion`, `propertyId`)
				REFERENCES `PRODUCT_PROPERTY` (`productId`, `productVersion`, `packageVersion`, `propertyId`)
				ON UPDATE CASCADE ON DELETE CASCADE
				"""
			)

		res = session.execute(
			"""
			SELECT DISTINCT `t1`.`CONSTRAINT_NAME`, t2.DELETE_RULE FROM `INFORMATION_SCHEMA`.`KEY_COLUMN_USAGE` AS `t1`
			INNER JOIN `INFORMATION_SCHEMA`.`REFERENTIAL_CONSTRAINTS` AS `t2` ON `t1`.`CONSTRAINT_NAME` = `t2`.`CONSTRAINT_NAME`
			WHERE `t1`.`REFERENCED_TABLE_SCHEMA` = :database AND `t1`.`TABLE_NAME` = 'CONFIG_VALUE'
			AND `t1`.`REFERENCED_TABLE_NAME` = 'CONFIG'
			""",
			params={"database": mysql.database},
		).fetchone()
		if not res or res[1] == "RESTRICT":
			remove_orphans_config_value(session=session, dry_run=False)
			if res:
				logger.notice("Removing FK to CONFIG on table CONFIG_VALUE with RESTRICT")
				session.execute(f"ALTER TABLE `CONFIG_VALUE` DROP FOREIGN KEY `{res[0]}`")

			logger.notice("Creating FK to CONFIG on table CONFIG_VALUE with CASCADE")
			session.execute(
				"""
				ALTER TABLE `CONFIG_VALUE` ADD CONSTRAINT `FK_CONFIG`
				FOREIGN KEY (`configId`)
				REFERENCES `CONFIG` (`configId`)
				ON UPDATE CASCADE ON DELETE CASCADE
				"""
			)

		create_index(
			session=session,
			database=mysql.database,
			table="AUDIT_SOFTWARE_TO_LICENSE_POOL",
			index="PRIMARY",
			columns=["licensePoolId", "name", "version", "subVersion", "language", "architecture"],
		)

		if "config_state_id" in mysql.tables["CONFIG_STATE"]:
			logger.notice("Removing duplicates from table CONFIG_STATE")
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
				logger.notice("Deleting duplicate config_state_ids: %s", duplicates)
				session.execute("DELETE FROM `CONFIG_STATE` WHERE `config_state_id` IN :ids", params={"ids": duplicates})

			logger.notice("Dropping column 'config_state_id' from table CONFIG_STATE")
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

			logger.notice("Removing duplicates from table LICENSE_ON_CLIENT")
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
				logger.notice("Deleting duplicate license_on_client_ids: %s", duplicates)
				session.execute(
					"DELETE FROM `LICENSE_ON_CLIENT` WHERE `license_on_client_id` IN :ids",
					params={"ids": duplicates},
				)

			logger.notice("Dropping column 'license_on_client_id' from table LICENSE_ON_CLIENT")
			session.execute("ALTER TABLE `LICENSE_ON_CLIENT` DROP COLUMN `license_on_client_id`")

		create_index(
			session=session,
			database=mysql.database,
			table="LICENSE_ON_CLIENT",
			index="PRIMARY",
			columns=["softwareLicenseId", "licensePoolId", "clientId"],
		)

		if "object_to_group_id" in mysql.tables["OBJECT_TO_GROUP"]:
			logger.notice("Removing duplicates from table OBJECT_TO_GROUP")
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
				logger.notice("Deleting duplicate object_to_group_ids: %s", duplicates)
				session.execute(
					"DELETE FROM `OBJECT_TO_GROUP` WHERE `object_to_group_id` IN :ids",
					params={"ids": duplicates},
				)

			logger.notice("Dropping column 'object_to_group_id' from table OBJECT_TO_GROUP")
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

			logger.notice("Removing duplicates from table PRODUCT_PROPERTY_STATE")
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
				logger.notice("Deleting duplicate product_property_state_ids: %s", duplicates)
				session.execute(
					"DELETE FROM `PRODUCT_PROPERTY_STATE` WHERE `product_property_state_id` IN :ids",
					params={"ids": duplicates},
				)

			logger.notice("Dropping column 'product_property_state_id' from table PRODUCT_PROPERTY_STATE")
			session.execute("ALTER TABLE `PRODUCT_PROPERTY_STATE` DROP COLUMN `product_property_state_id`")

		create_index(
			session=session,
			database=mysql.database,
			table="PRODUCT_PROPERTY_STATE",
			index="PRIMARY",
			columns=["productId", "propertyId", "objectId"],
		)

		if "config_id" in mysql.tables["SOFTWARE_CONFIG"]:
			logger.notice("Removing duplicates from table SOFTWARE_CONFIG")
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
				logger.notice("Deleting duplicate config_ids: %s", duplicates)
				session.execute(
					"DELETE FROM `SOFTWARE_CONFIG` WHERE `config_id` IN :ids",
					params={"ids": duplicates},
				)

			logger.notice("Dropping column 'config_id' from table SOFTWARE_CONFIG")
			session.execute("ALTER TABLE `SOFTWARE_CONFIG` DROP COLUMN `config_id`")

		create_index(
			session=session,
			database=mysql.database,
			table="SOFTWARE_CONFIG",
			index="PRIMARY",
			columns=["clientId", "name", "version", "subVersion", "language", "architecture"],
		)

		res = session.execute(
			"""
			SELECT DISTINCT `CONSTRAINT_NAME` FROM `INFORMATION_SCHEMA`.`KEY_COLUMN_USAGE`
			WHERE `REFERENCED_TABLE_SCHEMA` = :database AND `TABLE_NAME` = 'SOFTWARE_CONFIG'
			""",
			params={"database": mysql.database},
		).fetchall()
		fk_names = []  # pylint: disable=use-tuple-over-list
		if res:
			fk_names = [r[0] for r in res]

		if "FK_HOST" not in fk_names or "FK_SOFTWARE" not in fk_names:
			res = session.execute(
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
			if res:
				logger.notice("Removing orphan entries from SOFTWARE_CONFIG")
				for row in res:
					session.execute(
						"""
						DELETE FROM SOFTWARE_CONFIG
						WHERE name = :name AND version = :version AND subVersion = :subVersion
							AND `language` = :language AND architecture = :architecture
						""",
						params=dict(row),
					)

			if "FK_SOFTWARE" not in fk_names:
				session.execute(
					"""
					ALTER TABLE `SOFTWARE_CONFIG` ADD CONSTRAINT `FK_SOFTWARE`
					FOREIGN KEY (`name`, `version`, `subVersion`, `language`, `architecture`)
					REFERENCES `SOFTWARE` (`name`, `version`, `subVersion`, `language`, `architecture`)
					ON UPDATE CASCADE ON DELETE CASCADE
					"""
				)
			if "FK_HOST" not in fk_names:
				session.execute(
					"""
					ALTER TABLE `SOFTWARE_CONFIG` ADD CONSTRAINT `FK_HOST`
					FOREIGN KEY (`clientId`)
					REFERENCES `HOST` (`hostId`)
					ON UPDATE CASCADE ON DELETE CASCADE
					"""
				)

		if "LOG_CONFIG_VALUE" in mysql.tables:
			logger.notice("Dropping table LOG_CONFIG_VALUE")
			session.execute("DROP TABLE IF EXISTS `LOG_CONFIG_VALUE`")

		if "LOG_CONFIG" in mysql.tables:
			logger.notice("Dropping table LOG_CONFIG")
			session.execute("DROP TABLE IF EXISTS `LOG_CONFIG`")

		if "CONFIG_STATE_LOG" in mysql.tables:
			logger.notice("Dropping table CONFIG_STATE_LOG")
			session.execute("DROP TABLE IF EXISTS `CONFIG_STATE_LOG`")

		logger.info("All updates completed")

		if not schema_version or schema_version < mysql.schema_version:
			logger.notice("Setting updateEnded for schema version %r", mysql.schema_version)
			session.execute(
				"UPDATE `OPSI_SCHEMA` SET `updateEnded` = CURRENT_TIMESTAMP WHERE version = :version",
				params={"version": mysql.schema_version},
			)
