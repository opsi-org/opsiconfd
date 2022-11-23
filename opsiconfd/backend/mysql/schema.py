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


def update_database(mysql: MySQLConnection) -> None:
	with mysql.session() as session:

		schema_version = read_schema_version(session)
		logger.info("Current database schema version is %r", schema_version)

		if not schema_version or schema_version < mysql.schema_version:
			logger.notice("Starting update to schema version %r", mysql.schema_version)
			session.execute("INSERT INTO `OPSI_SCHEMA` (`version`) VALUES (:version)", params={"version": mysql.schema_version})

		logger.info("Running opsi 4.1 updates")

		if "BOOT_CONFIGURATION" in mysql.tables:
			logger.info("Dropping table BOOT_CONFIGURATION")
			session.execute("DROP TABLE IF EXISTS `BOOT_CONFIGURATION`")

		if not session.execute(
			"SELECT 1 FROM `INFORMATION_SCHEMA`.`STATISTICS`"
			" WHERE `TABLE_SCHEMA` = :database AND `TABLE_NAME` = 'PRODUCT_PROPERTY_VALUE' AND `INDEX_NAME` = 'index_product_property_value'",
			params={"database": mysql.database},
		).first():
			logger.info("Creating index index_product_property_value on table PRODUCT_PROPERTY_VALUE")
			session.execute(
				"CREATE INDEX `index_product_property_value` on `PRODUCT_PROPERTY_VALUE`"
				" (`productId`, `propertyId`, `productVersion`, `packageVersion`)"
			)

		if "workbenchLocalUrl" not in mysql.tables["HOST"]:
			logger.info("Adding column 'workbenchLocalUrl' on table HOST.")
			session.execute("ALTER TABLE `HOST` add `workbenchLocalUrl` varchar(128)")

		if "workbenchRemoteUrl" not in mysql.tables["HOST"]:
			logger.info("Adding column 'workbenchRemoteUrl' on table HOST.")
			session.execute("ALTER TABLE `HOST` add `workbenchRemoteUrl` varchar(255)")

		if mysql.tables["OBJECT_TO_GROUP"]["groupId"]["type"] != "varchar(255)":
			logger.info("Changing size of column 'groupId' on table OBJECT_TO_GROUP")
			session.execute("ALTER TABLE `OBJECT_TO_GROUP` MODIFY COLUMN `groupId` varchar(255) NOT NULL")

		if mysql.tables["HOST"]["inventoryNumber"]["type"] != "varchar(64)":
			logger.info("Changing size of column 'inventoryNumber' on table HOST")
			session.execute('ALTER TABLE `HOST` MODIFY COLUMN `inventoryNumber` varchar(64) NOT NULL DEFAULT ""')

		if "bigint" not in mysql.tables["SOFTWARE_CONFIG"]["config_id"]["type"]:  # type: ignore[operator]
			logger.info("Changing the type of SOFTWARE_CONFIG.config_id to bigint")
			session.execute("ALTER TABLE `SOFTWARE_CONFIG` MODIFY COLUMN `config_id` bigint auto_increment;")

		if not session.execute(
			"SELECT 1 FROM `INFORMATION_SCHEMA`.`STATISTICS`"
			" WHERE `TABLE_SCHEMA` = :database AND `TABLE_NAME` = 'WINDOWS_SOFTWARE_ID_TO_PRODUCT' AND `INDEX_NAME` = 'index_productId'",
			params={"database": mysql.database},
		).first():
			logger.info("Creating index index_productId on table WINDOWS_SOFTWARE_ID_TO_PRODUCT")
			session.execute("CREATE INDEX `index_productId` on `WINDOWS_SOFTWARE_ID_TO_PRODUCT` (`productId`)")

		if not session.execute(
			"SELECT 1 FROM `INFORMATION_SCHEMA`.`STATISTICS`"
			" WHERE `TABLE_SCHEMA` = :database AND `TABLE_NAME` = 'PRODUCT' AND `INDEX_NAME` = 'index_productId'",
			params={"database": mysql.database},
		).first():
			logger.info("Creating index index_productId on table PRODUCT")
			session.execute("CREATE INDEX `index_productId` on `PRODUCT` (`productId`)")

		logger.info("Running opsi 4.2 updates")

		if mysql.tables["HOST"]["ipAddress"]["type"] != "varchar(255)":
			logger.info("Changing size of column 'ipAddress' on table HOST")
			session.execute("ALTER TABLE `HOST` MODIFY COLUMN `ipAddress` varchar(255)")

		logger.info("Running opsi 4.3 updates")

		if "config_state_id" in mysql.tables["CONFIG_STATE"]:
			logger.info("Removing duplicates from table CONFIG_STATE")
			duplicates = []
			for row in session.execute(
				"SELECT GROUP_CONCAT(`config_state_id`) AS config_state_ids, `configId`, `objectId`, `values`, COUNT(*) AS num"
				" FROM `CONFIG_STATE` GROUP BY `configId`, `objectId` HAVING num > 1"
			).fetchall():
				config_state_ids = dict(row)["config_state_ids"].split(",")
				duplicates.extend(config_state_ids[1:])
			if duplicates:
				logger.info("Deleting duplicate config_state_ids: %s", duplicates)
				session.execute(
					"DELETE FROM `CONFIG_STATE` WHERE `config_state_id` IN :config_state_id", params={"config_state_id": duplicates}
				)

			logger.info("Dropping column 'config_state_id' from table CONFIG_STATE")
			session.execute("ALTER TABLE `CONFIG_STATE` DROP COLUMN `config_state_id`")

			logger.info("Adding new PRIMARY KEY to table CONFIG_STATE (`configId`, `objectId`)")
			session.execute("ALTER TABLE `CONFIG_STATE` ADD PRIMARY KEY (`configId`, `objectId`)")

		logger.info("All updates completed")

		if not schema_version or schema_version < mysql.schema_version:
			logger.notice("Setting updateEnded for schema version %r", mysql.schema_version)
			session.execute(
				"UPDATE `OPSI_SCHEMA` SET `updateEnded` = CURRENT_TIMESTAMP WHERE version = :version",
				params={"version": mysql.schema_version},
			)
