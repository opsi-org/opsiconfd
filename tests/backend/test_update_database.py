# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test update database
"""


from typing import Any, Generator

import pytest

from opsiconfd.backend.mysql import MySQLConnection
from opsiconfd.backend.mysql.schema import create_audit_hardware_tables, create_database, drop_database, update_database
from opsiconfd.config import get_configserver_id
from opsiconfd.setup.backend import setup_backend, setup_mysql
from tests.utils import (  # pylint: disable=unused-import
	Connection,
	database_connection,
)

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


GET_CONSTRAINTS = """
	SELECT DISTINCT `t1`.`CONSTRAINT_NAME`, t2.UPDATE_RULE, t2.DELETE_RULE FROM `INFORMATION_SCHEMA`.`KEY_COLUMN_USAGE` AS `t1`
	INNER JOIN `INFORMATION_SCHEMA`.`REFERENTIAL_CONSTRAINTS` AS `t2`
	ON `t1`.`CONSTRAINT_SCHEMA` = `t2`.`CONSTRAINT_SCHEMA` AND `t1`.`CONSTRAINT_NAME` = `t2`.`CONSTRAINT_NAME`
"""


@pytest.fixture(autouse=True)
def setup_and_cleanup_database(database_connection: Connection) -> Generator[None, None, None]:  # pylint: disable=redefined-outer-name
	with open("tests/data/opsi-config/backends/mysql.conf", mode="r", encoding="utf-8") as conf:
		_globals: dict[str, Any] = {}
		exec(conf.read(), _globals)  # pylint: disable=exec-used
		mysql_config = _globals["config"]
	mysql = MySQLConnection()
	with mysql.connection():
		with mysql.session() as session:
			session.execute(f"DROP DATABASE IF EXISTS `{mysql_config['database']}`")
			session.execute(f"CREATE DATABASE IF NOT EXISTS `{mysql.database}`")
			session.execute(f"USE `{mysql_config['database']}`")
			session.execute(CREATE_TABLES_SQL)
			session.commit()

	yield

	with mysql.connection():
		with mysql.session() as session:
			session.execute(f"DROP DATABASE IF EXISTS `{mysql_config['database']}`")

	print("Setup database")
	setup_mysql(explicit=True)
	print("Setup backend")
	setup_backend()


def test_update_databaset(database_connection: Connection) -> None:
	mysql = MySQLConnection()
	with mysql.connection():
		with mysql.session() as session:
			res = session.execute(GET_CONSTRAINTS).fetchall()
			assert len(res) < 50

	mysql = MySQLConnection()
	mysql.connect()
	update_database(mysql)

	mysql = MySQLConnection()
	with mysql.connection():
		with mysql.session() as session:
			res = session.execute(GET_CONSTRAINTS).fetchall()
			assert len(res) == 50
