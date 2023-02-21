# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.mysql.cleanup
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from opsiconfd.logging import logger

if TYPE_CHECKING:
	from . import MySQLConnection, Session


def remove_orphans_config_state(session: Session) -> None:
	result = session.execute(
		"""
		DELETE s.* FROM CONFIG_STATE AS s
		LEFT JOIN CONFIG AS c
		ON s.configId = c.configId
		WHERE c.configId IS NULL
		"""
	)
	if result.rowcount > 0:
		logger.notice("Removed %d orphaned entries from CONFIG_STATE", result.rowcount)


def remove_orphans_config_value(session: Session) -> None:
	result = session.execute(
		"""
		DELETE v.* FROM CONFIG_VALUE AS v
		LEFT JOIN CONFIG AS c ON v.configId = c.configId
		WHERE c.configId IS NULL
		"""
	)
	if result.rowcount > 0:
		logger.notice("Removed %d orphaned entries from CONFIG_VALUE", result.rowcount)


def remove_orphans_product_property_value(session: Session) -> None:
	result = session.execute(
		"""
		DELETE v.* FROM PRODUCT_PROPERTY_VALUE AS v
		LEFT JOIN PRODUCT_PROPERTY AS p
		ON v.productId = p.productId AND v.productVersion = p.productVersion AND v.packageVersion = p.packageVersion
		WHERE p.productId IS NULL
		"""
	)
	if result.rowcount > 0:
		logger.notice("Removed %d orphaned entries from PRODUCT_PROPERTY_VALUE", result.rowcount)


def remove_orphans_object_to_group_product(session: Session) -> None:
	result = session.execute(
		"""
		DELETE FROM OBJECT_TO_GROUP
		WHERE groupType = "ProductGroup" AND objectId NOT IN
		(SELECT DISTINCT productId FROM PRODUCT)
		"""
	)
	if result.rowcount > 0:
		logger.notice("Removed %d orphaned ProductGroup entries from OBJECT_TO_GROUP", result.rowcount)


def remove_orphans_object_to_group_host(session: Session) -> None:
	result = session.execute(
		"""
		DELETE FROM OBJECT_TO_GROUP
		WHERE groupType = "HostGroup" AND objectId NOT IN
		(SELECT DISTINCT hostId FROM HOST)
		"""
	)
	if result.rowcount > 0:
		logger.notice("Removed %d orphaned HostGroup entries from OBJECT_TO_GROUP", result.rowcount)


def remove_orphans_product_on_client(session: Session) -> None:
	result = session.execute(
		"""
		DELETE c.* FROM PRODUCT_ON_CLIENT AS c
		LEFT JOIN PRODUCT AS p
		ON c.productId = p.productId
		WHERE p.productId IS NULL
		"""
	)
	if result.rowcount > 0:
		logger.notice("Removed %d orphaned entries from PRODUCT_ON_CLIENT", result.rowcount)


def remove_orphans_product_property_state(session: Session) -> None:
	result = session.execute(
		"""
		DELETE s.* FROM PRODUCT_PROPERTY_STATE AS s
		LEFT JOIN PRODUCT AS p
		ON s.productId = p.productId
		WHERE p.productId IS NULL
		"""
	)
	if result.rowcount > 0:
		logger.notice("Removed %d orphaned entries from PRODUCT_PROPERTY_STATE", result.rowcount)


def remove_orphans_windows_software_id_to_product(session: Session) -> None:
	result = session.execute(
		"""
		DELETE wsi.* FROM WINDOWS_SOFTWARE_ID_TO_PRODUCT AS wsi
		LEFT JOIN PRODUCT AS p
		ON wsi.productId = p.productId
		WHERE p.productId IS NULL
		"""
	)
	if result.rowcount > 0:
		logger.notice("Removed %d orphaned entries from WINDOWS_SOFTWARE_ID_TO_PRODUCT", result.rowcount)


def remove_orphans_license_on_client_to_host(session: Session) -> None:
	result = session.execute(
		"""
		DELETE loc.* FROM LICENSE_ON_CLIENT AS loc
		LEFT JOIN HOST AS h
		ON loc.clientId = h.hostId
		WHERE h.hostId IS NULL
		"""
	)
	if result.rowcount > 0:
		logger.notice("Removed %d orphaned entries from WINDOWS_SOFTWARE_ID_TO_PRODUCT", result.rowcount)


def remove_orphans_product_id_to_license_pool(session: Session) -> None:
	result = session.execute(
		"""
		DELETE pid.* FROM PRODUCT_ID_TO_LICENSE_POOL AS pid
		LEFT JOIN LICENSE_POOL AS pool
		ON pid.licensePoolId = pool.licensePoolId
		WHERE pool.licensePoolId IS NULL
		"""
	)
	if result.rowcount > 0:
		logger.notice("Removed %d orphaned entries from PRODUCT_ID_TO_LICENSE_POOL", result.rowcount)


def cleanup_database(mysql: MySQLConnection) -> None:
	with mysql.session() as session:
		remove_orphans_config_value(session)
		remove_orphans_config_state(session)
		remove_orphans_product_property_value(session)
		remove_orphans_product_property_state(session)
		remove_orphans_object_to_group_host(session)
		remove_orphans_object_to_group_product(session)
		remove_orphans_product_on_client(session)
		remove_orphans_windows_software_id_to_product(session)
		remove_orphans_license_on_client_to_host(session)
		remove_orphans_product_id_to_license_pool(session)
