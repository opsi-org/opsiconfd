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


def remove_orphans_config_value(session: Session, dry_run: bool) -> None:
	res = session.execute(
		"""
		SELECT GROUP_CONCAT(DISTINCT v.config_value_id)
		FROM CONFIG_VALUE AS v
		LEFT JOIN CONFIG AS c ON v.configId = c.configId
		WHERE c.configId IS NULL
		"""
	).fetchone()
	if res and res[0]:
		ids = res[0].split(",")
		logger.notice("Removing orphan entries from CONFIG_VALUE: %s", ids)
		if not dry_run:
			session.execute("DELETE FROM CONFIG_VALUE WHERE config_value_id in :ids", params={"ids": ids})


def remove_orphans_product_property_value(session: Session, dry_run: bool) -> None:
	res = session.execute(
		"""
		SELECT GROUP_CONCAT(DISTINCT v.product_property_id)
		FROM PRODUCT_PROPERTY_VALUE AS v
		LEFT JOIN PRODUCT_PROPERTY AS p
		ON v.productId = p.productId AND v.productVersion = p.productVersion AND v.packageVersion = p.packageVersion
		WHERE p.productId IS NULL
		"""
	).fetchone()
	if res and res[0]:
		ids = res[0].split(",")
		logger.notice("Removing orphan entries from PRODUCT_PROPERTY_VALUE: %s", ids)
		if not dry_run:
			session.execute("DELETE FROM PRODUCT_PROPERTY_VALUE WHERE product_property_id in :ids", params={"ids": ids})


def cleanup_database(mysql: MySQLConnection, dry_run: bool = True) -> None:
	with mysql.session() as session:
		remove_orphans_config_value(session=session, dry_run=dry_run)
		remove_orphans_product_property_value(session=session, dry_run=dry_run)
