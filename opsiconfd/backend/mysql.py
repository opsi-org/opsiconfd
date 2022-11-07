# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
backend.mysql
"""

import re
from contextlib import contextmanager
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple, Type
from urllib.parse import quote, urlencode

from OPSI.Util import compareVersions  # type: ignore[import]
from opsicommon.exceptions import BackendPermissionDeniedError
from opsicommon.logging import secret_filter  # type: ignore[import]
from opsicommon.objects import (
	OBJECT_CLASSES,
	BaseObject,
	Host,
	get_ident_attributes,
	get_possible_class_attributes,
)
from sqlalchemy import create_engine  # type: ignore[import]
from sqlalchemy.engine.base import Connection  # type: ignore[import]
from sqlalchemy.engine.row import Row  # type: ignore[import]
from sqlalchemy.event import listen  # type: ignore[import]
from sqlalchemy.orm import Session, scoped_session, sessionmaker  # type: ignore[import]

from opsiconfd import contextvar_client_session
from opsiconfd.config import config
from opsiconfd.logging import logger


class MySQLBackend:  # pylint: disable=too-many-instance-attributes
	_column_to_attribute = {
		"HOST": {"hostId": "id"},
		"PRODUCT": {"productId": "id"},
		"GROUP": {"groupId": "id"},
		"CONFIG": {"configId": "id"},
		"LICENSE_CONTRACT": {"licenseContractId": "id"},
		"SOFTWARE_LICENSE": {"softwareLicenseId": "id"},
		"LICENSE_POOL": {"licensePoolId": "id"},
	}
	_attribute_to_column = {
		"HOST": {"id": "hostId"},
		"PRODUCT": {"id": "productId"},
		"GROUP": {"id": "groupId"},
		"CONFIG": {"id": "configId"},
		"LICENSE_CONTRACT": {"id": "licenseContractId"},
		"SOFTWARE_LICENSE": {"id": "softwareLicenseId"},
		"LICENSE_POOL": {"id": "licensePoolId"},
	}

	def __init__(self) -> None:
		self._address = "localhost"
		self._username = "opsi"
		self._password = "opsi"
		self._database = "opsi"
		self._database_charset = "utf8"
		self._connection_pool_size = 20
		self._connection_pool_max_overflow = 10
		self._connection_pool_timeout = 30
		self._connection_pool_recycling_seconds = -1
		self._unique_hardware_addresses = True
		self._log_queries = False

		self._Session: scoped_session | None = lambda: None  # pylint: disable=invalid-name
		self._session_factory = None
		self._engine = None
		self._tables: Dict[str, Dict[str, Type]] = {}

		self.read_config_file()

		secret_filter.add_secrets(self._password)

	def __repr__(self) -> str:
		return f"<{self.__class__.__name__}(address={self._address})>"

	def read_config_file(self) -> None:
		mysql_conf = Path(config.backend_config_dir) / "mysql.conf"
		loc: Dict[str, Any] = {}
		exec(compile(mysql_conf.read_bytes(), "<string>", "exec"), None, loc)  # pylint: disable=exec-used

		for key, val in loc["config"].items():
			if "password" in key:
				secret_filter.add_secrets(val)
			attr = "_" + "".join([f"_{c.lower()}" if c.isupper() else c for c in key])
			if hasattr(self, attr):
				setattr(self, attr, val)

		if self._address == "::1":
			self._address = "[::1]"

	@staticmethod
	def _on_engine_connect(conn: Connection, branch: Optional[Connection]) -> None:  # pylint: disable=unused-argument
		conn.execute(
			"""
			SET SESSION sql_mode=(SELECT
				REPLACE(
					REPLACE(
						REPLACE(@@sql_mode,
							'ONLY_FULL_GROUP_BY', ''
						),
						'NO_ZERO_IN_DATE', ''
					),
					'NO_ZERO_DATE', ''
				)
			);
			SET SESSION group_concat_max_len = 1000000;
			SET SESSION lock_wait_timeout = 60;
		"""
		)
		conn.execute("SET SESSION group_concat_max_len = 1000000;")
		# conn.execute("SHOW VARIABLES LIKE 'sql_mode';").fetchone()

	def _init_connection(self) -> None:
		password = quote(self._password)
		secret_filter.add_secrets(password)

		properties = {}
		if self._database_charset == "utf8":
			properties["charset"] = "utf8mb4"

		address = self._address
		if address.startswith("/"):
			properties["unix_socket"] = address
			address = "localhost"

		params = f"?{urlencode(properties)}" if properties else ""

		uri = f"mysql://{quote(self._username)}:{password}@{address}/{self._database}{params}"
		logger.info("Connecting to %s", uri)

		self._engine = create_engine(
			uri,
			pool_pre_ping=True,  # auto reconnect
			encoding=self._database_charset,
			pool_size=self._connection_pool_size,
			max_overflow=self._connection_pool_max_overflow,
			pool_timeout=self._connection_pool_timeout,
			pool_recycle=self._connection_pool_recycling_seconds,
		)
		if not self._engine:
			raise RuntimeError("Failed to create engine")

		self._engine._should_log_info = lambda: self._log_queries  # pylint: disable=protected-access

		listen(self._engine, "engine_connect", self._on_engine_connect)

		self._session_factory = sessionmaker(bind=self._engine, autocommit=False, autoflush=False)
		self._Session = scoped_session(self._session_factory)  # pylint: disable=invalid-name

		# Test connection
		with self.session() as session:
			version_string = session.execute("SELECT @@VERSION").fetchone()[0]
			logger.info("Connected to server version: %s", version_string)
			server_type = "MariaDB" if "maria" in version_string.lower() else "MySQL"
			match = re.search(r"^([\d\.]+)", version_string)
			if match:
				min_version = "5.6.5"
				if server_type == "MariaDB":
					min_version = "10.1"
				if compareVersions(match.group(1), "<", min_version):
					error = (
						f"{server_type} server version '{version_string}' to old."
						" Supported versions are MariaDB >= 10.1 and MySQL >= 5.6.5"
					)
					logger.error(error)
					raise RuntimeError(error)

	def connect(self) -> None:
		try:
			self._init_connection()
		except Exception as err:  # pylint: disable=broad-except
			if self._address != "localhost":
				raise
			logger.info("Failed to connect to socket (%s), retrying with tcp/ip", err)
			self._address = "127.0.0.1"
			self._init_connection()
		self._get_tables()

	def disconnect(self) -> None:
		if self._engine:
			self._engine.dispose()

	@contextmanager
	def session(self, commit: bool = True) -> Generator[Session, None, None]:
		if not self._Session:
			raise RuntimeError("Not initialized")

		session = self._Session()
		try:
			yield session
			if commit:
				session.commit()
		except Exception:  # pylint: disable=broad-except
			session.rollback()
			raise
		finally:
			self._Session.remove()  # pylint: disable=no-member

	def _get_tables(self) -> None:
		self._tables = {}
		with self.session() as session:
			for trow in session.execute("SHOW TABLES").fetchall():
				table_name = trow[0].upper()
				self._tables[table_name] = {}
				for row in session.execute(f"SHOW COLUMNS FROM `{table_name}`"):  # pylint: disable=loop-invariant-statement
					mysql_type = row["Type"].lower()
					py_type: Type = str
					if mysql_type == "tinyint(1)":
						py_type = bool
					elif "int" in mysql_type:
						py_type = int
					elif "double" in mysql_type:
						py_type = float
					elif "text" in mysql_type:
						py_type = str
					elif "varchar" in mysql_type:
						py_type = str
					elif "timestamp" in mysql_type:
						py_type = datetime
					else:
						logger.error("Failed to get python type for: %s", mysql_type)
					self._tables[table_name][row["Field"]] = py_type

	def _get_select(self, table: str, attributes: List[str] = None) -> str:
		#session = contextvar_client_session.get()
		#session.user_store
		columns = set(self._tables[table])
		if attributes:
			new_columns = set()
			for attr in attributes:
				attr = self._attribute_to_column.get(table, {}).get(attr, attr)
				if attr in columns:
					new_columns.add(attr)
			columns = new_columns
		if not columns:
			raise BackendPermissionDeniedError(f"Access to {table} denied")
		return f"SELECT {','.join([f'`{c}`' for c in columns])} FROM `{table}`"

	def _get_where(self, table: str, filter: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:  # pylint: disable=redefined-builtin
		filter = filter or {}
		columns = self._tables[table]

		conditions = []
		params: Dict[str, Any] = {}
		for f_key, f_val in filter.items():
			f_key = self._attribute_to_column.get(table, {}).get(f_key, f_key)
			if f_key not in columns or f_val is None:
				continue

			values = f_val if isinstance(f_val, list) else [f_val]

			operator = "IN" if len(values) > 1 else "="
			if values[0] is None:
				operator = "IS"
			elif isinstance(values[0], bool):
				values = [int(v) for v in values]
			elif isinstance(values[0], str):
				new_values = []
				for val in values:
					val = str(val)
					if "*" in val:
						operator = "LIKE"
						val = val.replace("*", "%")
					new_values.append(val)
				values = new_values

			cond = []
			if operator == "IN":
				param = f"p{len(params) + 1}"
				cond = [f"`{f_key}` {operator} :{param}"]
				params[param] = values
			else:
				for val in values:
					param = f"p{len(params) + 1}"
					cond.append(f"`{f_key}` {operator} :{param}")
					params[param] = val

			conditions.append(" OR ".join(cond))

		if conditions:
			return "WHERE " + " AND ".join([f"({c})" for c in conditions]), params
		return "", {}

	@lru_cache(maxsize=0)
	def _get_conversions(self, table: str) -> Dict[str, Callable]:
		conversions = {}
		for col, typ in self._tables.get(table, {}).items():
			if typ is bool:
				conversions[col] = bool
			elif typ is datetime:
				conversions[col] = lambda v: v.isoformat().replace("T", " ")
		return conversions

	@lru_cache(maxsize=0)
	def _get_possible_class_attributes(self, object_type: Type[BaseObject]) -> Dict[str, Type]:
		return get_possible_class_attributes(object_type)

	def _row_to_dict(self, table: str, row: Row, add_indent: bool = False) -> Dict[str, Any]:
		object_type = OBJECT_CLASSES.get(row.type)
		possible_attributes = self._get_possible_class_attributes(object_type)
		attribute_names = self._column_to_attribute.get(table, {})
		conversions = self._get_conversions(table)

		data = {}
		for key, val in dict(row).items():
			key = attribute_names.get(key, key)
			if key not in possible_attributes:
				continue
			conv = conversions.get(key)
			if conv:
				val = conv(val)
			data[key] = val

		if add_indent:
			data["ident"] = ",".join([data[a] for a in get_ident_attributes(object_type)])

		return data

	def host_getObjects(self, attributes: List[str] = None, **filter: Any) -> List[dict]:  # pylint: disable=redefined-builtin,invalid-name
		logger.info("Getting hosts, filter: %s", filter)
		select = self._get_select(table="HOST", attributes=attributes)
		where, params = self._get_where(table="HOST", filter=filter)
		with self.session() as session:
			result = session.execute(select + where, params=params).fetchall()
			return [self._row_to_dict(table="HOST", row=row, add_indent=True) for row in result] if result else []
