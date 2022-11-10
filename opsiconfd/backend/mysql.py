# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
backend.mysql
"""

from __future__ import annotations

import json
import re
from contextlib import contextmanager
from datetime import datetime
from functools import lru_cache
from inspect import signature
from pathlib import Path
from typing import (
	Any,
	Callable,
	Dict,
	Generator,
	List,
	Literal,
	Optional,
	Protocol,
	Tuple,
	Type,
	Union,
	overload,
)
from urllib.parse import quote, urlencode

from OPSI.Util import compareVersions  # type: ignore[import]
from opsicommon.exceptions import BackendPermissionDeniedError  # type: ignore[import]
from opsicommon.logging import secret_filter  # type: ignore[import]
from opsicommon.objects import (  # type: ignore[import]
	OBJECT_CLASSES,
	BaseObject,
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

from .auth import RPCACE

IdentType = Literal["unicode", "str", "dict", "hash", "list", "tuple"]


class BackendProtocol(Protocol):  # pylint: disable=too-few-public-methods
	@property
	def _mysql(self) -> MySQLConnection:
		...

	def _get_ace(self, method: str) -> Optional[RPCACE]:
		...


class MySQLConnection:  # pylint: disable=too-many-instance-attributes
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
	record_separator = "␞"

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
		self.tables: Dict[str, Dict[str, Type]] = {}

		self._read_config_file()
		secret_filter.add_secrets(self._password)

	def __repr__(self) -> str:
		return f"<{self.__class__.__name__}(address={self._address})>"

	def _read_config_file(self) -> None:
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
		self.tables = {}
		with self.session() as session:
			for trow in session.execute("SHOW TABLES").fetchall():
				table_name = trow[0].upper()
				self.tables[table_name] = {}
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
					self.tables[table_name][row["Field"]] = py_type  # pylint: disable=loop-invariant-statement

	def _get_select(self, table: str, ace: RPCACE = None, attributes: Union[List[str], Tuple[str, ...]] = None) -> str:
		select = []
		for col in self.tables[table]:
			attr = self._column_to_attribute.get(table, {}).get(col, col)
			if ace and ace.allowed_attributes and attr not in ace.allowed_attributes:
				continue
			if ace and ace.denied_attributes and attr in ace.denied_attributes:
				continue

			if attributes and attr not in attributes:
				continue
			if col == attr:
				select.append(f"`{col}`")
			else:
				select.append(f"`{col}` AS `{attr}`")

		if not select:
			raise BackendPermissionDeniedError(f"Access to {table} denied")
		return f"SELECT {','.join(select)} FROM `{table}` "

	def _get_columns(self, tables: List[str], ace: RPCACE = None, attributes: Union[List[str], Tuple[str, ...]] = None) -> Dict[str, str]:
		res = {}
		for table in tables:
			for col in self.tables[table]:
				attr = self._column_to_attribute.get(table, {}).get(col, col)
				if ace and ace.allowed_attributes and attr not in ace.allowed_attributes:
					continue
				if ace and ace.denied_attributes and attr in ace.denied_attributes:
					continue
				if attributes and attr not in attributes:
					continue
				res[attr] = f"{table}.{col}"
		return res

	def _get_where(  # pylint: disable=too-many-locals,too-many-branches
		self, columns: Dict[str, str], ace: RPCACE = None, filter: Dict[str, Any] = None  # pylint: disable=redefined-builtin
	) -> Tuple[str, Dict[str, Any]]:
		filter = filter or {}
		allowed_client_ids = self.get_allowed_client_ids(ace)

		conditions = []
		params: Dict[str, Any] = {}
		for f_attr, f_val in filter.items():
			if f_attr not in columns or f_val is None:
				continue

			values = f_val if isinstance(f_val, list) else [f_val]

			operator = "IN" if len(values) > 1 else "="
			if values[0] is None:
				operator = "IS"
			elif isinstance(values[0], bool):
				values = [int(v) for v in values]  # pylint: disable=loop-invariant-statement
			elif isinstance(values[0], str):
				new_values = []
				for val in values:
					val = str(val)
					if "*" in val:
						operator = "LIKE"
						val = val.replace("*", "%")
					new_values.append(val)
				values = new_values

			tab, col = columns[f_attr].split(".")
			cond = []
			if operator == "IN":
				param = f"p{len(params) + 1}"  # pylint: disable=loop-invariant-statement
				cond = [f"`{tab}`.`{col}` {operator} :{param}"]
				params[param] = values
			else:
				for val in values:
					param = f"p{len(params) + 1}"  # pylint: disable=loop-invariant-statement
					cond.append(f"`{tab}`.`{col}` {operator} :{param}")
					params[param] = val

			conditions.append(" OR ".join(cond))

		if allowed_client_ids is not None:
			for attr, col in columns.items():
				tab, col = columns[attr].split(".")
				if col.split(".")[1] in ("clientId", "hostId"):
					param = f"p{len(params) + 1}"  # pylint: disable=loop-invariant-statement
					conditions.append(f"type != 'OpsiClient' OR `{tab}`.`{col}` IN :{param}")
					params[param] = allowed_client_ids
					break

		if conditions:
			return "WHERE " + " AND ".join([f"({c})" for c in conditions]), params
		return "", {}

	@lru_cache(maxsize=0)
	def _get_conversions(self, object_type: str) -> Dict[str, Callable]:
		conversions: Dict[str, Callable] = {}
		sig = signature(getattr(OBJECT_CLASSES[object_type], "__init__"))
		for name, param in sig.parameters.items():
			if param.annotation is bool:
				conversions[name] = bool
			elif param.annotation is datetime:
				conversions[name] = lambda v: v.isoformat().replace("T", " ")
			elif name == "values":
				conversions[name] = json.loads  # pylint: disable=dotted-import-in-loop
		return conversions

	@lru_cache(maxsize=0)
	def _get_possible_class_attributes(self, object_type: str) -> Dict[str, Type]:
		return get_possible_class_attributes(OBJECT_CLASSES[object_type])

	@lru_cache(maxsize=0)
	def _get_ident_attributes(self, object_type: str) -> Tuple[str, ...]:
		return get_ident_attributes(OBJECT_CLASSES[object_type])

	def _row_to_dict(  # pylint: disable=too-many-arguments
		self, table: str, row: Row, object_type: Type[BaseObject] = None, ident_type: IdentType = None, aggregates: List[str] = None
	) -> Dict[str, Any]:
		if not object_type and row.type:
			object_type = OBJECT_CLASSES.get(row.type)
		if not object_type:
			raise ValueError(f"Missing object type for {table!r} in row: {dict(row)}")
		ident_attributes = self._get_ident_attributes(object_type.__name__)
		possible_attributes = self._get_possible_class_attributes(object_type.__name__)
		conversions = self._get_conversions(object_type.__name__)

		data = {}
		for key, val in dict(row).items():
			if key not in possible_attributes:
				continue
			conv = conversions.get(key)
			if conv:
				val = conv(val)
			data[key] = val.split(self.record_separator) if val and aggregates and key in aggregates else val

		if ident_type:
			data["ident"] = {a: data[a] for a in ident_attributes}
			if ident_type in ("unicode", "str"):
				data["ident"] = ",".join(data["ident"].values())
			elif ident_type == "list":
				data["ident"] = list(data["ident"].values())
			elif ident_type == "tuple":
				data["ident"] = tuple(data["ident"].values())

		return data

	def _row_to_object(self, row: Row, object_type: Type[BaseObject] = None, aggregates: List[str] = None) -> BaseObject:
		if not object_type and row.type:
			object_type = OBJECT_CLASSES.get(row.type)
		if not object_type:
			raise ValueError(f"Missing object type in row: {dict(row)}")
		possible_attributes = self._get_possible_class_attributes(object_type.__name__)
		kwargs = {
			key: val.split(self.record_separator) if val and aggregates and key in aggregates else val
			for key, val in dict(row).items() if key != "type" and key in possible_attributes
		}
		return object_type(**kwargs)

	def get_allowed_client_ids(self, ace: RPCACE = None) -> Optional[List[str]]:
		allowed_client_ids = None
		if ace and ace.type == "self":
			allowed_client_ids = []
			session = contextvar_client_session.get()
			if session and session.user_store.host:
				allowed_client_ids = [session.user_store.host.id]  # pylint: disable=use-tuple-over-list
		return allowed_client_ids

	@overload
	def get_objects(  # pylint: disable=too-many-arguments
		self,
		table: str,
		aggregates: Dict[str, str] = None,
		ace: RPCACE = None,
		object_type: Type[BaseObject] = None,
		ident_type: IdentType = "str",
		return_type: Literal["object"] = "object",
		attributes: List[str] | Tuple[str, ...] | None = None,
		filter: Dict[str, Any] = None,  # pylint: disable=redefined-builtin
	) -> List[BaseObject]:
		return []

	@overload
	def get_objects(  # pylint: disable=too-many-arguments
		self,
		table: str,
		aggregates: Dict[str, str] = None,
		ace: RPCACE = None,
		object_type: Type[BaseObject] = None,
		ident_type: IdentType = "str",
		return_type: Literal["dict"] = "dict",
		attributes: List[str] | Tuple[str, ...] | None = None,
		filter: Dict[str, Any] = None,  # pylint: disable=redefined-builtin
	) -> List[dict]:
		return []

	def get_objects(  # pylint: disable=too-many-arguments,too-many-locals
		self,
		table: str,
		aggregates: Dict[str, str] = None,
		ace: RPCACE = None,
		object_type: Type[BaseObject] = None,
		ident_type: IdentType = "str",
		return_type: Literal["object", "dict"] = "object",
		attributes: List[str] | Tuple[str, ...] | None = None,
		filter: Dict[str, Any] = None,  # pylint: disable=redefined-builtin
	) -> List[dict] | List[BaseObject]:
		aggregates = aggregates or {}
		if not table.lstrip().upper().startswith("FROM"):
			table = f"FROM {table}"
		tables = re.findall(r"(?:FROM|JOIN)\s+`?([a-zA-Z_]+)`?", table)
		columns = self._get_columns(tables=tables, ace=ace, attributes=attributes)
		aggs = [f"{agg} AS `{name}`" for name, agg in aggregates.items()] if aggregates else ""
		query = (
			"SELECT "
			f"{','.join(aggs) + ',' if aggs else ''}"
			f"""{','.join([f"`{c.split('.')[0]}`.`{c.split('.')[1]}` AS `{a}`" for a, c in columns.items()])}"""
			f" {table}"
		)
		where, params = self._get_where(columns=columns, ace=ace, filter=filter)
		with self.session() as session:
			query = f"{query} {where} {'GROUP BY id' if aggregates else ''}"
			result = session.execute(query, params=params).fetchall()
			if not result:
				return []
			if return_type == "dict":
				return [
					self._row_to_dict(table=table, row=row, object_type=object_type, ident_type=ident_type, aggregates=list(aggregates))
					for row in result
				]
			return [self._row_to_object(row=row, object_type=object_type, aggregates=list(aggregates)) for row in result]

	def get_idents(  # pylint: disable=too-many-arguments
		self, table: str, object_type: Type[BaseObject], ace: RPCACE = None, ident_type: IdentType = "str", filter: Dict[str, Any] = None  # pylint: disable=redefined-builtin
	) -> List[dict]:
		attributes = self._get_ident_attributes(object_type.__name__)
		if not attributes:
			raise ValueError(f"Failed to get ident attributes for {object_type}")
		# return [
		# 	obj.getIdent(ident_type)
		# 	for obj in self.get_objects(
		# 		table=table, ace=ace, object_type=object_type, ident_type=ident_type, return_type=BaseObject, attributes=attributes, filter=filter
		# 	)
		# ]
		return [
			obj["ident"]
			for obj in self.get_objects(
				table=table, ace=ace, object_type=object_type, ident_type=ident_type, return_type="dict", attributes=attributes, filter=filter
			)
		]

	def insert_object(  # pylint: disable=too-many-locals,too-many-arguments
		self, table: str, obj: BaseObject, ace: RPCACE = None, create: bool = True, set_null: bool = True
	) -> None:
		if not isinstance(obj, BaseObject):
			obj = OBJECT_CLASSES[obj["type"]].fromHash(obj)
		obj.setDefaults()
		data = obj.to_hash()
		ident: Tuple[str, ...] = tuple()
		if not create:
			ident = obj.getIdent("tuple")
		columns = self._get_columns([table], ace=ace)

		allowed_client_ids = self.get_allowed_client_ids(ace)

		cols = []
		vals = []
		where = []
		updates = []
		for attr, column in columns.items():
			if attr not in data:
				continue

			if allowed_client_ids and column.split(".")[1] in ("clientId", "hostId"):
				if data.get(attr) not in allowed_client_ids:
					raise BackendPermissionDeniedError(f"No permission for {column}/{attr}: {data.get(attr)}")

			if attr in ident:
				where.append(f"`{column.split('.')[1]}` = :{attr}")
			if not set_null and data.get(attr) is None:
				continue
			cols.append(f"`{column.split('.')[1]}`")
			vals.append(f":{attr}")
			updates.append(f"`{column.split('.')[1]}` = :{attr}")

		if not updates:
			return

		if create:
			query = f"INSERT INTO `{table}` ({','.join(cols)}) VALUES ({','.join(vals)}) ON DUPLICATE KEY UPDATE {','.join(updates)}"
		else:
			query = f"UPDATE `{table}` SET {','.join(updates)} WHERE {' AND '.join(where)}"
		with self.session() as session:
			session.execute(query, params=data)
