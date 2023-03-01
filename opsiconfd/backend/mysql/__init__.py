# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.mysql
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from inspect import signature
from json import JSONDecodeError, dumps, loads
from pathlib import Path
from time import sleep
from typing import (
	TYPE_CHECKING,
	Any,
	Callable,
	Generator,
	Literal,
	Optional,
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
	BaseObjectT,
	get_ident_attributes,
	get_object_type,
	get_possible_class_attributes,
)
from sqlalchemy import create_engine  # type: ignore[import]
from sqlalchemy.engine.base import Connection  # type: ignore[import]
from sqlalchemy.engine.result import Result  # type: ignore[import]
from sqlalchemy.engine.row import Row  # type: ignore[import]
from sqlalchemy.event import listen  # type: ignore[import]
from sqlalchemy.exc import DatabaseError, OperationalError  # type: ignore[import]
from sqlalchemy.orm import Session, scoped_session, sessionmaker  # type: ignore[import]

from opsiconfd import contextvar_client_session, server_timing
from opsiconfd.config import config
from opsiconfd.logging import logger

from ..auth import RPCACE
from .schema import create_database

if TYPE_CHECKING:
	from ..rpc.protocol import IdentType


@dataclass(slots=True)
class ColumnInfo:
	table: str
	column: str
	client_id_column: bool
	select: str | None


class MySQLSession(Session):  # pylint: disable=too-few-public-methods
	execute_attempts = 3

	def execute(self, statement: str, params: Any | None = None) -> Result:
		attempt = 0
		retry_wait = 0.01
		with server_timing("database") as timing:
			while True:
				attempt += 1
				try:
					result = super().execute(statement=statement, params=params)
					logger.trace(
						"Statement %r with params %r took %0.4f ms",
						statement,
						params,
						timing["database"],
					)
					return result
				except DatabaseError as err:
					logger.trace(
						"Failed statement %r (attempt: %d) with params %r: %s", statement, attempt, params, err.__cause__, exc_info=True
					)
					if attempt >= self.execute_attempts or "deadlock" not in str(err).lower():
						raise
					sleep(retry_wait)


class MySQLConnection:  # pylint: disable=too-many-instance-attributes
	_column_to_attribute = {
		"CONFIG": {"configId": "id"},
		"HOST": {"hostId": "id"},
		"PRODUCT": {"productId": "id"},
		"GROUP": {"groupId": "id"},
		"LICENSE_CONTRACT": {"licenseContractId": "id"},
		"SOFTWARE_LICENSE": {"softwareLicenseId": "id"},
		"LICENSE_POOL": {"licensePoolId": "id"},
	}
	_attribute_to_column = {
		"CONFIG": {"id": "configId"},
		"HOST": {"id": "hostId"},
		"PRODUCT": {"id": "productId"},
		"GROUP": {"id": "groupId"},
		"LICENSE_CONTRACT": {"id": "licenseContractId"},
		"SOFTWARE_LICENSE": {"id": "softwareLicenseId"},
		"LICENSE_POOL": {"id": "licensePoolId"},
	}
	_client_id_column = {
		"HOST": "hostId",
		"PRODUCT_ON_CLIENT": "clientId",
		"CONFIG_STATE": "objectId",
		"PRODUCT_PROPERTY_STATE": "objectId",
		"SOFTWARE_CONFIG": "clientId",
		"LICENSE_ON_CLIENT": "clientId",
	}
	record_separator = "␞"

	schema_version = 9

	def __init__(self) -> None:
		self.address = "localhost"
		self.username = "opsi"
		self.password = "opsi"
		self.database = "opsi"
		self._database_charset = "utf8"
		self._connection_pool_size = 20
		self._connection_pool_max_overflow = 10
		self._connection_pool_timeout = 30
		self._connection_pool_recycling_seconds = -1
		self._unique_hardware_addresses = True

		self._Session: scoped_session | None = lambda: None  # pylint: disable=invalid-name
		self._session_factory = None
		self._engine = None

		self.connected = False
		self.tables: dict[str, dict[str, dict[str, str | bool | None]]] = {}

		self.read_config_file()
		secret_filter.add_secrets(self.password)

	def __repr__(self) -> str:
		return f"<{self.__class__.__name__}(address={self.address})>"

	def read_config_file(self) -> None:
		mysql_conf = Path(config.backend_config_dir) / "mysql.conf"
		loc: dict[str, Any] = {}
		exec(compile(mysql_conf.read_bytes(), "<string>", "exec"), None, loc)  # pylint: disable=exec-used

		for key, val in loc["config"].items():
			if "password" in key:
				secret_filter.add_secrets(val)
			attr = "".join([f"_{c.lower()}" if c.isupper() else c for c in key])
			if hasattr(self, attr):
				setattr(self, attr, val)
			elif hasattr(self, f"_{attr}"):
				setattr(self, f"_{attr}", val)

		if self.address == "::1":
			self.address = "[::1]"

	def update_config_file(self) -> None:
		mysql_conf = Path(config.backend_config_dir) / "mysql.conf"
		config_regex = re.compile(r'^(\s*)"([^"]+)"(\s*:\s*)\S.*$')
		lines = mysql_conf.read_text(encoding="utf-8").split("\n")
		for idx, line in enumerate(lines):
			match = config_regex.search(line)
			if match:
				option = match.group(2)
				if option in ("address", "database", "username", "password"):
					value = getattr(self, option)
					lines[idx] = f'{match.group(1)}"{option}"{match.group(3)}"{value}",'
		mysql_conf.write_text("\n".join(lines), encoding="utf-8")

	def _create_engine(self, uri: str) -> None:
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

		self._session_factory = sessionmaker(bind=self._engine, class_=MySQLSession, autocommit=False, autoflush=False)
		self._Session = scoped_session(self._session_factory)  # pylint: disable=invalid-name

		listen(self._engine, "engine_connect", self._on_engine_connect)

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
		password = quote(self.password)
		secret_filter.add_secrets(password)

		properties = {}
		if self._database_charset == "utf8":
			properties["charset"] = "utf8mb4"

		address = self.address
		if address.startswith("/"):
			properties["unix_socket"] = address
			address = "localhost"

		params = f"?{urlencode(properties)}" if properties else ""

		uri = f"mysql://{quote(self.username)}:{password}@{address}/{self.database}{params}"
		self._create_engine(uri)

		logger.info("Connecting to %s", uri)
		# Test connection
		with self.session() as session:
			try:
				version_string = session.execute("SELECT @@VERSION").fetchone()[0]
			except OperationalError as err:
				if not str(err.orig).startswith("(1049"):
					raise
				# 1049 - Unknown database
				self._create_engine(f"mysql://{quote(self.username)}:{password}@{address}/{params}")
				create_database(self)
				self._create_engine(uri)
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

	@contextmanager
	def connection(self) -> Generator[None, None, None]:
		self.connect()
		try:
			yield
		finally:
			self.disconnect()

	def connect(self) -> None:
		try:
			self._init_connection()
		except OperationalError as err:
			if self.address != "localhost":
				raise
			logger.info("Failed to connect to socket (%s), retrying with tcp/ip", err)
			self.address = "127.0.0.1"
			self._init_connection()
		self.read_tables()
		self.connected = True

	def disconnect(self) -> None:
		self.connected = False
		if self._engine:
			self._engine.dispose()

	@contextmanager
	def session(self, session: Session | None = None, commit: bool = True) -> Generator[Session, None, None]:
		if session:
			yield session
			return

		if not self._Session or not isinstance(self._Session, scoped_session):
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

	@contextmanager
	def table_lock(self, session: Session, locks: dict[str, str]) -> Generator[None, None, None]:
		qlock = []
		for table, lock in locks.items():
			if lock.upper() not in ("READ", "WRITE"):
				raise ValueError(f"Invalid lock {lock!r}")
			qlock.append(f"`{table}` {lock}")

		try:
			session.execute(f"LOCK TABLES {', '.join(qlock)}")
			yield
		finally:
			session.execute("UNLOCK TABLES")

	def read_tables(self) -> None:
		with self.session() as session:
			self.tables = {trow[0].upper(): {} for trow in session.execute("SHOW TABLES").fetchall()}
			for table_name in self.tables:
				for row in session.execute(f"SHOW COLUMNS FROM `{table_name}`"):
					row_dict = {k.lower(): v for k, v in dict(row).items()}
					row_dict["null"] = row_dict["null"].upper() == "YES"
					row_dict["key"] = (row_dict["key"] or "").upper()
					row_dict["type"] = row_dict["type"].lower()
					self.tables[table_name][row_dict["field"]] = row_dict
				if table_name.startswith("HARDWARE_CONFIG_"):
					self._client_id_column[table_name] = "hostId"
				if table_name.startswith("HARDWARE_DEVICE_"):
					self._client_id_column[table_name] = ""

	def get_columns(  # pylint: disable=too-many-branches
		self, tables: list[str], ace: list[RPCACE], attributes: Union[list[str], tuple[str, ...]] | None = None
	) -> dict[str, ColumnInfo]:
		res: dict[str, ColumnInfo] = {}
		first_table = tables[0]
		client_id_column = self._client_id_column.get(first_table)

		for table in tables:
			is_first_table = table == first_table
			for col in self.tables[table]:
				attr = self._column_to_attribute.get(table, {}).get(col, col)
				if attr in res:
					# Prefer first table (needed for LEFT JOIN)
					continue
				res[attr] = ColumnInfo(table=table, column=col, client_id_column=is_first_table and col == client_id_column, select=None)
				if attr == "type":
					res[attr].select = f"`{table}`.`{col}`"
					continue

				if attributes and attr not in attributes:
					continue

				selected = not ace  # select if no ACEs given
				self_selected = False
				self_ace = None
				for _ace in ace:
					if _ace.allowed_attributes and attr not in _ace.allowed_attributes:
						continue
					if _ace.denied_attributes and attr in _ace.denied_attributes:
						continue

					if _ace.type == "self":
						self_ace = _ace
						self_selected = True
					else:
						selected = True

				if not selected and not self_selected:
					continue

				res[attr].select = f"`{table}`.`{col}`" if selected else "NULL"
				if self_selected and self_ace:
					if client_id_column is None:
						raise RuntimeError(f"No client id attribute defined for table {first_table} using ace {self_ace}")
					if client_id_column:
						res[attr].select = f"IF(`{first_table}`.`{client_id_column}`='{self_ace.id}',`{table}`.`{col}`,{res[attr].select})"
		return res

	def get_where(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
		self,
		columns: dict[str, ColumnInfo],
		ace: list[RPCACE],
		filter: dict[str, Any] | None = None,  # pylint: disable=redefined-builtin
	) -> tuple[str, dict[str, Any]]:
		filter = filter or {}
		allowed_client_ids = self.get_allowed_client_ids(ace)

		conditions = []
		params: dict[str, Any] = {}
		for f_attr, f_val in filter.items():
			if f_attr not in columns:
				if f_attr != "type":
					# logger.warning(
					# 	"Invalid filter %r=%r used, possible attributes are: %s",
					# 	f_attr,
					# 	f_val,
					# 	", ".join(columns),
					# )
					raise ValueError(f"Invalid filter {f_attr!r}={f_val!r} used, possible attributes are: {', '.join(columns)}")
				continue
			if f_val is None:
				continue

			values = []
			if isinstance(f_val, list):
				values = f_val
			elif isinstance(f_val, (tuple, set)):
				values = list(f_val)
			else:
				values = [f_val]
			if len(values) == 0:
				continue

			if f_attr == "type" and "OpsiDepotserver" in values and "OpsiConfigserver" not in values:
				values.append("OpsiConfigserver")

			col = columns[f_attr]
			cond = []

			if len(values) > 10:
				param = f"p{len(params) + 1}"
				cond = [f"`{col.table}`.`{col.column}` IN :{param}"]
				params[param] = values
			else:
				for val in values:
					operator = "="
					if val is None:
						operator = "IS"
					elif isinstance(val, bool):
						val = int(val)
					elif isinstance(val, str):
						if "*" in val:
							operator = "LIKE"
							val = val.replace("*", "%")
						elif val.startswith(("<", ">")):
							operator = val[0]
							val = val[1:]
					param = f"p{len(params) + 1}"
					cond.append(f"`{col.table}`.`{col.column}` {operator} :{param}")
					params[param] = val

			conditions.append(" OR ".join(cond))

		if allowed_client_ids is not None:
			for col in columns.values():
				if col.client_id_column:
					param = f"p{len(params) + 1}"
					conditions.append(f"`{col.table}`.`{col.column}` IN :{param}")
					params[param] = allowed_client_ids
					break

		if conditions:
			return "WHERE " + " AND ".join([f"({c})" for c in conditions]), params
		return "", {}

	@lru_cache()
	def _get_read_conversions(self, object_type: Type[BaseObject]) -> dict[str, Callable]:
		conversions: dict[str, Callable] = {}
		sig = signature(getattr(object_type, "__init__"))
		for name, param in sig.parameters.items():  # pylint: disable=unused-variable
			if name == "values":
				conversions[name] = loads
		return conversions

	@lru_cache()
	def _get_write_conversions(self, object_type: Type[BaseObject]) -> dict[str, Callable]:
		conversions: dict[str, Callable] = {}
		sig = signature(getattr(object_type, "__init__"))
		for name, param in sig.parameters.items():  # pylint: disable=unused-variable
			if name == "values":
				conversions[name] = dumps
		return conversions

	@overload
	def get_ident(self, data: dict[str, Any], ident_attributes: tuple[str, ...] | list[str], ident_type: Literal["unicode", "str"]) -> str:
		...

	@overload
	def get_ident(
		self, data: dict[str, Any], ident_attributes: tuple[str, ...] | list[str], ident_type: Literal["dict", "hash"]
	) -> dict[str, Any]:
		...

	@overload
	def get_ident(self, data: dict[str, Any], ident_attributes: tuple[str, ...] | list[str], ident_type: Literal["list"]) -> list[Any]:
		...

	@overload
	def get_ident(
		self, data: dict[str, Any], ident_attributes: tuple[str, ...] | list[str], ident_type: Literal["tuple"]
	) -> tuple[Any, ...]:
		...

	def get_ident(
		self, data: dict[str, Any], ident_attributes: tuple[str, ...] | list[str], ident_type: IdentType
	) -> str | dict[str, Any] | list[Any] | tuple[Any, ...]:
		ident = {a: data[a] for a in ident_attributes}
		if ident_type in ("dict", "hash"):
			return ident
		if ident_type in ("unicode", "str"):
			return ";".join(v or "" for v in ident.values())
		if ident_type == "list":
			return list(ident.values())
		if ident_type == "tuple":
			return tuple(ident.values())
		raise ValueError(f"Invalid ident type {ident_type!r}")

	def _process_aggregates(self, data: dict[str, Any], aggregates: list[str]) -> None:
		for attr in aggregates:
			try:
				data[attr] = data[attr].split(self.record_separator) if data[attr] else []
			except KeyError:
				pass

	def _process_conversions(self, data: dict[str, Any], conversions: dict[str, Callable]) -> None:
		for attr, func in conversions.items():
			try:
				data[attr] = func(data[attr])
			except KeyError:
				pass
			except JSONDecodeError as err:
				logger.warning(err)

	def _row_to_dict(  # pylint: disable=too-many-arguments
		self,
		row: Row,
		object_type: Type[BaseObject] | None = None,
		ident_type: IdentType | None = None,
		aggregates: list[str] | None = None,
		conversions: dict[str, Callable] | None = None,
	) -> dict[str, Any]:
		data = dict(row)
		try:
			object_type = get_object_type(data["type"]) or object_type
		except KeyError:
			pass

		possible_attributes = get_possible_class_attributes(object_type)  # type: ignore

		if aggregates:
			self._process_aggregates(data, aggregates)
		if conversions:
			self._process_conversions(data, conversions)

		res = {attr: val for attr, val in data.items() if attr in possible_attributes}
		if ident_type:
			ident_attributes = get_ident_attributes(object_type)  # type: ignore
			res["ident"] = self.get_ident(data=data, ident_attributes=ident_attributes, ident_type=ident_type)

		return res

	def _row_to_object(
		self,
		row: Row,
		object_type: Type[BaseObjectT] | None = None,
		aggregates: list[str] | None = None,
		conversions: dict[str, Callable] | None = None,
	) -> BaseObject:
		data = dict(row)

		if aggregates:
			self._process_aggregates(data, aggregates)
		if conversions:
			self._process_conversions(data, conversions)

		return object_type.fromHash(data)  # type: ignore

	def get_allowed_client_ids(self, ace: list[RPCACE]) -> list[str] | None:
		allowed_client_ids: list[str] | None = None
		for _ace in ace:
			if _ace.type == "self":
				allowed_client_ids = []
				session = contextvar_client_session.get()
				if session and session.host:
					allowed_client_ids = [session.host.id]
			else:
				# All client_ids allowed
				allowed_client_ids = None
				break
		return allowed_client_ids

	@overload
	def get_objects(  # pylint: disable=too-many-arguments
		self,
		table: str,
		object_type: Type[BaseObjectT],
		return_type: Literal["object"] = "object",
		aggregates: dict[str, str] | None = None,
		ace: list[RPCACE] | None = None,
		ident_type: IdentType = "str",
		attributes: list[str] | tuple[str, ...] | None = None,
		filter: dict[str, Any] | None = None,  # pylint: disable=redefined-builtin
	) -> list[BaseObjectT] | list:  # list for empty list
		...

	@overload
	def get_objects(  # pylint: disable=too-many-arguments
		self,
		table: str,
		object_type: Type[BaseObjectT],
		return_type: Literal["dict", "ident"],
		aggregates: dict[str, str] | None = None,
		ace: list[RPCACE] | None = None,
		ident_type: IdentType = "str",
		attributes: list[str] | tuple[str, ...] | None = None,
		filter: dict[str, Any] | None = None,  # pylint: disable=redefined-builtin
	) -> list[dict] | list:  # list for empty list
		...

	def get_objects(  # pylint: disable=too-many-arguments,too-many-locals
		self,
		table: str,
		object_type: Type[BaseObjectT],
		return_type: Literal["object", "dict", "ident"] = "object",
		aggregates: dict[str, str] | None = None,
		ace: list[RPCACE] | None = None,
		ident_type: IdentType = "str",
		attributes: list[str] | tuple[str, ...] | None = None,
		filter: dict[str, Any] | None = None,  # pylint: disable=redefined-builtin
	) -> list[dict] | list[BaseObjectT] | list:  # list for empty list
		if not self.connected:
			raise RuntimeError("Not connected to MySQL server")
		ace = ace or []
		aggregates = aggregates or {}
		if not table.lstrip().upper().startswith("FROM"):
			if " " not in table:
				table = f"`{table}`"
			table = f"FROM {table}"
		tables = re.findall(r"(?:FROM|JOIN)\s+`?([a-zA-Z_]+)`?", table)

		ident_attributes: tuple[str, ...] = tuple()
		if return_type == "ident" or attributes or aggregates:
			ident_attributes = get_ident_attributes(object_type)  # type: ignore[arg-type]

		if return_type == "ident":
			attributes = ident_attributes
		elif attributes:
			attributes = list(attributes)
			for attr in ident_attributes:
				if attr not in attributes:
					attributes.append(attr)

		columns = self.get_columns(tables=tables, ace=ace, attributes=attributes)
		aggs = [f"{agg} AS `{name}`" for name, agg in aggregates.items()] if aggregates else ""
		query = (
			"SELECT "
			f"{', '.join(aggs) + ', ' if aggs else ''}"
			f"""{', '.join([f"{c.select} AS `{a}`" for a, c in columns.items() if c.select])}"""
			f" {table}"
		)
		where, params = self.get_where(columns=columns, ace=ace, filter=filter)
		group_by = ""
		if aggregates:
			# Use first table for performance!
			group_by = "GROUP BY " + ", ".join(
				[f"`{tables[0]}`.`{col.column}`" for attr, col in columns.items() if attr in ident_attributes]
			)

		with self.session() as session:
			query = f"{query} {where} {group_by}"
			result = session.execute(query, params=params).fetchall()

			with server_timing("database_result_processing"):
				l_aggregates = list(aggregates)

				if not result:
					return []
				if return_type == "ident":
					return [self.get_ident(data=dict(row), ident_attributes=ident_attributes, ident_type=ident_type) for row in result]

				conversions = self._get_read_conversions(object_type)  # type: ignore[arg-type]
				if return_type == "dict":
					return [
						self._row_to_object(row=row, object_type=object_type, aggregates=l_aggregates, conversions=conversions).to_hash()
						for row in result
					]
				return [
					self._row_to_object(row=row, object_type=object_type, aggregates=l_aggregates, conversions=conversions)
					for row in result
				]

	def get_idents(  # pylint: disable=too-many-arguments
		self,
		table: str,
		object_type: Type[BaseObject],
		ace: list[RPCACE],
		ident_type: IdentType = "str",
		filter: dict[str, Any] | None = None,  # pylint: disable=redefined-builtin
	) -> list[dict]:
		ident_attributes = get_ident_attributes(object_type)  # type: ignore[arg-type]
		if not ident_attributes:
			raise ValueError(f"Failed to get ident attributes for {object_type}")
		return self.get_objects(  # type: ignore[call-overload]
			table=table,
			ace=ace,
			object_type=object_type,
			ident_type=ident_type or "str",
			return_type="ident",
			attributes=ident_attributes,
			filter=filter,
		)

	def insert_query(  # pylint: disable=too-many-locals,too-many-arguments,too-many-branches
		self,
		table: str,
		obj: BaseObject | dict[str, Any],
		ace: list[RPCACE],
		create: bool = True,
		set_null: bool = True,
		additional_data: dict[str, Any] | None = None,
	) -> tuple[str, dict[str, Any]]:
		if not isinstance(obj, BaseObject):
			obj = OBJECT_CLASSES[obj["type"]].fromHash(obj)
		assert isinstance(obj, BaseObject)
		if set_null:
			obj.setDefaults()
		data = obj.to_hash()
		ident_attrs = []
		if not create:
			ident_attrs = list(obj.getIdent("dict"))
		columns = self.get_columns([table], ace=ace)
		conversions = self._get_write_conversions(type(obj))  # type: ignore[arg-type]

		allowed_client_ids = self.get_allowed_client_ids(ace)

		cols = []
		vals = []
		where = []
		updates = []
		for attr, column in columns.items():
			if attr not in data:
				continue

			if allowed_client_ids and column.client_id_column:
				if data.get(attr) not in allowed_client_ids:
					raise BackendPermissionDeniedError(f"No permission for {column}/{attr}: {data.get(attr)}")

			if attr in ident_attrs:
				where.append(f"`{column.column}` = :{attr}")
			if not set_null and data.get(attr) is None:
				continue

			try:
				data[attr] = conversions[attr](data[attr])
			except KeyError:
				pass

			cols.append(f"`{column.column}`")
			vals.append(f":{attr}")
			updates.append(f"`{column.column}` = :{attr}")

		if additional_data:
			for col, val in additional_data.items():
				cols.append(f"`{col}`")
				vals.append(f":{col}")
				updates.append(f"`{col}` = :{col}")
				data[col] = val

		if not updates:
			return "", {}

		if create:
			query = f"INSERT INTO `{table}` ({','.join(cols)}) VALUES ({','.join(vals)}) ON DUPLICATE KEY UPDATE {','.join(updates)}"
		else:
			if not where:
				raise RuntimeError("No where")
			query = f"UPDATE `{table}` SET {','.join(updates)} WHERE {' AND '.join(where)}"
		return query, data

	def insert_object(  # pylint: disable=too-many-locals,too-many-arguments
		self,
		table: str,
		obj: BaseObject | dict[str, Any],
		ace: list[RPCACE],
		create: bool = True,
		set_null: bool = True,
		additional_data: dict[str, Any] | None = None,
		session: Session | None = None,
	) -> Any:
		if not self.connected:
			raise RuntimeError("Not connected to MySQL server")
		query, params = self.insert_query(table=table, obj=obj, ace=ace, create=create, set_null=set_null, additional_data=additional_data)
		if query:
			with self.session(session) as session:  # pylint: disable=redefined-argument-from-local
				result = session.execute(query, params=params)
				return result.lastrowid
		return None

	def bulk_insert_objects(  # pylint: disable=too-many-locals,too-many-arguments
		self,
		table: str,
		objs: list[BaseObject | dict[str, Any]],
		session: Session | None = None,
	) -> Any:
		if not self.connected:
			raise RuntimeError("Not connected to MySQL server")
		obj_type = type(objs[0]) if isinstance(objs[0], BaseObject) else OBJECT_CLASSES[objs[0]["type"]]
		columns = self.get_columns([table], ace=[])
		conversions = self._get_write_conversions(obj_type)  # type: ignore[arg-type]

		cols = []
		vals = []
		attrs = []
		for attr, column in columns.items():
			attrs.append(attr)
			cols.append(f"`{column.column}`")
			vals.append(f":{attr}")

		data = []
		for obj in objs:
			if isinstance(obj, BaseObject):
				obj = obj.to_hash()

			dat = {}
			for attr in attrs:
				val = obj.get(attr)
				if val is not None:
					conv = conversions.get(attr)
					if conv:
						val = conv(val)
				dat[attr] = val
			data.append(dat)

		query = f"INSERT INTO `{table}` ({','.join(cols)}) VALUES ({','.join(vals)})"
		with self.session(session) as session:  # pylint: disable=redefined-argument-from-local
			session.execute(query, params=data)

	def delete_query(  # pylint: disable=too-many-locals
		self,
		table: str,
		object_type: Type[BaseObjectT],
		obj: list[BaseObjectT] | BaseObjectT | list[dict[str, Any]] | dict[str, Any],
		ace: list[RPCACE],
	) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
		ident_attributes = get_ident_attributes(object_type)  # type: ignore[arg-type]
		columns = self.get_columns(tables=[table], ace=ace, attributes=ident_attributes)
		if len(columns) < len(ident_attributes):
			raise BackendPermissionDeniedError("No permission")
		allowed_client_ids = self.get_allowed_client_ids(ace)

		conditions = []
		params: dict[str, Any] = {}
		idents: list[dict[str, Any]] = []
		for entry in obj if isinstance(obj, (list, tuple, set)) else [obj]:
			cond = []
			ident = {}
			for attr in ident_attributes:
				col = columns[attr]
				val = None
				if isinstance(entry, dict):
					val = entry.get(attr)
				else:
					val = getattr(entry, attr)
				if not val:
					if attr == "type":
						continue
					if val is None:
						# Empty string allowed
						raise ValueError(f"No value for ident attribute {attr!r}")

				if col.client_id_column and allowed_client_ids is not None and val not in allowed_client_ids:
					# No permission
					break

				param = f"p{len(params) + 1}"
				cond.append(f"`{col.column}` = :{param}")
				params[param] = val
				ident[attr] = val
			if cond and ident:
				idents.append(ident)
				conditions.append(f"({' AND '.join(cond)})")

		if not conditions:
			raise BackendPermissionDeniedError("No objects to delete")

		return f"DELETE FROM `{table}` WHERE {' OR '.join(conditions)}", params, idents

	def delete_objects(  # pylint: disable=too-many-locals
		self,
		table: str,
		object_type: Type[BaseObjectT],
		obj: list[BaseObjectT] | BaseObjectT | list[dict[str, Any]] | dict[str, Any],
		ace: list[RPCACE],
	) -> None:
		if not self.connected:
			raise RuntimeError("Not connected to MySQL server")
		query, params, _idents = self.delete_query(table=table, object_type=object_type, obj=obj, ace=ace)
		with self.session() as session:
			session.execute(query, params=params)
