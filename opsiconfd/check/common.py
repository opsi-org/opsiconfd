# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import dataclass, field, fields
from enum import StrEnum
from typing import Any, Generator, Iterator

from msgspec.msgpack import decode, encode
from MySQLdb import OperationalError as MySQLdbOperationalError  # type: ignore[import]
from opsicommon.utils import compare_versions
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import OperationalError  # type: ignore[import]

from opsiconfd.config import get_server_role
from opsiconfd.logging import logger
from opsiconfd.redis import redis_client
from opsiconfd.utils import Singleton
from opsiconfd.utils.modules import check_module

CACHE_EXPIRATION = 24 * 3600  # In seconds


class CheckStatus(StrEnum):
	OK = "ok"
	WARNING = "warning"
	ERROR = "error"

	def return_code(self) -> int:
		if self == CheckStatus.OK:
			return 0
		if self == CheckStatus.WARNING:
			return 1
		if self == CheckStatus.ERROR:
			return 2


@dataclass(init=False)
class Check:
	# id: str = field(default="")
	# name: str = field(default="")
	# description: str = field(default="")
	# documentation: str = field(default="")
	# depot_check: bool = field(default=True)
	# cache: bool = field(default=True)
	# cache_expiration: int = field(default=CACHE_EXPIRATION)
	id: str = ""
	name: str = ""
	description: str = ""
	documentation: str = ""
	depot_check: bool = True
	cache: bool = True
	cache_expiration: int = CACHE_EXPIRATION
	partial_checks: list[Check] = field(default_factory=list)
	partial_check: bool = False

	def __init__(self, **kwargs: Any) -> None:
		names = set([f.name for f in fields(self)])
		for k, v in kwargs.items():
			if k in names:
				setattr(self, k, v)

	# def __init__(
	# 	self,
	# 	**kwargs: Any,
	# ) -> None:
	# 	# if self.id == "":
	# 	# 	raise ValueError("Check id must be set")
	# 	self.id = self.id or self.__class__.__name__
	# 	self.name = self.name or self.id
	# 	self.description = self.description or self.name
	# 	self.documentation = self.documentation or ""
	# 	self.depot_check = self.depot_check or True
	# 	self.cache = self.cache or True
	# 	self.cache_expiration = self.cache_expiration or 24 * 3600

	def __post_init__(self) -> None:
		if self.id == "":
			raise ValueError("Check id must be set")
		self.name = self.name or self.id
		self.description = self.description or self.name
		self.documentation = self.documentation or ""
		self.depot_check = self.depot_check or True
		self.cache = self.cache or True
		self.cache_expiration = self.cache_expiration or CACHE_EXPIRATION
		self.partial_check = self.partial_check or False

	def add_partial_checks(self, *checks: Check) -> None:
		role = get_server_role()
		for check in checks:
			if role == "depotserver" and not check.depot_check:
				return
			self.partial_checks.append(check)

	def check(self) -> CheckResult | None:
		return CheckResult(
			check=self,
			message="No check function defined",
			check_status=CheckStatus.ERROR,
		)

	def run(self, use_cache: bool = True, issues: list = []) -> CheckResult:
		if not self.partial_check:
			issues = []

			if self.cache and use_cache:
				result = self.check_cache_load()
				if result is not None:
					return result
		result = self.check()

		for partial_check in self.partial_checks:
			partial_result = partial_check.run(use_cache, issues)

			if CheckStatus(result.check_status).return_code() < CheckStatus(partial_result.check_status).return_code():
				result.check_status = partial_result.check_status
			if partial_result:
				result.add_partial_result(partial_result)

		if self.partial_check and result.check_status != CheckStatus.OK:
			issues.append(result.check.id)

		if not self.partial_check:
			if len(issues) > 0:
				result.message = f"{len(issues)} issue(s) found."
			# self.check_cache_store(result, self.cache_expiration)
		return result

	def check_cache_store(self, result: Any, expiration: int = CACHE_EXPIRATION) -> None:
		if self.id not in CheckManager().check_ids:
			logger.error("Invalid check cache id: %s", self.id)
		redis_key = f"opsiconfd:checkcache:{self.id}"
		logger.debug("Check cache store: %s", redis_key)
		redis_client().set(redis_key, encode(result), ex=expiration)

	def check_cache_load(self) -> Any:
		redis_key = f"opsiconfd:checkcache:{self.id}"
		msgpack_data = redis_client().get(redis_key)
		if msgpack_data:
			logger.debug("Check cache hit: %s", redis_key)

			print("Check cache hit:", redis_key)
			data = decode(msgpack_data)
			data["check"] = Check(**data.get("check", self))
			check_result = CheckResult(**data)
			check_result.partial_results = []
			for partial_result in data.get("partial_results", []):
				partial_result["check"] = Check(**partial_result.get("check", self))
				partial_result = CheckResult(**partial_result)
				check_result.add_partial_result(partial_result)
			return check_result
		logger.debug("Check cache miss: %s", redis_key)
		print("cache miss")
		return None


class CheckManager(metaclass=Singleton):
	_checks: dict[str, Check] = {}

	def __init__(self) -> None:
		self._checks = {}

	# def register(self, *checks: Check | List[Check]) -> None:
	def register(self, *checks: Check) -> None:
		role = get_server_role()
		# if isinstance(checks, Check):
		# 	checks = [checks]
		for check in checks:
			if role == "depotserver" and not check.depot_check:
				continue
			self._checks[check.id] = check
		self._checks[check.id] = check

	def get(self, check_id: str) -> Check:
		return self._checks[check_id]

	@property
	def check_ids(self) -> list[str]:
		return list(self._checks.keys())

	def __iter__(self) -> Iterator[Check]:
		return iter(self._checks.values())


# @dataclass(slots=True, kw_only=True)
# class PartialCheckResult:
# 	check = Check
# 	check_status: CheckStatus = CheckStatus.OK
# 	message: str = ""
# 	details: dict[str, Any] = field(default_factory=dict)
# 	upgrade_issue: str | None = None  # version str


# @dataclass(slots=True, kw_only=True)
@dataclass(kw_only=True)
class CheckResult:
	check: Check
	check_status: CheckStatus = CheckStatus.OK
	message: str = ""
	details: dict[str, Any] = field(default_factory=dict)
	upgrade_issue: str | None = None  # version str

	partial_results: list[CheckResult] = field(default_factory=list)

	def add_partial_result(self, partial_result: CheckResult) -> None:
		self.partial_results.append(partial_result)
		if partial_result.check_status == CheckStatus.ERROR:
			self.check_status = CheckStatus.ERROR
		if partial_result.check_status == CheckStatus.WARNING and self.check_status != CheckStatus.ERROR:
			self.check_status = CheckStatus.WARNING
		if partial_result.upgrade_issue:
			if not self.upgrade_issue or compare_versions(partial_result.upgrade_issue, "<", self.upgrade_issue):
				self.upgrade_issue = partial_result.upgrade_issue

	def to_checkmk(self) -> str:
		if not check_module("monitoring"):
			return "You need to enable the monitoring module to use checkmk output. Please check your opsi licenses."
		newline = "\\n"
		message = self.message.replace("\n", " ")
		details = ""
		if self.details:
			details = "{newline} {details}".format(
				newline=newline, details=newline.join(f"{key}: {value}" for key, value in self.details.items())
			)
		for partial_result in self.partial_results:
			details += "{newline} '{name}': {message}".format(
				newline=newline, name=partial_result.check.name, message=partial_result.message.replace("\n", newline)
			)
			if partial_result.details:
				details += "{newline} {details}".format(
					newline=newline, details=newline.join(f"{key}: {value}" for key, value in partial_result.details.items())
				)

		return f"{self.check_status.return_code()} 'opsi: {self.check.name}' - {message if message else self.check_status.value.upper()}{details}"


@contextmanager
def exc_to_result(result: CheckResult) -> Generator[None, None, None]:
	try:
		yield
	except (OperationalError, MySQLdbOperationalError) as err:
		result.check_status = CheckStatus.ERROR
		error_str = str(err).split("\n", 1)[0]
		match = re.search(r"\((\d+),\s+(\S.*)\)", error_str)
		if match:
			error_str = match.group(1) + " - " + match.group(2).strip("'").replace("\\'", "'")
		result.message = error_str
	except RedisConnectionError as err:
		result.check_status = CheckStatus.ERROR
		result.message = f"Cannot connect to Redis: {err}"
	except Exception as err:
		result.check_status = CheckStatus.ERROR
		result.message = str(err)


def get_json_result(results: Iterator[CheckResult]) -> dict[str, CheckResult]:
	summary = {CheckStatus.OK: 0, CheckStatus.WARNING: 0, CheckStatus.ERROR: 0}
	json_result: dict["str" | CheckStatus, Any] = {}
	json_result["check_status"] = CheckStatus.OK
	for result in results:
		json_result[result.check.id] = result
		if result.check_status.return_code() > json_result["check_status"].return_code():
			json_result["check_status"] = result.check_status
		summary[result.check_status] += 1
	json_result["summary"] = summary  # type: ignore
	return json_result


check_manager = CheckManager()


def register_check(*checks: Check) -> None:
	CheckManager().register(*checks)
