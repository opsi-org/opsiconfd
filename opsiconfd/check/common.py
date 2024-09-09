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
from dataclasses import dataclass, field
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


class Check:
	def __init__(
		self,
		id: str,
		name: str = "",
		description: str = "",
		documentation: str = "",
		status: CheckStatus = CheckStatus.OK,
		message: str = "",
		depot_check: bool = True,
		cache: bool = True,
		cache_expiration: int = 24 * 3600,
	) -> None:
		self.id = id
		self.name = name
		if not name:
			name = id
		self.description = description
		self.documentation = documentation
		self.depot_check = depot_check

		self.cache = cache
		self.cache_expiration = cache_expiration
		self.message = message
		self.status = status

		self.result = CheckResult(
			check_id=id,
			check_name=name,
			check_description=description,
			message=message,
			check_status=status,
			details={},
		)

	def check(self) -> CheckResult:
		return CheckResult(
			check_id=self.id,
			check_name=self.name,
			check_description=self.description,
			message="No check function defined",
			check_status=CheckStatus.ERROR,
		)

	def run(self, use_cache: bool = True) -> CheckResult:
		if not self.cache or not use_cache:
			return self.check()
		result = self.check_cache_load()
		if result is not None:
			check_result = CheckResult(**result)
			check_result.partial_results = []
			for partial_result in result.get("partial_results", []):
				partial_result = PartialCheckResult(**partial_result)
				check_result.add_partial_result(partial_result)
			return check_result
		result = self.check()
		self.check_cache_store(result, self.cache_expiration)
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
			return decode(msgpack_data)
		logger.debug("Check cache miss: %s", redis_key)
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

		role = get_server_role()
		if role == "depotserver" and not check.depot_check:
			return
		self._checks[check.id] = check

	def get(self, check_id: str) -> Check:
		return self._checks[check_id]

	@property
	def check_ids(self) -> list[str]:
		return list(self._checks.keys())

	def __iter__(self) -> Iterator[Check]:
		return iter(self._checks.values())


@dataclass(slots=True, kw_only=True)
class PartialCheckResult:
	check_id: str
	check_name: str = ""
	check_description: str = ""
	check_status: CheckStatus = CheckStatus.OK
	message: str = ""
	details: dict[str, Any] = field(default_factory=dict)
	upgrade_issue: str | None = None  # version str


@dataclass(slots=True, kw_only=True)
class CheckResult(PartialCheckResult):
	partial_results: list[PartialCheckResult] = field(default_factory=list)

	def add_partial_result(self, partial_result: PartialCheckResult) -> None:
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
				newline=newline, name=partial_result.check_name, message=partial_result.message.replace("\n", newline)
			)
			if partial_result.details:
				details += "{newline} {details}".format(
					newline=newline, details=newline.join(f"{key}: {value}" for key, value in partial_result.details.items())
				)

		return f"{self.check_status.return_code()} 'opsi: {self.check_name}' - {message if message else self.check_status.value.upper()}{details}"


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
		json_result[result.check_id] = result
		if result.check_status.return_code() > json_result["check_status"].return_code():
			json_result["check_status"] = result.check_status
		summary[result.check_status] += 1
	json_result["summary"] = summary  # type: ignore
	return json_result


check_manager = CheckManager()
