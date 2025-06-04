# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
health check
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field, fields
from enum import StrEnum
from textwrap import dedent
from typing import Any, Iterator

from msgspec.msgpack import decode, encode
from MySQLdb import OperationalError as MySQLdbOperationalError  # type: ignore[import]
from opsicommon.utils import compare_versions
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import OperationalError  # type: ignore[import]

from opsiconfd.check.cache import check_cache_clear
from opsiconfd.config import config, get_server_role
from opsiconfd.logging import logger
from opsiconfd.redis import redis_client
from opsiconfd.utils import Singleton
from opsiconfd.utils.modules import module_available

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

	def checkmk_status(self) -> str:
		return str(self.return_code())

	def nagios_status(self) -> str:
		if self == CheckStatus.OK:
			return "OK"
		if self == CheckStatus.WARNING:
			return "WARNING"
		if self == CheckStatus.ERROR:
			return "CRITICAL"


@dataclass(init=False)
class Check:
	id: str = ""
	name: str = ""
	description: str = ""
	documentation: str = ""
	depot_check: bool = False
	cache: bool = True
	cache_expiration: int = CACHE_EXPIRATION
	partial_checks: list[Check] = field(default_factory=list)

	def __init__(self, **kwargs: Any) -> None:
		names = set([f.name for f in fields(self)])
		for k, v in kwargs.items():
			if k in names:
				setattr(self, k, v)

	def __post_init__(self) -> None:
		if self.id == "":
			raise ValueError("Check id must be set")
		self.name = self.name or self.id
		self.description = dedent(self.description or self.name)
		self.documentation = dedent(self.documentation or "")
		self.cache_expiration = self.cache_expiration or CACHE_EXPIRATION

	def __eq__(self, other: object) -> bool:
		return isinstance(other, Check) and self.id == other.id

	def add_partial_checks(self, *checks: Check) -> None:
		is_depot = get_server_role() == "depotserver"
		for check in checks:
			if is_depot and not check.depot_check:
				return
			if check not in self.partial_checks:
				self.partial_checks.append(check)

	def check(self) -> CheckResult:
		try:
			return self._check()
		except Exception as err:
			result = CheckResult(
				check=self,
				message=str(err),
				check_status=CheckStatus.ERROR,
			)
			if isinstance(err, (OperationalError, MySQLdbOperationalError)):
				error_str = str(err).split("\n", 1)[0]
				match = re.search(r"\((\d+),\s+(\S.*)\)", error_str)
				if match:
					error_str = match.group(1) + " - " + match.group(2).strip("'").replace("\\'", "'")
				result.message = error_str
			elif isinstance(err, RedisConnectionError):
				result.message = f"Cannot connect to Redis: {err}"

			logger.error("Error during check %s: %s", self.id, err, exc_info=True)
			return result

	def _check(self) -> CheckResult:
		return CheckResult(
			check=self,
			message="No check function defined",
			check_status=CheckStatus.ERROR,
		)

	def run(self, clear_cache: bool = False) -> CheckResult:
		result = None
		issue_counter = 0
		if clear_cache:
			check_cache_clear(self.id)
		elif self.cache:
			result = self.load_result_from_cache()
		if result is None:
			result = self.check()

		for partial_check in self.partial_checks:
			partial_result = partial_check.run(clear_cache)
			result.add_partial_result(partial_result)
			if partial_result.check_status != CheckStatus.OK:
				issue_counter += 1
				if partial_result.upgrade_issue:
					result.upgrade_issue = partial_result.upgrade_issue

		if issue_counter > 0:
			result.message = f"{issue_counter} issue(s) found."
		if self.cache:
			self.store_result_in_cache(result, self.cache_expiration)
		return result

	def store_result_in_cache(self, result: Any, expiration: int = CACHE_EXPIRATION) -> None:
		# TODO: check if check id is valid. With partial checks...
		if self.cache is False:
			return
		redis_key = f"opsiconfd:checkcache:{self.id}"
		logger.debug("Check cache store: %s", redis_key)
		redis_client().set(redis_key, encode(result), ex=expiration)

	def load_result_from_cache(self) -> CheckResult | None:
		redis_key = f"opsiconfd:checkcache:{self.id}"
		msgpack_data = redis_client().get(redis_key)
		if msgpack_data:
			logger.debug("Check cache hit: %s", redis_key)
			data = decode(msgpack_data)
			data["check"] = Check(**data.get("check", self))
			data["from_cache"] = True
			check_result = CheckResult(**data)
			check_result.partial_results = []
			for partial_result in data.get("partial_results", []):
				partial_result["check"] = Check(**partial_result.get("check", self))
				partial_result["from_cache"] = True
				partial_result = CheckResult(**partial_result)
				check_result.add_partial_result(partial_result)
			return check_result
		logger.debug("Check cache miss: %s", redis_key)
		return None


class CheckManager(metaclass=Singleton):
	_checks: dict[str, Check] = {}
	_possible_checks: dict[str, Check] = {}

	def __init__(self) -> None:
		self._checks = {}

	def register(self, *checks: Check) -> None:
		role = get_server_role()
		for check in checks:
			self._possible_checks[check.id] = check
			if role == "depotserver" and not check.depot_check:
				continue
			if (config.checks and check.id not in config.checks) or (config.skip_checks and check.id in config.skip_checks):
				continue
			self._checks[check.id] = check

	def get(self, check_id: str) -> Check:
		return self._checks[check_id]

	def remove_check(self, check_id: str) -> None:
		if check_id == "all":
			self._checks = {}
			return
		if check_id in self._checks:
			del self._checks[check_id]

	@property
	def check_ids(self) -> list[str]:
		return list(self._checks.keys())

	@property
	def possible_checks(self) -> dict[str, Check]:
		return self._possible_checks

	def __iter__(self) -> Iterator[Check]:
		return iter(self._checks.values())


@dataclass(kw_only=True)
class CheckResult:
	check: Check
	check_status: CheckStatus = CheckStatus.OK
	message: str = ""
	details: dict[str, Any] = field(default_factory=dict)
	upgrade_issue: str | None = None  # version str
	partial_results: list[CheckResult] = field(default_factory=list)
	from_cache: bool = False

	def __repr__(self) -> str:
		return f"{self.__class__.__name__}({json.dumps(asdict(self), indent=2)}"

	def __str__(self) -> str:
		return f"{self.__class__.__name__}: {self.check.id} - {self.check_status}"

	def __post_init__(self) -> None:
		if isinstance(self.check_status, str):
			self.check_status = CheckStatus(self.check_status)

	def add_partial_result(self, partial_result: CheckResult) -> None:
		if partial_result in self.partial_results:
			return
		self.partial_results.append(partial_result)
		if partial_result.check_status == CheckStatus.ERROR:
			self.check_status = CheckStatus.ERROR
		if partial_result.check_status == CheckStatus.WARNING and self.check_status != CheckStatus.ERROR:
			self.check_status = CheckStatus.WARNING
		if partial_result.upgrade_issue:
			if not self.upgrade_issue or compare_versions(partial_result.upgrade_issue, "<", self.upgrade_issue):
				self.upgrade_issue = partial_result.upgrade_issue

	def monitoring_details(self, prefix: str, newline: str = "\\n", level: int = 0) -> str:
		message = self.message.replace("\n", " ") if self.message else self.check_status.value.upper()
		if level == 0:
			out = f"{prefix}{message}{newline}"
		else:
			out = f"{self.check_status.upper()} - '{message}{newline}"

		if self.details:
			indent = "   " if level > 0 else ""
			out += newline.join(f"{indent}{key}: {str(value)}" for key, value in self.details.items()) + newline

		if self.partial_results:
			out += (
				newline
				+ "".join(partial_result.monitoring_details(prefix, newline, level + 1) for partial_result in self.partial_results)
				+ newline
			)

		return out

	def to_checkmk(self) -> str:
		if not module_available("monitoring"):
			return "Monitoring module not licensed, Checkmk output not available. Please check your opsi licenses."

		prefix = f"{self.check_status.checkmk_status()} 'opsi: {self.check.name}' - "
		return self.monitoring_details(prefix)

	def to_nagios(self) -> str:
		if not module_available("monitoring"):
			return "Monitoring module not licensed, Nagios output not available. Please check your opsi licenses."

		prefix = f"{self.check_status.nagios_status()}: {self.check.name}: "
		return self.monitoring_details(prefix)

	def to_zabbix(self) -> str:
		if not module_available("monitoring"):
			return "Monitoring module not licensed, Nagios output not available. Please check your opsi licenses."

		prefix = f"{self.check_status.nagios_status()}: {self.check.name}: "
		return self.monitoring_details(prefix, newline="\n")


def get_json_result(results: Iterator[CheckResult]) -> dict[str, CheckResult]:
	summary = {CheckStatus.OK: 0, CheckStatus.WARNING: 0, CheckStatus.ERROR: 0}
	json_result: dict["str" | CheckStatus, Any] = {}
	json_result["check_status"] = CheckStatus.OK
	for result in results:
		json_result[result.check.id] = result
		if CheckStatus(result.check_status).return_code() > CheckStatus(json_result["check_status"]).return_code():
			json_result["check_status"] = result.check_status
		summary[result.check_status] += 1
	json_result["summary"] = summary  # type: ignore
	return json_result


check_manager = CheckManager()


def register_check(*checks: Check) -> None:
	CheckManager().register(*checks)
