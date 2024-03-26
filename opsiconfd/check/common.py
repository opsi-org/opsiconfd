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
from typing import Any, Generator

from MySQLdb import OperationalError as MySQLdbOperationalError  # type: ignore[import]
from opsicommon.utils import compare_versions
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import OperationalError  # type: ignore[import]

from opsiconfd.utils.modules import check_module


class CheckStatus(StrEnum):
	OK = "ok"
	WARNING = "warning"
	ERROR = "error"

	def checkmk(self) -> int:
		if self == CheckStatus.OK:
			return 0
		if self == CheckStatus.WARNING:
			return 1
		if self == CheckStatus.ERROR:
			return 2


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

		return (
			f"{self.check_status.checkmk()} 'opsi: {self.check_name}' - {message if message else self.check_status.value.upper()}{details}"
		)


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
