# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
health check
"""

from __future__ import annotations

import json

from opsicommon.utils import compare_versions
from rich.console import Console
from rich.markdown import Markdown
from rich.padding import Padding

from opsiconfd.check.cache import check_cache_clear
from opsiconfd.check.common import CheckManager, CheckResult, CheckStatus, get_json_result
from opsiconfd.check.main import health_check
from opsiconfd.check.register import register_checks
from opsiconfd.config import config
from opsiconfd.utils import DataclassCapableJSONEncoder

STYLES = {CheckStatus.OK: "bold green", CheckStatus.WARNING: "bold yellow", CheckStatus.ERROR: "bold red"}


def print_health_check_manual(console: Console) -> None:
	text = """
	# health check manual

	The opsiconfd provides a health check that checks various settings and version and can detect possible problems.
	The health check can be called in different ways.
	All variants get their data from the API call `service_healthCheck`.
	The opsi API returns the data of the health check as JSON.
	Such a JSON file is especially useful for support requests.

	* opsiconfd health-check
	* [opsi-cli](https://docs.opsi.org/opsi-docs-en/4.3/server/components/commandline.html#server-components-opsi-cli-commands-support)
	* JSONRPC method `service_healthCheck`


	> 💡: You can use the RPC interface on the admin page to call the `service_healthCheck` method.

	All the checks are described below:
	"""
	console.print(Markdown(text.replace("\t", "")))
	# for check_id in CHECKS:
	# 	check = globals()[f"check_{check_id}"]
	# 	console.print(Markdown((check.__doc__ or "").replace("\t", "")))
	for check in CheckManager():
		console.print(Markdown(check.documentation.replace("\t", "")))


def console_print_message(check_result: CheckResult, console: Console, indent: int = 0) -> None:
	style = STYLES[check_result.check_status]
	status = check_result.check_status.upper()
	msg_ident = " " * (len(status) + 3)
	message = "\n".join([f"{msg_ident if idx > 0 else ''}{line}" for idx, line in enumerate(check_result.message.split("\n"))])
	console.print(Padding(f"[{style}]{status}[/{style}] - {message}", (0, indent)))


def process_check_result(result: CheckResult, console: Console, check_version: str | None = None, detailed: bool = False) -> None:
	status = result.check_status
	message = result.message
	partial_results = []
	for pres in result.partial_results:
		if check_version and (not pres.upgrade_issue or compare_versions(pres.upgrade_issue, ">", check_version)):
			continue
		partial_results.append(pres)

	if check_version:
		if partial_results:
			status = CheckStatus.ERROR
			message = f"{len(partial_results)} upgrade issues"
		elif result.upgrade_issue and compare_versions(result.upgrade_issue, "<=", check_version):
			status = CheckStatus.ERROR
			message = "1 upgrade issue"
		else:
			status = CheckStatus.OK
			message = "No upgrade issues"
			if status == CheckStatus.OK and not detailed:
				return

	style = STYLES[status]
	console.print(f"[{style}]●[/{style}] [b]{result.check.name}[/b]: [{style}]{status.upper()}[/{style}]")
	console.print(Padding(f"[{style}]➔[/{style}] [b]{message}[/b]", (0, 3)))

	if status == CheckStatus.OK and not detailed:
		console.print("")
		return
	if partial_results:
		console.print("")
	for partial_result in partial_results:
		console_print_message(partial_result, console, 3)
	console.print("")


def overall_check_status(summary: dict[CheckStatus, int]) -> CheckStatus:
	if summary[CheckStatus.ERROR]:
		return CheckStatus.ERROR
	elif summary[CheckStatus.WARNING]:
		return CheckStatus.WARNING
	return CheckStatus.OK


def console_health_check() -> int:
	summary = {CheckStatus.OK: 0, CheckStatus.WARNING: 0, CheckStatus.ERROR: 0}
	check_version = None
	if config.upgrade_check:
		if config.upgrade_check is True:
			check_version = "1000"
		else:
			check_version = config.upgrade_check
	if config.clear_cache:
		check_cache_clear("all")

	if config.format == "checkmk":
		for result in health_check():
			summary[result.check_status] += 1
			print(result.to_checkmk())
		return overall_check_status(summary).return_code()

	console = Console(log_time=False)

	if config.format == "json":
		json_result = get_json_result(health_check())
		console.print_json(json.dumps(json_result, cls=DataclassCapableJSONEncoder, indent=2))
		status = json_result.get("check_status", CheckStatus.ERROR)
		if isinstance(status, str):
			status = CheckStatus(status)
		return status.return_code()  # type: ignore[union-attr]

	styles = STYLES
	with console.status("Health check running", spinner="arrow3"):
		if config.documentation:
			register_checks()
			print_health_check_manual(console=console)
			return 0
		for result in health_check():
			summary[result.check_status] += 1
			process_check_result(result=result, console=console, check_version=check_version, detailed=config.detailed)

	status = overall_check_status(summary)
	style = styles[status]
	res = f"Check completed with {summary[CheckStatus.ERROR]} errors and {summary[CheckStatus.WARNING]} warnings."
	console.print(f"[{style}]{status.upper()}[/{style}]: [b]{res}[/b]")
	return status.return_code()
