# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""


import os
import re
import sys
from typing import Any, Dict, List, Optional

from OPSI.System.Posix import (  # type: ignore[import]
	execute,
	isOpenSUSE,
	isRHEL,
	isSLES,
)
from packaging.version import parse
from redis.exceptions import ConnectionError as RedisConnectionError
from requests import get
from requests.exceptions import ConnectionError as RequestConnectionError
from requests.exceptions import ConnectTimeout

from opsiconfd.utils import decode_redis_result

from .logging import logger
from .utils import redis_client

ATTRIBUTES = dict(list(zip(["bold", "dark", "", "underline", "blink", "", "reverse", "concealed"], list(range(1, 9)))))
del ATTRIBUTES[""]

HIGHLIGHTS = dict(
	list(zip(["on_grey", "on_red", "on_green", "on_yellow", "on_blue", "on_magenta", "on_cyan", "on_white"], list(range(40, 48))))
)

COLORS = dict(
	list(
		zip(
			[
				"grey",
				"red",
				"green",
				"yellow",
				"blue",
				"magenta",
				"cyan",
				"white",
			],
			list(range(30, 38)),
		)
	)
)

RESET = "\033[0m"


REPO_URL = "https://download.opensuse.org/repositories/home:/uibmz:/opsi:/4.2:/stable/Debian_11/"

MT_INFO = "info"
MT_SUCCESS = "success"
MT_WARNING = "warning"
MT_ERROR = "error"


def health_check(print_messages: bool = False) -> dict:
	if print_messages:
		show_message("Started health check...")
	result = {}
	result["system_packages"] = check_system_packages(print_messages)
	result["redis"] = check_redis(print_messages)
	result["mysql"] = check_mysql(print_messages)
	if print_messages:
		show_message("Health check done...")
	return result


def check_system_packages(print_messages: bool = False) -> dict:  # pylint: disable=too-many-branches, too-many-statements
	if print_messages:
		show_message("Checking packages...")
	packages = ("opsiconfd", "opsi-utils", "opsipxeconfd")
	package_versions: Dict[str, Dict[str, Any]] = {}
	result: Dict[str, Dict[str, Any]] = {}
	url = REPO_URL
	repo_data = None
	try:
		repo_data = get(url, timeout=10)
	except (RequestConnectionError, ConnectTimeout) as err:
		logger.error(str(err))
	if not repo_data or repo_data.status_code >= 400:
		logger.error("Could not get package versions from repository.")
		return result
	for package in packages:
		package_versions[package] = {"version": "0", "version_found": "0", "status": None}

		match = re.search(f"{package}_(.+?).tar.gz", repo_data.text)  # pylint: disable=dotted-import-in-loop
		if match:
			version = match.group(1)
			package_versions[package]["version"] = version
			logger.debug("Available version for %s: %s.", package, version)

	if isRHEL() or isSLES():
		cmd = ["yum", "list", "installed"]
		regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+).*$")
		for line in execute(cmd, shell=False):
			match = regex.search(line)
			if not match:
				continue
			p_name = match.group(1).split(".")[0]
			if p_name in package_versions:
				logger.info("Package '%s' found: version '%s'", p_name, match.group(2))
				package_versions[p_name]["version_found"] = match.group(2)
	elif isOpenSUSE():
		cmd = ["zypper", "search", "-is", "opsi*"]
		regex = re.compile(r"^[^S]\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+).*$")
		for line in execute(cmd, shell=False):
			match = regex.search(line)
			if not match:
				continue
			p_name = match.group(1)
			if p_name in package_versions:
				logger.info("Package '%s' found: version '%s'", p_name, match.group(3))
				package_versions[p_name]["version_found"] = match.group(3)
	else:
		cmd = ["dpkg", "-l"]  # pylint: disable=use-tuple-over-list
		regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+.*$")
		for line in execute(cmd, shell=False):
			match = regex.search(line)
			if not match:
				continue
			if match.group(2) in package_versions:
				logger.info("Package '%s' found: version '%s'", match.group(2), match.group(3))
				if match.group(1) == "ii":
					package_versions[match.group(2)]["version_found"] = match.group(3)
	logger.info("Installed packages: %s", package_versions)

	for package, info in package_versions.items():
		result[package] = {}
		if "version_found" not in info:
			result[package] = {"status": "error", "details": f"Package '{package}' is not installed."}
			if print_messages:
				show_message(f"Package {package} should be installed.", MT_ERROR)  # pylint: disable=loop-global-usage
		elif parse(info.get("version", "0")) > parse(info.get("version_found", "0")):
			if print_messages:
				show_message(
					f"Package {package} is outdated. Installed version: {info.get('version_found')} - available version: {info.get('version')}",
					MT_WARNING,  # pylint: disable=loop-global-usage
				)
			result[package] = {
				"status": "warn",
				"details": f"Installed version: {info.get('version_found')} - available version: {info.get('version')}",
			}
		else:
			if print_messages:
				show_message(
					f"Package {package} is up to date. Installed version: {info.get('version_found')}",
					MT_SUCCESS,  # pylint: disable=loop-global-usage
				)
			result[package] = {"status": "ok", "details": f"Installed version: {info.get('version_found')}"}
	return result


def check_redis(print_messages: bool = False) -> dict:
	if print_messages:
		show_message("Checking redis...")
	try:
		with redis_client(timeout=5, test_connection=True) as redis:
			redis_info = decode_redis_result(redis.execute_command("INFO"))
			logger.info(redis_info)
			modules = [module["name"] for module in redis_info["modules"]]
			if "timeseries" not in modules:
				if print_messages:
					show_message("Redis-Timeseries not loaded.", MT_ERROR)
				return {"status": "err", "details": "Redis-Timeseries not loaded."}
			if print_messages:
				show_message("Redis is running and Redis-Timeseries is loaded.", MT_SUCCESS)
			return {"status": "ok", "details": "Redis is running and Redis-Timeseries is loaded."}
	except RedisConnectionError as err:
		logger.info(str(err))
		if print_messages:
			show_message("Cannot connect to redis!", MT_ERROR)
		return {"status": "error", "details": str(err)}


def check_mysql(print_messages: bool = False) -> dict:
	if print_messages:
		show_message("Checking mysql...")
	mysql_data = {"module": "", "config": {}}

	with open("/etc/opsi/backends/mysql.conf", encoding="utf-8") as config_file:
		exec(config_file.read(), mysql_data)  # pylint: disable=exec-used

	mysql_config = mysql_data["config"]
	try:
		execute(
			[
				"mysql",
				f"--user={mysql_config.get('username')}",  # type: ignore[attr-defined]
				f"--password={mysql_config.get('password')}",  # type: ignore[attr-defined]
				f"--host={mysql_config.get('address')}",  # type: ignore[attr-defined]
				f"--database={mysql_config.get('database')}",  # type: ignore[attr-defined]
				"-e",
				"SHOW TABLES;",
			],
			shell=False,
		)
		if print_messages:
			show_message("Connection to mysql ist working.", MT_SUCCESS)
		return {"status": "ok", "details": "Connection to mysql is working."}
	except RuntimeError as err:
		if print_messages:
			show_message(str(err).split("\n")[1], MT_ERROR)
		return {"status": "error", "details": str(err).split("\n")[1]}


def show_message(message: str, msg_type: str = MT_INFO, newline: bool = True, msg_format: Optional[str] = None, log: bool = False) -> None:
	if log:
		log_level = "info"
		if msg_type == MT_WARNING:
			log_level = "warning"
		elif msg_type == MT_ERROR:
			log_level = "error"
		exc_info = msg_type == MT_ERROR
		getattr(logger, log_level)(message, exc_info=exc_info)

	color = "white"
	attrs = ["bold"]  # pylint: disable=use-tuple-over-list
	if msg_type == MT_WARNING:
		color = "yellow"
	elif msg_type == MT_ERROR:
		color = "red"
	elif msg_type == MT_SUCCESS:
		color = "green"
	if msg_format:
		message = msg_format % message
	message = colored(message, color, attrs=attrs)
	sys.stdout.write(message)
	if newline:
		sys.stdout.write("\n")
	sys.stdout.flush()


def colored(text: str, color: Optional[str] = None, on_color: Optional[str] = None, attrs: Optional[List[str]] = None) -> str:
	"""Colorize text.

	Available text colors:
		red, green, yellow, blue, magenta, cyan, white.

	Available text highlights:
		on_red, on_green, on_yellow, on_blue, on_magenta, on_cyan, on_white.

	Available attributes:
		bold, dark, underline, blink, reverse, concealed.

	Example:
		colored('Hello, World!', 'red', 'on_grey', ['blue', 'blink'])
		colored('Hello, World!', 'green')
	"""
	if os.getenv("ANSI_COLORS_DISABLED") is None:
		fmt_str = "\033[%dm%s"
		if color is not None:
			text = fmt_str % (COLORS[color], text)

		if on_color is not None:
			text = fmt_str % (HIGHLIGHTS[on_color], text)

		if attrs is not None:
			for attr in attrs:
				text = fmt_str % (ATTRIBUTES[attr], text)  # pylint: disable=loop-global-usage

		text += RESET
	return text
