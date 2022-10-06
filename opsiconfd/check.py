# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""

import re
import subprocess
from distutils.version import LooseVersion

from .logging import logger


def health_check():
	logger.notice("Started health check...")
	check_system_packages()
	logger.notice("Health check done...")


def check_system_packages():
	packages = ["opsiconfd", "opsi-utils"]
	package_versions = {}
	for package in packages:
		package_versions[package] = {"version_found": None, "status": None}
	regex = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+.*$")
	for line in run_command(["dpkg", "-l"]).split("\n"):
		match = regex.search(line)
		if not match:
			continue
		if match.group(2) in package_versions:
			logger.info("Package '%s' found: version '%s', status '%s'", match.group(2), match.group(3), match.group(1))
			package_versions[match.group(2)]["version_found"] = match.group(3)
			package_versions[match.group(2)]["status"] = match.group(1)
	logger.devel(package_versions)


def run_command(cmd, shell=False, log_command=True, log_output=True):
	if log_command:
		logger.info("Executing: %s", cmd)

	try:
		out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=shell).decode("utf-8").strip()
		if log_output:
			logger.debug(out)
	except subprocess.CalledProcessError as err:
		out = err.output.decode("utf-8", "replace")
		logger.error("Command failed: %s", err)
		if log_output:
			logger.error(out)
		raise
	return out
