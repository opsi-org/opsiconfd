# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd main.config
"""

import json
from typing import Any

from opsiconfd.config import config
from opsiconfd.logging import init_logging, logger
from opsiconfd.utils import reload_opsiconfd_if_running, restart_opsiconfd_if_running


def get_config_main() -> None:
	init_logging(log_mode="local")
	print(json.dumps(config.items(), indent=2))


def set_config_main() -> None:
	init_logging(log_mode="local")

	config._parse_args(ignore_env=True)
	cur_conf = config.items().copy()
	logger.debug("Current config: %s", cur_conf)
	logger.debug("Configs passed: %s", config.set_configs)
	options: dict[str, Any] = {}
	for option_value_pair in config.set_configs:
		if "=" not in option_value_pair:
			raise ValueError(f"Invalid option value pair: {option_value_pair}")
		option, value = option_value_pair.split("=", 1)
		option = option.strip().lower().strip("-").replace("-", "_")
		value = value.strip()
		options[option] = value

	logger.info("Setting config options: %s", options)
	# Parse the options to get the correct types
	conf = config.get_parser().parse_args(
		args=["set-config"], config_file_contents="\n".join([f"{o.replace('_', '-')} = {v}" for o, v in options.items()])
	)
	for option in list(options):
		options[option] = conf.__dict__[option]

	# Set the options and trigger post processing
	config.set_items(options)

	changed = False
	for option in list(options):
		value = getattr(config, option)
		if value == cur_conf[option]:
			logger.info("Option '%s' already has value '%s'", option, value)
		else:
			changed = True
			logger.info("Changing option '%s' from '%s' to '%s'", option, cur_conf[option], value)
		# Always set config to ensure that the configuration file is up to date
		config.set_config_in_config_file(option.replace("_", "-"), value)

	if changed:
		if config.on_change == "reload":
			reload_opsiconfd_if_running()
		elif config.on_change == "restart":
			restart_opsiconfd_if_running()
