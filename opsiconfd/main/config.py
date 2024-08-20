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


def get_config_main() -> None:
	init_logging(log_mode="local")
	print(json.dumps(config.items(), indent=2))


def set_config_main() -> None:
	init_logging(log_mode="local")
	config._parse_args(ignore_env=True)
	logger.debug("Configs passed: %s", config.set_configs)
	if not config.set_configs:
		raise ValueError("No config options passed")
	options: dict[str, Any] = {}
	for option_value_pair in config.set_configs:
		if "=" not in option_value_pair:
			raise ValueError(f"Invalid option value pair: {option_value_pair}")
		option, value = option_value_pair.split("=", 1)
		option = option.strip().lower().strip("-").replace("-", "_")
		value = value.strip()
		options[option] = value

	config.update_config(options, parse_values=True, on_change=config.on_change)
