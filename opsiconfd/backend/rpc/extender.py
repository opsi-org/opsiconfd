# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.backend.rpc.extender
"""

from inspect import isfunction
from pathlib import Path
from types import MethodType
from typing import Any, Dict

from opsiconfd.config import config
from opsiconfd.logging import logger

# deprecated can be used in extension config files
from . import deprecated, rpc_method  # pylint: disable=unused-import


class RPCExtenderMixin:  # pylint: disable=too-few-public-methods
	def __init__(self) -> None:
		for file in sorted(Path(config.extension_config_dir).glob("*.conf")):
			logger.info("Reading rpc extension methods from '%s'", file)
			loc: Dict[str, Any] = {}  # pylint: disable=loop-invariant-statement
			if file.is_file():
				exec(compile(file.read_bytes(), "<string>", "exec"), None, loc)  # pylint: disable=exec-used
			for function_name, function in loc.items():
				if isfunction(function):
					logger.info("Adding rpc extension method '%s'", function_name)
					rpc_method(function)
					setattr(self, function_name, MethodType(function, self))
