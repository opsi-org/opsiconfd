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
from typing import Any, Callable, Dict, Protocol

from opsiconfd.config import config
from opsiconfd.logging import logger

from . import rpc_method


def deprecated(func: Callable | None = None, *, alternative_method: str | None = None) -> Callable:
	return rpc_method(func, deprecated=True, alternative_method=alternative_method)


class RPCExtenderMixin(Protocol):  # pylint: disable=too-few-public-methods
	def __init__(self) -> None:
		for file in sorted(Path(config.extension_config_dir).glob("*.conf")):
			logger.info("Reading rpc extension methods from '%s'", file)
			try:  # pylint: disable=loop-try-except-usage
				loc: Dict[str, Any] = {}  # pylint: disable=loop-invariant-statement
				if file.is_file():
					exec(compile(file.read_bytes(), "<string>", "exec"), None, loc)  # pylint: disable=exec-used
				for function_name, function in loc.items():
					if not function_name.startswith("_") and isfunction(function):
						logger.info("Adding rpc extension method '%s'", function_name)
						func = rpc_method(function)
						setattr(self, function_name, MethodType(func, self))
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to load extension file '%s' %s", file, err, exc_info=True)
