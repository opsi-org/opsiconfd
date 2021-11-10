# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd - addon manager
"""

import os
import sys
import importlib
from urllib.parse import quote, unquote
from importlib._bootstrap import BuiltinImporter
from typing import Dict, List

from ..config import config
from ..logging import logger
from ..utils import Singleton

from .addon import Addon


class AddonImporter(BuiltinImporter):
	@classmethod
	def find_spec(cls, fullname, path=None, target=None):
		if not fullname.startswith("opsiconfd.addon"):
			return None
		addon_path = unquote(fullname.split("_", 1)[1])
		init_path = os.path.join(addon_path, "python", "__init__.py")
		if not os.path.exists(init_path):
			return None
		return importlib.util.spec_from_file_location(fullname, init_path)

sys.meta_path.append(AddonImporter)


class AddonManager(metaclass=Singleton):
	def __init__(self):
		self._addons: Dict[str, Addon] = {}

	@classmethod
	def module_name(cls, addon_path: str) -> str:
		return f'opsiconfd.addon_{quote(addon_path)}'

	@property
	def addons(self) -> List[Addon]:
		return list(self._addons.values())

	def load_addon(self, addon_path: str) -> None:
		from ..application import app  # pylint: disable=import-outside-toplevel
		logger.info("Loading addon from '%s'", addon_path)
		module_name = self.module_name(addon_path)
		module = None
		if module_name in sys.modules:
			reload = []
			for sys_module in list(sys.modules):
				if sys_module.startswith(module_name):
					reload.append(sys_module)
					#del sys.modules[sys_module]
			reload.sort(reverse=True)
			for sys_module in reload:
				importlib.reload(sys.modules[sys_module])
			module = sys.modules[module_name]
		else:
			module = importlib.import_module(module_name)

		for cls in module.__dict__.values():
			if isinstance(cls, type) and issubclass(cls, Addon) and cls != Addon:
				logger.notice("Loading addon '%s' (%s)", cls.id, cls.name)
				self._addons[cls.id] = cls(addon_path)
				self._addons[cls.id].on_load(app)
				# Only one class per module
				break

	def load_addons(self) -> None:
		logger.debug("Loading addons")
		self._addons = {}
		for addon_dir in config.addon_dirs:
			if not os.path.isdir(addon_dir):
				logger.debug("Addon dir '%s' not found", addon_dir)
				continue
			logger.info("Loading addons from dir '%s'", addon_dir)
			for entry in os.listdir(addon_dir):
				addon_path = os.path.abspath(os.path.join(addon_dir, entry))
				if not os.path.exists(os.path.join(addon_path, "python", "__init__.py")):
					continue
				try:
					self.load_addon(addon_path=addon_path)
				except Exception as err:  # pylint: disable=broad-except
					logger.error("Failed to load addon from %s: %s", addon_path, err, exc_info=True)

	def unload_addon(self, addon_id: str) -> None:
		from ..application import app  # pylint: disable=import-outside-toplevel
		if not addon_id in self._addons:
			raise ValueError(f"Addon '{addon_id} not loaded")
		self._addons[addon_id].on_unload(app)
		del self._addons[addon_id]

	def unload_addons(self) -> None:
		for addon in list(self._addons.values()):
			self.unload_addon(addon.id)

	def reload_addon(self, addon_id: str) -> None:
		if not addon_id in self._addons:
			raise ValueError(f"Addon '{addon_id} not loaded")
		addon = self._addons[addon_id]
		path = addon.path
		self.unload_addon(addon_id)
		self.load_addon(path)

	def reload_addons(self):
		self.unload_addons()
		self.load_addons()

	def get_addon_by_path(self, path: str) -> Addon:
		path = path or ""
		for addon in self.addons:
			if path.lower().startswith(addon.router_prefix.lower()):
				return addon
		return None
