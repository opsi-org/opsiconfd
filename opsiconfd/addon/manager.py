# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd - addon manager
"""

import importlib
import os
import sys
from functools import lru_cache
from importlib._bootstrap import BuiltinImporter, ModuleSpec  # type: ignore[import]
from os import listdir
from os.path import abspath, exists, isdir, join
from pathlib import Path
from typing import Optional
from urllib.parse import quote, unquote

from opsiconfd.addon.addon import Addon
from opsiconfd.application import app
from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.redis import decode_redis_result, redis_client
from opsiconfd.utils import Singleton


class AddonImporter(BuiltinImporter):
	@classmethod
	def find_spec(cls: type, fullname: str, path: str | None = None, target: str | None = None) -> ModuleSpec | None:
		if not fullname.startswith("opsiconfd.addon"):
			return None
		addon_path = unquote(fullname.split("_", 1)[1])
		init_path = os.path.join(addon_path, "python", "__init__.py")
		if not exists(init_path):
			return None
		return importlib.util.spec_from_file_location(fullname, init_path)


sys.meta_path.append(AddonImporter)  # type: ignore[arg-type]


class AddonManager(metaclass=Singleton):
	_initialized = False

	def __init__(self) -> None:
		if self._initialized:
			return
		self._initialized = True
		self._addons: dict[str, Addon] = {}

	@classmethod
	def module_name(cls, addon_path: str) -> str:
		return f"opsiconfd.addon_{quote(addon_path)}"

	@property
	def addons(self) -> list[Addon]:
		return list(self._addons.values())

	def load_addon(self, addon_path: str) -> None:
		logger.info("Loading addon from '%s'", addon_path)
		module_name = self.module_name(addon_path)
		if module_name in sys.modules:
			reload = [sys_module for sys_module in list(sys.modules) if sys_module.startswith(module_name)]
			reload.sort(reverse=True)
			for sys_module in reload:
				importlib.reload(sys.modules[sys_module])
			module = sys.modules[module_name]
		else:
			module = importlib.import_module(module_name)

		for cls in module.__dict__.values():
			if isinstance(cls, type) and issubclass(cls, Addon) and cls != Addon and cls.id:
				logger.notice("Loading addon '%s' (%s)", cls.id, cls.name)
				self._addons[cls.id] = cls(addon_path)
				self._addons[cls.id].on_load(app)
				# Only one class per module
				break
		self.get_addon_by_path.cache_clear()

	def load_addons(self) -> None:
		logger.debug("Loading addons")
		self._addons = {}
		redis = redis_client()
		failed_addons = decode_redis_result(redis.lrange(f"{config.redis_key('state')}:application:addons:errors", 0, -1))
		for failed_addon in failed_addons:
			redis.delete(f"{config.redis_key('state')}:application:addons:errors:{failed_addon}")
		redis.delete(f"{config.redis_key('state')}:application:addons:errors")
		for addon_dir in config.addon_dirs:
			if not isdir(addon_dir):
				logger.debug("Addon dir '%s' not found", addon_dir)
				continue
			logger.info("Loading addons from dir '%s'", addon_dir)
			for entry in listdir(addon_dir):
				addon_path = abspath(join(addon_dir, entry))
				if not exists(join(addon_path, "python", "__init__.py")):
					continue
				try:
					self.load_addon(addon_path=addon_path)
				except Exception as err:
					addon_folder = Path(addon_path).name
					redis.lpush(f"{config.redis_key('state')}:application:addons:errors", addon_folder)
					redis.hset(
						f"{config.redis_key('state')}:application:addons:errors:{addon_folder}",
						mapping={"addon_path": addon_path, "error": str(err)},
					)
					logger.error("Failed to load addon from %s: %s", addon_path, err, exc_info=True)

	def unload_addon(self, addon_id: str) -> None:
		if addon_id not in self._addons:
			raise ValueError(f"Addon '{addon_id} not loaded")
		self._addons[addon_id].on_unload(app)
		del self._addons[addon_id]
		self.get_addon_by_path.cache_clear()

	def unload_addons(self) -> None:
		for addon in list(self._addons.values()):
			self.unload_addon(addon.id)

	def reload_addon(self, addon_id: str) -> None:
		if addon_id not in self._addons:
			raise ValueError(f"Addon '{addon_id} not loaded")
		addon = self._addons[addon_id]
		path = addon.path
		self.unload_addon(addon_id)
		self.load_addon(path)

	def reload_addons(self) -> None:
		self.unload_addons()
		self.load_addons()

	@lru_cache(maxsize=50)
	def get_addon_by_path(self, path: str) -> Optional[Addon]:
		path = path or ""
		for addon in self.addons:
			if path.lower().startswith(addon.router_prefix.lower()):
				return addon
		return None
