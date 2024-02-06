# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webdav
"""

import os
from typing import Optional

import wsgidav.fs_dav_provider  # type: ignore[import]
from fastapi import FastAPI
from fastapi.routing import Mount
from wsgidav import util  # type: ignore[import]
from wsgidav.dav_error import HTTP_FORBIDDEN, DAVError  # type: ignore[import]
from wsgidav.dav_provider import (  # type: ignore[import]
	DAVCollection,
	DAVProvider,
	_DAVResource,
)
from wsgidav.fs_dav_provider import FilesystemProvider, FolderResource
from wsgidav.wsgidav_app import WsgiDAVApp  # type: ignore[import]

from opsiconfd import __version__
from opsiconfd.config import (
	BOOT_DIR,
	DEPOT_DIR,
	PUBLIC_DIR,
	REPOSITORY_DIR,
	WORKBENCH_DIR,
	config,
	get_depotserver_id,
)
from opsiconfd.logging import logger

# Not using WSGIMiddleware because of high memory usage on file transfers.
# from a2wsgi import WSGIMiddleware
from opsiconfd.wsgi import WSGIMiddleware

BLOCK_SIZE = 64 * 1024

# Set file buffer size for reading and writing.
# Sent message chunks will have the same body size.
wsgidav.fs_dav_provider.BUFFER_SIZE = BLOCK_SIZE


# Prevent warning in log
def is_share_anonymous(self: wsgidav.dc.base_dc.BaseDomainController, path_info: str) -> bool:
	return False


wsgidav.dc.base_dc.BaseDomainController.is_share_anonymous = is_share_anonymous


class IgnoreCaseFilesystemProvider(FilesystemProvider):
	def _loc_to_file_path(self, path: str, environ: dict[str, str] | None = None) -> str:
		"""Convert resource path to a unicode absolute file path.
		Optional environ argument may be useful e.g. in relation to per-user
		sub-folder chrooting inside root_folder_path.
		"""
		root_path = self.root_folder_path
		assert root_path is not None
		assert util.is_str(root_path)
		assert util.is_str(path)

		path_parts = path.strip("/").split("/")
		file_path = os.path.abspath(os.path.join(root_path, *path_parts))
		if not os.path.exists(file_path):
			cur_path = root_path
			name_found = None
			for part in path_parts:
				cur_path = os.path.join(cur_path, part)
				if not os.path.exists(cur_path):
					part_lower = part.lower()
					name_found = None
					for name in os.listdir(os.path.dirname(cur_path)):
						if name.lower() == part_lower:
							name_found = name
							break
					if not name_found:
						# Give up
						break
					cur_path = os.path.join(os.path.dirname(cur_path), name_found)
			if name_found and cur_path.lower() == file_path.lower():
				file_path = cur_path

		is_shadow, file_path = self._resolve_shadow_path(path, environ, file_path)
		if not file_path.startswith(root_path) and not is_shadow:
			raise RuntimeError(f"Security exception: tried to access file outside root: {file_path}")

		# Convert to unicode
		file_path = util.to_unicode_safe(file_path)
		return file_path


class VirtualRootFilesystemCollection(DAVCollection):
	def __init__(self, environ: dict[str, str], provider: DAVProvider) -> None:
		DAVCollection.__init__(self, "/", environ)
		self.provider = provider

	def get_member_names(self) -> list[str]:
		return [name.lstrip("/") for name in self.provider.provider_mapping if name != "/"]

	def get_member(self, name: str) -> Optional[FolderResource]:
		if not (provider := self.provider.provider_mapping.get(f"/{name}")):
			raise DAVError(HTTP_FORBIDDEN)
		resource = FolderResource(f"/{name}", self.environ, provider.root_folder_path)
		resource.name = name
		return resource


class VirtualRootFilesystemProvider(DAVProvider):
	def __init__(self, provider_mapping: dict[str, FilesystemProvider]) -> None:
		super().__init__()
		self.provider_mapping = provider_mapping
		self.readonly = True

	def get_resource_inst(self, path: str, environ: dict) -> _DAVResource:
		root = VirtualRootFilesystemCollection(environ, self)
		return root.resolve("", path)


def webdav_setup(app: FastAPI) -> None:
	try:
		depot_id = get_depotserver_id()
	except Exception as err:
		logger.warning("%s, WebDAV disabled.", err)
		return

	app_config_template = {
		"simple_dc": {"user_mapping": {"*": True}},  # Anonymous access
		"hotfixes": {
			"re_encode_path_info": True,
		},
		"http_authenticator": {
			"domain_controller": None,
			"accept_basic": False,  # Allow basic authentication, True or False
			"accept_digest": False,  # Allow digest authentication, True or False
			"trusted_auth_header": None,
		},
		"verbose": 1,
		"logging": {"enable_loggers": []},
		"property_manager": True,  # True: use property_manager.PropertyManager
		"lock_storage": True,  # True: use lock_manager.LockManager
		"block_size": BLOCK_SIZE,  # default = 8192
		"ssl_certificate": True,  # Prevent warning in log
		"dir_browser": {
			"response_trailer": f"opsiconfd {__version__} (uvicorn/WsgiDAV)",
			"davmount": True,
			"davmount_links": False,
			"htdocs_path": os.path.join(config.static_dir, "wsgidav"),
		},
		"cors": {"allow_origin": "*"},
		"provider_mapping": {},
		"mount_path": None,
	}

	filesystems = {}
	try:
		path = REPOSITORY_DIR
		logger.info("Running on depot server %r, exporting repository directory %r", depot_id, path)
		if not os.path.isdir(path):
			raise RuntimeError(f"Cannot add webdav content 'repository': directory '{path}' does not exist.")
		if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
			raise RuntimeError(f"Cannot add webdav content 'repository': permissions on directory '{path}' not sufficient.")

		filesystems["repository"] = {"path": path, "ignore_case": False, "read_only": False}
	except Exception as exc:
		logger.error(exc, exc_info=True)

	try:
		path = DEPOT_DIR
		logger.info("Running on depot server %r, exporting depot directory %r", depot_id, path)
		if not os.path.isdir(path):
			raise RuntimeError(f"Cannot add webdav content 'depot': directory '{path}' does not exist.")
		if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
			raise RuntimeError(f"Cannot add webdav content 'depot': permissions on directory '{path}' not sufficient.")

		filesystems["depot"] = {"path": path, "ignore_case": True, "read_only": False}
	except Exception as exc:
		logger.error(exc, exc_info=True)

	try:
		path = WORKBENCH_DIR
		logger.info("Running on depot server %r, exporting workbench directory %r", depot_id, path)
		if not os.path.isdir(path):
			raise RuntimeError(f"Cannot add webdav content 'workbench': directory '{path}' does not exist.")
		if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
			raise RuntimeError(f"Cannot add webdav content 'workbench': permissions on directory '{path}' not sufficient.")

		filesystems["workbench"] = {"path": path, "ignore_case": False, "read_only": False}
	except Exception as exc:
		logger.error(exc, exc_info=True)

	if "public-folder" not in config.disabled_features:
		try:
			path = PUBLIC_DIR
			logger.info("Running on depot server %r, exporting public directory %r", depot_id, path)
			if not os.path.isdir(path):
				raise RuntimeError(f"Cannot add webdav content 'public': directory '{path}' does not exist.")
			if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
				raise RuntimeError(f"Cannot add webdav content 'public': permissions on directory '{path}' not sufficient.")

			filesystems["public"] = {"path": path, "ignore_case": False, "read_only": True}
		except Exception as exc:
			logger.error(exc, exc_info=True)

	if os.path.isdir(BOOT_DIR):
		try:
			path = BOOT_DIR
			logger.info("Running on depot server %r, exporting boot directory %r", depot_id, path)
			if not os.access(path, os.R_OK | os.X_OK):
				raise RuntimeError(f"Cannot add webdav content 'boot': permissions on directory '{path}' not sufficient.")

			filesystems["boot"] = {"path": path, "ignore_case": True, "read_only": True}
		except Exception as err:
			logger.error(err, exc_info=True)

	for name, conf in filesystems.items():
		app_config = app_config_template.copy()
		prov_class = IgnoreCaseFilesystemProvider if conf["ignore_case"] else FilesystemProvider
		app_config["dir_browser"]["davmount_links"] = True  # type: ignore[index]
		app_config["provider_mapping"]["/"] = prov_class(  # type: ignore[index]
			conf["path"], readonly=conf["read_only"], fs_opts={"follow_symlinks": True}
		)
		app_config["mount_path"] = f"/{name}"
		app.routes.append(Mount(f"/{name}", WSGIMiddleware(WsgiDAVApp(app_config))))  # type: ignore[arg-type]

	# Virtual filesystem /dav
	app_config = app_config_template.copy()
	for name, conf in filesystems.items():
		prov_class = IgnoreCaseFilesystemProvider if conf["ignore_case"] else FilesystemProvider
		app_config["dir_browser"]["davmount_links"] = True  # type: ignore[index]
		app_config["provider_mapping"][f"/{name}"] = prov_class(  # type: ignore[index]
			conf["path"], readonly=conf["read_only"], fs_opts={"follow_symlinks": True}
		)
	virt_root_provider = VirtualRootFilesystemProvider(app_config["provider_mapping"])  # type: ignore[arg-type]
	app_config["provider_mapping"]["/"] = virt_root_provider  # type: ignore[index]
	app_config["mount_path"] = "/dav"
	app.routes.append(Mount("/dav", WSGIMiddleware(WsgiDAVApp(app_config))))  # type: ignore[arg-type]
