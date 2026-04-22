# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
webdav
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import wsgidav.fs_dav_provider
from fastapi import FastAPI
from fastapi.routing import Mount
from wsgidav import util
from wsgidav.dav_error import HTTP_FORBIDDEN, DAVError
from wsgidav.dav_provider import (
	DAVCollection,
	DAVProvider,
	_DAVResource,
)
from wsgidav.fs_dav_provider import FileResource, FilesystemProvider, FolderResource
from wsgidav.wsgidav_app import WsgiDAVApp

from opsiconfd import __version__
from opsiconfd.config import (
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
wsgidav.fs_dav_provider.BUFFER_SIZE = BLOCK_SIZE  # ty: ignore[invalid-assignment]


# Prevent warning in log
def is_share_anonymous(self: wsgidav.dc.base_dc.BaseDomainController, path_info: str) -> bool:  # ty: ignore[possibly-missing-submodule]
	return False


wsgidav.dc.base_dc.BaseDomainController.is_share_anonymous = is_share_anonymous  # ty: ignore[possibly-missing-submodule]


class OpsiconfdFolderResource(FolderResource):
	provider: OpsiconfdFilesystemProvider

	def create_empty_resource(self, name: str) -> FileResource:
		# Override to set permissions for new files
		resource: FileResource = super().create_empty_resource(name)
		assert isinstance(resource._file_path, str)
		# Remove all permissions for others, add write permissions for group
		os.chmod(resource._file_path, (os.stat(resource._file_path).st_mode & 0o770) | 0o020)
		return resource

	def create_collection(self, name: str) -> None:
		# Override to set permissions for new directories
		assert "/" not in name
		if self.provider.readonly:
			raise DAVError(HTTP_FORBIDDEN)
		path = util.join_uri(self.path, name)
		fp = self.provider._loc_to_file_path(path, self.environ)
		os.mkdir(fp)
		os.chmod(fp, 0o770)


class OpsiconfdFilesystemProvider(FilesystemProvider):
	def _loc_to_file_path(self, path: str, environ: dict | None = None) -> str:
		"""
		Convert resource path to a unicode absolute file path.
		Check if the path is within the root folder.
		If file does not exist, try to find a case-insensitive match.

		Args:
			path: The resource path.
			environ: The WSGI environment.

		Returns:
			The absolute unicode file path.

		Raises:
			RuntimeError: If access is denied.
		"""

		assert util.is_str(self.root_folder_path)
		assert util.is_str(path)
		root_path = Path(self.root_folder_path).resolve()
		file_path = root_path / path.strip("/")

		if self.fs_opts.get("ignore_case") and not file_path.exists():
			alt_path = root_path
			alt_found = False
			for part in file_path.relative_to(root_path).parts:
				test_path = alt_path / part
				alt_found = test_path.exists()
				if alt_found:
					alt_path = test_path
					continue

				part_lower = part.lower()
				for entry in alt_path.iterdir():
					if entry.name.lower() == part_lower:
						alt_found = True
						alt_path = alt_path / entry.name
						break

				if not alt_found:
					# Give up
					break

			if alt_found:
				file_path = alt_path

		if not file_path.resolve().is_relative_to(root_path):
			full_path = (environ.get("asgi.scope") or {}).get("path") if environ else path or path
			raise RuntimeError(f"Access to '{util.to_unicode_safe(full_path)}' denied")

		return util.to_unicode_safe(file_path.as_posix())

	def get_resource_inst(self, path: str, environ: dict) -> FileResource | OpsiconfdFolderResource | None:  # ty: ignore[invalid-method-override]
		"""Return info dictionary for path.

		See DAVProvider.get_resource_inst()
		"""
		self._count_get_resource_inst += 1
		fp = self._loc_to_file_path(path, environ)

		if not os.path.exists(fp):
			return None
		if not self.fs_opts.get("follow_symlinks") and os.path.islink(fp):
			raise DAVError(HTTP_FORBIDDEN, f"Symlink support is disabled: {fp!r}")
		if os.path.isdir(fp):
			return OpsiconfdFolderResource(path, environ, fp)
		return FileResource(path, environ, fp)


class VirtualRootFilesystemCollection(DAVCollection):
	def __init__(self, environ: dict[str, str], provider: VirtualRootFilesystemProvider) -> None:
		DAVCollection.__init__(self, "/", environ)
		self.provider: VirtualRootFilesystemProvider = provider

	def get_member_names(self) -> list[str]:
		return [name.lstrip("/") for name in self.provider.provider_mapping if name != "/"]

	def get_member(self, name: str) -> FolderResource | None:
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

	app_config_template: dict[str, Any] = {
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

	for name, conf in filesystems.items():
		app_config = app_config_template.copy()
		app_config["dir_browser"]["davmount_links"] = True
		app_config["provider_mapping"]["/"] = OpsiconfdFilesystemProvider(
			conf["path"], readonly=conf["read_only"], fs_opts={"follow_symlinks": True, "ignore_case": conf["ignore_case"]}
		)
		app_config["mount_path"] = f"/{name}"
		app.routes.append(Mount(f"/{name}", WSGIMiddleware(WsgiDAVApp(app_config))))

	# Virtual filesystem /dav
	app_config = app_config_template.copy()
	for name, conf in filesystems.items():
		app_config["dir_browser"]["davmount_links"] = True
		app_config["provider_mapping"][f"/{name}"] = OpsiconfdFilesystemProvider(
			conf["path"], readonly=conf["read_only"], fs_opts={"follow_symlinks": True, "ignore_case": conf["ignore_case"]}
		)
	virt_root_provider = VirtualRootFilesystemProvider(app_config["provider_mapping"])
	app_config["provider_mapping"]["/"] = virt_root_provider
	app_config["mount_path"] = "/dav"
	app.routes.append(Mount("/dav", WSGIMiddleware(WsgiDAVApp(app_config))))
