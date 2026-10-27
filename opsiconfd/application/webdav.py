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
from wsgidav import util
from wsgidav.dav_error import HTTP_BAD_REQUEST, HTTP_CONFLICT, HTTP_FORBIDDEN, HTTP_METHOD_NOT_ALLOWED, DAVError
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
	provider: OpsiconfdFilesystemProvider  # ty: ignore[invalid-mutable-override]

	def create_empty_resource(self, name: str) -> FileResource:
		"""
		Create an empty file with permissions 0660 (no access for others, write access for group).

		The file is created exclusively and without following symlinks.

		Args:
			name: Name of the new file.

		Returns:
			The new file resource.

		Raises:
			DAVError: If the provider is read-only or the file cannot be created.
		"""
		assert "/" not in name
		if self.provider.readonly:
			raise DAVError(HTTP_FORBIDDEN)
		path = util.join_uri(self.path, name)
		fp = self.provider._loc_to_file_path(path, self.environ)
		try:
			# Create with restrictive permissions, O_EXCL | O_NOFOLLOW prevents writing through (dangling) symlinks
			fd = os.open(fp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
		except FileExistsError as err:
			raise DAVError(HTTP_FORBIDDEN) from err
		except FileNotFoundError as err:
			raise DAVError(HTTP_CONFLICT) from err
		try:
			os.fchmod(fd, 0o660)
		finally:
			os.close(fd)

		resource = self.provider.get_resource_inst(path, self.environ)
		assert isinstance(resource, FileResource)
		return resource

	def create_collection(self, name: str) -> None:
		"""
		Create a new directory with permissions 0770.

		Args:
			name: Name of the new directory.

		Raises:
			DAVError: If the provider is read-only or the directory cannot be created.
		"""
		assert "/" not in name
		if self.provider.readonly:
			raise DAVError(HTTP_FORBIDDEN)
		path = util.join_uri(self.path, name)
		fp = self.provider._loc_to_file_path(path, self.environ)
		try:
			# Create restrictive first, the umask would remove group permissions
			os.mkdir(fp, 0o700)
		except FileExistsError as err:
			raise DAVError(HTTP_METHOD_NOT_ALLOWED) from err
		except FileNotFoundError as err:
			raise DAVError(HTTP_CONFLICT) from err
		os.chmod(fp, 0o770)


def _find_case_insensitive(root_path: Path, relative_path: Path) -> Path:
	"""
	Resolve a relative path below root_path, matching each missing part case-insensitively.

	Parts that cannot be matched (e.g. the name of a file to be created) are appended unchanged.
	If multiple entries match case-insensitively, the first one in sorted order is used.

	Args:
		root_path: The root directory.
		relative_path: The path relative to root_path. Must not contain "..".

	Returns:
		The path below root_path.
	"""
	current = root_path
	parts = relative_path.parts
	for idx, part in enumerate(parts):
		candidate = current / part
		if os.path.lexists(candidate):
			current = candidate
			continue

		part_lower = part.lower()
		try:
			with os.scandir(current) as entries:
				matches = sorted(entry.name for entry in entries if entry.name.lower() == part_lower)
		except OSError:
			# Not a directory or not readable
			matches = []

		if not matches:
			return current.joinpath(*parts[idx:])
		current = current / matches[0]
	return current


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
			DAVError: If the path is invalid or access is denied.
		"""

		assert self.root_folder_path
		assert util.is_str(path)
		if "\x00" in path:
			raise DAVError(HTTP_BAD_REQUEST)

		root_path = Path(self.root_folder_path).resolve()
		file_path = root_path / path.strip("/")

		try:
			# ".." is not resolved here, it is rejected by the check below.
			# Do not scan directories outside the root folder.
			if self.fs_opts.get("ignore_case") and ".." not in file_path.parts and not file_path.exists():
				file_path = _find_case_insensitive(root_path, file_path.relative_to(root_path))
			allowed = file_path.resolve().is_relative_to(root_path)
		except OSError, RuntimeError, ValueError:
			allowed = False

		if not allowed:
			full_path = ((environ or {}).get("asgi.scope") or {}).get("path") or path
			logger.warning("Access to '%s' denied", util.to_unicode_safe(full_path))
			raise DAVError(HTTP_FORBIDDEN, f"Access to '{util.to_unicode_safe(full_path)}' denied")

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
		self.provider: VirtualRootFilesystemProvider = provider  # ty: ignore[invalid-mutable-override]

	def get_member_names(self) -> list[str]:
		return [name.lstrip("/") for name in self.provider.provider_mapping]

	def get_member(self, name: str) -> FolderResource | None:
		if not (provider := self.provider.get_share_provider(name)):
			return None
		resource = FolderResource(f"/{name}", self.environ, provider.root_folder_path)
		resource.name = name
		return resource


class VirtualRootFilesystemProvider(DAVProvider):
	def __init__(self, provider_mapping: dict[str, FilesystemProvider]) -> None:
		super().__init__()
		# Copy to make sure the mapping never contains this provider itself
		self.provider_mapping = dict(provider_mapping)
		self.readonly = True
		# wsgidav >= 4.3 accesses provider.fs_opts in FolderResource.get_member_names()
		self.fs_opts = {"follow_symlinks": True}

	def get_share_provider(self, share: str) -> FilesystemProvider | None:
		"""
		Get the provider of a share.

		Args:
			share: Name of the share (without slashes).

		Returns:
			The provider or `None` if there is no such share.
		"""
		if not share or "/" in share:
			return None
		return self.provider_mapping.get(f"/{share}")

	def get_resource_inst(self, path: str, environ: dict) -> _DAVResource | None:
		if path in ("", "/"):
			return VirtualRootFilesystemCollection(environ, self)

		share, _, sub_path = path.strip("/").partition("/")
		if not (provider := self.get_share_provider(share)):
			return None

		fp = provider._loc_to_file_path(f"/{sub_path}", environ)
		if not os.path.exists(fp):
			return None
		if os.path.isdir(fp):
			return FolderResource(path, environ, fp)
		return FileResource(path, environ, fp)


def _get_app_config(mount_path: str, provider_mapping: dict[str, DAVProvider], allow_origin: str | None = None) -> dict[str, Any]:
	"""
	Create a new WsgiDAV configuration.

	A new configuration is created for every app, because wsgidav may keep references to the nested dicts.

	Args:
		mount_path: The path the app is mounted at.
		provider_mapping: Mapping of share paths to providers.
		allow_origin: Value for the CORS `allow_origin` option. CORS is disabled if `None`.

	Returns:
		The WsgiDAV configuration.
	"""
	return {
		"simple_dc": {"user_mapping": {"*": True}},  # Anonymous access, authentication is done by the SessionMiddleware
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
			"davmount_links": True,
			"htdocs_path": os.path.join(config.static_dir, "wsgidav"),
		},
		"cors": {"allow_origin": allow_origin},
		"provider_mapping": provider_mapping,
		"mount_path": mount_path,
	}


def webdav_setup(app: FastAPI) -> None:
	"""
	Mount the WebDAV shares and the virtual root `/dav`.

	Args:
		app: The FastAPI app.
	"""
	try:
		depot_id = get_depotserver_id()
	except Exception as err:
		logger.warning("%s, WebDAV disabled.", err)
		return

	# name, path, ignore_case, read_only
	shares: list[tuple[str, str, bool, bool]] = [
		("repository", REPOSITORY_DIR, False, False),
		("depot", DEPOT_DIR, True, False),
		("workbench", WORKBENCH_DIR, False, False),
	]
	if "public-folder" not in config.disabled_features:
		shares.append(("public", PUBLIC_DIR, False, True))

	filesystems: dict[str, dict[str, Any]] = {}
	for name, path, ignore_case, read_only in shares:
		try:
			logger.info("Running on depot server %r, exporting %s directory %r", depot_id, name, path)
			if not os.path.isdir(path):
				raise RuntimeError(f"Cannot add webdav content '{name}': directory '{path}' does not exist.")
			# Write access is not needed for read-only shares
			access = os.R_OK | os.X_OK if read_only else os.R_OK | os.W_OK | os.X_OK
			if not os.access(path, access):
				raise RuntimeError(f"Cannot add webdav content '{name}': permissions on directory '{path}' not sufficient.")

			filesystems[name] = {"path": path, "ignore_case": ignore_case, "read_only": read_only}
		except Exception as exc:
			logger.error(exc, exc_info=True)

	def create_provider(name: str) -> OpsiconfdFilesystemProvider:
		"""Create a new provider for the share."""
		conf = filesystems[name]
		return OpsiconfdFilesystemProvider(
			conf["path"], readonly=conf["read_only"], fs_opts={"follow_symlinks": True, "ignore_case": conf["ignore_case"]}
		)

	for name in filesystems:
		# CORS only for the public (anonymous, read-only) share
		app_config = _get_app_config(
			mount_path=f"/{name}", provider_mapping={"/": create_provider(name)}, allow_origin="*" if name == "public" else None
		)
		app.mount(f"/{name}", WSGIMiddleware(WsgiDAVApp(app_config)))

	# Virtual filesystem /dav
	shares_mapping: dict[str, FilesystemProvider] = {f"/{name}": create_provider(name) for name in filesystems}
	provider_mapping: dict[str, DAVProvider] = {**shares_mapping, "/": VirtualRootFilesystemProvider(shares_mapping)}
	app.mount("/dav", WSGIMiddleware(WsgiDAVApp(_get_app_config(mount_path="/dav", provider_mapping=provider_mapping))))
