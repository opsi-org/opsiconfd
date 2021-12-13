# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webdav
"""

import os

from wsgidav import compat, util
import wsgidav.fs_dav_provider
from wsgidav.fs_dav_provider import FilesystemProvider
from wsgidav.wsgidav_app import WsgiDAVApp

from .. import __version__
from ..logging import logger
from ..config import FQDN
from ..backend import get_backend
from ..wsgi import WSGIMiddleware


PUBLIC_FOLDER = "/var/lib/opsi/public"

# Prevent warning in log
def is_share_anonymous(self, path_info):  # pylint: disable=unused-argument
	return False
wsgidav.dc.base_dc.BaseDomainController.is_share_anonymous = is_share_anonymous


class IgnoreCaseFilesystemProvider(FilesystemProvider):

	def _loc_to_file_path(self, path, environ=None):
		"""Convert resource path to a unicode absolute file path.
		Optional environ argument may be useful e.g. in relation to per-user
		sub-folder chrooting inside root_folder_path.
		"""
		root_path = self.root_folder_path
		assert root_path is not None
		assert compat.is_native(root_path)
		assert compat.is_native(path)

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

		if not file_path.startswith(root_path):
			raise RuntimeError(f"Security exception: tried to access file outside root: {file_path}")

		# Convert to unicode
		file_path = util.to_unicode_safe(file_path)
		return file_path


def webdav_setup(app): # pylint: disable=too-many-statements, too-many-branches
	block_size = 64*1024
	app_config_template = {
		"simple_dc": {
			"user_mapping": {"*": True}  # anonymous access
		},
		"http_authenticator": {
			# None: dc.simple_dc.SimpleDomainController(user_mapping)
			"domain_controller": None,
			"accept_basic": False,  # Allow basic authentication, True or False
			"accept_digest": False,  # Allow digest authentication, True or False
			"trusted_auth_header": None,
		},
		"verbose": 1,
		"enable_loggers": [],
		"property_manager": True,  # True: use property_manager.PropertyManager
		"lock_manager": True,  # True: use lock_manager.LockManager
		"block_size": block_size, # default = 8192
		"ssl_certificate": True,  # Prevent warning in log
		"dir_browser": {
			"show_user": False,
			"icon": False,
			"response_trailer": f"opsiconfd {__version__} (uvicorn/WsgiDAV)"
		}
	}
	# Set file buffer size for reading and writing.
	# Sent message chunks will have the same body size.
	wsgidav.fs_dav_provider.BUFFER_SIZE = block_size

	hosts = get_backend().host_getObjects(type='OpsiDepotserver', id=FQDN)  # pylint: disable=no-member
	if not hosts:
		logger.warning("Running on host %s which is not a depot server, webdav disabled.", FQDN)
		return

	depot = hosts[0]
	depot_id = depot.getId()
	#self.app_config['depotId'] = depot.getId()

	try:
		logger.notice(f"Running on depot server '{depot_id}', exporting repository directory")
		if not depot.getRepositoryLocalUrl():
			raise Exception(f"Repository local url for depot '{depot_id}' not found")
		if not depot.getRepositoryLocalUrl().startswith('file:///'):
			raise Exception(f"Invalid repository local url '{depot.getRepositoryLocalUrl()}'")
		path = depot.getRepositoryLocalUrl()[7:]
		logger.debug("Repository local path is '%s'", path)
		if not os.path.isdir(path):
			raise Exception(f"Cannot add webdav content 'repository': directory '{path}' does not exist.")
		if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
			raise Exception(f"Cannot add webdav content 'repository': permissions on directory '{path}' not sufficient.")

		app_config = dict(app_config_template)
		app_config["provider_mapping"] = {"/": FilesystemProvider(path)}
		app_config["mount_path"] = "/repository"
		repository_dav = WsgiDAVApp(app_config)
		app.mount("/repository", WSGIMiddleware(repository_dav))
	except Exception as exc: # pylint: disable=broad-except
		logger.error(exc, exc_info=True)

	try:
		logger.notice(f"Running on depot server '{depot_id}', exporting depot directory")
		if not depot.getDepotLocalUrl():
			raise Exception(f"Repository local url for depot '{depot_id}' not found")
		if not depot.getDepotLocalUrl().startswith('file:///'):
			raise Exception(f"Invalid repository local url '{depot.getDepotLocalUrl()}' not allowed")
		path = depot.getDepotLocalUrl()[7:]
		logger.debug("Depot local path is '%s'", path)
		if not os.path.isdir(path):
			raise Exception(f"Cannot add webdav content 'depot': directory '{path}' does not exist.")
		if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
			raise Exception(f"Cannot add webdav content 'depot': permissions on directory '{path}' not sufficient.")

		app_config = dict(app_config_template)
		app_config["provider_mapping"] = {"/": IgnoreCaseFilesystemProvider(path, readonly=False)}
		app_config["mount_path"] = "/depot"
		depot_dav = WsgiDAVApp(app_config)
		app.mount("/depot", WSGIMiddleware(depot_dav))
	except Exception as exc: # pylint: disable=broad-except
		logger.error(exc, exc_info=True)

	try:
		logger.notice(f"Running on depot server '{depot_id}', exporting workbench directory")
		if not depot.getWorkbenchLocalUrl():
			raise Exception(f"Workbench local url for depot '{depot_id}' not found")
		if not depot.getWorkbenchLocalUrl().startswith('file:///'):
			raise Exception(f"Invalid workbench local url '{depot.getWorkbenchLocalUrl()}' not allowed")
		path = depot.getWorkbenchLocalUrl()[7:]
		logger.debug("Workbench local path is '%s'", path)
		if not os.path.isdir(path):
			raise Exception(f"Cannot add webdav content 'workbench': directory '{path}' does not exist.")
		if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
			raise Exception(f"Cannot add webdav content 'workbench': permissions on directory '{path}' not sufficient.")

		app_config = dict(app_config_template)
		app_config["provider_mapping"] = {"/": FilesystemProvider(path, readonly=False)}
		app_config["mount_path"] = "/workbench"
		workbench_dav = WsgiDAVApp(app_config)
		app.mount("/workbench", WSGIMiddleware(workbench_dav))
	except Exception as exc: # pylint: disable=broad-except
		logger.error(exc, exc_info=True)

	try:
		logger.notice(f"Running on depot server '{depot_id}', exporting public directory")
		logger.debug("Public path is '%s'", PUBLIC_FOLDER)
		if not os.path.isdir(PUBLIC_FOLDER):
			raise Exception(f"Cannot add webdav content 'public': directory '{PUBLIC_FOLDER}' does not exist.")
		if not os.access(PUBLIC_FOLDER, os.R_OK | os.W_OK | os.X_OK):
			raise Exception(f"Cannot add webdav content 'public': permissions on directory '{PUBLIC_FOLDER}' not sufficient.")

		app_config = dict(app_config_template)
		app_config["provider_mapping"] = {"/": FilesystemProvider(PUBLIC_FOLDER, readonly=False)}
		app_config["mount_path"] = "/public"
		public_dav = WsgiDAVApp(app_config)
		app.mount("/public", WSGIMiddleware(public_dav))
	except Exception as exc: # pylint: disable=broad-except
		logger.error(exc, exc_info=True)

	if os.path.isdir("/tftpboot"):
		path = "/tftpboot"
		logger.notice(f"Running on depot server '{depot_id}', exporting boot directory")
		if not os.access(path, os.R_OK | os.X_OK):
			raise Exception(f"Cannot add webdav content 'boot': permissions on directory '{path}' not sufficient.")

		try:
			app_config = dict(app_config_template)
			app_config["provider_mapping"] = {"/": FilesystemProvider(path, readonly=True)}
			app_config["mount_path"] = "/boot"
			boot = WsgiDAVApp(app_config)
			app.mount("/boot", WSGIMiddleware(boot))
		except Exception as exc: # pylint: disable=broad-except
			logger.error(exc, exc_info=True)
