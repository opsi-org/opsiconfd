# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
:copyright: uib GmbH <info@uib.de>
:author: Jan Schneider <j.schneider@uib.de>
:license: GNU Affero General Public License version 3
"""

import os

import wsgidav.fs_dav_provider
from wsgidav.fs_dav_provider import FilesystemProvider
from wsgidav.wsgidav_app import WsgiDAVApp

from OPSI.Util import getfqdn

from ..logging import logger
from ..backend import get_backend
from ..wsgi import WSGIMiddleware

def webdav_setup(app): # pylint: disable=too-many-statements, too-many-branches
	block_size = 64*1024
	app_config_template = {
		#	"accept_basic": True,  # Allow basic authentication, True or False
		#	"accept_digest": False,  # Allow digest authentication, True or False
		#	"default_to_digest": False,  # True (default digest) or False (default basic)
		#},
		"simple_dc": {"user_mapping": {"*": True}},  # anonymous access
		"verbose": 1,
		"enable_loggers": [],
		"property_manager": True,  # True: use property_manager.PropertyManager
		"lock_manager": True,  # True: use lock_manager.LockManager
		"block_size": block_size, # default = 8192
	}
	# Set file buffer size for reading and writing.
	# Sent message chunks will have the same body size.
	wsgidav.fs_dav_provider.BUFFER_SIZE = block_size

	fqdn = getfqdn()
	hosts = get_backend().host_getObjects(type='OpsiDepotserver', id=fqdn) # pylint: disable=no-member
	if not hosts:
		logger.warning("Running on host %s which is not a depot server, webdav disabled.", fqdn)
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
		app_config["provider_mapping"] = {"/": FilesystemProvider(path, readonly=False)}
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
