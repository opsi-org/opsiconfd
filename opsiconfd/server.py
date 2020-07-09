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

import gunicorn
import gunicorn.app.base
import uvicorn

from . import __version__
from .logging import GunicornLoggerSetup, logger
from .config import config
from .utils import running_in_docker, get_node_name

internal_url = None
def get_internal_url():
	global internal_url
	if not internal_url:
		if config.internal_url:
			internal_url = config.internal_url
		else:
			scheme = "http"
			if config.ssl_server_key and config.ssl_server_cert:
				scheme = "https"
			addr = "localhost"
			if running_in_docker():
				addr = get_node_name()
			internal_url = f"{scheme}://{addr}:{config.port}"
	return internal_url

external_url = None
def get_external_url():
	global external_url
	if not external_url:
		if config.external_url:
			external_url = config.external_url
		else:
			scheme = "http"
			if config.ssl_server_key and config.ssl_server_cert:
				scheme = "https"
			addr = get_node_name()
			external_url = f"{scheme}://{addr}:{config.port}"
	return external_url


class GunicornApplication(gunicorn.app.base.BaseApplication):

	def __init__(self, app, options=None):
		self.options = options or {}
		self.application = app
		super().__init__()

	def load_config(self):
		config = {
			key: value for key, value in self.options.items()
			if key in self.cfg.settings and value is not None
		}
		for (key, value) in config.items():
			self.cfg.set(key.lower(), value)

	def load(self):
		return self.application

def run_gunicorn():
	gunicorn.SERVER_SOFTWARE = f"opsiconfd {__version__} (gunicorn)"
	from .application import app
	# https://docs.gunicorn.org/en/stable/settings.html
	options = {
		"bind": f"{config.interface}:{config.port}",
		"reuse_port": True,
		"workers": config.workers,
		#"worker_class": "uvicorn.workers.UvicornWorker",
		# Not using UvicornWorker because of:
		#  1) https://github.com/encode/uvicorn/issues/441
		#     Invalid HTTP request received. data received after completed connection: close message
		#  2) configed produces: httptools_impl.py: 161   Invalid HTTP request received. 
		"worker_class": "uvicorn.workers.UvicornH11Worker",
		"logger_class": GunicornLoggerSetup,
		"timeout": 120,
		"graceful_timeout": 5,
		#"preload_app": True,
		#"reload": True,
	}
	if config.ssl_server_key and config.ssl_server_cert:
		options["ssl_version"] = "TLS"
		options["keyfile"] = config.ssl_server_key
		options["certfile"] = config.ssl_server_cert

	logger.notice("gunicorn server starting")
	GunicornApplication(app, options).run()
	logger.notice("gunicorn server exited")

def run_uvicorn():
	options = {
		"interface": "asgi3",
		"http": "h11",#"httptools"
		"host": config.interface,
		"port": config.port,
		"workers": config.workers,
		"log_config": None,
		"debug": config.debug,
		"headers": [
			["Server", f"opsiconfd {__version__} (uvicorn)"]
		]
	}
	if config.ssl_server_key and config.ssl_server_cert:
		options["ssl_keyfile"] = config.ssl_server_key
		options["ssl_certfile"] = config.ssl_server_cert
	
	gunicorn.SERVER_SOFTWARE = f"opsiconfd {__version__} (gunicorn)"

	logger.notice("uvicorn server starting")
	uvicorn.run("opsiconfd.application:app", **options)
	logger.notice("uvicorn server exited")
