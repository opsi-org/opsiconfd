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

import re
import sys
import codecs
import configargparse
from argparse import HelpFormatter, ArgumentTypeError, SUPPRESS

from .utils import Singleton

DEFAULT_CONFIG_FILE = "/etc/opsi/opsiconfd.conf"

def upgrade_config_files():
	defaults = {}
	for action in parser._actions:
		defaults[action.dest] = action.default
	mapping = {
		"backend config dir": "backend-config-dir",
		"dispatch config file": "dispatch-config-file",
		"extension config dir": "extension-config-dir",
		"acl file": "acl-file",
		"admin networks": "admin-networks",
		"log file": "log-file",
		"symlink logs": "symlink-logs",
		"log level": "log-level",
		"monitoring user": "monitoring-user",
		"monitoring debug": "monitoring-debug",
		"interface": "interface",
		"https port": "port",
		"ssl server cert": "ssl-server-cert",
		"ssl server key": "ssl-server-key",
		"verify ip": "verify-ip",
		"update ip": "update-ip",
		"max inactive interval": "session-lifetime",
		"max authentication failures": "max-auth-failures",
		"max sessions per ip": "max-session-per-ip"
	}

	for c in parser._open_config_files(sys.argv[1:]):
		data = c.read()
		c.close()
		if data.find('[global]') == -1:
			continue
		
		re_opt = re.compile(r"^\s*([^#;\s][^=]+)\s*=\s*(\S.*)\s*$")
		with codecs.open(c.name, "w", "utf-8") as f:
			for line in data.split('\n'):
				match = re_opt.match(line)
				if match:
					opt = match.group(1).strip().lower()
					val = match.group(2).strip()
					if not opt in mapping:
						continue
					if val.lower() in ("yes", "no", "true", "false"):
						val = val.lower() in ("yes", "true")
					default = defaults.get(mapping[opt].replace('-', '_'))
					if str(default) == str(val):
						continue
					if type(val) is bool:
						val = str(val).lower()
					f.write(f"{mapping[opt]} = {val}\n")

def network_address(value):
	if not re.search(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/\d\d?$", value):
		raise ArgumentTypeError(f"Invalid network address: {value}")
	return value

def expert_help(help):
	if '--ex-help' in sys.argv:
		return help
	return SUPPRESS

parser = configargparse.ArgParser(
	formatter_class=lambda prog: HelpFormatter(
		prog, max_help_position=30, width=100
	)
)
parser.add(
	"-c", "--config-file",
	required=False,
	is_config_file=True,
	default=DEFAULT_CONFIG_FILE,
	help="Path to config file."
)
parser.add(
	"--workers",
	env_var="OPSICONFD_WORKERS",
	type=int,
	default=1,
	help="Number of workers to fork."
)
parser.add(
	"--backend-config-dir",
	env_var="OPSICONFD_BACKEND_CONFIG_DIR",
	default="/etc/opsi/backends",
	help="Location of the backend config dir."
)
parser.add(
	"--dispatch-config-file",
	env_var="OPSICONFD_DISPATCH_CONFIG_FILE",
	default="/etc/opsi/backendManager/dispatch.conf",
	help="Location of the backend dispatcher config file."
)
parser.add(
	"--extension-config-dir",
	env_var="OPSICONFD_EXTENSION_CONFIG_DIR",
	default="/etc/opsi/backendManager/extend.d",
	help="Location of the backend extension config dir."
)
parser.add(
	"--acl-file",
	env_var="OPSICONFD_ACL_FILE",
	default="/etc/opsi/backendManager/acl.conf",
	help="Location of the acl file."
)
# TODO: Implement
parser.add(
	"--admin-networks",
	nargs="+",
	env_var="OPSICONFD_ADMIN_NETWORKS",
	default="0.0.0.0/0",
	type=network_address,
	help="Comma separated list of network addresses from which administrative connections are allowed."
)
parser.add(
	"--log-file",
	env_var="OPSICONFD_LOG_FILE",
	default="/var/log/opsi/opsiconfd/%m.log",
	help="The macro %%m can be used to create use a separate log file for each client."
		+ " %%m will be replaced by <client-ip>"
)
parser.add(
	"--symlink-logs",
	env_var="OPSICONFD_SYMLINK_LOGS",
	action='store_true',
	help="If separate log files are used and this option is enabled"
		+ " opsiconfd will create a symlink in the log dir which points"
		+ " to the clients log file. The name of the symlink will be the same"
		+ " as the log files but %%m will be replaced by <client-fqdn>."
)
parser.add(
	"--log-level",
	env_var="OPSICONFD_LOG_LEVEL",
	type=int,
	default=5,
	choices=range(0, 10),
	help="Set the log level."
		+ "0: nothing, 1: essential, 2: critical, 3: errors, 4: warnings, 5: notices"
		+ " 6: infos, 7: debug messages, 8: trace messages, 9: secrets"
)
parser.add(
	"--log-format",
	env_var="OPSICONFD_LOG_FORMAT",
	default="[%(log_color)s%(levelname)-9s %(asctime)s]%(reset)s %(message)s",
	help="Set the log format."
)
parser.add(
	"--max-log-size",
	env_var="OPSICONFD_MAX_LOG_SIZE",
	type=float,
	default=5.0,
	help="Limit the size of logfiles to SIZE megabytes."
		+ "Setting this to 0 will disable any limiting."
		+ "If you set this to 0 we recommend using a proper logrotate configuration"
		+ "so that your disk does not get filled by the logs."
)
parser.add(
	"--keep-rotated-logs",
	env_var="OPSICONFD_KEEP_ROTATED_LOGS",
	type=int,
	default=1,
	help="Number of rotated log files to keep."
)
#parser.add(
#	"--max-execution-statistics",
#	env_var="OPSICONFD_MAX_EXECUTION_STATISTICS",
#	type=int,
#	default=250,
#	help="Maximum number of execution statistics to store."
#)
parser.add(
	"--monitoring-user",
	env_var="OPSICONFD_MONITORING_USER",
	default="monitoring",
	help="The User for opsi-Nagios-Connetor."
)
parser.add(
	"--monitoring-debug",
	env_var="OPSICONFD_MONITORING_DEBUG",
	action='store_true',
	help="If enabled monitoring will be logged using the main log-level."
)
parser.add(
	"--internal-url",
	env_var="OPSICONFD_INTERNAL_URL",
	help="The internal base url."
)
parser.add(
	"--external-url",
	env_var="OPSICONFD_EXTERNAL_URL",
	help="The external base url."
)
parser.add(
	"--interface",
	env_var="OPSICONFD_INTERFACE",
	default='0.0.0.0',
	help="The network interface to bind to (ip address of an network interface)."
		+ "Use 0.0.0.0 to listen on all interfaces"
)
parser.add(
	"--port",
	env_var="OPSICONFD_PORT",
	type=int,
	default=4447,
	help="The port where opsiconfd will listen for https requests."
)
parser.add(
	"--ssl-server-key",
	env_var="OPSICONFD_SSL_SERVER_KEY",
	default='/etc/opsi/opsiconfd.pem',
	help="TThe location of the ssl server key."
)
parser.add(
	"--ssl-server-cert",
	env_var="OPSICONFD_SSL_SERVER_CERT",
	default='/etc/opsi/opsiconfd.pem',
	help="TThe location of the ssl server certificate."
)
parser.add(
	"--verify-ip",
	env_var="OPSICONFD_VERIFY_IP",
	action='store_true',
	help="If a client uses its fqdn and opsi-host-key for authentication,"
		+ " opsiconfd will try to resolve the fqdn (username) by a system call."
		+ " If there is no result or the resulting IP address does not match"
		+ " the client's address, the access will be denied."
)
parser.add(
	"--update-ip",
	env_var="OPSICONFD_UPDATE_IP",
	action='store_true',
	help="If enabled, a client's ip address will be updated in the opsi database,"
		" when the client connects to the service and authentication is successful."
)
parser.add(
	"--session-lifetime",
	env_var="OPSICONFD_SESSION_LIFETIME",
	type=int,
	default=120,
	help="The interval in seconds after an inactive session expires."
)
parser.add(
	"--max-auth-failures",
	env_var="OPSICONFD_MAX_AUTH_FAILURES",
	type=int,
	default=5,
	help="The maximum number of authentication failures before a client ip is blocked."
)
parser.add(
	"--max-session-per-ip",
	env_var="OPSICONFD_MAX_SESSIONS_PER_IP",
	type=int,
	default=25,
	help="The maximum number of sessions that can be opened through one ip address."
)
parser.add(
	"--redis-internal-url",
	env_var="OPSICONFD_REDIS_INTERNAL_URL",
	default='redis://redis',
	help="Redis connection url"
)
parser.add(
	"--grafana-internal-url",
	env_var="OPSICONFD_GRAFANA_INTERNAL_URL",
	default='http://grafana:3000',
	help="Grafana base url for internal use"
)
parser.add(
	"--grafana-external-url",
	env_var="OPSICONFD_GRAFANA_EXTERNAL_URL",
	default='http://grafana:3000',
	help="External grafana base url"
)
parser.add(
	"--ex-help",
	action='store_true',
	help=expert_help("Show expert help message and exit")
)
parser.add(
	"--debug",
	env_var="OPSICONFD_DEBUG",
	action='store_true',
	help=expert_help("Turn debug mode on, never use in production.")
)
parser.add(
	"--profiler",
	env_var="OPSICONFD_PROFILER",
	action='store_true',
	help=expert_help("Turn profiler on. This will slow down requests, never use in production.")
)
parser.add(
	"--server-type",
	env_var="OPSICONFD_SERVER_TYPE",
	default="uvicorn",
	choices=("uvicorn", "gunicorn"),
	help=expert_help("Server type to use.")
)
parser.add(
	"--node-name",
	env_var="OPSICONFD_NODE_NAME",
	help=expert_help("Node name to use.")
)
parser.add(
	"--executor-type",
	env_var="OPSICONFD_EXECUTOR_TYPE",
	choices=('thread', 'process'),
	default='thread',
	help=expert_help("Asyncio executor type.")
)
parser.add(
	"--executor-workers",
	env_var="OPSICONFD_EXECUTOR_WORKERS",
	type=int,
	default=25,
	help=expert_help("Number of thread / process pool workers for asyncio.")
)
parser.add(
	"--log-slow-async-callbacks",
	env_var="OPSICONFD_LOG_SLOW_ASYNC_CALLBACKS",
	type=float,
	default=0.0,
	metavar="THRESHOLD",
	help=expert_help("Log asyncio callbacks which takes THRESHOLD seconds ore more.")
)
class Config(metaclass=Singleton):
	def __init__(self):
		self._config = None
		upgrade_config_files()
		if '--ex-help' in sys.argv:
			args = sys.argv
			if not '--help' in args:
				args.append('--help')
			self._parse_args(args)

	def _parse_args(self, args=None):
		self._config = parser.parse_args(args)
	
	def __getattr__(self, attr):
		if attr.startswith('_'):
			raise AttributeError()
		if not self._config:
			self._parse_args()
		return getattr(self._config, attr)
	
	def items(self):
		return self._config.__dict__

config = Config()
