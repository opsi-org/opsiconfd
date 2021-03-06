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
import getpass
import socket
import ipaddress

from typing import Union
from argparse import HelpFormatter, ArgumentTypeError, SUPPRESS, OPTIONAL, ZERO_OR_MORE

import configargparse

from .utils import Singleton


DEFAULT_CONFIG_FILE = "/etc/opsi/opsiconfd.conf"
CONFIG_FILE_HEADER = """
# This file was automatically migrated from an older opsiconfd version
# For available options see: opsiconfd --help
# config examples:
# log-level-file = 5
# networks = [192.168.0.0/16, 10.0.0.0/8, ::/0]
# update-ip = true
"""
CA_DAYS = 360
CA_RENEW_DAYS = 300 # If only CA_RENEW_DAYS days left, The CA will be renewed
CERT_DAYS = 90
CERT_RENEW_DAYS = 30 # If only CERT_RENEW_DAYS days left, a new cert will be created
PRIVATE_KEY_CIPHER = "DES3"
CA_KEY_DEFAULT_PASSPHRASE = "Toohoerohpiep8yo"
SERVER_KEY_DEFAULT_PASSPHRASE = "ye3heiwaiLu9pama"

PYTEST = sys.argv[0].endswith("/pytest") or "pytest" in sys.argv

fqdn = socket.getfqdn()

def upgrade_config_files():
	defaults = {}
	for action in parser._actions:  # pylint: disable=protected-access
		defaults[action.dest] = action.default
	# Do not migrate ssl key/cert
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
		"verify ip": "verify-ip",
		"update ip": "update-ip",
		"max inactive interval": "session-lifetime",
		"max authentication failures": "max-auth-failures",
		"max sessions per ip": "max-session-per-ip",
	}

	for config_file in parser._open_config_files(sys.argv[1:]):  # pylint: disable=protected-access
		data = config_file.read()
		config_file.close()
		if data.find("[global]") == -1:
			continue

		re_opt = re.compile(r"^\s*([^#;\s][^=]+)\s*=\s*(\S.*)\s*$")
		with codecs.open(config_file.name, "w", "utf-8") as file:
			file.write(CONFIG_FILE_HEADER.lstrip())
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
					if isinstance(val, bool):
						val = str(val).lower()
					if ',' in val:
						val = f"[{val}]"
					file.write(f"{mapping[opt]} = {val}\n")
			file.write("\n")

def set_config_in_config_file(arg: str, value: Union[str,int,float]):
	arg = arg.lstrip("-").replace("_", "-")
	config_file = parser._open_config_files(sys.argv[1:])[0]  # pylint: disable=protected-access
	data = config_file.read()
	config_file.close()

	conf_line = f"{arg} = {value}"
	re_opt = re.compile(r"^\s*([^#;\s][^=]+)\s*=\s*(\S.*)\s*$")
	lines = []
	found = False
	for line in data.split("\n"):
		match = re_opt.match(line)
		if match and match.group(1).strip().lower() == arg:
			line = conf_line
			found = True
		lines.append(line)
	if not found:
		if lines[-1] == "":
			lines.pop()
		lines.append(conf_line)
	with codecs.open(config_file.name, "w", "utf-8") as file:
		file.write("\n".join(lines))

	config.reload()

def network_address(value):
	try:
		ipaddress.ip_network(value)
	except ValueError as err:
		raise ArgumentTypeError(f"Invalid network address: {value}") from err
	return value

def ip_address(value):
	try:
		return ipaddress.ip_address(value).compressed
	except ValueError as err:
		raise ArgumentTypeError(f"Invalid ip address: {value}") from err

def str2bool(value):
	if isinstance(value, bool):
		return value
	return str(value).lower() in ('yes', 'true', 'y', '1')

def expert_help(help):  # pylint: disable=redefined-builtin
	if "--ex-help" in sys.argv:
		return help
	return SUPPRESS

class OpsiconfdHelpFormatter(HelpFormatter):
	CN = ''
	CB = ''
	CC = ''
	CW = ''
	if sys.stdout.isatty():
		CN = '\033[0;0;0m'
		CB = '\033[1;34;49m'
		CC = '\033[1;36;49m'
		CW = '\033[1;39;49m'
		CY = '\033[0;33;49m'

	def format_help(self):
		text = HelpFormatter.format_help(self)
		text = re.sub("usage:\s+(\S+)\s+", f"Usage: {self.CW}\g<1>{self.CN} ", text) # pylint: disable=anomalous-backslash-in-string
		#text = re.sub("(--?\S+)", f"{self.CW}\g<1>{self.CN}", text)
		return text

	def _format_actions_usage(self, actions, groups):
		text = HelpFormatter._format_actions_usage(self, actions, groups)
		text = re.sub("(--?\S+)", f"{self.CW}\g<1>{self.CN}", text) # pylint: disable=anomalous-backslash-in-string
		text = re.sub("([A-Z_]{2,})", f"{self.CC}\g<1>{self.CN}", text) # pylint: disable=anomalous-backslash-in-string
		return text

	def _format_action_invocation(self, action):
		text = HelpFormatter._format_action_invocation(self, action)
		text = re.sub("(--?\S+)", f"{self.CW}\g<1>{self.CN}", text) # pylint: disable=anomalous-backslash-in-string
		text = re.sub("([A-Z_]{2,})", f"{self.CC}\g<1>{self.CN}", text) # pylint: disable=anomalous-backslash-in-string
		return text

	def _format_args(self, action, default_metavar):
		text = HelpFormatter._format_args(self, action, default_metavar)
		return f"{self.CC}{text}{self.CN}"

	def _get_help_string(self, action):
		text = action.help
		if "passphrase" not in action.dest and "%(default)" not in action.help:
			if action.default is not SUPPRESS:
				defaulting_nargs = [OPTIONAL, ZERO_OR_MORE]
				if action.option_strings or action.nargs in defaulting_nargs:
					text += " (default: %(default)s)"
		return text

parser = configargparse.ArgParser(
	formatter_class=lambda prog: OpsiconfdHelpFormatter(
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
	"--version",
	action="store_true",
	help="Show version info and exit."
)
parser.add(
	"--setup",
	action="store_true",
	help="Run full setup tasks on start."
)
parser.add(
	"--run-as-user",
	env_var="OPSICONFD_RUN_AS_USER",
	default=getpass.getuser(),
	metavar="USER",
	help="Run service as USER."
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
parser.add(
	"--static-dir",
	env_var="OPSICONFD_STATIC_DIR",
	default="/usr/share/opsiconfd/static",
	help="Location of the static files."
)
parser.add(
	"--networks",
	nargs="+",
	env_var="OPSICONFD_NETWORKS",
	default=["0.0.0.0/0", "::/0"],
	type=network_address,
	help="A list of network addresses from which connections are allowed."
)
parser.add(
	"--admin-networks",
	nargs="+",
	env_var="OPSICONFD_ADMIN_NETWORKS",
	default=["0.0.0.0/0", "::/0"],
	type=network_address,
	help="A list of network addresses from which administrative connections are allowed."
)
parser.add(
	"--trusted-proxies",
	nargs="+",
	env_var="OPSICONFD_TRUSTED_PROXIES",
	default=["127.0.0.1", "::1"],
	type=ip_address,
	help="A list of trusted reverse proxy addresses."
)
parser.add(
	"--log-mode",
	env_var="OPSICONFD_LOG_MODE",
	default="redis",
	choices=("redis", "local"),
	help="Set the logging mode. 'redis': use centralized redis logging, 'local': local logging."
)
parser.add(
	"--log-level",
	env_var="OPSICONFD_LOG_LEVEL",
	type=int,
	default=5,
	choices=range(0, 10),
	help="Set the general log level."
		+ "0: nothing, 1: essential, 2: critical, 3: errors, 4: warnings, 5: notices"
		+ " 6: infos, 7: debug messages, 8: trace messages, 9: secrets"
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
	type=str2bool,
	nargs='?',
	const=True,
	default=False,
	help="If separate log files are used and this option is enabled"
		+ " opsiconfd will create a symlink in the log dir which points"
		+ " to the clients log file. The name of the symlink will be the same"
		+ " as the log files but %%m will be replaced by <client-fqdn>."
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
parser.add(
	"--log-level-file",
	env_var="OPSICONFD_LOG_LEVEL_FILE",
	type=int,
	default=4,
	choices=range(0, 10),
	help="Set the log level for logfiles."
		+ "0: nothing, 1: essential, 2: critical, 3: errors, 4: warnings, 5: notices"
		+ " 6: infos, 7: debug messages, 8: trace messages, 9: secrets"
)
parser.add(
	"--log-format-file",
	env_var="OPSICONFD_LOG_FORMAT_FILE",
	default="[%(opsilevel)d] [%(asctime)s.%(msecs)03d] [%(contextstring)-15s] %(message)s   (%(filename)s:%(lineno)d)",
	help="Set the log format for logfiles."
)
parser.add(
	"-l", "--log-level-stderr",
	env_var="OPSICONFD_LOG_LEVEL_STDERR",
	type=int,
	default=4,
	choices=range(0, 10),
	help="Set the log level for stderr."
		+ "0: nothing, 1: essential, 2: critical, 3: errors, 4: warnings, 5: notices"
		+ " 6: infos, 7: debug messages, 8: trace messages, 9: secrets"
)
parser.add(
	"--log-format-stderr",
	env_var="OPSICONFD_LOG_FORMAT_STDERR",
	default="%(log_color)s[%(opsilevel)d] [%(asctime)s.%(msecs)03d]%(reset)s [%(contextstring)-15s] %(message)s   (%(filename)s:%(lineno)d)",
	help="Set the log format for stder."
)
parser.add(
	"--log-max-msg-len",
	env_var="OPSICONFD_LOG_MAX_MSG_LEN",
	default=5000,
	help=expert_help("Set maximum log message length.")
)
parser.add(
	"--log-filter",
	env_var="OPSICONFD_LOG_FILTER",
	help="Filter log records contexts (<ctx-name-1>=<val1>[,val2][;ctx-name-2=val3])"
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
	type=str2bool,
	nargs='?',
	const=True,
	default=False,
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
	type=ip_address,
	env_var="OPSICONFD_INTERFACE",
	default="0.0.0.0",
	help="The network interface to bind to (ip address of an network interface)."
		+ " Use 0.0.0.0 to listen on all ipv4 interfaces."
		+ " Use :: to listen on all ipv6 (and ipv4) interfaces."
)
parser.add(
	"--port",
	env_var="OPSICONFD_PORT",
	type=int,
	default=4447,
	help="The port where opsiconfd will listen for https requests."
)
parser.add(
	"--ssl-ca-key",
	env_var="OPSICONFD_SSL_CA_KEY",
	default="/etc/opsi/ssl/opsi-ca-key.pem",
	help="The location of the opsi ssl ca key."
)
parser.add(
	"--ssl-ca-key-passphrase",
	env_var="OPSICONFD_SSL_CA_KEY_PASSPHRASE",
	default=CA_KEY_DEFAULT_PASSPHRASE,
	help="Passphrase to use to encrypt CA key."
)
parser.add(
	"--ssl-ca-cert",
	env_var="OPSICONFD_SSL_CA_CERT",
	default="/etc/opsi/ssl/opsi-ca-cert.pem",
	help="The location of the opsi ssl ca certificate."
)
parser.add(
	"--ssl-server-key",
	env_var="OPSICONFD_SSL_SERVER_KEY",
	default="/etc/opsi/ssl/opsiconfd-key.pem",
	help="The location of the ssl server key."
)
parser.add(
	"--ssl-server-key-passphrase",
	env_var="OPSICONFD_SSL_SERVER_KEY_PASSPHRASE",
	default=SERVER_KEY_DEFAULT_PASSPHRASE,
	help="Passphrase to use to encrypt server key."
)
parser.add(
	"--ssl-server-cert",
	env_var="OPSICONFD_SSL_SERVER_CERT",
	default="/etc/opsi/ssl/opsiconfd-cert.pem",
	help="The location of the ssl server certificate."
)
# Cipher Strings from https://www.openssl.org/docs/man1.0.2/man1/ciphers.html
# iPXE 1.20.1 supports these TLS v1.2 cipher suites:
# AES128-SHA256 (TLS_RSA_WITH_AES_128_CBC_SHA256, 0x003c)
# AES256-SHA256 (TLS_RSA_WITH_AES_256_CBC_SHA256, 0x003d)
parser.add(
	"--ssl-ciphers",
	env_var="OPSICONFD_SSL_CIPHERS",
	default="TLSv1.2",
	help="TLS cipher suites to enable."
)
parser.add(
	"--verify-ip",
	env_var="OPSICONFD_VERIFY_IP",
	type=str2bool,
	nargs='?',
	const=True,
	default=False,
	help="If a client uses its fqdn and opsi-host-key for authentication,"
		+ " opsiconfd will try to resolve the fqdn (username) by a system call."
		+ " If there is no result or the resulting IP address does not match"
		+ " the client's address, the access will be denied."
)
parser.add(
	"--update-ip",
	env_var="OPSICONFD_UPDATE_IP",
	type=str2bool,
	nargs='?',
	const=True,
	default=True,
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
	default=10,
	help="The maximum number of authentication failures before a client ip is blocked."
)
parser.add(
	"--auth-failures-interval",
	env_var="OPSICONFD_AUTH_FAILURES_INTERVAL",
	type=int,
	default=120,
	help="The time window in seconds in which max auth failures are counted."
)
parser.add(
	"--client-block-time",
	env_var="OPSICONFD_CLIENT_BLOCK_TIME",
	type=int,
	default=120,
	help="Time in seconds for which the client is blocked after max auth failures."
)
parser.add(
	"--max-session-per-ip",
	env_var="OPSICONFD_MAX_SESSIONS_PER_IP",
	type=int,
	default=25,
	help="The maximum number of sessions that can be opened through one ip address."
)
parser.add(
	"--skip-setup",
	nargs="+",
	env_var="OPSICONFD_SKIP_SETUP",
	default=None,
	help="A list of setup tasks to skip "
		" (tasks: all, users, groups, grafana, backend, ssl, systemd, file_permissions, limits)."
)
parser.add(
	"--redis-internal-url",
	env_var="OPSICONFD_REDIS_INTERNAL_URL",
	default="redis://localhost",
	help="Redis connection url."
)
parser.add(
	"--grafana-internal-url",
	env_var="OPSICONFD_GRAFANA_INTERNAL_URL",
	default="http://localhost:3000",
	help="Grafana base url for internal use."
)
parser.add(
	"--grafana-external-url",
	env_var="OPSICONFD_GRAFANA_EXTERNAL_URL",
	default=f"http://{fqdn}:3000",
	help="External grafana base url."
)
parser.add(
	"--grafana-data-source-url",
	env_var="OPSICONFD_GRAFANA_DATA_SOURCE_URL",
	help="Grafana data source base url."
)
parser.add(
	"--restart-worker-mem",
	env_var="OPSICONFD_RESTART_WORKER_MEM",
	type=int,
	help="Restart worker if allocated process memory (rss) exceeds this value (in MB).",
	default=1000
)

parser.add(
	"--ex-help",
	action="store_true",
	help=expert_help("Show expert help message and exit.")
)
parser.add(
	"--debug",
	env_var="OPSICONFD_DEBUG",
	type=str2bool,
	nargs='?',
	const=True,
	default=False,
	help=expert_help("Turn debug mode on, never use in production.")
)
parser.add(
	"--profiler",
	env_var="OPSICONFD_PROFILER",
	type=str2bool,
	nargs='?',
	const=True,
	default=False,
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
	"--executor-workers",
	env_var="OPSICONFD_EXECUTOR_WORKERS",
	type=int,
	default=15,
	help=expert_help("Number of thread / process pool workers for asyncio.")
)
parser.add(
	"--log-slow-async-callbacks",
	env_var="OPSICONFD_LOG_SLOW_ASYNC_CALLBACKS",
	type=float,
	default=0.0,
	metavar="THRESHOLD",
	help=expert_help("Log asyncio callbacks which takes THRESHOLD seconds or more.")
)
parser.add(
	"--use-jemalloc",
	env_var="OPSICONFD_USE_JEMALLOC",
	type=str2bool,
	nargs='?',
	const=True,
	default=False,
	help=expert_help("Use jemalloc if available.")
)
if PYTEST:
	parser.add(
		"args",
		nargs="*"
	)
else:
	parser.add(
		"action",
		nargs="?",
		choices=("start", "stop", "reload", "setup", "log-viewer"),
		default="start",
		metavar="ACTION",
		help="The ACTION to perform."
	)

class Config(metaclass=Singleton):
	def __init__(self):
		self._config = None
		upgrade_config_files()
		if "--ex-help" in sys.argv:
			args = sys.argv
			if "--help" not in args:
				args.append("--help")
			self._parse_args(args)

	def _parse_args(self, args=None):
		if PYTEST:
			self._config, _unknown = parser.parse_known_args(args)
		else:
			self._config = parser.parse_args(args)

	def __getattr__(self, name):
		if name.startswith("_"):
			raise AttributeError()
		if not self._config:
			self._parse_args()
		return getattr(self._config, name)

	def __setattr__(self, name, value):
		if not name.startswith("_") and hasattr(self._config, name):
			return setattr(self._config, name, value)
		return super().__setattr__(name, value)

	def reload(self):
		self._parse_args()

	def items(self):
		return self._config.__dict__

config = Config()
