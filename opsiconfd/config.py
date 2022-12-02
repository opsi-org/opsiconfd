# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
global config
"""

import getpass
import ipaddress
import os
import re
import socket
import sys
from argparse import (
	OPTIONAL,
	SUPPRESS,
	ZERO_OR_MORE,
	Action,
	ArgumentTypeError,
	HelpFormatter,
)
from typing import Any, Dict, Iterable, List, Union
from urllib.parse import urlparse

import certifi
import configargparse  # type: ignore[import]
import psutil
from dns import resolver, reversename
from dns.exception import DNSException
from fastapi.templating import Jinja2Templates
from OPSI.Util import getfqdn  # type: ignore[import]
from opsicommon.config import OpsiConfig
from opsicommon.logging import secret_filter  # type: ignore[import]

from .utils import Singleton, is_manager, is_opsiconfd, running_in_docker

DEFAULT_CONFIG_FILE = "/etc/opsi/opsiconfd.conf"
CONFIG_FILE_HEADER = """
# This file was automatically migrated from an older opsiconfd version
# For available options see: opsiconfd --help
# config examples:
# log-level-file = 5
# networks = [192.168.0.0/16, 10.0.0.0/8, ::/0]
# update-ip = true
"""
DEPRECATED = ("monitoring-debug", "verify-ip", "dispatch-config-file")

CA_KEY_DEFAULT_PASSPHRASE = "Toohoerohpiep8yo"
SERVER_KEY_DEFAULT_PASSPHRASE = "ye3heiwaiLu9pama"

FQDN = getfqdn().lower()
DEFAULT_NODE_NAME = socket.gethostname()
VAR_ADDON_DIR = "/var/lib/opsiconfd/addons"
RPC_DEBUG_DIR = "/tmp/opsiconfd-rpc-debug"
REDIS_PREFIX_MESSAGEBUS = "opsiconfd:messagebus"
REDIS_PREFIX_SESSION = "opsiconfd:session"
GC_THRESHOLDS = (150_000, 50, 100)
OPSI_PASSWD_FILE = "/etc/opsi/passwd"
LOG_DIR = "/var/log/opsi"
LOG_SIZE_HARD_LIMIT = 10000000
OPSI_LICENSE_PATH = "/etc/opsi/licenses"
OPSI_MODULES_PATH = "/etc/opsi/modules"


opsi_config = OpsiConfig()


if running_in_docker():
	try:
		ip = socket.gethostbyname(socket.getfqdn())  # pylint: disable=invalid-name
		rev = reversename.from_address(ip)
		DEFAULT_NODE_NAME = str(resolver.resolve(str(rev), "PTR")[0]).split(".", 1)[0].replace("docker_", "")
	except DNSException:
		pass


def network_address(value: str) -> str:
	try:
		return ipaddress.ip_network(value).compressed
	except ValueError as err:
		raise ArgumentTypeError(f"Invalid network address '{value}: {err}") from err


def ip_address(value: str) -> str:
	try:
		return ipaddress.ip_address(value).compressed
	except ValueError as err:
		raise ArgumentTypeError(f"Invalid ip address: {value}: {err}") from err


def str2bool(value: str) -> bool:
	if isinstance(value, bool):
		return value
	return str(value).lower() in ("yes", "true", "y", "1")


class OpsiconfdHelpFormatter(HelpFormatter):
	CN = ""
	CB = ""
	CC = ""
	CW = ""
	if sys.stdout.isatty():
		CN = "\033[0;0;0m"
		CB = "\033[1;34;49m"
		CC = "\033[1;36;49m"
		CW = "\033[1;39;49m"
		CY = "\033[0;33;49m"

	def _split_lines(self, text: str, width: int) -> List[str]:
		# The textwrap module is used only for formatting help.
		# Delay its import for speeding up the common usage of argparse.
		text = text.replace("[env var: ", "\n[env var: ")
		text = text.replace("(default: ", "\n(default: ")
		lines = []  # pylint: disable=use-tuple-over-list
		from textwrap import wrap  # pylint: disable=import-outside-toplevel

		for line in text.split("\n"):
			lines += wrap(line, width)
		return lines

	def format_help(self) -> str:
		text = HelpFormatter.format_help(self)
		text = re.sub(r"usage:\s+(\S+)\s+", rf"Usage: {self.CW}\g<1>{self.CN} ", text)
		return text

	def _format_actions_usage(self, actions: Iterable[Action], groups: Iterable) -> str:
		text = HelpFormatter._format_actions_usage(self, actions, groups)
		text = re.sub(r"(--?\S+)", rf"{self.CW}\g<1>{self.CN}", text)
		text = re.sub(r"([A-Z_]{2,})", rf"{self.CC}\g<1>{self.CN}", text)
		return text

	def _format_action_invocation(self, action: Action) -> str:
		text = HelpFormatter._format_action_invocation(self, action)
		text = re.sub(r"(--?\S+)", rf"{self.CW}\g<1>{self.CN}", text)
		text = re.sub(r"([A-Z_]{2,})", rf"{self.CC}\g<1>{self.CN}", text)
		return text

	def _format_args(self, action: Action, default_metavar: str) -> str:
		text = HelpFormatter._format_args(self, action, default_metavar)
		return f"{self.CC}{text}{self.CN}"

	def _get_help_string(self, action: Action) -> str:
		text = action.help or ""
		if "passphrase" not in action.dest and "%(default)" not in (action.help or ""):
			if action.default is not SUPPRESS:
				defaulting_nargs = (OPTIONAL, ZERO_OR_MORE)
				if action.dest == "config_file":
					text += f" (default: {DEFAULT_CONFIG_FILE})"
				elif action.option_strings or action.nargs in defaulting_nargs:
					text += " (default: %(default)s)"
		return text


class Config(metaclass=Singleton):
	_initialized = False

	def __init__(self) -> None:
		if self._initialized:
			return
		self._initialized = True
		self._pytest = sys.argv[0].endswith("/pytest") or "pytest" in sys.argv
		self._args: List[str] = []
		self._ex_help = False
		self._parser: configargparse.ArgParser | None = None
		self._config: Any = None
		self.jinja_templates = Jinja2Templates(directory="")

		self._set_args()

	def __getattr__(self, name: str) -> Any:
		if not name.startswith("_") and self._config:
			return getattr(self._config, name)
		raise AttributeError()

	def __setattr__(self, name: str, value: Any) -> None:
		if not name.startswith("_") and hasattr(self._config, name):
			return setattr(self._config, name, value)
		return super().__setattr__(name, value)

	def _set_args(self, args: List[str] | None = None) -> None:
		self._args = sys.argv[1:] if args is None else args
		self._ex_help = "--ex-help" in self._args
		if self._ex_help and "--help" not in self._args:
			self._args.append("--help")
		# if "health-check" in self._args():
		self._init_parser()

		if is_manager(psutil.Process(os.getpid())):
			self._upgrade_config_files()
			self._update_config_files()

		self._parse_args()

	def _expert_help(self, help_text: str) -> str:
		return help_text if self._ex_help else SUPPRESS

	def _parse_args(self) -> None:
		if not self._parser:
			raise RuntimeError("Parser not initialized")
		if is_opsiconfd(psutil.Process(os.getpid())):
			self._parser.exit_on_error = True
			self._config = self._parser.parse_args(self._args)
		else:
			self._parser.exit_on_error = False
			self._config, _unknown = self._parser.parse_known_args(self._args)
		self._update_config()

	def _update_config(self) -> None:  # pylint: disable=too-many-branches
		self.jinja_templates = Jinja2Templates(directory=os.path.join(self.static_dir, "templates"))

		if not self._config.ssl_ca_key_passphrase:
			# Use None if empty string
			self._config.ssl_ca_key_passphrase = None
		if not self._config.ssl_server_key_passphrase:
			# Use None if empty string
			self._config.ssl_server_key_passphrase = None

		scheme = "http"
		if self._config.ssl_server_key and self._config.ssl_server_cert:
			scheme = "https"

		os.putenv("SSL_CERT_FILE", self._config.ssl_trusted_certs)

		if not self._config.internal_url:
			self._config.internal_url = f"{scheme}://{FQDN}:{self._config.port}"
		if not self._config.external_url:
			self._config.external_url = f"{scheme}://{FQDN}:{self._config.port}"
		if not self._config.grafana_data_source_url:
			self._config.grafana_data_source_url = f"{scheme}://{FQDN}:{self._config.port}"
		if self._config.grafana_internal_url:
			url = urlparse(self._config.grafana_internal_url)
			if url.password:
				secret_filter.add_secrets(url.password)
		if not self._config.skip_setup:
			self._config.skip_setup = []
		if self._parser and "all" in self._config.skip_setup:
			for action in self._parser._actions:  # pylint: disable=protected-access
				if action.dest == "skip_setup":
					self._config.skip_setup = action.choices
					break
		elif "ssl" in self._config.skip_setup:
			if "opsi_ca" not in self._config.skip_setup:
				self._config.skip_setup.append("opsi_ca")
			if "server_cert" not in self._config.skip_setup:
				self._config.skip_setup.append("server_cert")
		if not self._config.admin_interface_disabled_features:
			self._config.admin_interface_disabled_features = []

	def reload(self) -> None:
		self._parse_args()

	def items(self) -> Dict[str, Any]:
		return self._config.__dict__

	def set_config_file(self, config_file: str) -> None:
		for idx, arg in enumerate(self._args):
			if arg in ("-c", "--config-file"):
				if len(self._args) > idx + 1:
					self._args[idx + 1] = config_file
					return
			elif arg.startswith("--config-file="):
				self._args[idx] = f"--config-file={config_file}"  # pylint: disable=loop-invariant-statement
				return
		self._args = ["--config-file", config_file] + self._args

	def set_config_in_config_file(self, arg: str, value: Union[str, int, float]) -> None:
		if not self._parser:
			raise RuntimeError("Parser not initialized")
		config_files = self._parser._open_config_files(self._args)  # pylint: disable=protected-access
		if not config_files:
			raise RuntimeError("No config file defined")
		config_file = config_files[0]

		arg = arg.lstrip("-").replace("_", "-")
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
			lines.append("")
		with open(config_file.name, "w", encoding="utf-8") as file:
			file.write("\n".join(lines))

	def _upgrade_config_files(self) -> None:
		if not self._parser:
			raise RuntimeError("Parser not initialized")
		defaults = {action.dest: action.default for action in self._parser._actions}  # pylint: disable=protected-access
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
			"interface": "interface",
			"https port": "port",
			"update ip": "update-ip",
			"max inactive interval": "session-lifetime",
			"max authentication failures": "max-auth-failures",
			"max sessions per ip": "max-session-per-ip",
		}

		re_opt = re.compile(r"^\s*([^#;\s][^=]+)\s*=\s*(\S.*)\s*$")
		for config_file in self._parser._open_config_files(self._args):  # pylint: disable=protected-access
			data = config_file.read()
			config_file.close()
			if "[global]" not in data:
				# Config file not in opsi 4.1 format
				continue

			with open(config_file.name, "w", encoding="utf-8") as file:
				file.write(CONFIG_FILE_HEADER.lstrip())  # pylint: disable=loop-global-usage
				for line in data.split("\n"):
					match = re_opt.match(line)
					if match:
						opt = match.group(1).strip().lower()
						val = match.group(2).strip()
						if opt not in mapping:
							continue
						if val.lower() in ("yes", "no", "true", "false"):
							val = val.lower() in ("yes", "true")
						default = defaults.get(mapping[opt].replace("-", "_"))
						if str(default) == str(val):
							continue
						if isinstance(val, bool):
							val = str(val).lower()
						if "," in val:
							val = f"[{val}]"
						file.write(f"{mapping[opt]} = {val}\n")
				file.write("\n")

	def _update_config_files(self) -> None:
		if not self._parser:
			raise RuntimeError("Parser not initialized")
		re_opt = re.compile(r"^\s*([^#;\s][^=]+)\s*=")
		for config_file in self._parser._open_config_files(self._args):  # pylint: disable=protected-access
			data = config_file.read()
			config_file.close()
			new_data = ""
			for idx, line in enumerate(data.split("\n")):
				match = re_opt.match(line)
				if match and match.group(1).strip().lower() in DEPRECATED:  # pylint: disable=loop-global-usage
					continue
				new_data += line
				if idx < len(data.split("\n")) - 1:
					new_data += "\n"
			if data != new_data:
				with open(config_file.name, "w", encoding="utf-8") as file:
					file.write(new_data)

	def _init_parser(self) -> None:  # pylint: disable=too-many-statements

		self._parser = configargparse.ArgParser(formatter_class=lambda prog: OpsiconfdHelpFormatter(prog, max_help_position=30, width=100))
		if "health-check" in self._args:
			self._parser.add("--detailed", action="store_true", help="Print details to each check.")

		self._parser.add(
			"-c",
			"--config-file",
			env_var="OPSICONFD_CONFIG_FILE",
			required=False,
			is_config_file=True,
			default=DEFAULT_CONFIG_FILE if os.path.exists(DEFAULT_CONFIG_FILE) else None,
			help="Path to config file.",
		)
		self._parser.add("--version", action="store_true", help="Show version info and exit.")
		self._parser.add("--setup", action="store_true", help="Run full setup tasks on start.")
		self._parser.add(
			"--run-as-user", env_var="OPSICONFD_RUN_AS_USER", default=getpass.getuser(), metavar="USER", help="Run service as USER."
		)
		self._parser.add("--workers", env_var="OPSICONFD_WORKERS", type=int, default=1, help="Number of workers to fork.")
		self._parser.add(
			"--worker-stop-timeout",
			env_var="OPSICONFD_WORKER_STOP_TIMEOUT",
			type=int,
			default=120,
			help=(
				"A worker terminates only when all open client connections have been closed."
				"How log, in seconds, to wait for a worker to stop."
				"After the timeout expires the worker will be forced to stop."
			),
		)
		self._parser.add(
			"--backend-config-dir",
			env_var="OPSICONFD_BACKEND_CONFIG_DIR",
			default="/etc/opsi/backends",
			help="Location of the backend config dir.",
		)
		self._parser.add(
			"--dispatch-config-file",
			env_var="OPSICONFD_DISPATCH_CONFIG_FILE",
			default="/etc/opsi/backendManager/dispatch.conf",
			help="Location of the backend dispatcher config file.",
		)
		self._parser.add(
			"--extension-config-dir",
			env_var="OPSICONFD_EXTENSION_CONFIG_DIR",
			default="/etc/opsi/backendManager/extend.d",
			help="Location of the backend extension config dir.",
		)
		self._parser.add(
			"--acl-file", env_var="OPSICONFD_ACL_FILE", default="/etc/opsi/backendManager/acl.conf", help="Location of the acl file."
		)
		self._parser.add(
			"--static-dir", env_var="OPSICONFD_STATIC_DIR", default="/usr/share/opsiconfd/static", help="Location of the static files."
		)
		self._parser.add(
			"--networks",
			nargs="+",
			env_var="OPSICONFD_NETWORKS",
			default=["0.0.0.0/0", "::/0"],
			type=network_address,
			help="A list of network addresses from which connections are allowed.",
		)
		self._parser.add(
			"--admin-networks",
			nargs="+",
			env_var="OPSICONFD_ADMIN_NETWORKS",
			default=["0.0.0.0/0", "::/0"],
			type=network_address,
			help="A list of network addresses from which administrative connections are allowed.",
		)
		self._parser.add(
			"--trusted-proxies",
			nargs="+",
			env_var="OPSICONFD_TRUSTED_PROXIES",
			default=["127.0.0.1", "::1"],
			type=ip_address,
			help="A list of trusted reverse proxy addresses.",
		)
		self._parser.add(
			"--log-mode",
			env_var="OPSICONFD_LOG_MODE",
			default="redis",
			choices=("redis", "local"),
			help="Set the logging mode. 'redis': use centralized redis logging, 'local': local logging.",
		)
		self._parser.add(
			"--log-level",
			env_var="OPSICONFD_LOG_LEVEL",
			type=int,
			default=5,
			choices=range(0, 10),
			help=(
				"Set the general log level. "
				"0: nothing, 1: essential, 2: critical, 3: errors, 4: warnings, 5: notices, "
				"6: infos, 7: debug messages, 8: trace messages, 9: secrets"
			),
		)
		self._parser.add(
			"--log-levels",
			env_var="OPSICONFD_LOG_LEVELS",
			type=str,
			default="",
			help=self._expert_help(
				"Set the log levels of individual loggers. "
				"<logger-regex>:<level>[,<logger-regex-2>:<level-2>]"
				r'Example: --log-levels=".*:4,opsiconfd\.headers:8"'
			),
		)
		self._parser.add(
			"--log-file",
			env_var="OPSICONFD_LOG_FILE",
			default="/var/log/opsi/opsiconfd/%m.log",
			help=("The macro %%m can be used to create use a separate log file for each client. %%m will be replaced by <client-ip>"),
		)
		self._parser.add(
			"--symlink-logs",
			env_var="OPSICONFD_SYMLINK_LOGS",
			type=str2bool,
			nargs="?",
			const=True,
			default=True,
			help=(
				"If separate log files are used and this option is enabled "
				"opsiconfd will create a symlink in the log dir which points "
				"to the clients log file. The name of the symlink will be the same "
				"as the log files but %%m will be replaced by <client-fqdn>."
			),
		)
		self._parser.add(
			"--max-log-size",
			env_var="OPSICONFD_MAX_LOG_SIZE",
			type=float,
			default=5.0,
			help=(
				"Limit the size of logfiles to SIZE megabytes. "
				"Setting this to 0 will disable any limiting. "
				"If you set this to 0 we recommend using a proper logrotate configuration "
				"so that your disk does not get filled by the logs."
			),
		)
		self._parser.add(
			"--keep-rotated-logs", env_var="OPSICONFD_KEEP_ROTATED_LOGS", type=int, default=1, help="Number of rotated log files to keep."
		)
		self._parser.add(
			"--log-level-file",
			env_var="OPSICONFD_LOG_LEVEL_FILE",
			type=int,
			default=4,
			choices=range(0, 10),
			help=(
				"Set the log level for logfiles. "
				"0: nothing, 1: essential, 2: critical, 3: errors, 4: warnings, 5: notices, "
				"6: infos, 7: debug messages, 8: trace messages, 9: secrets"
			),
		)
		self._parser.add(
			"--log-format-file",
			env_var="OPSICONFD_LOG_FORMAT_FILE",
			default="[%(opsilevel)d] [%(asctime)s.%(msecs)03d] [%(contextstring)-15s] %(message)s   (%(filename)s:%(lineno)d)",
			help="Set the log format for logfiles.",
		)
		self._parser.add(
			"-l",
			"--log-level-stderr",
			env_var="OPSICONFD_LOG_LEVEL_STDERR",
			type=int,
			default=4,
			choices=range(0, 10),
			help=(
				"Set the log level for stderr. "
				"0: nothing, 1: essential, 2: critical, 3: errors, 4: warnings, 5: notices "
				"6: infos, 7: debug messages, 8: trace messages, 9: secrets"
			),
		)
		self._parser.add(
			"--log-format-stderr",
			env_var="OPSICONFD_LOG_FORMAT_STDERR",
			default="%(log_color)s[%(opsilevel)d] [%(asctime)s.%(msecs)03d]%(reset)s [%(contextstring)-15s] %(message)s   (%(filename)s:%(lineno)d)",
			help="Set the log format for stder.",
		)
		self._parser.add(
			"--log-max-msg-len",
			env_var="OPSICONFD_LOG_MAX_MSG_LEN",
			type=int,
			default=5000,
			help=self._expert_help("Set maximum log message length."),
		)
		self._parser.add(
			"--log-filter",
			env_var="OPSICONFD_LOG_FILTER",
			help=(
				"Filter log records contexts (<ctx-name-1>=<val1>[,val2][;ctx-name-2=val3]).\n"
				'Example: --log-filter="client_address=192.168.20.101"'
			),
		)
		self._parser.add(
			"--monitoring-user", env_var="OPSICONFD_MONITORING_USER", default="monitoring", help="The User for opsi-Nagios-Connetor."
		)
		self._parser.add("--internal-url", env_var="OPSICONFD_INTERNAL_URL", help="The internal base url.")
		self._parser.add("--external-url", env_var="OPSICONFD_EXTERNAL_URL", help="The external base url.")
		self._parser.add(
			"--interface",
			type=ip_address,
			env_var="OPSICONFD_INTERFACE",
			default="0.0.0.0",
			help=(
				"The network interface to bind to (ip address of an network interface). "
				"Use 0.0.0.0 to listen on all ipv4 interfaces. "
				"Use :: to listen on all ipv6 (and ipv4) interfaces."
			),
		)
		self._parser.add(
			"--port", env_var="OPSICONFD_PORT", type=int, default=4447, help="The port where opsiconfd will listen for https requests."
		)
		self._parser.add(
			"--ssl-trusted-certs",
			env_var="OPSICONFD_SSL_TRUSTED_CERTS",
			default=certifi.where(),
			help="Path to the database of trusted certificates",
		)
		# Cipher Strings from https://www.openssl.org/docs/man1.0.2/man1/ciphers.html
		# iPXE 1.20.1 supports these TLS v1.2 cipher suites:
		# AES128-SHA256 (TLS_RSA_WITH_AES_128_CBC_SHA256, 0x003c)
		# AES256-SHA256 (TLS_RSA_WITH_AES_256_CBC_SHA256, 0x003d)
		self._parser.add(
			"--ssl-ciphers",
			env_var="OPSICONFD_SSL_CIPHERS",
			default="TLSv1.2",
			help=("TLS cipher suites to enable (OpenSSL cipher list format https://www.openssl.org/docs/man1.0.2/man1/ciphers.html)."),
		)
		self._parser.add(
			"--ssl-ca-subject-cn",
			env_var="OPSICONFD_SSL_CA_SUBJECT_CN",
			default="opsi CA",
			help="The common name to use in the opsi CA subject.",
		)
		self._parser.add(
			"--ssl-ca-key",
			env_var="OPSICONFD_SSL_CA_KEY",
			default="/etc/opsi/ssl/opsi-ca-key.pem",
			help="The location of the opsi ssl ca key.",
		)
		self._parser.add(
			"--ssl-ca-key-passphrase",
			env_var="OPSICONFD_SSL_CA_KEY_PASSPHRASE",
			default=CA_KEY_DEFAULT_PASSPHRASE,
			help="Passphrase to use to encrypt CA key.",
		)
		self._parser.add(
			"--ssl-ca-cert",
			env_var="OPSICONFD_SSL_CA_CERT",
			default="/etc/opsi/ssl/opsi-ca-cert.pem",
			help="The location of the opsi ssl ca certificate.",
		)
		self._parser.add(
			"--ssl-ca-cert-valid-days",
			env_var="OPSICONFD_SSL_CA_CERT_VALID_DAYS",
			type=int,
			default=360,
			help=self._expert_help("The period of validity of the opsi ssl ca certificate in days."),
		)
		self._parser.add(
			"--ssl-ca-cert-renew-days",
			env_var="OPSICONFD_SSL_CA_CERT_RENEW_DAYS",
			type=int,
			default=300,
			help=self._expert_help("The CA will be renewed if the validity falls below the specified number of days."),
		)
		self._parser.add(
			"--ssl-server-key",
			env_var="OPSICONFD_SSL_SERVER_KEY",
			default="/etc/opsi/ssl/opsiconfd-key.pem",
			help="The location of the ssl server key.",
		)
		self._parser.add(
			"--ssl-server-key-passphrase",
			env_var="OPSICONFD_SSL_SERVER_KEY_PASSPHRASE",
			default=SERVER_KEY_DEFAULT_PASSPHRASE,
			help="Passphrase to use to encrypt server key.",
		)
		self._parser.add(
			"--ssl-server-cert",
			env_var="OPSICONFD_SSL_SERVER_CERT",
			default="/etc/opsi/ssl/opsiconfd-cert.pem",
			help="The location of the ssl server certificate.",
		)
		self._parser.add(
			"--ssl-server-cert-valid-days",
			env_var="OPSICONFD_SSL_SERVER_CERT_VALID_DAYS",
			type=int,
			default=90,
			help=self._expert_help("The period of validity of the server certificate in days."),
		)
		self._parser.add(
			"--ssl-server-cert-renew-days",
			env_var="OPSICONFD_SSL_SERVER_CERT_RENEW_DAYS",
			type=int,
			default=30,
			help=self._expert_help("The server certificate will be renewed if the validity falls below the specified number of days."),
		)
		self._parser.add(
			"--ssl-client-cert-valid-days",
			env_var="OPSICONFD_SSL_CLIENT_CERT_VALID_DAYS",
			type=int,
			default=360,
			help=self._expert_help("The period of validity of a client certificate in days."),
		)
		self._parser.add(
			"--ssl-server-cert-check-interval",
			env_var="OPSICONFD_SSL_SERVER_CERT_CHECK_INTERVAL",
			type=int,
			default=86400,
			help=self._expert_help("The interval in seconds at which the server certificate is checked for validity."),
		)
		self._parser.add(
			"--update-ip",
			env_var="OPSICONFD_UPDATE_IP",
			type=str2bool,
			nargs="?",
			const=True,
			default=True,
			help=(
				"If enabled, a client's ip address will be updated in the opsi database, "
				"when the client connects to the service and authentication is successful."
			),
		)
		self._parser.add(
			"--session-lifetime",
			env_var="OPSICONFD_SESSION_LIFETIME",
			type=int,
			default=60,
			help="The interval in seconds after an inactive session expires.",
		)
		self._parser.add(
			"--max-auth-failures",
			env_var="OPSICONFD_MAX_AUTH_FAILURES",
			type=int,
			default=10,
			help="The maximum number of authentication failures before a client ip is blocked.",
		)
		self._parser.add(
			"--auth-failures-interval",
			env_var="OPSICONFD_AUTH_FAILURES_INTERVAL",
			type=int,
			default=120,
			help="The time window in seconds in which max auth failures are counted.",
		)
		self._parser.add(
			"--client-block-time",
			env_var="OPSICONFD_CLIENT_BLOCK_TIME",
			type=int,
			default=120,
			help="Time in seconds for which the client is blocked after max auth failures.",
		)
		self._parser.add(
			"--max-session-per-ip",
			env_var="OPSICONFD_MAX_SESSIONS_PER_IP",
			type=int,
			default=30,
			help="The maximum number of sessions that can be opened through one ip address.",
		)
		self._parser.add(
			"--max-sessions-excludes",
			nargs="+",
			env_var="OPSICONFD_MAX_SESSIONS_EXCLUDES",
			default=["127.0.0.1", "::1"],
			help=self._expert_help("Allow unlimited sessions for these addresses."),
		)
		self._parser.add(
			"--skip-setup",
			nargs="+",
			env_var="OPSICONFD_SKIP_SETUP",
			default=None,
			help=(
				"A list of setup tasks to skip "
				"(tasks: all, limits, users, groups, grafana, backend, ssl, server_cert, opsi_ca, "
				"systemd, files, file_permissions, log_files, metric_downsampling)."
			),
			choices=[
				"all",
				"limits",
				"users",
				"groups",
				"grafana",
				"backend",
				"ssl",
				"server_cert",
				"opsi_ca",
				"systemd",
				"files",
				"file_permissions",
				"log_files",
				"metric_downsampling",
			],
		)
		self._parser.add(
			"--redis-internal-url",
			env_var="OPSICONFD_REDIS_INTERNAL_URL",
			default="redis://localhost",
			help=(
				"Redis connection url. Examples:\n"
				"rediss://<username>:<password>@redis-server:6379/0\n"
				"unix:///var/run/redis/redis-server.sock"
			),
		)
		self._parser.add(
			"--grafana-internal-url",
			env_var="OPSICONFD_GRAFANA_INTERNAL_URL",
			default="http://localhost:3000",
			help="Grafana base url for internal use.",
		)
		self._parser.add(
			"--grafana-external-url",
			env_var="OPSICONFD_GRAFANA_EXTERNAL_URL",
			default="/grafana",
			help="External grafana base url.",
		)
		self._parser.add(
			"--grafana-verify-cert",
			env_var="OPSICONFD_GRAFANA_VERIFY_CERT",
			type=str2bool,
			nargs="?",
			const=True,
			default=True,
			help=("If enabled, opsiconfd will check the tls certificate when connecting to grafana."),
		)
		self._parser.add("--grafana-data-source-url", env_var="OPSICONFD_GRAFANA_DATA_SOURCE_URL", help="Grafana data source base url.")
		self._parser.add(
			"--restart-worker-mem",
			env_var="OPSICONFD_RESTART_WORKER_MEM",
			type=int,
			default=0,
			help="Restart worker if allocated process memory (rss) exceeds this value (in MB).",
		)
		self._parser.add(
			"--welcome-page",
			env_var="OPSICONFD_WELCOME_PAGE",
			type=str2bool,
			default=True,
			help="Show welcome page on index.",
		)
		self._parser.add(
			"--zeroconf",
			env_var="OPSICONFD_ZEROCONF",
			type=str2bool,
			default=True,
			help="Publish opsiconfd service via zeroconf.",
		)
		self._parser.add("--ex-help", action="store_true", help=self._expert_help("Show expert help message and exit."))
		self._parser.add(
			"--debug",
			env_var="OPSICONFD_DEBUG",
			type=str2bool,
			nargs="?",
			const=True,
			default=False,
			help=self._expert_help("Turn debug mode on, never use in production."),
		)
		self._parser.add(
			"--debug-options",
			nargs="+",
			env_var="OPSICONFD_DEBUG_OPTIONS",
			default=None,
			help=self._expert_help("A list of debug options (possible options are: rpc-error-log)"),
		)
		self._parser.add(
			"--profiler",
			env_var="OPSICONFD_PROFILER",
			type=str2bool,
			nargs="?",
			const=True,
			default=False,
			help=self._expert_help("Turn profiler on. This will slow down requests, never use in production."),
		)
		self._parser.add(
			"--node-name", env_var="OPSICONFD_NODE_NAME", help=self._expert_help("Node name to use."), default=DEFAULT_NODE_NAME
		)
		self._parser.add(
			"--executor-workers",
			env_var="OPSICONFD_EXECUTOR_WORKERS",
			type=int,
			default=10,
			help=self._expert_help("Number of thread pool workers for asyncio."),
		)
		self._parser.add(
			"--log-slow-async-callbacks",
			env_var="OPSICONFD_LOG_SLOW_ASYNC_CALLBACKS",
			type=float,
			default=0.0,
			metavar="THRESHOLD",
			help=self._expert_help("Log asyncio callbacks which takes THRESHOLD seconds or more."),
		)
		self._parser.add(
			"--addon-dirs",
			nargs="+",
			env_var="OPSI_ADDON_DIRS",
			default=["/usr/lib/opsiconfd/addons", VAR_ADDON_DIR],
			help=self._expert_help("A list of addon directories"),
		)
		self._parser.add(
			"--jsonrpc-time-to-cache",
			env_var="OPSICONFD_JSONRPC_TIME_TO_CACHE",
			default=0.5,
			type=float,
			help=self._expert_help("Minimum time in seconds that a jsonrpc must take before the data is cached."),
		)
		self._parser.add(
			"--admin-interface-disabled-features",
			nargs="+",
			env_var="OPSICONFD_ADMIN_INTERFACE_DISABLED_FEATURES",
			default=None,
			help=("A list of admin interface features to disable (features: terminal, rpc-interface)."),
			choices=["terminal", "rpc-interface"],
		)
		self._parser.add(
			"--admin-interface-terminal-shell",
			env_var="OPSICONFD_ADMIN_INTERFACE_TERMINAL_SHELL",
			default="/bin/bash",
			help=("Shell command for admin interface terminal"),
		)
		self._parser.add(
			"--allow-host-key-only-auth",
			env_var="OPSICONFD_ALLOW_HOST_KEY_ONLY_AUTH",
			type=str2bool,
			nargs="?",
			const=True,
			default=False,
			help=self._expert_help("Clients are allowed to login with the host key only."),
		)
		if self._pytest:
			self._parser.add("args", nargs="*")
		else:
			self._parser.add(
				"action",
				nargs="?",
				choices=("start", "stop", "force-stop", "status", "restart", "reload", "setup", "log-viewer", "health-check"),
				default="start",
				metavar="ACTION",
				help="The ACTION to perform (start / force-stop / stop / status / restart / reload / setup / log-viewer / health-check).",
			)


config = Config()
