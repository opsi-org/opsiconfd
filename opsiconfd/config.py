# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
global config
"""

from __future__ import annotations

import getpass
import ipaddress
import os
import re
import socket
import sys
import warnings
from argparse import OPTIONAL, SUPPRESS, ZERO_OR_MORE, Action, ArgumentTypeError, HelpFormatter, _MutuallyExclusiveGroup
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Iterable, TextIO
from urllib.parse import unquote, urlparse

import certifi
import configargparse  # type: ignore[import]
import DNS  # type: ignore[import]
import psutil
from opsicommon.config import OpsiConfig
from opsicommon.logging import secret_filter
from opsicommon.system.network import get_fqdn
from opsicommon.utils import ip_address_in_network
from packaging.version import Version

from opsiconfd.check.const import CHECKS
from opsiconfd.utils import lock_file

from .utils import Singleton, is_manager, is_opsiconfd, running_in_docker

if TYPE_CHECKING:
	from fastapi.templating import Jinja2Templates

DEFAULT_CONFIG_FILE = "/etc/opsi/opsiconfd.conf"
CONFIG_FILE_HEADER = """
# This file was automatically migrated from an older opsiconfd version
# For available options see: opsiconfd --help
# config examples:
# log-level-file = 5
# networks = [192.168.0.0/16, 10.0.0.0/8, ::/0]
# update-ip = true
"""
DEPRECATED = ("monitoring-debug", "verify-ip", "dispatch-config-file", "jsonrpc-time-to-cache", "debug")
CA_KEY_DEFAULT_PASSPHRASE = "Toohoerohpiep8yo"
SERVER_KEY_DEFAULT_PASSPHRASE = "ye3heiwaiLu9pama"
GC_THRESHOLDS = (150_000, 50, 100)
LOG_SIZE_HARD_LIMIT = 10000000
BOOT_DIR = "/tftpboot"
if not os.path.exists(BOOT_DIR) and os.path.exists("/var/lib/tftpboot"):
	BOOT_DIR = "/var/lib/tftpboot"
TMP_DIR = "/var/lib/opsi/tmp"
DEPOT_DIR = "/var/lib/opsi/depot"
FILE_TRANSFER_STORAGE_DIR = "/var/lib/opsi/tmp/file-transfer"
LOG_DIR = "/var/log/opsi"
NTFS_IMAGES_DIR = "/var/lib/opsi/ntfs-images"
OPSI_LICENSE_DIR = "/etc/opsi/licenses"
OPSI_MODULES_FILE = "/etc/opsi/modules"
OPSI_PASSWD_FILE = "/etc/opsi/passwd"
OPSICONFD_DIR = "/var/lib/opsiconfd"
OPSICONFD_HOME = "/var/lib/opsiconfd/home"
PUBLIC_DIR = "/var/lib/opsi/public"
REPOSITORY_DIR = "/var/lib/opsi/repository"
RPC_DEBUG_DIR = "/tmp/opsiconfd-rpc-debug"
PROD_DEP_DEBUG_DIR = "/tmp/opsiconfd-prod-dep-debug"
SSH_COMMANDS_CUSTOM_FILE = "/var/lib/opsi/server_commands_custom.conf"
SSH_COMMANDS_DEFAULT_FILE = "/etc/opsi/server_commands_default.conf"
VAR_ADDON_DIR = "/var/lib/opsiconfd/addons"
WORKBENCH_DIR = "/var/lib/opsi/workbench"
SMB_CONF = "/etc/samba/smb.conf"
SUDOERS_CONF = "/etc/sudoers"
PACKAGE_SCRIPT_TIMEOUT = 600  # Seconds
AUDIT_HARDWARE_CONFIG_FILE = "/etc/opsi/hwaudit/opsihwaudit.conf"
AUDIT_HARDWARE_CONFIG_LOCALES_DIR = "/etc/opsi/hwaudit/locales"
MANAGER_THREAD_POOL_WORKERS = 8
REDIS_LOG_ADAPTER_THREAD_POOL_WORKERS = 4
REDIS_CONECTION_TIMEOUT = 30
SKIP_SETUP_ACTIONS = [
	"limits",
	"users",
	"groups",
	"grafana",
	"backend",
	"redis",
	"ssl",
	"server_cert",
	"opsi_ca",
	"systemd",
	"files",
	"file_permissions",
	"log_files",
	"metric_downsampling",
	"samba",
	"dhcpd",
	"sudoers",
]

try:
	FQDN = get_fqdn()
except RuntimeError:
	FQDN = socket.gethostname()

DEFAULT_NODE_NAME = FQDN.split(".", 1)[0]

opsi_config = OpsiConfig()


def configure_warnings() -> None:
	# Disable sqlalchemy 2.0 deprecation warnings
	# Import here because import is slow
	import sqlalchemy.util.deprecations  # type: ignore[import]

	sqlalchemy.util.deprecations.SILENCE_UBER_WARNING = True
	warnings.filterwarnings(
		"ignore", category=DeprecationWarning, module="redis.asyncio.connection", message="There is no current event loop"
	)
	warnings.filterwarnings("ignore", category=ResourceWarning, module="asyncio.runners", message="unclosed resource")
	if getattr(sys, "frozen", False):
		# Disable warnings if frozen
		warnings.simplefilter("ignore", ResourceWarning)
		warnings.simplefilter("ignore", DeprecationWarning)


if running_in_docker():
	try:
		ip = socket.gethostbyname(FQDN)
		if ip not in ("127.0.0.1", "::1"):
			if name := DNS.revlookup(ip).split(".", 1)[0].replace("docker_", ""):
				DEFAULT_NODE_NAME = name
	except DNS.DNSError:
		pass


def get_server_role() -> str:
	return opsi_config.get("host", "server-role")


def get_configserver_id() -> str:
	server_role = get_server_role()
	if server_role != "configserver":
		raise ValueError(f"Not a configserver (server-role {server_role!r} configured in {opsi_config.config_file!r})")
	return opsi_config.get("host", "id")


def get_depotserver_id() -> str:
	server_role = get_server_role()
	if server_role not in ("depotserver", "configserver"):
		raise ValueError(f"Not a depotsever (no server-role configured in {opsi_config.config_file!r})")
	return opsi_config.get("host", "id")


@lru_cache
def jinja_templates() -> Jinja2Templates:
	from fastapi.templating import Jinja2Templates

	return Jinja2Templates(directory=config.jinja_templates_dir)


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


def str2version(value: str) -> Version:
	return Version(value)


def format_help_without_msg(parser: configargparse.ArgumentParser) -> str:
	return parser.orig_format_help().rsplit("\n\n", 1)[0]


setattr(configargparse.ArgumentParser, "orig_format_help", configargparse.ArgumentParser.format_help)
configargparse.ArgumentParser.format_help = format_help_without_msg


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

	def __init__(self, sub_command: str | None = None) -> None:
		super().__init__("opsiconfd", max_help_position=10, width=100)
		self._sub_command = sub_command

	def _split_lines(self, text: str, width: int) -> list[str]:
		# The textwrap module is used only for formatting help.
		# Delay its import for speeding up the common usage of argparse.
		text = text.replace("[env var: ", "\n[env var: ")
		text = text.replace("(default: ", "\n(default: ")
		lines = []
		from textwrap import wrap

		for line in text.split("\n"):
			lines += wrap(line, width)
		return lines

	def format_help(self) -> str:
		text = HelpFormatter.format_help(self)
		text = text.split("Args that start")[0].rstrip()
		if self._sub_command:
			text += "\n\n"
		else:
			text += (
				"\n"
				"\n"
				"Arguments can also be set in the configuration file and environment variables.\n"
				"Entries in the configuration file overwrite the defaults.\n"
				"Environment variables overwrite entries in the configuration file.\n"
				"Command line parameters overwrite environment variables.\n"
				"Config file and environment var syntax allows: option=value, flag=true, list-option=[a,b,c].\n"
				"\n"
			)
		return text

	def _format_usage(
		self, usage: str | None, actions: Iterable[Action], groups: Iterable[_MutuallyExclusiveGroup], prefix: str | None
	) -> str:
		text = super()._format_usage(usage, actions, groups, prefix)
		sub = f" {self._sub_command}" if self._sub_command else ""
		text = re.sub(r"usage:\s+(\S+)\s+", rf"Usage: {self.CW}\g<1>{sub}{self.CN} ", text)
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
		self._pytest = "pytest" in sys.argv[0] or "pytest" in sys.argv
		self._args: list[str] = []
		self._ex_help = False
		self._parser: configargparse.ArgParser | None = None
		self._sub_command = None
		self._config = configargparse.Namespace()
		self._config.config_file = DEFAULT_CONFIG_FILE
		self.jinja_templates_dir = "."

		self._set_args()

	def __getattr__(self, name: str) -> Any:
		if not name.startswith("_") and self._config:
			return getattr(self._config, name)
		raise AttributeError()

	def __setattr__(self, name: str, value: Any) -> None:
		if not name.startswith("_") and hasattr(self._config, name):
			return setattr(self._config, name, value)
		return super().__setattr__(name, value)

	def _set_args(self, args: list[str] | None = None) -> None:
		self._args = sys.argv[1:] if args is None else args

		try:
			# Pre-parse command line / env to get sub_command and ex-help (may fail)
			self._init_parser()
			assert self._parser
			# type: ignore[union-attr]
			conf, _unknown = self._parser.parse_known_args(self._args, ignore_help_args=True, config_file_contents="")
			self._config.config_file = conf.config_file
			self._ex_help = conf.ex_help
			if self._ex_help and "--help" not in self._args:
				self._args.append("--help")
			self._sub_command = (
				conf.action
				if conf.action
				in ("health-check", "diagnostic-data", "log-viewer", "setup", "backup", "backup-info", "restore", "get-config", "test")
				else None
			)
			if self._sub_command:
				self._args.remove(self._sub_command)
		except BaseException:
			pass

		self._init_parser()

		if is_manager(psutil.Process(os.getpid())):
			self._update_config_file()

		self._parse_args()

	def _help(self, help_type: str | tuple[str, ...], help_text: str) -> str:
		help_type = help_type if isinstance(help_type, tuple) else (help_type,)
		if "expert" in help_type:
			return help_text if self._ex_help and self._sub_command is None else SUPPRESS

		if "all" in help_type or not self._sub_command:
			return help_text

		return help_text if self._sub_command in help_type else SUPPRESS

	def _parse_args(self) -> None:
		if not self._parser:
			raise RuntimeError("Parser not initialized")
		if is_opsiconfd(psutil.Process(os.getpid())):
			self._parser.exit_on_error = True
			self._config = self._parser.parse_args(self._args, config_file_contents=self._config_file_contents())
		else:
			self._parser.exit_on_error = False
			self._config, _unknown = self._parser.parse_known_args(self._args, config_file_contents=self._config_file_contents())
		self._update_config()

	def _update_config(self) -> None:
		if self._sub_command:
			self._config.action = self._sub_command

		opsi_config.config_file = os.path.abspath(self._config.opsi_config)

		self.jinja_templates_dir = os.path.join(self.static_dir, "templates")

		if not self._config.ssl_ca_key_passphrase:
			# Use None if empty string
			self._config.ssl_ca_key_passphrase = None
		if not self._config.ssl_server_key_passphrase:
			# Use None if empty string
			self._config.ssl_server_key_passphrase = None

		if self._config.ssl_ca_permitted_domains:
			ssl_ca_permitted_domains = {f".{d.lstrip('.')}" for d in self._config.ssl_ca_permitted_domains}
			ssl_ca_permitted_domains.add("localhost")
			self._config.ssl_ca_permitted_domains = sorted(list(ssl_ca_permitted_domains))
		else:
			self._config.ssl_ca_permitted_domains = None

		secret_filter.add_secrets(self._config.ssl_ca_key_passphrase, self._config.ssl_server_key_passphrase)

		try:
			if self._config.password:
				secret_filter.add_secrets(self._config.password)
		except AttributeError:
			pass

		scheme = "http"
		if self._config.ssl_server_key and self._config.ssl_server_cert:
			scheme = "https"

		os.putenv("SSL_CERT_FILE", self._config.ssl_trusted_certs)

		if self._config.redis_internal_url:
			url = urlparse(self._config.redis_internal_url)
			if url.password:
				secret_filter.add_secrets(url.password)
				secret_filter.add_secrets(unquote(url.password))

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
				secret_filter.add_secrets(unquote(url.password))
		if not self._config.skip_setup:
			self._config.skip_setup = []
		elif "all" in self._config.skip_setup:
			self._config.skip_setup = SKIP_SETUP_ACTIONS
		elif "ssl" in self._config.skip_setup:
			if "opsi_ca" not in self._config.skip_setup:
				self._config.skip_setup.append("opsi_ca")
			if "server_cert" not in self._config.skip_setup:
				self._config.skip_setup.append("server_cert")
		if not self._config.ssl_server_cert_sans:
			self._config.ssl_server_cert_sans = []
		if not self._config.client_cert_auth:
			self._config.client_cert_auth = []
		if not self._config.disabled_features:
			self._config.disabled_features = []
		if "terminal" in self._config.disabled_features:
			self._config.disabled_features.remove("terminal")
			self._config.disabled_features.append("messagebus_terminal")
		if not self._config.debug_options:
			self._config.debug_options = []
		if not self._config.development_options:
			self._config.development_options = []
		if not self._config.profiler:
			self._config.profiler = []
		for attr in "networks", "admin_networks":
			conf = getattr(self._config, attr)
			if conf:
				add = True
				for network in conf:
					if ip_address_in_network("127.0.0.1", network):
						add = False
				if add:
					conf.append("127.0.0.1/32")

		jinja_templates.cache_clear()

	def redis_key(self, prefix_type: str | None = None) -> str:
		if not prefix_type:
			return self._config.redis_prefix
		return f"{self._config.redis_prefix}:{prefix_type}"

	def reload(self) -> None:
		self._parse_args()

	def items(self) -> dict[str, Any]:
		return self._config.__dict__

	def set_items(self, items: dict[str, Any]) -> None:
		return self._config.__dict__.update(items)

	def set_config_file(self, config_file: str) -> None:
		self._config.config_file = config_file
		for idx, arg in enumerate(self._args):
			if arg in ("-c", "--config-file"):
				if len(self._args) > idx + 1:
					self._args[idx + 1] = self._config.config_file
					return
			elif arg.startswith("--config-file="):
				self._args[idx] = f"--config-file={self._config.config_file}"
				return
		self._args = ["--config-file", self._config.config_file] + self._args

	def _parse_config_file(self, file: TextIO) -> dict[str, Any]:
		conf: dict[str, Any] = {}
		file.seek(0)
		data = file.read()
		re_opt = re.compile(r"^\s*([^#;\s][^=]+)\s*=\s*(\S.*)\s*$")
		for line in data.split("\n"):
			match = re_opt.match(line)
			if match:
				conf[match.group(1).strip().lower()] = match.group(2).strip()
		return conf

	def _generate_config_file(self, file: TextIO, conf: dict[str, Any]) -> str:
		conf = conf.copy()
		data = ""
		file.seek(0)
		data = file.read()
		re_opt = re.compile(r"^(\s*)([^#;\s][^=]+)\s*=\s*(\S.*)\s*$")
		new_lines = []
		for line in data.split("\n"):
			match = re_opt.match(line)
			if match:
				indent = match.group(1)
				arg = match.group(2).strip().lower()
				val = match.group(3).strip()
				if arg in conf:
					new_val = conf.pop(arg)
					if val != new_val:
						# Update argument value in file
						line = f"{indent}{arg} = {new_val}"
				else:
					# Remove argument from file
					continue
			new_lines.append(line)

		if conf:
			# Add new arguments
			if new_lines and not new_lines[-1]:
				new_lines.pop()
			new_lines.extend(f"{arg} = {val}" for arg, val in conf.items())
			new_lines.append("")

		data = "\n".join(new_lines)
		file.seek(0)
		file.truncate()
		file.write(data)
		return data

	def _config_file_contents(self) -> str:
		with open(self._config.config_file, "a+", encoding="utf-8") as file:
			with lock_file(file):
				conf = self._parse_config_file(file)
				masked_config_file_arguments: tuple[str, ...] = tuple()
				if self._sub_command:
					masked_config_file_arguments = ("log-level-stderr", "log-level-file", "log-level")
				return "\n".join([f"{arg} = {val}" for arg, val in conf.items() if arg not in masked_config_file_arguments])

	def set_config_in_config_file(self, arg: str, value: Any) -> str:
		with open(self._config.config_file, "a+", encoding="utf-8") as file:
			with lock_file(file):
				conf = self._parse_config_file(file)
				conf[arg] = value
				return self._generate_config_file(file, conf)

	def _update_config_file(self) -> str:
		with open(self._config.config_file, "a+", encoding="utf-8") as file:
			with lock_file(file):
				conf = self._parse_config_file(file)
				for deprecated in DEPRECATED:
					conf.pop(deprecated, None)
				return self._generate_config_file(file, conf)

	def _init_parser(self) -> None:
		self._parser = configargparse.ArgParser(formatter_class=lambda prog: OpsiconfdHelpFormatter(self._sub_command))
		assert self._parser

		self._parser.add(
			"-c",
			"--config-file",
			env_var="OPSICONFD_CONFIG_FILE",
			required=False,
			is_config_file=True,
			default=DEFAULT_CONFIG_FILE,
			help=self._help("opsiconfd", "Path to config file."),
		)
		self._parser.add("--version", action="store_true", help=self._help("opsiconfd", "Show version info and exit."))
		self._parser.add("--setup", action="store_true", help=self._help("opsiconfd", "Run full setup tasks on start."))
		self._parser.add(
			"--run-as-user",
			env_var="OPSICONFD_RUN_AS_USER",
			default=getpass.getuser(),
			metavar="USER",
			help=self._help("opsiconfd", "Run service as USER."),
		)
		self._parser.add(
			"--workers",
			env_var="OPSICONFD_WORKERS",
			type=int,
			default=1,
			help=self._help("opsiconfd", "Number of workers to fork."),
		)
		self._parser.add(
			"--worker-stop-timeout",
			env_var="OPSICONFD_WORKER_STOP_TIMEOUT",
			type=int,
			default=15,
			help=self._help(
				"opsiconfd",
				"A worker terminates only when all open client connections have been closed."
				"How log, in seconds, to wait for a worker to stop."
				"After the timeout expires the worker will be forced to stop.",
			),
		)
		self._parser.add(
			"--backend-config-dir",
			env_var="OPSICONFD_BACKEND_CONFIG_DIR",
			default="/etc/opsi/backends",
			help=self._help("opsiconfd", "Location of the backend config dir."),
		)
		self._parser.add(
			"--dispatch-config-file",
			env_var="OPSICONFD_DISPATCH_CONFIG_FILE",
			default="/etc/opsi/backendManager/dispatch.conf",
			help=self._help("opsiconfd", "Location of the backend dispatcher config file."),
		)
		self._parser.add(
			"--extension-config-dir",
			env_var="OPSICONFD_EXTENSION_CONFIG_DIR",
			default="/etc/opsi/backendManager/extend.d",
			help=self._help("opsiconfd", "Location of the backend extension config dir."),
		)
		self._parser.add(
			"--acl-file",
			env_var="OPSICONFD_ACL_FILE",
			default="/etc/opsi/backendManager/acl.conf",
			help=self._help("opsiconfd", "Location of the acl file."),
		)
		self._parser.add(
			"--opsi-config",
			env_var="OPSICONFD_OPSI_CONFIG",
			default="/etc/opsi/opsi.conf",
			help=self._help("expert", "Location of the opsi.conf."),
		)
		self._parser.add(
			"--static-dir",
			env_var="OPSICONFD_STATIC_DIR",
			default="/usr/share/opsiconfd/static",
			help=self._help("opsiconfd", "Location of the static files."),
		)
		self._parser.add(
			"--networks",
			nargs="+",
			env_var="OPSICONFD_NETWORKS",
			default=[],
			type=network_address,
			help=self._help("opsiconfd", "A list of network addresses from which connections are allowed."),
		)
		self._parser.add(
			"--admin-networks",
			nargs="+",
			env_var="OPSICONFD_ADMIN_NETWORKS",
			default=[],
			type=network_address,
			help=self._help("opsiconfd", "A list of network addresses from which administrative connections are allowed."),
		)
		self._parser.add(
			"--trusted-proxies",
			nargs="+",
			env_var="OPSICONFD_TRUSTED_PROXIES",
			default=["127.0.0.1/32", "::1/128"],
			type=network_address,
			help=self._help("opsiconfd", "A list of trusted reverse proxy addresses."),
		)
		self._parser.add(
			"--log-mode",
			env_var="OPSICONFD_LOG_MODE",
			default="redis",
			choices=("redis", "local"),
			help=self._help("opsiconfd", "Set the logging mode. 'redis': use centralized redis logging, 'local': local logging."),
		)
		self._parser.add(
			"--log-level",
			env_var="OPSICONFD_LOG_LEVEL",
			type=int,
			default=0 if self._sub_command in ("health-check", "test") else 4,
			choices=range(0, 10),
			help=self._help(
				"opsiconfd",
				"Set the general log level. "
				"0: nothing, 1: essential, 2: critical, 3: errors, 4: warnings, 5: notices, "
				"6: infos, 7: debug messages, 8: trace messages, 9: secrets",
			),
		)
		self._parser.add(
			"--log-levels",
			env_var="OPSICONFD_LOG_LEVELS",
			type=str,
			default="",
			help=self._help(
				"expert",
				"Set the log levels of individual loggers. "
				"<logger-regex>:<level>[,<logger-regex-2>:<level-2>]"
				r'Example: --log-levels=".*:4,opsiconfd\.headers:8"',
			),
		)
		self._parser.add(
			"--log-file",
			env_var="OPSICONFD_LOG_FILE",
			default=f"{LOG_DIR}/opsiconfd/%m.log",
			help=self._help(
				"opsiconfd",
				"The macro %%m can be used to create use a separate log file for each client. %%m will be replaced by <client-ip>",
			),
		)
		self._parser.add(
			"--symlink-logs",
			env_var="OPSICONFD_SYMLINK_LOGS",
			type=str2bool,
			nargs="?",
			const=True,
			default=True,
			help=self._help(
				"opsiconfd",
				"If separate log files are used and this option is enabled "
				"opsiconfd will create a symlink in the log dir which points "
				"to the clients log file. The name of the symlink will be the same "
				"as the log files but %%m will be replaced by <client-fqdn>.",
			),
		)
		self._parser.add(
			"--max-log-size",
			env_var="OPSICONFD_MAX_LOG_SIZE",
			type=float,
			default=5.0,
			help=self._help(
				"opsiconfd",
				"Limit the size of logfiles to SIZE megabytes. "
				"Setting this to 0 will disable any limiting. "
				"If you set this to 0 we recommend using a proper logrotate configuration "
				"so that your disk does not get filled by the logs.",
			),
		)
		self._parser.add(
			"--keep-rotated-logs",
			env_var="OPSICONFD_KEEP_ROTATED_LOGS",
			type=int,
			default=1,
			help=self._help("opsiconfd", "Number of rotated log files to keep."),
		)
		self._parser.add(
			"--log-level-file",
			env_var="OPSICONFD_LOG_LEVEL_FILE",
			type=int,
			default=0 if self._sub_command else 4,
			choices=range(0, 10),
			help=self._help(
				"opsiconfd",
				"Set the log level for logfiles. "
				"0: nothing, 1: essential, 2: critical, 3: errors, 4: warnings, 5: notices, "
				"6: infos, 7: debug messages, 8: trace messages, 9: secrets",
			),
		)
		self._parser.add(
			"--log-format-file",
			env_var="OPSICONFD_LOG_FORMAT_FILE",
			default="[%(opsilevel)d] [%(asctime)s.%(msecs)03d] [%(contextstring)-15s] %(message)s   (%(filename)s:%(lineno)d)",
			help=self._help("opsiconfd", "Set the log format for logfiles."),
		)
		self._parser.add(
			"-l",
			"--log-level-stderr",
			env_var="OPSICONFD_LOG_LEVEL_STDERR",
			type=int,
			default=0 if self._sub_command in ("health-check", "test") else 4,
			choices=range(0, 10),
			help=self._help(
				"all",
				"Set the log level for stderr. "
				"0: nothing, 1: essential, 2: critical, 3: errors, 4: warnings, 5: notices "
				"6: infos, 7: debug messages, 8: trace messages, 9: secrets",
			),
		)
		self._parser.add(
			"--log-format-stderr",
			env_var="OPSICONFD_LOG_FORMAT_STDERR",
			default=(
				"%(log_color)s[%(opsilevel)d] [%(asctime)s.%(msecs)03d]%(reset)s "
				"[%(contextstring)-15s] %(message)s   (%(filename)s:%(lineno)d)"
			),
			help=self._help("opsiconfd", "Set the log format for stder."),
		)
		self._parser.add(
			"--log-max-msg-len",
			env_var="OPSICONFD_LOG_MAX_MSG_LEN",
			type=int,
			default=5000,
			help=self._help("expert", "Set maximum log message length."),
		)
		self._parser.add(
			"--log-filter",
			env_var="OPSICONFD_LOG_FILTER",
			help=self._help(
				("opsiconfd", "log-viewer"),
				"Filter log records contexts (<ctx-name-1>=<val1>[,val2][;ctx-name-2=val3]).\n"
				'Example: --log-filter="client_address=192.168.20.101"',
			),
		)
		self._parser.add(
			"--monitoring-user",
			env_var="OPSICONFD_MONITORING_USER",
			default="monitoring",
			help=self._help("opsiconfd", "The User for opsi-Nagios-Connetor."),
		)
		self._parser.add("--internal-url", env_var="OPSICONFD_INTERNAL_URL", help=self._help("opsiconfd", "The internal base url."))
		self._parser.add("--external-url", env_var="OPSICONFD_EXTERNAL_URL", help=self._help("opsiconfd", "The external base url."))
		self._parser.add(
			"--interface",
			type=ip_address,
			env_var="OPSICONFD_INTERFACE",
			default="0.0.0.0",
			help=self._help(
				"opsiconfd",
				"The network interface to bind to (ip address of an network interface). "
				"Use 0.0.0.0 to listen on all ipv4 interfaces. "
				"Use :: to listen on all ipv6 (and ipv4) interfaces.",
			),
		)
		self._parser.add(
			"--port",
			env_var="OPSICONFD_PORT",
			type=int,
			default=4447,
			help=self._help("opsiconfd", "The port where opsiconfd will listen for https requests."),
		)
		self._parser.add(
			"--ssl-trusted-certs",
			env_var="OPSICONFD_SSL_TRUSTED_CERTS",
			default=certifi.where(),
			help=self._help("opsiconfd", "Path to the database of trusted certificates"),
		)
		# Cipher Strings from https://www.openssl.org/docs/man1.1.1/man1/ciphers.html
		# iPXE 1.20.1 supports these TLS v1.2 cipher suites:
		# AES128-SHA256 (TLS_RSA_WITH_AES_128_CBC_SHA256, 0x003c)
		# AES256-SHA256 (TLS_RSA_WITH_AES_256_CBC_SHA256, 0x003d)
		self._parser.add(
			"--ssl-ciphers",
			env_var="OPSICONFD_SSL_CIPHERS",
			default="TLSv1.2",
			help=self._help(
				"opsiconfd",
				"TLS cipher suites to enable (OpenSSL cipher list format https://www.openssl.org/docs/man1.1.1/man1/ciphers.html).",
			),
		)
		self._parser.add(
			"--ssl-ca-subject-cn",
			env_var="OPSICONFD_SSL_CA_SUBJECT_CN",
			default="opsi CA",
			help=self._help("opsiconfd", "The common name to use in the opsi CA subject."),
		)
		self._parser.add(
			"--ssl-ca-key",
			env_var="OPSICONFD_SSL_CA_KEY",
			default="/etc/opsi/ssl/opsi-ca-key.pem",
			help=self._help("expert", "The location of the opsi ssl ca key."),
		)
		self._parser.add(
			"--ssl-ca-key-passphrase",
			env_var="OPSICONFD_SSL_CA_KEY_PASSPHRASE",
			default=CA_KEY_DEFAULT_PASSPHRASE,
			help=self._help("opsiconfd", "Passphrase to use to encrypt CA key."),
		)
		self._parser.add(
			"--ssl-ca-cert",
			env_var="OPSICONFD_SSL_CA_CERT",
			default="/etc/opsi/ssl/opsi-ca-cert.pem",
			help=self._help("expert", "The location of the opsi ssl ca certificate."),
		)
		self._parser.add(
			"--ssl-ca-cert-valid-days",
			env_var="OPSICONFD_SSL_CA_CERT_VALID_DAYS",
			type=int,
			default=730,
			help=self._help("expert", "The period of validity of the opsi ssl ca certificate in days."),
		)
		self._parser.add(
			"--ssl-ca-cert-renew-days",
			env_var="OPSICONFD_SSL_CA_CERT_RENEW_DAYS",
			type=int,
			default=700,
			help=self._help("expert", "The CA will be renewed if the validity falls below the specified number of days."),
		)
		self._parser.add(
			"--ssl-ca-permitted-domains",
			env_var="OPSICONFD_SSL_CA_PERMITTED_DOMAINS",
			nargs="+",
			default=[],
			help=self._help("opsiconfd", "The CA will be limited to these domains (X.509 Name Constraints)."),
		)
		self._parser.add(
			"--ssl-server-key",
			env_var="OPSICONFD_SSL_SERVER_KEY",
			default="/etc/opsi/ssl/opsiconfd-key.pem",
			help=self._help("expert", "The location of the ssl server key."),
		)
		self._parser.add(
			"--ssl-server-key-passphrase",
			env_var="OPSICONFD_SSL_SERVER_KEY_PASSPHRASE",
			default=SERVER_KEY_DEFAULT_PASSPHRASE,
			help=self._help("opsiconfd", "Passphrase to use to encrypt server key."),
		)
		self._parser.add(
			"--ssl-server-cert",
			env_var="OPSICONFD_SSL_SERVER_CERT",
			default="/etc/opsi/ssl/opsiconfd-cert.pem",
			help=self._help("expert", "The location of the ssl server certificate."),
		)
		self._parser.add(
			"--ssl-server-cert-valid-days",
			env_var="OPSICONFD_SSL_SERVER_CERT_VALID_DAYS",
			type=int,
			default=90,
			help=self._help("expert", "The period of validity of the server certificate in days."),
		)
		self._parser.add(
			"--ssl-server-cert-renew-days",
			env_var="OPSICONFD_SSL_SERVER_CERT_RENEW_DAYS",
			type=int,
			default=30,
			help=self._help(
				"expert",
				"The server certificate will be renewed if the validity falls below the specified number of days.",
			),
		)
		self._parser.add(
			"--ssl-server-cert-sans",
			nargs="+",
			env_var="OPSICONFD_SSL_SERVER_CERT_SANS",
			default=[],
			help=self._help("opsiconfd", "Subject alternative names for the opsi server certificate."),
		)
		self._parser.add(
			"--ssl-client-cert-valid-days",
			env_var="OPSICONFD_SSL_CLIENT_CERT_VALID_DAYS",
			type=int,
			default=360,
			help=self._help("expert", "The period of validity of a client certificate in days."),
		)
		self._parser.add(
			"--ssl-server-cert-check-interval",
			env_var="OPSICONFD_SSL_SERVER_CERT_CHECK_INTERVAL",
			type=int,
			default=86400,
			help=self._help(
				"expert",
				"The interval in seconds at which the server certificate is checked for validity.",
			),
		)
		self._parser.add(
			"--update-ip",
			env_var="OPSICONFD_UPDATE_IP",
			type=str2bool,
			nargs="?",
			const=True,
			default=True,
			help=self._help(
				"opsiconfd",
				"If enabled, a client's ip address will be updated in the opsi database, "
				"when the client connects to the service and authentication is successful.",
			),
		)
		self._parser.add(
			"--session-lifetime",
			env_var="OPSICONFD_SESSION_LIFETIME",
			type=int,
			default=120,
			help=self._help("opsiconfd", "The interval in seconds after an inactive session expires."),
		)
		self._parser.add(
			"--max-auth-failures",
			env_var="OPSICONFD_MAX_AUTH_FAILURES",
			type=int,
			default=10,
			help=self._help("opsiconfd", "The maximum number of authentication failures before a client ip is blocked."),
		)
		self._parser.add(
			"--auth-failures-interval",
			env_var="OPSICONFD_AUTH_FAILURES_INTERVAL",
			type=int,
			default=120,
			help=self._help("opsiconfd", "The time window in seconds in which max auth failures are counted."),
		)
		self._parser.add(
			"--multi-factor-auth",
			env_var="OPSICONFD_MULTI_FACTOR_AUTH",
			default="inactive",
			help=self._help("opsiconfd", "The multi factor authentication mode to use."),
			choices=("inactive", "totp_optional", "totp_mandatory"),
		)
		self._parser.add(
			"--client-cert-auth",
			env_var="OPSICONFD_CLIENT_CERT_AUTH",
			nargs="+",
			default=None,
			help=self._help("expert", "HTTPS client certificate authentication settings."),
			choices=("client", "depot", "user"),
		)
		self._parser.add(
			"--saml-idp-entity-id",
			env_var="OPSICONFD_SAML_IDP_ENTITY_ID",
			default=None,
			help=self._help(
				"opsiconfd",
				"Entity ID of the SAML Identity Provider (IdP)\nExample:\nhttps://keycloak.my.corp/realms/master\n",
			),
		)
		self._parser.add(
			"--saml-idp-x509-cert",
			env_var="OPSICONFD_SAML_IDP_X509_CERT",
			default=None,
			help=self._help(
				"opsiconfd",
				"Public X.509 certificate of the SAML Identity Provider (IdP) as Base64 encoded string.",
			),
		)
		self._parser.add(
			"--saml-idp-sso-url",
			env_var="OPSICONFD_SAML_IDP_SSO_URL",
			default=None,
			help=self._help(
				"opsiconfd",
				"URL target of the IdP where the Authentication Request Message will be sent.\n"
				"Example:\nhttps://keycloak.my.corp/realms/master/protocol/saml\n",
			),
		)
		self._parser.add(
			"--saml-idp-slo-url",
			env_var="OPSICONFD_SAML_IDP_SLO_URL",
			default=None,
			help=self._help(
				"opsiconfd",
				"URL target of the IdP where the Logout Request Message will be sent.\n"
				"Example:\nhttps://keycloak.my.corp/realms/master/protocol/saml\n",
			),
		)
		self._parser.add(
			"--client-block-time",
			env_var="OPSICONFD_CLIENT_BLOCK_TIME",
			type=int,
			default=120,
			help=self._help("opsiconfd", "Time in seconds for which the client is blocked after max auth failures."),
		)
		self._parser.add(
			"--max-session-per-ip",
			env_var="OPSICONFD_MAX_SESSIONS_PER_IP",
			type=int,
			default=30,
			help=self._help("opsiconfd", "The maximum number of sessions that can be opened through one ip address."),
		)
		self._parser.add(
			"--max-sessions-excludes",
			nargs="+",
			env_var="OPSICONFD_MAX_SESSIONS_EXCLUDES",
			default=["127.0.0.1", "::1"],
			help=self._help("expert", "Allow unlimited sessions for these addresses."),
		)
		self._parser.add(
			"--min-configed-version",
			env_var="OPSICONFD_MIN_CONFIGED_VERSION",
			type=str,
			default="4.3.2.18",
			help=self._help("opsiconfd", "Minimum opsi-configed version allowed to connect."),
		)
		self._parser.add(
			"--collect-metrics",
			env_var="OPSICONFD_COLLECT_METRICS",
			type=str2bool,
			nargs="?",
			const=True,
			default=True,
			help=self._help(
				"opsiconfd",
				"Collect metrics and write them to redis.",
			),
		)
		self._parser.add(
			"--check-running",
			env_var="OPSICONFD_CHECK_RUNNING",
			type=str2bool,
			nargs="?",
			const=True,
			default=True,
			help=self._help(
				"expert",
				"Check if other opsiconfd manager instance already running on startup.",
			),
		)
		self._parser.add(
			"--skip-setup",
			nargs="+",
			env_var="OPSICONFD_SKIP_SETUP",
			default=None,
			help=self._help(
				("opsiconfd", "setup"),
				"A list of setup tasks to skip " f"(tasks: {','.join(['all'] + SKIP_SETUP_ACTIONS)}).",
			),
			choices=["all"] + SKIP_SETUP_ACTIONS,
		)

		self._parser.add(
			"--checks",
			nargs="+",
			env_var="OPSICONFD_CHECKS",
			default=None,
			help=self._help(
				("opsiconfd", "health-check"),
				"A list of checks to perform. If not set, all checks are executed. " f"(checks: all, { ', '.join(CHECKS) }).",
			),
			choices=CHECKS,
		)

		self._parser.add(
			"--skip-checks",
			nargs="+",
			env_var="OPSICONFD_SKIP_CHECKS",
			default=None,
			help=self._help(
				("opsiconfd", "health-check"),
				f"A list of checks to skip (checks: { ', '.join(CHECKS) }).",
			),
			choices=CHECKS,
		)
		self._parser.add(
			"--format",
			env_var="OPSICONFD_HEALTH_CHECK_FORMAT",
			default="cli",
			help=self._help(("opsiconfd", "health-check"), "Health-Check output format."),
			choices=("cli", "checkmk", "json"),
		)

		self._parser.add(
			"--mysql-internal-url",
			env_var="OPSICONFD_MYSQL_INTERNAL_URL",
			default=None,
			help=self._help(
				"opsiconfd",
				"MySQL connection url."
				"By default the config from /etc/opsi/backends/mysql.conf will be used!\n"
				"Examples:\n"
				"mysql://<username>:<password>@mysql-server:3306/opsi?ssl=true\n"
				"mysql://<username>:<password>@mysql-server\n",
			),
		)
		self._parser.add(
			"--redis-internal-url",
			env_var="OPSICONFD_REDIS_INTERNAL_URL",
			default="redis://localhost",
			help=self._help(
				"opsiconfd",
				"Redis connection url. Examples:\n"
				"rediss://<username>:<password>@redis-server:6379/0\n"
				"unix:///var/run/redis/redis-server.sock",
			),
		)
		self._parser.add(
			"--redis-prefix",
			env_var="OPSICONFD_REDIS_PREFIX",
			default="opsiconfd",
			help=self._help("expert", "Prefix for redis keys"),
		)
		self._parser.add(
			"--grafana-internal-url",
			env_var="OPSICONFD_GRAFANA_INTERNAL_URL",
			default="http://localhost:3000",
			help=self._help("opsiconfd", "Grafana base url for internal use."),
		)
		self._parser.add(
			"--grafana-external-url",
			env_var="OPSICONFD_GRAFANA_EXTERNAL_URL",
			default="/grafana",
			help=self._help("opsiconfd", "External grafana base url."),
		)
		self._parser.add(
			"--grafana-verify-cert",
			env_var="OPSICONFD_GRAFANA_VERIFY_CERT",
			type=str2bool,
			nargs="?",
			const=True,
			default=True,
			help=self._help("opsiconfd", "If enabled, opsiconfd will check the tls certificate when connecting to grafana."),
		)
		self._parser.add(
			"--grafana-data-source-url",
			env_var="OPSICONFD_GRAFANA_DATA_SOURCE_URL",
			help=self._help("opsiconfd", "Grafana data source base url."),
		)
		self._parser.add(
			"--restart-worker-mem",
			env_var="OPSICONFD_RESTART_WORKER_MEM",
			type=int,
			default=0,
			help=self._help("opsiconfd", "Restart worker if allocated process memory (rss) exceeds this value (in MB)."),
		)
		self._parser.add(
			"--welcome-page",
			env_var="OPSICONFD_WELCOME_PAGE",
			type=str2bool,
			default=True,
			help=self._help("opsiconfd", "Show welcome page on index."),
		)
		self._parser.add(
			"--zeroconf",
			env_var="OPSICONFD_ZEROCONF",
			type=str2bool,
			default=True,
			help=self._help("opsiconfd", "Publish opsiconfd service via zeroconf."),
		)
		self._parser.add("--ex-help", action="store_true", help=self._help("expert", "Show expert help message and exit."))
		self._parser.add(
			"--debug-options",
			nargs="+",
			env_var="OPSICONFD_DEBUG_OPTIONS",
			default=None,
			help=self._help(
				"expert",
				"A list of debug options (possible options are: asyncio, rpc-log, rpc-error-log, prod-dep-log).",
			),
			choices=("asyncio", "rpc-log", "rpc-error-log", "prod-dep-log"),
		)
		self._parser.add(
			"--development-options",
			nargs="+",
			env_var="OPSICONFD_DEVELOPMENT_OPTIONS",
			default=None,
			help=self._help(
				"expert",
				"A list of development options (possible options are: delay-get-session).",
			),
			choices=("delay-get-session",),
		)
		self._parser.add(
			"--profiler",
			nargs="+",
			env_var="OPSICONFD_PROFILER",
			default=None,
			help=self._help("expert", "Turn profilers on. This will slow down requests, never use in production."),
			choices=("yappi", "tracemalloc"),
		)
		self._parser.add(
			"--node-name",
			env_var="OPSICONFD_NODE_NAME",
			help=self._help("expert", "Node name to use."),
			default=DEFAULT_NODE_NAME,
		)
		self._parser.add(
			"--executor-workers",
			env_var="OPSICONFD_EXECUTOR_WORKERS",
			type=int,
			default=16,
			help=self._help("expert", "Number of thread pool workers for asyncio."),
		)
		self._parser.add(
			"--websocket-protocol",
			env_var="OPSICONFD_WEBSOCKET_PROTOCOL",
			default="wsproto_opsiconfd",
			help=self._help("expert", "Set the websocket protocol."),
			choices=("wsproto_opsiconfd", "websockets_opsiconfd", "wsproto", "websockets"),
		)
		self._parser.add(
			"--websocket-open-timeout",
			env_var="OPSICONFD_WEBSOCKET_OPEN_TIMEOUT",
			type=int,
			default=30,
			help=self._help("expert", "Set the websocket open timeout, in seconds."),
		)
		self._parser.add(
			"--websocket-queue-size",
			env_var="OPSICONFD_WEBSOCKET_QUEUE_SIZE",
			type=int,
			default=32,
			help=self._help("expert", "Maximum number of incoming messages in websockets receive buffer."),
		)
		self._parser.add(
			"--websocket-ping-interval",
			env_var="OPSICONFD_WEBSOCKET_PING_INTERVAL",
			type=int,
			default=15,
			help=self._help(
				"expert",
				"Set the websocket ping interval, in seconds.",
			),
		)
		self._parser.add(
			"--websocket-ping-timeout",
			env_var="OPSICONFD_WEBSOCKET_PING_TIMEOUT",
			type=int,
			default=10,
			help=self._help("expert", "Set the websocket ping timeout, in seconds."),
		)
		# https://www.getpagespeed.com/server-setup/nginx/maximizing-nginx-performance-a-comprehensive-guide-to-tuning-the-backlog-and-net-core-somaxconn-parameters
		self._parser.add(
			"--socket-backlog",
			env_var="OPSICONFD_SOCKET_BACKLOG",
			type=int,
			default=4096,
			help=self._help(
				"expert",
				"Limit for the queue of incoming connections (SOMAXCONN).",
			),
		)
		self._parser.add(
			"--log-slow-async-callbacks",
			env_var="OPSICONFD_LOG_SLOW_ASYNC_CALLBACKS",
			type=float,
			default=0.0,
			metavar="THRESHOLD",
			help=self._help("expert", "Log asyncio callbacks which takes THRESHOLD seconds or more."),
		)
		self._parser.add(
			"--addon-dirs",
			nargs="+",
			env_var="OPSICONFD_ADDON_DIRS",
			default=["/usr/lib/opsiconfd/addons", VAR_ADDON_DIR],
			help=self._help("expert", "A list of addon directories"),
		)
		self._parser.add(
			"--jsonrpc-time-to-cache",
			env_var="OPSICONFD_JSONRPC_TIME_TO_CACHE",
			default=0.5,
			type=float,
			help=self._help("expert", "Minimum time in seconds that a jsonrpc must take before the data is cached."),
		)
		self._parser.add(
			"--disabled-features",
			nargs="+",
			env_var="OPSICONFD_DISABLED_FEATURES",
			default=None,
			help=self._help(
				"opsiconfd",
				"A list of features to disable "
				"(features: status-page, public-folder, rpc-interface, messagebus_terminal, messagebus_execute_process).",
			),
			# terminal was renamed to messagebus_terminal
			choices=("status-page", "public-folder", "rpc-interface", "messagebus_terminal", "terminal", "messagebus_execute_process"),
		)
		self._parser.add(
			"--admin-interface-terminal-shell",
			env_var="OPSICONFD_ADMIN_INTERFACE_TERMINAL_SHELL",
			default="/bin/bash",
			help=self._help("opsiconfd", "Shell command for admin interface terminal"),
		)
		self._parser.add(
			"--allow-host-key-only-auth",
			env_var="OPSICONFD_ALLOW_HOST_KEY_ONLY_AUTH",
			type=str2bool,
			nargs="?",
			const=True,
			default=False,
			help=self._help("expert", "Clients are allowed to login with the host key only."),
		)
		self._parser.add(
			"--recover-clients",
			env_var="OPSICONFD_RECOVER_CLIENTS",
			type=str2bool,
			nargs="?",
			const=True,
			default=False,
			help=self._help(
				"expert",
				(
					"Accept all clients and create host objects if they do not exist.\n"
					"WARNING! This overrides the client authentication.\n"
					"The option should only be used in an emergency for a limited period of time."
				),
			),
		)
		self._parser.add(
			"--maintenance",
			nargs="*",
			env_var="OPSICONFD_MAINTENANCE",
			default=False,
			help=self._help("opsiconfd", "Start opsiconfd in maintenance mode, except for these addresses."),
		)
		self._parser.add(
			"--delete-locks",
			env_var="OPSICONFD_DELETE_LOCKS",
			type=str2bool,
			nargs="?",
			const=True,
			default=False,
			help=self._help(("opsiconfd", "setup", "backup", "restore"), "Delete all locks on startup."),
		)
		self._parser.add(
			"--provide-deprecated-methods",
			env_var="OPSICONFD_PROVIDE_DEPRECATED_METHODS",
			type=str2bool,
			nargs="?",
			const=True,
			default=True,
			help=self._help("opsiconfd", "Provide deprecated methods in API."),
		)
		self._parser.add(
			"--http-security-headers",
			env_var="HTTP_SECURITY_HEADERS",
			type=str2bool,
			nargs="?",
			const=True,
			default=True,
			help=self._help(
				"opsiconfd",
				"If enabled, opsiconfd will send security headers in http responses.",
			),
		)

		if self._pytest:
			self._parser.add("args", nargs="*")
			return

		if not self._sub_command:
			self._parser.add(
				"action",
				nargs=None if self._sub_command else "?",
				choices=(
					"start",
					"stop",
					"force-stop",
					"status",
					"restart",
					"reload",
					"setup",
					"log-viewer",
					"health-check",
					"diagnostic-data",
					"backup",
					"backup-info",
					"restore",
					"get-config",
					"test",
				),
				default="start",
				metavar="ACTION",
				help=self._help(
					"opsiconfd",
					"The ACTION to perform:\n"
					"start:           Start opsiconfd.\n"
					"stop:            Stop opsiconfd, wait for connections to complete.\n"
					"force-stop:      Force stop opsiconfd, close all connections.\n"
					"status:          Get opsiconfd running status.\n"
					"restart:         Restart opsiconfd.\n"
					"reload:          Reload config from file.\n"
					"setup:           Run setup tasks.\n"
					"log-viewer:      Show log stream on console.\n"
					"health-check:    Run a health-check.\n"
					"diagnostic-data: Collect diagnostic data.\n"
					"backup:          Run backup.\n"
					"backup-info:     Show backup info.\n"
					"restore:         Restore backup.\n"
					"get-config:      Show opsiconfd config.\n"
					"test:            Run a test.\n",
				),
			)
			return

		if self._sub_command == "setup":
			self._parser.add(
				"--non-interactive", action="store_true", help=self._help("setup", "Run non interactive, do not ask questions.")
			)
			self._parser.add("--configure-mysql", action="store_true", help=self._help("setup", "Configure MySQL connection."))
			self._parser.add("--register-depot", action="store_true", help=self._help("setup", "Register this server as a depotserver."))
			self._parser.add(
				"--unattended",
				metavar="UNATTENDED_CONFIG",
				nargs="?",
				const=True,
				type=str,
				default=False,
				help=self._help("setup", 'Pass unattended config for --register-depot  as \'{"key":"value"}\''),
			)
			self._parser.add(
				"--set-depot-user-password",
				nargs="?",
				const=True,
				type=str,
				default=None,
				help=self._help("setup", "Set password for user."),
			)
			self._parser.add(
				"--rename-server",
				metavar="NEW_SERVER_ID",
				nargs="?",
				const=True,
				default=False,
				help=self._help("setup", "Rename server if needed. Takes provided ID or host.id from opsi.conf."),
			)

		if self._sub_command == "health-check":
			self._parser.add("--detailed", action="store_true", help=self._help("health-check", "Print details of each check."))
			self._parser.add(
				"--upgrade-check",
				nargs="?",
				const=True,
				default=False,
				help=self._help(
					"health-check",
					"Check for upgrade issues only. If a version number is specified, the check is performed for that specific version.",
				),
			)
			self._parser.add(
				"--documentation",
				action="store_true",
				help=self._help("health-check", "Outputs a description of each check on the console."),
			)

		if self._sub_command == "diagnostic-data":
			self._parser.add(
				"target",
				nargs="?",
				default=None,
				metavar="TARGET",
				help=self._help(
					"diagnostic-data",
					(
						"The TARGET (file or directory) to write to.\n"
						"If no file name is specified, the name of the file is selected automatically.\n"
						"The compression format is determined by the file extension.\n"
						"Valid compressions are: 'lz4' and 'gz'\n"
					),
				),
			)

		if self._sub_command in ("backup", "backup-info", "restore"):
			self._parser.add(
				"--password",
				nargs="?",
				default=False,
				help=self._help(
					("backup", "restore"),
					"Password for backup encryption and decryption. "
					"If the argument is given without a value, the user will be prompted for a password.",
				),
			)

		if self._sub_command in ("diagnostic-data", "backup", "restore"):
			self._parser.add(
				"--quiet",
				action="store_true",
				help=self._help(("diagnostic-data", "backup", "restore"), "Do not show output or progress except errors."),
			)

		if self._sub_command == "backup":
			self._parser.add(
				"--no-maintenance",
				action="store_true",
				help=self._help("backup", "Run backup without maintenance mode."),
			)
			self._parser.add(
				"--no-config-files",
				action="store_true",
				help=self._help("backup", "Do not add config files to backup."),
			)
			self._parser.add(
				"--no-redis-data",
				action="store_true",
				help=self._help("backup", "Do not add redis data to backup."),
			)
			self._parser.add(
				"--overwrite",
				action="store_true",
				help=self._help("backup", "Overwrite existing backup file."),
			)
			self._parser.add(
				"backup_target",
				nargs="?",
				default=None,
				metavar="BACKUP_TARGET",
				help=self._help(
					"backup",
					(
						"The BACKUP_TARGET (file or directory) to write to.\n"
						"If no file name is specified, the name of the backup file is selected automatically.\n"
						"The compression and format are determined by the file extension.\n"
						"Valid encodings are: 'msgpack' and 'json'\n"
						"Valid compressions are: 'lz4' and 'gz'\n"
						"Valid encryptions are: 'aes'\n"
						"Example for a msgpack encoded, lz4 compressed and aes encrypted backup: opsi-backup.msgpack.lz4.aes"
					),
				),
			)

		if self._sub_command == "backup-info":
			self._parser.add(
				"backup_file",
				metavar="BACKUP_FILE",
				help=self._help("backup-info", "The BACKUP_FILE for which the information is to be displayed."),
			)

		if self._sub_command == "restore":
			self._parser.add(
				"--config-files",
				action="store_true",
				help=self._help("restore", "Restore config files from backup."),
			)
			self._parser.add(
				"--redis-data",
				action="store_true",
				help=self._help("restore", "Restore redis data from backup."),
			)
			self._parser.add(
				"--ignore-errors",
				action="store_true",
				help=self._help("restore", "Continue on errors."),
			)
			self._parser.add(
				"--no-hw-audit",
				action="store_true",
				help=self._help("restore", "Do not restore hardware audit data."),
			)
			self._parser.add(
				"--server-id",
				env_var="OPSICONFD_SERVER_ID",
				default="backup",
				help=self._help(
					"restore",
					(
						"The server ID to set. The following special values can be used: \n"
						"local: Use the locally configured server ID from opsi.conf.\n"
						"backup: Use the ID of the server from which the backup was created."
					),
				),
			)
			self._parser.add(
				"backup_file",
				metavar="BACKUP_FILE",
				help=self._help("restore", "The BACKUP_FILE to restore from."),
			)

		if self._sub_command == "test":
			self._parser.add(
				"test_function",
				choices=("pam_auth", "ldap_auth"),
				metavar="TEST_FUNCTION",
				help=self._help(
					"test",
					"The TEST_FUNCTION to run:\npam_auth: Try to authenticate a user with pam.\nldap_auth: Try to authenticate a user with ldap.",
				),
			)


config = Config()
