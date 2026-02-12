# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
utils module for opsiconfd.

Provides various utility functions and classes for device management solutions.
"""

from __future__ import annotations

import asyncio
import dataclasses
import functools
import getpass
import gzip
import json
import os
import pwd
import random
import re
import secrets
import shlex
import signal
import string
import subprocess
import sys
import sysconfig
import threading
import time
import zlib
from dataclasses import asdict, dataclass
from enum import StrEnum
from functools import lru_cache
from hashlib import md5
from ipaddress import IPv4Interface, IPv4Network, IPv6Address, IPv6Interface, ip_address
from json import JSONEncoder
from logging import DEBUG, INFO
from pathlib import Path
from socket import AF_INET, AF_INET6
from subprocess import run
from typing import TYPE_CHECKING, Any, Callable, Coroutine, Generator, Iterable

import lz4.frame
import psutil
import requests
from opsicommon.logging.logging import OPSILogger
from opsicommon.system.info import is_ucs
from opsicommon.types import forceStringLower
from opsicommon.utils import prepare_proxy_environment

from opsiconfd import __version__
from opsiconfd.utils.ucs import get_server_role as get_ucs_server_role

NSSWITCH_CONF = Path("/etc/nsswitch.conf")

config = None
opsi_config = None

if TYPE_CHECKING:
	from config import Config, OpsiConfig  # type: ignore[import]

	config: "Config" | None = None
	opsi_config: "OpsiConfig" | None = None


@lru_cache
def get_logger() -> OPSILogger:
	"""
	Get the global logger instance.

	Returns:
		OPSILogger: The logger instance.
	"""
	from opsiconfd.logging import logger

	return logger


def get_config() -> Config:
	"""
	Get the global configuration instance.

	Returns:
		Config: The configuration instance.
	"""
	global config
	if not config:
		from opsiconfd.config import config
	return config


def get_opsi_config() -> OpsiConfig:
	"""
	Get the global opsi configuration instance.

	Returns:
		OpsiConfig: The opsi configuration instance.
	"""
	global opsi_config
	if not opsi_config:
		from opsiconfd.config import opsi_config
	return opsi_config


class Singleton(type):
	"""
	Metaclass for implementing the Singleton design pattern.
	"""

	_instances: dict[type, type] = {}

	def __call__(cls: "Singleton", *args: Any, **kwargs: Any) -> type:
		if cls not in cls._instances:
			cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
		return cls._instances[cls]


def log_config(log_level: int = INFO) -> None:
	"""
	Log the current configuration.

	Args:
		log_level (int): The logging level. Defaults to INFO.
	"""
	get_logger().log(log_level, "Config: %s", json.dumps(get_config().items(), indent=2, sort_keys=True))


def get_python_info() -> dict[str, Any]:
	"""
	Get detailed information about the Python environment.

	Returns:
		dict[str, Any]: A dictionary containing Python version, configuration flags, and other details.
	"""
	config_vars = sysconfig.get_config_vars()
	py_core_cflags = shlex.split(config_vars["PY_CORE_CFLAGS"])
	jit_supported = "-D_Py_JIT" in py_core_cflags
	return {
		"version": sys.version,
		"MULTIARCH": config_vars["MULTIARCH"],
		"CONFIG_ARGS": shlex.split(config_vars["CONFIG_ARGS"]),
		"PY_CORE_CFLAGS": py_core_cflags,
		"free_threading_supported": sysconfig.get_config_var("Py_GIL_DISABLED") == "1",
		"free_threading_enabled": not sys._is_gil_enabled(),
		"jit_supported": jit_supported,
		"jit_enabled": jit_supported and os.environ.get("PYTHON_JIT", "0") == "1",
	}


def log_python_info(log_level: int = DEBUG) -> None:
	"""
	Log detailed Python environment information.

	Args:
		log_level (int): The logging level. Defaults to DEBUG.
	"""
	get_logger().log(log_level, "Python info: %s", json.dumps(get_python_info(), indent=2))


def running_in_docker() -> bool:
	"""
	Check if the application is running inside a Docker container.

	Returns:
		bool: True if running in Docker, False otherwise.
	"""
	try:
		with open("/proc/2/stat", encoding="utf-8", errors="replace") as file:
			return "kthreadd" not in file.read()
	except FileNotFoundError:
		return True
	except Exception:
		pass
	return False


def is_opsiconfd(proc: psutil.Process) -> bool:
	"""
	Check if the given process is an opsiconfd process.

	Args:
		proc (psutil.Process): The process to check.

	Returns:
		bool: True if the process is opsiconfd, False otherwise.
	"""
	return proc.name() == "opsiconfd" or (
		proc.name() in ("python", "python3") and ("opsiconfd" in proc.cmdline() or "opsiconfd.__main__" in " ".join(proc.cmdline()))
	)


def is_manager(proc: psutil.Process) -> bool:
	"""
	Check if the given process is an opsiconfd manager process.

	Args:
		proc (psutil.Process): The process to check.

	Returns:
		bool: True if the process is a manager, False otherwise.
	"""
	from opsiconfd.config import OPSICONFD_SUB_COMMANDS

	return is_opsiconfd(proc) and not any(arg in OPSICONFD_SUB_COMMANDS + ["debugpy"] or "multiprocessing" in arg for arg in proc.cmdline())


def get_manager_process(ignore_self: bool = False, ignore_parents: bool = False) -> tuple[int | None, str | None]:
	"""
	Get the PID and command of the opsiconfd manager process.

	Args:
		ignore_self (bool): Whether to ignore the current process. Defaults to False.
		ignore_parents (bool): Whether to ignore parent processes. Defaults to False.

	Returns:
		tuple[int | None, str | None]: The PID and command of the manager process, or None if not found.
	"""
	container_procs = ("containerd-shim", "lxc-start")

	manager_pid = None
	manager_cmd = None
	ignore_pids = []
	if ignore_self:
		our_pid = os.getpid()
		our_proc = psutil.Process(our_pid)
		ignore_pids += [our_pid]
		ignore_pids += [p.pid for p in our_proc.children(recursive=True)]
	if ignore_parents:
		ignore_pids += [p.pid for p in our_proc.parents()]

	for proc in psutil.process_iter():
		if proc.pid in ignore_pids or proc.status() == psutil.STATUS_ZOMBIE:
			continue

		running_in_container_pid = 0
		for parent in proc.parents():
			if parent.name() in container_procs:
				running_in_container_pid = parent.pid
				break
		if running_in_container_pid:
			get_logger().debug("Process %d is running in container %d, skipping", proc.pid, running_in_container_pid)
			continue

		if is_manager(proc) and (not manager_pid or proc.pid > manager_pid):
			# Do not return, prefer higher pids
			manager_pid = proc.pid
			manager_cmd = shlex.join(proc.cmdline())

	return manager_pid, manager_cmd


def systemd_running() -> bool:
	"""
	Check if systemd is running.

	Returns:
		bool: True if systemd is running, False otherwise.
	"""
	for proc in psutil.process_iter():
		if proc.name() == "systemd":
			return True
	return False


def opsiconfd_running() -> bool:
	"""
	Check if opsiconfd is running.

	Returns:
		bool: True if opsiconfd is running, False otherwise.
	"""
	if not systemd_running():
		get_logger().debug("Systemd not running")
		return False
	try:
		return subprocess.run(["systemctl", "is-active", "--quiet", "opsiconfd"], check=False).returncode == 0
	except FileNotFoundError as err:
		get_logger().debug("systemctl not found: %s", err)
		return False


def restart_opsiconfd() -> None:
	"""
	Restart the opsiconfd service using systemd.
	"""
	if not systemd_running():
		get_logger().debug("Systemd not running")
		return
	subprocess.run("systemctl --no-pager --lines 0 restart opsiconfd &", shell=True, check=False)


def restart_opsiconfd_if_running() -> None:
	"""
	Restart the opsiconfd service if it is currently running.
	"""
	get_logger().info("Restarting opsiconfd")
	if not opsiconfd_running():
		get_logger().info("opsiconfd not running")
		return
	restart_opsiconfd()


def reload_opsiconfd_if_running() -> None:
	"""
	Reload the opsiconfd service if it is currently running.
	"""
	get_logger().info("Reloading opsiconfd")
	manager_pid = get_manager_process(ignore_self=True)[0]
	if not manager_pid:
		get_logger().info("opsiconfd not running")
		return
	os.kill(manager_pid, signal.SIGHUP)


def switch_to_user(username: str) -> None:
	if not username:
		raise ValueError("Username is empty")

	if getpass.getuser() == username:
		return

	logger = get_logger()
	logger.debug("Switching to user %s", username)
	try:
		user = pwd.getpwnam(username)
		gids = os.getgrouplist(user.pw_name, user.pw_gid)
		logger.debug("Set uid=%r, gid=%r, groups=%r", user.pw_uid, user.pw_gid, gids)
		if getattr(sys, "frozen", False):
			if os.path.isdir(user.pw_dir):
				logger.debug("Changing working directory to %r", user.pw_dir)
				try:
					os.chdir(user.pw_dir)
				except Exception as err:
					logger.warning("Failed to change working directory to %r: %s", user.pw_dir, err)
			else:
				logger.warning("Home directory %r of user %r does not exist, not changing working directory", user.pw_dir, user.pw_name)
		os.setgid(user.pw_gid)
		os.setgroups(gids)
		os.setuid(user.pw_uid)
		os.environ["HOME"] = user.pw_dir
	except Exception as err:
		raise RuntimeError(f"Failed to switch to user '{username}': {err}") from err


def normalize_ip_address(address: str, exploded: bool = False) -> str:
	"""
	Normalize an IP address.

	Args:
		address (str): The IP address to normalize.
		exploded (bool): Whether to return the exploded form of the address. Defaults to False.

	Returns:
		str: The normalized IP address.
	"""
	ipa = ip_address(address)
	if isinstance(ipa, IPv6Address) and ipa.ipv4_mapped:
		ipa = ipa.ipv4_mapped
	if exploded:
		return ipa.exploded
	return ipa.compressed


class NamedIPv4Interface(IPv4Interface):
	"""
	Represents a named IPv4 interface.

	Attributes:
		name (str): The name of the interface.
	"""

	def __init__(self, name: str, address: str) -> None:
		super().__init__(address)
		self.name = name

	def __str__(self) -> str:
		return f"{super().__str__()} ({self.name})"


class NamedIPv6Interface(IPv6Interface):
	"""
	Represents a named IPv6 interface.

	Attributes:
		name (str): The name of the interface.
	"""

	def __init__(self, name: str, address: str) -> None:
		super().__init__(address)
		self.name = name

	def __str__(self) -> str:
		return f"{super().__str__()} ({self.name})"


def get_ip_interfaces(family: int | Iterable[int] | None = None) -> Generator[NamedIPv4Interface | NamedIPv6Interface, None, None]:
	"""
	Get all IP interfaces for the specified address family.

	Args:
		family (int | Iterable[int] | None): The address family (e.g., AF_INET, AF_INET6). Defaults to None.

	Returns:
		Generator[NamedIPv4Interface | NamedIPv6Interface, None, None]: A generator of named IP interfaces.
	"""
	if not family:
		family = [AF_INET, AF_INET6]
	elif isinstance(family, int):
		family = [family]

	for interface_name, snics in psutil.net_if_addrs().items():
		for snic in snics:
			# Interfaces will be yielded in the order of the family list
			for fam in family:
				if snic.family != fam or not snic.netmask:
					continue
				try:
					if snic.family == AF_INET6:
						prefixlen = ip_address(snic.netmask).exploded.count("f")
						yield NamedIPv6Interface(interface_name, f"{snic.address.split('%')[0]}/{prefixlen}")
					else:
						prefixlen = IPv4Network(f"0.0.0.0/{snic.netmask}").prefixlen
						yield NamedIPv4Interface(interface_name, f"{snic.address}/{prefixlen}")
				except ValueError:
					get_logger().warning("Invalid IP interface: %s/%s", snic.address, snic.netmask)


def get_primary_ip_interface(family: int | Iterable[int] | None = None) -> NamedIPv4Interface | NamedIPv6Interface:
	"""
	Get the primary IP interface for the specified address family.

	Args:
		family (int | Iterable[int] | None): The address family (e.g., AF_INET, AF_INET6). Defaults to None.

	Returns:
		NamedIPv4Interface | NamedIPv6Interface: The primary IP interface.

	Raises:
		RuntimeError: If no primary interface is found.
	"""
	if not family:
		family = [AF_INET, AF_INET6]
	elif isinstance(family, int):
		family = [family]

	for iface in get_ip_interfaces(family):
		if not iface.ip.is_loopback:
			return iface

	family_name = ["IPv4" if f == AF_INET else "IPv6" for f in family]
	raise RuntimeError(f"No primary {'/'.join(family_name)} interface found")


def get_random_string(length: int, *, alphabet: str | None = None, mandatory_alphabet: str | None = None) -> str:
	"""
	Generate a random string.

	Args:
		length (int): The length of the string.
		alphabet (str | None): The alphabet to use. Defaults to None.
		mandatory_alphabet (str | None): Characters that must be included. Defaults to None.

	Returns:
		str: The generated random string.
	"""
	if not alphabet:
		alphabet = string.ascii_letters + string.digits + string.punctuation
	result_str = "".join(secrets.choice(alphabet) for i in range(length))
	if mandatory_alphabet:
		chars = list(mandatory_alphabet + result_str[len(mandatory_alphabet) :])
		random.shuffle(chars)
		result_str = "".join(chars[:length])
	return result_str


def decompress_data(data: bytes, compression: str) -> bytes:
	"""
	Decompress data using the specified compression method.

	Args:
		data (bytes): The compressed data.
		compression (str): The compression method (e.g., "lz4", "gzip").

	Returns:
		bytes: The decompressed data.

	Raises:
		ValueError: If the compression method is unsupported.
	"""
	compressed_size = len(data)

	decompress_start = time.perf_counter()
	if compression == "lz4":
		data = lz4.frame.decompress(data)
	elif compression == "deflate":
		data = zlib.decompress(data)
	elif compression in ("gz", "gzip"):
		data = gzip.decompress(data)
	else:
		raise ValueError(f"Unhandled compression {compression!r}")
	decompress_end = time.perf_counter()

	uncompressed_size = len(data)
	get_logger().debug(
		"%s decompression ratio: %d => %d = %0.2f%%, time: %0.2fms",
		compression,
		compressed_size,
		uncompressed_size,
		100 - 100 * (compressed_size / uncompressed_size),
		1000 * (decompress_end - decompress_start),
	)
	return data


def compress_data(data: bytes, compression: str, compression_level: int = 0, lz4_block_linked: bool = True) -> bytes:
	"""
	Compress data using the specified compression method.

	Args:
		data (bytes): The data to compress.
		compression (str): The compression method (e.g., "lz4", "gzip").
		compression_level (int): The compression level. Defaults to 0.
		lz4_block_linked (bool): Whether to use block linking for LZ4. Defaults to True.

	Returns:
		bytes: The compressed data.

	Raises:
		ValueError: If the compression method is unsupported.
	"""
	uncompressed_size = len(data)

	compress_start = time.perf_counter()
	if compression == "lz4":
		data = lz4.frame.compress(data, compression_level=compression_level, block_linked=lz4_block_linked)
	elif compression == "deflate":
		data = zlib.compress(data)
	elif compression in ("gz", "gzip"):
		data = gzip.compress(data)
	else:
		raise ValueError(f"Unhandled compression {compression!r}")
	compress_end = time.perf_counter()

	compressed_size = len(data)
	get_logger().debug(
		"%s compression ratio: %d => %d = %0.2f%%, time: %0.2fms",
		compression,
		uncompressed_size,
		compressed_size,
		100 - 100 * (compressed_size / uncompressed_size),
		1000 * (compress_end - compress_start),
	)
	return data


# From https://docs.python.org/3/library/asyncio-task.html:
# Important: Save a reference to the result of this function,
# to avoid a task disappearing mid-execution.
# The event loop only keeps weak references to tasks.
# A task that isn’t referenced elsewhere may get garbage collected at any time, even before it’s done.
# For reliable “fire-and-forget” background tasks, gather them in a collection
background_tasks = set()
background_tasks_lock = threading.Lock()


def _asyncio_remove_task(task: asyncio.Task) -> None:
	with background_tasks_lock:
		background_tasks.discard(task)


def asyncio_create_task(coro: Coroutine, loop: asyncio.AbstractEventLoop | None = None) -> asyncio.Task:
	"""
	Create an asyncio task and manage its lifecycle.

	Args:
		coro (Coroutine): The coroutine to run.
		loop (asyncio.AbstractEventLoop | None): The event loop. Defaults to None.

	Returns:
		asyncio.Task: The created task.
	"""
	if loop:
		task = loop.create_task(coro)
	else:
		task = asyncio.create_task(coro)
	with background_tasks_lock:
		background_tasks.add(task)
	task.add_done_callback(_asyncio_remove_task)
	return task


@dataclass(slots=True, kw_only=True)
class DiskUsage:
	"""
	Represents disk usage statistics.

	Attributes:
		capacity (float): Total disk capacity.
		available (float): Available disk space.
		used (float): Used disk space.
		usage (float): Percentage of disk usage.
	"""

	capacity: float
	available: float
	used: float
	usage: float

	def as_dict(self) -> dict[str, float]:
		return asdict(self)


def get_disk_usage(path: Path | str) -> DiskUsage:
	"""
	Get disk usage statistics for the specified path.

	Args:
		path (Path | str): The path to check.

	Returns:
		DiskUsage: The disk usage statistics.
	"""
	disk = os.statvfs(path)
	return DiskUsage(
		capacity=disk.f_bsize * disk.f_blocks,
		available=disk.f_bsize * disk.f_bavail,
		used=disk.f_bsize * (disk.f_blocks - disk.f_bavail),
		usage=float(disk.f_blocks - disk.f_bavail) / float(disk.f_blocks),
	)


def get_file_md5sum(file_path: Path | str) -> str:
	"""
	Calculate the MD5 checksum of a file.

	Args:
		file_path (Path | str): The path to the file.

	Returns:
		str: The MD5 checksum as a hex digest.
	"""
	md5_hash = md5()
	with open(file_path, "rb") as file:
		while data := file.read(1_000_000):
			md5_hash.update(data)
	return md5_hash.hexdigest()


def ldap3_uri_to_str(ldap_url: dict) -> str:
	"""
	Convert an LDAP URL dictionary to a string.

	Args:
		ldap_url (dict): The LDAP URL dictionary.

	Returns:
		str: The LDAP URL as a string.
	"""
	url = ldap_url["host"]
	if ldap_url["port"]:
		url = url + ":" + str(ldap_url["port"])
	if ldap_url["ssl"]:
		url = "ldaps://" + url
	else:
		url = "ldap://" + url
	return url


_NODENAME_REGEX = re.compile(r"^[a-z0-9][a-z0-9\-_]*$")


def force_nodename(var: Any) -> str:
	"""
	Force a variable to be a valid nodename.

	Args:
		var (Any): The variable to validate.

	Returns:
		str: The validated nodename.

	Raises:
		ValueError: If the nodename is invalid.
	"""
	var = forceStringLower(var)
	if not _NODENAME_REGEX.search(var):
		raise ValueError(f"Bad nodename: '{var}'")
	return var


def is_local_user(username: str) -> bool:
	"""
	Check if a user is a local user.

	Args:
		username (str): The username to check.

	Returns:
		bool: True if the user is local, False otherwise.
	"""
	for line in Path("/etc/passwd").read_text(encoding="utf-8").splitlines():
		if line.startswith(f"{username}:"):
			return True
	return False


class NameService(StrEnum):
	"""
	Enumeration for name services.

	Attributes:
		is_local (bool): Whether the service is local.
	"""

	SSS = "sss"
	WINBIND = "winbind"
	LDAP = "ldap"
	NISPLUS = "nisplus"
	NIS = "nis"
	COMPAT = "compat"
	SYSTEMD = "systemd"
	FILES = "files"

	@property
	def is_local(self) -> bool:
		return self in (NameService.SYSTEMD, NameService.COMPAT, NameService.FILES)


@dataclass(unsafe_hash=True)
class UserInfo:
	"""
	Represents user information.

	Attributes:
		username (str): The username.
		uid (int): The user ID.
		gid (int): The group ID.
		gecos (str): The GECOS field.
		home (Path): The home directory.
		shell (Path): The login shell.
		service (NameService): The name service.
	"""

	username: str
	uid: int
	gid: int
	gecos: str  # https://en.wikipedia.org/wiki/Gecos_field
	home: Path
	shell: Path
	service: NameService


def user_exists(username: str) -> bool:
	"""
	Check if a user exists.

	Args:
		username (str): The username to check.

	Returns:
		bool: True if the user exists, False otherwise.
	"""
	try:
		subprocess.run(["id", username], check=True, capture_output=True, timeout=5)
	except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as err:
		get_logger().debug("id %s failed: %s", username, err)
		return False
	return True


###
# One of the following exit values can be returned by getent:
#           0      Command completed successfully.
#           1      Missing arguments, or database unknown.
#           2      One or more supplied key could not be found in the database.
#           3      Enumeration not supported on this database.
###
def get_user_passwd_details(username: str) -> list[UserInfo]:
	"""
	Get user details from the passwd database.

	Args:
		username (str): The username to query.

	Returns:
		list[UserInfo]: A list of user information.
	"""
	user_details = []
	services = get_passwd_services()
	for service in services:
		cmd = ["getent", "passwd", "--service", service.value, username]
		try:
			getent_result = subprocess.run(cmd, check=True, capture_output=True, timeout=5).stdout.decode("utf-8")
		except (subprocess.CalledProcessError, FileNotFoundError) as err:
			get_logger().info("Command %s failed: %s", cmd, err)
			continue
		except subprocess.TimeoutExpired as err:
			get_logger().warning("Command %s timed out: %s", cmd, err)
			continue
		if getent_result:
			user_info = getent_result.strip().split(":")
			user_details.append(
				UserInfo(
					username=user_info[0],
					uid=int(user_info[2]),
					gid=int(user_info[3]),
					gecos=user_info[4],
					home=Path(user_info[5]),
					shell=Path(user_info[6]),
					service=service,
				)
			)

	return user_details


# This Method requires the univention-ldapsearch command, which is only available on UCS systems as root.
def get_ucs_user_details(username: str) -> UserInfo | None:
	"""
	Get user details from UCS LDAP.

	Args:
		username (str): The username to query.

	Returns:
		UserInfo | None: The user information, or None if not found.
	"""
	try:
		result = (
			subprocess.run(
				[
					"univention-ldapsearch",
					"-LLL",
					f"uid={username}",
					"uid",
					"gidNumber",
					"uidNumber",
					"gecos",
					"homeDirectory",
					"loginShell",
				],
				check=True,
				capture_output=True,
				timeout=10,
			)
			.stdout.decode("utf-8")
			.strip()
		)

		get_logger().debug("univention-ldapsearch result: %s", result)
		ldap_data = {line.split(":")[0].strip(): line.split(":")[1].strip() for line in result.splitlines() if ":" in line}

		if any(key not in ldap_data for key in ("uid", "uidNumber", "gidNumber")):
			return None

		return UserInfo(
			username=ldap_data["uid"],
			uid=int(ldap_data["uidNumber"]),
			gid=int(ldap_data["gidNumber"]),
			gecos=ldap_data.get("gecos", ""),
			home=Path(ldap_data.get("homeDirectory", "")),
			shell=Path(ldap_data.get("loginShell", "")),
			service=NameService.LDAP,
		)
	except (subprocess.CalledProcessError, FileNotFoundError) as err:
		get_logger().warning("univention-ldapsearch failed: %s", err)
		return None
	except subprocess.TimeoutExpired as err:
		get_logger().warning("univention-ldapsearch timed out: %s", err)
		return None


def get_passwd_services() -> list[NameService]:
	"""
	Get the list of name services for the passwd database.

	Returns:
		list[NameService]: The list of name services.
	"""
	if not NSSWITCH_CONF.is_file():
		return []

	passwd_service = []

	with open(NSSWITCH_CONF, "r", encoding="utf-8") as handle:
		for line in handle:
			if line.startswith("passwd:"):
				for service in line.split()[1:]:
					try:
						passwd_service.append(NameService(service))
					except ValueError:
						get_logger().info("Unknown name service %r in '%s'", service, NSSWITCH_CONF)
				break
	return passwd_service


def set_ucs_user_password(username: str, password: str) -> None:
	logger = get_logger()
	univention_server_role = get_ucs_server_role()

	logger.debug("Running on univention %s", univention_server_role)
	if univention_server_role not in ("domaincontroller_prim", "domaincontroller_master", "domaincontroller_backup"):
		logger.warning("Did not change the password for %r, please change it on the master server.", username)
		return

	user_dn = ""
	cmd = ["univention-admin", "users/user", "list", "--filter", f"(uid={username})"]
	logger.debug("Executing: %s", cmd)
	out = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=5).stdout
	logger.debug(out)
	for line in out.strip().splitlines():
		line = line.strip()
		if line.startswith("DN"):
			user_dn = line.split(" ")[1]
			break

	if not user_dn:
		raise RuntimeError(f"Failed to get DN for user {username}")

	escaped_password = password.replace("'", "\\'")
	cmd = [
		"univention-admin",
		"users/user",
		"modify",
		"--dn",
		user_dn,
		"--set",
		f"password={escaped_password}",
		"--set",
		"overridePWLength=1",
		"--set",
		"overridePWHistory=1",
	]
	logger.debug("Executing: %s", cmd)
	out = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10).stdout
	logger.debug(out)


def set_system_user_password(username: str, password: str) -> None:
	logger = get_logger()
	if is_ucs():
		try:
			set_ucs_user_password(username, password)
		except Exception as err:
			logger.error("Failed to set UCS user password for %r: %s", username, err)
		return

	try:
		pwd.getpwnam(username)
	except KeyError:
		logger.error("System user %r not found", username)
		return

	try:
		# smbldap
		cmd = ["smbldap-passwd", username]
		logger.debug("Executing: %s", cmd)
		inp = f"{password}\n{password}\n"
		out = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10, input=inp).stdout
		logger.debug(out)
		return
	except Exception as err:
		logger.debug("Setting password using smbldap failed: %s", err)

	if not is_local_user(username):
		logger.warning("The user %r is not a local user, please change password also in Active Directory", username)
		return

	try:
		cmd = ["chpasswd"]
		logger.debug("Executing: %s", cmd)
		inp = f"{username}:{password}\n"
		out = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10, input=inp).stdout
		logger.debug(out)
	except Exception as err:
		logger.debug("Setting password using chpasswd failed: %s", err)

	try:
		cmd = ["smbpasswd", "-a", "-s", username]
		logger.debug("Executing: %s", cmd)
		inp = f"{password}\n{password}\n"
		out = run(cmd, shell=False, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10, input=inp).stdout
		logger.debug(out)
	except Exception as err:
		logger.debug("Setting password using smbpasswd failed: %s", err)


class DataclassCapableJSONEncoder(JSONEncoder):
	"""
	JSON encoder capable of handling dataclasses.
	"""

	def default(self, o: Any) -> Any:
		if not isinstance(o, type) and dataclasses.is_dataclass(o):
			return dataclasses.asdict(o)
		return super().default(o)


def get_requests_session(hostname: str) -> requests.Session:
	"""
	Get a configured requests session for the specified hostname.

	Args:
		hostname (str): The hostname to configure the session for.

	Returns:
		requests.Session: The configured session.
	"""
	session = prepare_proxy_environment(hostname)
	session.verify = get_config().ssl_trusted_certs
	session.headers.update({"User-Agent": f"opsiconfd {__version__}"})
	return session


def timed_lru_cache(timeout: float, maxsize: int = 128) -> Callable:
	"""
	Decorator for creating a timed LRU cache.

	Args:
		timeout (float): The cache timeout in seconds.
		maxsize (int): The maximum size of the cache. Defaults to 128.

	Returns:
		Callable: The decorated function.
	"""

	def wrapper(func: Callable) -> Callable:
		# Apply functools.lru_cache with maxsize
		cached_func = functools.lru_cache(maxsize=maxsize)(func)
		# Store the expiration time
		cache_expiration = {"time": time.time() + timeout}

		@functools.wraps(func)
		def wrapped(*args: Any, **kwargs: Any) -> Any:
			# If expired, clear the cache and reset expiration
			if time.time() > cache_expiration["time"]:
				cached_func.cache_clear()
				cache_expiration["time"] = time.time() + timeout
			return cached_func(*args, **kwargs)

		# Expose cache control methods
		setattr(wrapped, "cache_clear", cached_func.cache_clear)
		setattr(wrapped, "cache_info", cached_func.cache_info)
		return wrapped

	return wrapper


def patch_markupsafe() -> None:
	import markupsafe
	from markupsafe._native import _escape_inner

	# Monkey-patch _escape_inner to override the one loaded from _speedups
	# because the _speedups module has Py_MOD_GIL_NOT_USED set and seems to produce segfaults
	markupsafe._escape_inner = _escape_inner
	if markupsafe._escape_inner.__module__ != "markupsafe._native":
		raise RuntimeError("Failed to patch markupsafe")


@dataclass
class FileCacheEntry:
	path: Path
	mtime: float
	content: str


class FileCache:
	def __init__(self) -> None:
		self._cache: dict[Path, FileCacheEntry] = {}
		self._cache_lock: threading.Lock = threading.Lock()

	def get_file_content(self, file_path: Path) -> str | None:
		with self._cache_lock:
			try:
				mtime = file_path.stat().st_mtime
			except FileNotFoundError:
				return None

			entry = self._cache.get(file_path)
			if entry and entry.mtime == mtime:
				return entry.content

			content = file_path.read_text(encoding="utf-8")
			self._cache[file_path] = FileCacheEntry(path=file_path, mtime=mtime, content=content)
			return content
