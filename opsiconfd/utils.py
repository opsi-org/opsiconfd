# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
utils
"""

from __future__ import annotations

import asyncio
import datetime
import gzip
import os
import random
import re
import secrets
import string
import subprocess
import threading
import time
import zlib
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from enum import StrEnum
from fcntl import LOCK_EX, LOCK_NB, LOCK_UN, flock
from hashlib import md5
from ipaddress import IPv4Network, IPv6Address, ip_address, ip_interface
from logging import INFO  # type: ignore[import]
from pathlib import Path
from pprint import pformat
from socket import AF_INET, AF_INET6
from typing import TYPE_CHECKING, Any, BinaryIO, Coroutine, Generator, List, Optional, TextIO

import lz4.frame  # type: ignore[import]
import psutil
from Crypto.Cipher import AES, Blowfish
from Crypto.Cipher._mode_gcm import GcmMode
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from fastapi import APIRouter, FastAPI
from opsicommon.logging.logging import OPSILogger
from opsicommon.system.info import is_ucs
from opsicommon.types import forceString, forceStringLower
from starlette.routing import Route

logger: OPSILogger | None = None
config = None
if TYPE_CHECKING:
	from config import Config  # type: ignore[import]

	config: "Config" | None = None  # type: ignore[no-redef]


def get_logger() -> OPSILogger:
	global logger
	if not logger:
		from .logging import (
			logger,
		)
	return logger  # type: ignore[return-value]


def get_config() -> Config:
	global config
	if not config:
		from .config import (  # type: ignore[assignment]
			config,
		)
	return config


class Singleton(type):
	_instances: dict[type, type] = {}

	def __call__(cls: "Singleton", *args: Any, **kwargs: Any) -> type:
		if cls not in cls._instances:
			cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
		return cls._instances[cls]


def log_config(log_level: int = INFO) -> None:
	conf = "{\n " + pformat(get_config().items(), width=200).strip("{}") + "\n}\n"
	get_logger().log(log_level, "Config: %s", conf)


_now = datetime.datetime.now
_utc = datetime.timezone.utc


def utc_timestamp() -> float:
	return _now(tz=_utc).timestamp()


def running_in_docker() -> bool:
	try:
		with open("/proc/2/stat", encoding="utf-8", errors="replace") as file:
			return "kthreadd" not in file.read()
	except FileNotFoundError:
		return True
	except Exception:
		pass
	return False


def is_opsiconfd(proc: psutil.Process) -> bool:
	return proc.name() == "opsiconfd" or (
		proc.name() in ("python", "python3") and ("opsiconfd" in proc.cmdline() or "opsiconfd.__main__" in " ".join(proc.cmdline()))
	)


def is_manager(proc: psutil.Process) -> bool:
	manager = False
	if is_opsiconfd(proc):
		manager = True
		for arg in proc.cmdline():
			if "multiprocessing" in arg or "log-viewer" in arg or "debugpy" in arg:
				manager = False
				break
	return manager


def get_manager_pid(ignore_self: bool = False, ignore_parents: bool = False) -> Optional[int]:
	container_procs = ("containerd-shim", "lxc-start")

	manager_pid = None
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

	return manager_pid


def normalize_ip_address(address: str, exploded: bool = False) -> str:
	ipa = ip_address(address)
	if isinstance(ipa, IPv6Address) and ipa.ipv4_mapped:
		ipa = ipa.ipv4_mapped
	if exploded:
		return ipa.exploded
	return ipa.compressed


def get_ip_addresses() -> Generator[dict[str, Any], None, None]:
	for interface, snics in psutil.net_if_addrs().items():
		for snic in snics:
			family = None
			if snic.family == AF_INET:
				family = "ipv4"
			elif snic.family == AF_INET6:
				family = "ipv6"
			else:
				continue

			if not snic.netmask:
				continue

			try:
				prefixlen = 0
				if family == "ipv6":
					prefixlen = ip_address(snic.netmask).exploded.count("f")
				else:
					prefixlen = IPv4Network(f"0.0.0.0/{snic.netmask}").prefixlen
				ipi = f"{snic.address.split('%')[0]}/{prefixlen}"
				iface = ip_interface(ipi)
			except ValueError:
				if logger:
					logger.warning("Unrecognised ip interface: %s/%s", snic.address, snic.netmask)
				continue
			yield {
				"family": family,
				"interface": interface,
				"ip_address": iface.ip,
				"ip_network": iface.network,
				"ip_netmask": iface.netmask,
				"address": iface.ip.exploded,
				"network": iface.network.exploded,
				"netmask": iface.netmask.exploded,
				"prefixlen": prefixlen,
			}


def get_random_string(length: int, *, alphabet: str | None = None, mandatory_alphabet: str | None = None) -> str:
	if not alphabet:
		alphabet = string.ascii_letters + string.digits + string.punctuation
	result_str = "".join(secrets.choice(alphabet) for i in range(length))
	if mandatory_alphabet:
		chars = list(mandatory_alphabet + result_str[len(mandatory_alphabet) :])
		random.shuffle(chars)
		result_str = "".join(chars[:length])
	return result_str


def remove_router(app: FastAPI, router: APIRouter, router_prefix: str) -> None:
	paths = [f"{router_prefix}{route.path}" for route in router.routes if isinstance(route, Route)]
	for route in app.routes:
		if isinstance(route, Route) and route.path in paths:
			app.routes.remove(route)


def remove_route_path(app: FastAPI, path: str) -> None:
	# Needs to be done twice to work for unknown reason
	for _ in range(2):
		for route in app.routes:
			if isinstance(route, Route) and route.path.lower().startswith(path.lower()):
				app.routes.remove(route)


def decompress_data(data: bytes, compression: str) -> bytes:
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


def aes_encryption_key_from_password(password: str, salt: bytes) -> bytes:
	if not password:
		raise ValueError("Empty password")
	return PBKDF2(password=password, salt=salt, dkLen=32, count=200_000, hmac_hash_module=SHA256)


def aes_encrypt_with_password(plaintext: bytes, password: str) -> tuple[bytes, bytes, bytes, bytes]:
	if not isinstance(plaintext, bytes):
		raise TypeError("Plaintext must be bytes")
	if not isinstance(password, str):
		raise TypeError("Password must be string")
	key_salt = get_random_bytes(32)
	key = aes_encryption_key_from_password(password, salt=key_salt)
	cipher = AES.new(key=key, mode=AES.MODE_GCM)
	assert isinstance(cipher, GcmMode)
	ciphertext, mac_tag = cipher.encrypt_and_digest(plaintext=plaintext)
	return ciphertext, key_salt, mac_tag, cipher.nonce


def aes_decrypt_with_password(ciphertext: bytes, key_salt: bytes, mac_tag: bytes, nonce: bytes, password: str) -> bytes:
	if not isinstance(ciphertext, bytes):
		raise TypeError("Plaintext must be bytes")
	if not isinstance(password, str):
		raise TypeError("Password must be string")
	key = aes_encryption_key_from_password(password, salt=key_salt)
	cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce)
	assert isinstance(cipher, GcmMode)
	try:
		plaintext = cipher.decrypt_and_verify(ciphertext=ciphertext, received_mac_tag=mac_tag)
	except ValueError as err:
		raise ValueError(f"Failed to decrypt, password incorrect or file corrupted ({err})") from err
	return plaintext


BLOWFISH_IV = b"OPSI1234"


def blowfish_encrypt(key: str, cleartext: str) -> str:
	"""
	Takes `cleartext` string, returns hex-encoded,
	blowfish-encrypted string.
	`key` must a string of hexadecimal numbers.
	"""
	if not key:
		raise ValueError("Missing key")

	bkey = bytes.fromhex(key)
	btext = forceString(cleartext).encode("utf-8")
	while len(btext) % 8 != 0:
		# Fill up with \0 until length is a mutiple of 8
		btext += b"\x00"

	blowfish = Blowfish.new(bkey, Blowfish.MODE_CBC, BLOWFISH_IV)
	return blowfish.encrypt(btext).hex()


def blowfish_decrypt(key: str, crypt: str) -> str:
	"""
	Takes hex-encoded, blowfish-encrypted string, returns cleartext string.
	"""
	if not key:
		raise ValueError("Missing key")

	bkey = bytes.fromhex(key)
	bcrypt = bytes.fromhex(crypt)
	blowfish = Blowfish.new(bkey, Blowfish.MODE_CBC, BLOWFISH_IV)
	# Remove possible \0-chars
	return blowfish.decrypt(bcrypt).rstrip(b"\0").decode("utf-8")


@contextmanager
def lock_file(file: TextIO | BinaryIO, lock_flags: int = LOCK_EX | LOCK_NB, timeout: float = 5.0) -> Generator[None, None, None]:
	start = time.time()
	while True:
		try:
			flock(file, lock_flags)
			break
		except (IOError, BlockingIOError):
			if time.time() >= start + timeout:
				raise
			time.sleep(0.1)
	try:
		yield
	finally:
		flock(file, LOCK_UN)


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
	capacity: float
	available: float
	used: float
	usage: float

	def as_dict(self) -> dict[str, float]:
		return asdict(self)


def get_disk_usage(path: Path | str) -> DiskUsage:
	disk = os.statvfs(path)
	return DiskUsage(
		capacity=disk.f_bsize * disk.f_blocks,
		available=disk.f_bsize * disk.f_bavail,
		used=disk.f_bsize * (disk.f_blocks - disk.f_bavail),
		usage=float(disk.f_blocks - disk.f_bavail) / float(disk.f_blocks),
	)


def get_file_md5sum(file_path: Path | str) -> str:
	"""Returns the md5sum of the given file as hex digest string."""
	md5_hash = md5()
	with open(file_path, "rb") as file:
		while data := file.read(1_000_000):
			md5_hash.update(data)
	return md5_hash.hexdigest()


def ldap3_uri_to_str(ldap_url: dict) -> str:
	url = ldap_url["host"]
	if ldap_url["port"]:
		url = url + ":" + str(ldap_url["port"])
	if ldap_url["ssl"]:
		url = "ldaps://" + url
	else:
		url = "ldap://" + url
	return url


_NODENAME_REGEX = re.compile(r"^[a-z0-9][a-z0-9\-_]*$")


def forceNodename(var: Any) -> str:
	var = forceStringLower(var)
	if not _NODENAME_REGEX.search(var):
		raise ValueError(f"Bad nodename: '{var}'")
	return var


def is_local_user(username: str) -> bool:
	for line in Path("/etc/passwd").read_text(encoding="utf-8").splitlines():
		if line.startswith(f"{username}:"):
			return True
	return False


class NameService(StrEnum):
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
	username: str
	uid: int
	gid: int
	gecos: str  # https://en.wikipedia.org/wiki/Gecos_field
	home: str
	shell: str
	service: NameService


def user_exists(username: str) -> bool:
	try:
		return_code = subprocess.run(["id", username], check=True, capture_output=True, timeout=5).returncode
		if return_code != 0:
			return False
	except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as err:
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
def get_user_passwd_details(username: str) -> List[UserInfo]:
	user_details = []
	if is_ucs():
		ucs_details = get_ucs_user_details(username)
		if ucs_details:
			user_details.append(ucs_details)
	services = get_passwd_services()
	for service in services:
		try:
			getent_result = subprocess.run(
				["getent", "passwd", "--service", service, username], check=True, capture_output=True, timeout=5
			).stdout.decode("utf-8")
		except subprocess.CalledProcessError as err:
			get_logger().warning("getent passwd --service %s %s failed: %s", service, username, err)
			continue
		except subprocess.TimeoutExpired as err:
			get_logger().warning("getent passwd --service %s %s timed out: %s", service, username, err)
			continue
		if getent_result:
			user_info = getent_result.strip().split(":")
			user_details.append(
				UserInfo(
					username=user_info[0],
					uid=int(user_info[2]),
					gid=int(user_info[3]),
					gecos=user_info[4],
					home=user_info[5],
					shell=user_info[6],
					service=service,
				)
			)

	return user_details


def get_ucs_user_details(username: str) -> UserInfo | None:
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

		return UserInfo(
			username=ldap_data.get("uid", username),
			uid=int(ldap_data.get("uidNumber", -1)),
			gid=int(ldap_data.get("gidNumber", -1)),
			gecos=ldap_data.get("gecos", ""),
			home=ldap_data.get("homeDirectory", ""),
			shell=ldap_data.get("loginShell", ""),
			service=NameService.LDAP,
		)
	except subprocess.CalledProcessError as err:
		get_logger().warning("univention-ldapsearch failed: %s", err)
		return None


def get_passwd_services() -> List[NameService]:
	nsswitch_conf = Path("/etc/nsswitch.conf")
	if not nsswitch_conf.is_file():
		return []

	passwd_service = []

	with open(nsswitch_conf, "r", encoding="utf-8") as handle:
		for line in handle:
			if line.startswith("passwd:"):
				passwd_service = [NameService(service) for service in line.split()[1:]]
				break
	return passwd_service
