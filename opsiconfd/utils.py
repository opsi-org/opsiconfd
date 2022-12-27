# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
utils
"""

from __future__ import annotations

import datetime
import gzip
import os
import random
import string
import time
import zlib
from ipaddress import (
	IPv4Address,
	IPv4Network,
	IPv6Address,
	IPv6Network,
	ip_address,
	ip_network,
)
from logging import INFO  # type: ignore[import]
from pprint import pformat
from socket import AF_INET, AF_INET6
from typing import TYPE_CHECKING, Any, Generator, Optional

import lz4.frame  # type: ignore[import]
import psutil
from Crypto.Cipher import AES
from Crypto.Cipher._mode_gcm import GcmMode
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from fastapi import APIRouter, FastAPI
from opsicommon.logging.logging import OPSILogger  # type: ignore[import]
from starlette.routing import Route

logger: OPSILogger | None = None  # pylint: disable=invalid-name
config = None  # pylint: disable=invalid-name
if TYPE_CHECKING:
	from config import Config  # type: ignore[import]
	config: "Config" | None = None  # type: ignore[no-redef]  # pylint: disable=invalid-name


def get_logger() -> OPSILogger:
	global logger  # pylint: disable=global-statement, invalid-name, global-variable-not-assigned
	if not logger:
		from .logging import (  # pylint: disable=import-outside-toplevel, redefined-outer-name
			logger,
		)
	return logger  # type: ignore[return-value]


def get_config() -> Config:
	global config  # pylint: disable=global-statement, invalid-name, global-variable-not-assigned
	if not config:
		from .config import (  # type: ignore[assignment]  # pylint: disable=import-outside-toplevel, redefined-outer-name
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


def utc_time_timestamp() -> float:
	return datetime.datetime.utcnow().timestamp()


def running_in_docker() -> bool:
	return os.path.exists("/.dockerenv")


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
	manager_pid = None
	ignore_pids = []  # pylint: disable=use-tuple-over-list
	if ignore_self:
		our_pid = os.getpid()
		our_proc = psutil.Process(our_pid)
		ignore_pids += [our_pid]
		ignore_pids += [p.pid for p in our_proc.children(recursive=True)]
	if ignore_parents:
		ignore_pids += [p.pid for p in our_proc.parents()]

	for proc in psutil.process_iter():  # pylint: disable=dotted-import-in-loop
		if proc.pid in ignore_pids or proc.status() == psutil.STATUS_ZOMBIE:  # pylint: disable=dotted-import-in-loop
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
	for interface, snics in psutil.net_if_addrs().items():  # pylint: disable=dotted-import-in-loop
		for snic in snics:
			family = None
			if snic.family == AF_INET:
				family = "ipv4"
			elif snic.family == AF_INET6:
				family = "ipv6"
			else:
				continue

			ipa = None
			try:  # pylint: disable=loop-try-except-usage
				ipa = ip_address(snic.address.split("%")[0])  # pylint: disable=dotted-import-in-loop
			except ValueError:
				if logger:  # pylint: disable=loop-global-usage
					logger.warning("Unrecognised ip address: %r", snic.address)  # pylint: disable=loop-global-usage

			yield {"family": family, "interface": interface, "address": snic.address, "ip_address": ipa}


def ip_address_in_network(address: str | IPv4Address | IPv6Address, network: str | IPv4Network | IPv6Network) -> bool:
	"""
	Checks if the given IP address is in the given network range.
	Returns ``True`` if the given address is part of the network.
	Returns ``False`` if the given address is not part of the network.

	:param address: The IP which we check.
	:type address: str
	:param network: The network address written with slash notation.
	:type network: str
	"""
	if not isinstance(address, (IPv4Address, IPv6Address)):
		address = ip_address(address)
	if isinstance(address, IPv6Address) and address.ipv4_mapped:
		address = address.ipv4_mapped

	if not isinstance(network, (IPv4Network, IPv6Network)):
		network = ip_network(network)

	return address in network


def get_random_string(length: int) -> str:
	letters = string.ascii_letters
	result_str = "".join(random.choice(letters) for i in range(length))
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


def aes_encryption_key_from_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
	if not password:
		raise ValueError("Empty password")
	salt = salt or get_random_bytes(32)
	return PBKDF2(password=password, salt=salt, dkLen=32, count=1_000_000, hmac_hash_module=SHA256), salt


def aes_encrypt(plaintext: bytes, password: str) -> tuple[bytes, bytes, bytes, bytes]:
	if not isinstance(plaintext, bytes):
		raise TypeError("Plaintext must be bytes")
	if not isinstance(password, str):
		raise TypeError("Password must be string")
	key, key_salt = aes_encryption_key_from_password(password)
	cipher = AES.new(key=key, mode=AES.MODE_GCM)
	assert isinstance(cipher, GcmMode)
	ciphertext, mac_tag = cipher.encrypt_and_digest(plaintext=plaintext)
	return ciphertext, key_salt, mac_tag, cipher.nonce


def aes_decrypt(ciphertext: bytes, key_salt: bytes, mac_tag: bytes, nonce: bytes, password: str) -> bytes:
	if not isinstance(ciphertext, bytes):
		raise TypeError("Plaintext must be bytes")
	if not isinstance(password, str):
		raise TypeError("Password must be string")
	key, _key_salt = aes_encryption_key_from_password(password, salt=key_salt)
	cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce)
	assert isinstance(cipher, GcmMode)
	plaintext = cipher.decrypt_and_verify(ciphertext=ciphertext, received_mac_tag=mac_tag)
	return plaintext
