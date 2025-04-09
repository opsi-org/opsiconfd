# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test_utiles
"""

from contextlib import nullcontext
from pathlib import Path
from socket import AF_INET, AF_INET6

import pytest

from opsiconfd.utils import (
	NameService,
	get_file_md5sum,
	get_ip_interfaces,
	get_primary_ip_interface,
	get_user_passwd_details,
)
from opsiconfd.utils.cryptography import aes_decrypt_with_password, aes_encrypt_with_password


@pytest.mark.parametrize("family", (None, AF_INET, AF_INET6, [AF_INET, AF_INET6]))
def test_get_ip_interfaces(family: int | list[int] | None) -> None:
	interfaces = list(get_ip_interfaces(family))
	assert interfaces
	for iface in interfaces:
		assert iface.name
		assert iface.ip
		if family == AF_INET:
			assert iface.ip.version == 4
		elif family == AF_INET6:
			assert iface.ip.version == 6
		if iface.name == "lo":
			assert iface.ip.is_loopback
			if family == AF_INET:
				assert iface.ip.exploded == "127.0.0.1"
				assert iface.netmask.exploded == "255.0.0.0"
				assert iface.network.exploded == "127.0.0.0/8"
				assert iface.network.prefixlen == 8
				assert iface.network.network_address.exploded == "127.0.0.0"
				assert iface.network.netmask.exploded == "255.0.0.0"
			elif family == AF_INET6:
				assert iface.ip.compressed == "::1"
				assert iface.netmask.compressed == "ffff:ffff::"
				assert iface.network.compressed == "::/32"
				assert iface.network.prefixlen == 32
				assert iface.network.network_address.compressed == "::"
				assert iface.network.netmask.compressed == "ffff:ffff::"


def test_get_primary_ip_interface() -> None:
	iface = get_primary_ip_interface(AF_INET)
	assert iface
	assert iface.ip.version == 4
	assert not iface.ip.is_loopback

	try:
		iface = get_primary_ip_interface(AF_INET6)
		assert iface
		assert iface.ip.version == 6
		assert not iface.ip.is_loopback
	except RuntimeError as err:
		assert "No primary IPv6 interface found" in str(err)


@pytest.mark.parametrize(
	"password, plaintext, exc",
	(
		("0213uejSoiwu92u3oesdZjlkahdsa983elCjsaldk", b"", None),
		("key", b"x", None),
		(b"key", b"x", TypeError),
		("key", "data", TypeError),
		("", b"x", ValueError),
		(
			"boveik0quaacohseeweDo9thaepohng6geitahree1ahleeVo6Uri9thaiceu5ta",
			b"Ohchahl7loo3iehaeb0xaePhee1yah3eeyooPhoh9Ieng5OpoeTohng5Niek9eiS",
			None,
		),
	),
)
def test_aes_encrypt_decrypt(password: str, plaintext: bytes, exc: type[Exception | None]) -> None:
	ctx = pytest.raises(exc) if exc else nullcontext()  # type: ignore[type-var]
	with ctx:  # type: ignore[attr-defined]
		ciphertext, key_salt, mac_tag, nonce = aes_encrypt_with_password(plaintext=plaintext, password=password)
		decytped_data = aes_decrypt_with_password(ciphertext=ciphertext, key_salt=key_salt, mac_tag=mac_tag, nonce=nonce, password=password)
		assert decytped_data == plaintext


def test_get_file_md5sum(tmp_path: Path) -> None:
	test_file = tmp_path / "file"
	test_file.write_bytes(b"opsi" * 1_000_000)
	assert get_file_md5sum(test_file) == "ec80d22881b1da0e1869957931545495"


def test_get_user_passwd_details() -> None:
	info = get_user_passwd_details("root")[0]
	assert info.uid == 0
	assert info.gid == 0
	assert info.home == "/root"
	assert info.service == NameService.FILES
