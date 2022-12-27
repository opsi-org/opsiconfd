# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test_utiles
"""

from contextlib import nullcontext
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

import pytest

from opsiconfd.utils import aes_decrypt, aes_encrypt, ip_address_in_network


@pytest.mark.parametrize(
	"address, network, expected",
	[
		("10.10.1.1", "10.10.0.0/16", True),
		("10.10.1.1", "10.10.0.0/23", True),
		("10.10.1.1", "10.10.0.0/24", False),
		("10.10.1.1", "10.10.0.0/25", False),
		("10.10.1.1", "0.0.0.0/0", True),
		("10.10.1.1", "10.10.0.0/255.255.0.0", True),
		(IPv4Address("192.168.1.1"), IPv4Network("192.168.1.0/24"), True),
		(IPv4Address("192.168.1.1"), IPv4Network("192.168.2.0/24"), False),
	],
)
def test_ip_address_in_network(address: str | IPv4Address | IPv6Address, network: str | IPv4Network | IPv6Network, expected: bool) -> None:
	assert ip_address_in_network(address, network) == expected


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
		ciphertext, key_salt, mac_tag, nonce = aes_encrypt(plaintext=plaintext, password=password)
		decytped_data = aes_decrypt(ciphertext=ciphertext, key_salt=key_salt, mac_tag=mac_tag, nonce=nonce, password=password)
		assert decytped_data == plaintext
