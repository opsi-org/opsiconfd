# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test_utiles
"""

import time
from contextlib import nullcontext
from pathlib import Path
from socket import AF_INET, AF_INET6
from unittest import mock

import pytest
from opsi.crypt.blowfish import blowfish_encrypt
from opsi.crypt.hash import verify_password
from opsi.opsi.service.model.object import User

from opsiconfd.config import opsi_config
from opsiconfd.utils import (
	FileCache,
	NameService,
	get_file_md5sum,
	get_ip_interfaces,
	get_passwd_services,
	get_primary_ip_interface,
	get_user_passwd_details,
	running_in_docker,
	timed_lru_cache,
)
from opsiconfd.utils.cryptography import (
	aes_decrypt_with_password,
	aes_encrypt_with_password,
	create_auth_token,
	create_token_hash,
	decrypt,
	encrypt,
	get_encryption_key,
)
from opsiconfd.utils.user import migrate_opsi_passwd_file
from tests.utils import cleanup_checks, get_opsi_config  # noqa: F401

from .utils import UnprotectedBackend, backend, get_config  # noqa: F401


def test_get_passwd_services(tmp_path: Path) -> None:
	nsswitch_conf = tmp_path / "nsswitch.conf"
	with mock.patch("opsiconfd.utils.NSSWITCH_CONF", nsswitch_conf):
		nsswitch_conf.write_text("passwd:     files sss winbind\n# passwd:     files ldap\n")
		assert get_passwd_services() == [NameService.FILES, NameService.SSS, NameService.WINBIND]

		nsswitch_conf.write_text("passwd: files vas4 sss\n")
		assert get_passwd_services() == [NameService.FILES, NameService.SSS]

		nsswitch_conf.unlink()
		assert get_passwd_services() == []


@pytest.mark.parametrize("family", (None, AF_INET, AF_INET6, [AF_INET, AF_INET6]))
def test_get_ip_interfaces(family: int | list[int] | None) -> None:
	interfaces = list(get_ip_interfaces(family))
	if not running_in_docker() or family != AF_INET6:
		# In Docker, the IPv6 interface is not always available
		# and can lead to an empty list.
		# So we skip the test for IPv6 in Docker.
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
	ctx = pytest.raises(exc) if exc else nullcontext()
	with ctx:
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
	assert info.home == Path("/root")
	assert info.service == NameService.FILES


def test_timed_lru_cache() -> None:
	# Test timeout
	@timed_lru_cache(timeout=1, maxsize=10)
	def some_func(arg: int) -> float:
		return time.time()

	res = some_func(1)
	assert some_func(2) != res
	assert some_func(1) == res
	assert some_func(1) == res
	time.sleep(1.1)
	assert some_func(1) != res

	# Test maxsize
	@timed_lru_cache(timeout=60, maxsize=2)
	def some_func2(arg: int) -> float:
		return time.time()

	some_func2(1)
	some_func2(2)
	some_func2(3)
	assert some_func2.cache_info().currsize == 2


def test_get_encryption_key() -> None:
	with get_config(
		{
			"database-encryption-keys": [
				"key1=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"key2=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			]
		}
	):
		# Default key (first in sorted order)
		get_encryption_key.cache_clear()
		key_id, key = get_encryption_key()
		assert key_id == "key2"
		assert key == bytes.fromhex("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")

		get_encryption_key.cache_clear()
		key_id, key = get_encryption_key("key1")
		assert key_id == "key1"
		assert key == bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

		with pytest.raises(ValueError, match="Encryption key with id 'nonexistent' not found"):
			get_encryption_key.cache_clear()
			get_encryption_key("nonexistent")

	with get_config(
		{
			"database-encryption-keys": [
				"0=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				"key1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"k e y=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"key2=0123456789abcdef",
			]
		}
	):
		# Invalid formats are skipped with a warning, but do not raise an exception
		get_encryption_key.cache_clear()
		key_id, key = get_encryption_key()
		assert key_id == "0"
		assert key == bytes.fromhex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

	with get_config(
		{
			"database-encryption-keys": [
				"key2=0123456789abcdef",
			]
		}
	):
		with pytest.raises(ValueError, match="No valid encryption keys configured"):
			get_encryption_key.cache_clear()
			get_encryption_key()


def test_encrypt_decrypt() -> None:
	get_encryption_key.cache_clear()
	with get_config(
		{
			"database-encryption-keys": [
				"2024-12=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"2025-01=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			]
		}
	):
		plaintext = "This is a test string."
		encrypted_value = encrypt(plaintext)
		assert encrypted_value.startswith("ENCv1[ALG=AESGCM|KID=2025-01]")

		decrypted_str = decrypt(encrypted_value, return_type=str)
		assert isinstance(decrypted_str, str)
		assert decrypted_str == plaintext

		decrypted_bytes = decrypt(encrypted_value, return_type=bytes)
		assert isinstance(decrypted_bytes, bytes)
		assert decrypted_bytes.decode("utf-8") == plaintext

		# Test with specific key_id
		encrypted_value = encrypt(plaintext.encode("utf-8"), key_id="2024-12")
		assert encrypted_value.startswith("ENCv1[ALG=AESGCM|KID=2024-12]")
		decrypted_str = decrypt(encrypted_value)
		assert decrypted_str == plaintext

		# Test decrypting value encrypted with different key_id
		encrypted_value_different_key = encrypted_value.replace("KID=2024-12", "KID=2025-01")
		with pytest.raises(ValueError, match="Decryption failed"):
			decrypt(encrypted_value_different_key)

		# Test key not found
		with pytest.raises(ValueError, match="Encryption key with id '2000-01' not found"):
			encrypt(plaintext, key_id="2000-01")

		with pytest.raises(ValueError, match="Encryption key with id '2000-01' not found"):
			decrypt("ENCv1[ALG=AESGCM|KID=2000-01]")

		# Test with unsupported algorithm
		with pytest.raises(ValueError, match="'UnsupportedAlg' is not a valid EncryptionAlgorithm"):
			encrypt(plaintext, algorithm="UnsupportedAlg")  # ty: ignore[invalid-argument-type]

		# Test decryption with unsupported algorithm
		invalid_encrypted_value = "ENCv1[ALG=UnsupportedAlg|KID=2025-01]abcd"
		with pytest.raises(ValueError, match="'UnsupportedAlg' is not a valid EncryptionAlgorithm"):
			decrypt(invalid_encrypted_value)

		# Test decryption with invalid format
		invalid_formats = [
			"InvalidFormatWithoutColon",
			"ENCv1ALG=AESGCM|KID=2025-01]abcd",
			"ENCv1[ALG=AESGCM|KID=2025-01abcd",
			"ENCv2[ALG=AESGCM|KID=2025-01]abcd",
		]
		for invalid_value in invalid_formats:
			with pytest.raises(ValueError):
				decrypt(invalid_value, ignore_unencrypted=False)

		# Test ignore_unencrypted
		plain_value = "Just a normal string."
		with pytest.raises(ValueError, match="Invalid encrypted format"):
			decrypt(plain_value, ignore_unencrypted=False)

		result = decrypt(plain_value, ignore_unencrypted=True)
		assert result == plain_value

		with pytest.raises(ValueError, match="Decryption failed"):
			decrypt("ENCv1[ALG=AESGCM|KID=2024-12]invalid", ignore_unencrypted=True)


def test_create_token_hash() -> None:
	with pytest.raises(ValueError, match="Token must be 64 characters long"):
		assert create_token_hash("short")
	token = "a" * 64
	token_hash = create_token_hash(token)
	assert token_hash.startswith("$6$rounds=1000$................$")
	assert len(token_hash) == 118
	# Test that the same token produces the same hash
	assert create_token_hash(token) == token_hash


def test_create_auth_token() -> None:
	token1, hash1 = create_auth_token()
	token2, hash2 = create_auth_token()

	assert isinstance(token1, str)
	assert len(token1) == 64
	assert isinstance(hash1, str)
	assert verify_password(token1, hash1)

	assert isinstance(token2, str)
	assert len(token2) == 64
	assert isinstance(hash2, str)
	assert verify_password(token2, hash2)

	assert token1 != token2


def test_migrate_opsi_passwd_file(tmp_path: Path, backend: UnprotectedBackend) -> None:  # noqa: F811
	configserver = backend.host_getObjects(type="OpsiConfigserver")[0]
	depot_user = opsi_config.get("depot_user", "username")
	users = {
		depot_user: "depot_user_password",
		"monitoring": "TPNc5JezvwDm9CjtkyEUymu",
		"someone": "some_password",
	}

	for broken_passwords in (True, False):
		passwd_file = tmp_path / "passwd"
		data = ""
		for username, password in users.items():
			encoded_password = blowfish_encrypt(configserver.opsiHostKey, password)
			if broken_passwords:
				encoded_password = encoded_password[:-4]  # Truncate to simulate broken password
			data += f"{username}:{encoded_password}\n"
		passwd_file.write_text(data, encoding="utf-8")

		user_objs: list[User] = backend.user_getObjects()
		assert len(user_objs) == 0
		with mock.patch("opsiconfd.utils.user.get_passwd_file", return_value=passwd_file):
			migrate_opsi_passwd_file()
		user_objs = backend.user_getObjects()
		assert len(user_objs) == 3

		user_objs_by_id = {user.id: user for user in user_objs}
		for username, password in users.items():
			user_obj = user_objs_by_id[username]
			assert user_obj.id == username
			assert user_obj.groups == ["{readonly}"]

			if username == depot_user:
				assert user_obj.encryptedPassword is not None
				assert user_obj.passwordHash is None
			else:
				assert user_obj.encryptedPassword is None
				assert user_obj.passwordHash is not None

			if not broken_passwords and username != depot_user:
				assert user_obj.passwordHash and verify_password(password, user_obj.passwordHash)

		assert not passwd_file.exists()
		assert passwd_file.with_suffix(".old").exists()

		backend.user_deleteObjects(user_objs)
		user_objs = backend.user_getObjects()
		assert len(user_objs) == 0


def test_file_cache(tmp_path: Path) -> None:
	orig_read_text = Path.read_text

	read_text_called = 0

	def read_text(self: Path, encoding: str | None = None, errors: str | None = None, newline: str | None = None) -> str:
		nonlocal read_text_called
		read_text_called += 1
		return orig_read_text(self, encoding=encoding, errors=errors, newline=newline)

	with mock.patch("opsiconfd.utils.Path.read_text", read_text):
		file_cache = FileCache()

		test_file = tmp_path / "test_file_cache.txt"
		test_file.write_text("Initial content", encoding="utf-8")

		content = file_cache.get_file_content(test_file)
		assert content == "Initial content"
		assert read_text_called == 1

		content = file_cache.get_file_content(test_file)
		assert content == "Initial content"
		assert read_text_called == 1  # Cached, so read_text should not be called

		time.sleep(1)
		test_file.write_text("Updated content", encoding="utf-8")

		content = file_cache.get_file_content(test_file)
		assert content == "Updated content"
		assert read_text_called == 2
		content = file_cache.get_file_content(test_file)
		assert content == "Updated content"
		assert read_text_called == 2  # Cached again

		assert file_cache.get_file_content(tmp_path / "non_existent_file.txt") is None
