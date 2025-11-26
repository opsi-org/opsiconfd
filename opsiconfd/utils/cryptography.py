# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
utils
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
from enum import StrEnum
from functools import lru_cache
from random import randbytes
from typing import Type, overload

import bcrypt
import crypt_r  # type: ignore[import-untyped]
from Crypto.Cipher import AES, Blowfish
from Crypto.Cipher._mode_gcm import GcmMode
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from opsiconfd.config import config
from opsiconfd.logging import logger

ENCRYPTION_KEY_ID_REGEX = re.compile(r"^[0-9a-z\-\_]{1,16}$")
ENCRYPTION_KEY_REGEX = re.compile(r"^[0-9a-f]{64}$")


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
		raise TypeError("Ciphertext must be bytes")
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


def blowfish_encrypt(key: str, cleartext: str | bytes) -> str:
	"""
	Takes `cleartext` string, returns hex-encoded,
	blowfish-encrypted string.
	`key` must a string of hexadecimal numbers.
	"""
	if not key:
		raise ValueError("Missing key")

	bkey = bytes.fromhex(key)
	if isinstance(cleartext, str):
		cleartext = cleartext.encode("utf-8")
	while len(cleartext) % 8 != 0:
		# Fill up with \0 until length is a mutiple of 8
		cleartext += b"\x00"

	blowfish = Blowfish.new(bkey, Blowfish.MODE_CBC, BLOWFISH_IV)
	return blowfish.encrypt(cleartext).hex()


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


@lru_cache
def get_encryption_key(key_id: str | None = None) -> tuple[str, bytes]:
	for conf_key in sorted(config.database_encryption_keys, reverse=True):
		if "=" not in conf_key:
			logger.warning("Invalid database encryption key format: %r", conf_key)
			continue
		kid, key = conf_key.split("=", 1)
		kid = kid.strip()
		key = key.strip()
		if not ENCRYPTION_KEY_ID_REGEX.match(kid):
			logger.warning("Invalid database encryption key id: %r", kid)
			continue
		if not ENCRYPTION_KEY_REGEX.match(key):
			logger.warning("Invalid database encryption key: %r", key)
			continue
		if key_id is None or kid == key_id:
			return (kid, bytes.fromhex(key))

	if key_id is None:
		raise ValueError("No valid encryption keys configured")
	raise ValueError(f"Encryption key with id {key_id!r} not found")


class EncryptionAlgorithm(StrEnum):
	AESGCM = "AESGCM"


def encrypt(value: str | bytes, *, key_id: str | None = None, algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AESGCM) -> str:
	"""
	Encrypts a string using the specified algorithm.
	Returns a string with format: ENCv1[ALG=<algorithm>|KID=<key_id>]base64(nonce+ciphertext)
	"""
	if not isinstance(algorithm, EncryptionAlgorithm):
		algorithm = EncryptionAlgorithm(algorithm)

	if not isinstance(value, bytes):
		value = value.encode("utf-8")

	key_id, key = get_encryption_key(key_id)
	if algorithm == EncryptionAlgorithm.AESGCM:
		cipher = AESGCM(key)
		nonce = randbytes(12)
		ciphertext = cipher.encrypt(nonce, value, None)
		b64_encoded = base64.b64encode(nonce + ciphertext).decode("utf-8")
		return f"ENCv1[ALG={algorithm.value}|KID={key_id}]{b64_encoded}"

	raise ValueError(f"Unsupported algorithm: {algorithm!r}")


@overload
def decrypt(value: str, *, return_type: Type[str] = ..., ignore_unencrypted: bool = False) -> str: ...


@overload
def decrypt(value: str, *, return_type: Type[bytes], ignore_unencrypted: bool = False) -> bytes: ...


def decrypt(value: str, *, return_type: Type[str] | Type[bytes] = str, ignore_unencrypted: bool = False) -> str | bytes:
	"""
	Decrypts a string formatted as ENCv1[ALG|KID=key_id]base64(nonce+ciphertext)
	Returns the decrypted value as bytes or str depending on return_type.
	If ignore_unencrypted is True, non-encrypted values are returned as-is.
	"""
	try:
		if not value or "]" not in value:
			raise ValueError(f"Invalid encrypted format: {value!r}")
		prefix, b64_data = value.split("]", 1)
		enc_version, info = prefix.split("[", 1)
		if enc_version != "ENCv1":
			raise ValueError(f"Unsupported encryption version: {enc_version!r}")
	except ValueError:
		if not ignore_unencrypted:
			raise
		if return_type is str:
			return value  # type: ignore[return-value]
		raise TypeError("Value is not encrypted and not a string")

	info_dict = {k: v for part in info.split("|") for k, v in [part.split("=", 1)]}

	key = get_encryption_key(info_dict.get("KID") or None)[1]
	algorithm = EncryptionAlgorithm(info_dict.get("ALG") or EncryptionAlgorithm.AESGCM.value)
	if algorithm == EncryptionAlgorithm.AESGCM:
		try:
			data = base64.b64decode(b64_data)
			nonce = data[:12]
			ciphertext = data[12:]
			cipher = AESGCM(key)
			result = cipher.decrypt(nonce, ciphertext, None)
			if return_type is str:
				return result.decode("utf-8")  # type: ignore[return-value]
			return result  # type: ignore[return-value]
		except Exception as err:
			raise ValueError(f"Decryption failed: {err}") from err

	raise ValueError(f"Unsupported algorithm: {algorithm!r}")


class PasswordHashFormat(StrEnum):
	SHADOW = "SHADOW"
	GRUB = "GRUB"

	@classmethod
	def _missing_(cls, value: object) -> PasswordHashFormat:
		value = str(value).upper()
		for member in cls:
			if member.value == value:
				return member
		raise ValueError(f"{value!r} is not a valid {cls.__name__}")


class HashingAlgorithm(StrEnum):
	SHA512 = "SHA512"
	BCRYPT = "BCRYPT"
	PBKDF2_SHA512 = "PBKDF2_SHA512"

	@classmethod
	def _missing_(cls, value: object) -> HashingAlgorithm:
		value = str(value).upper().replace("-", "_")
		for member in cls:
			if member.value == value:
				return member
		raise ValueError(f"{value!r} is not a valid {cls.__name__}")

	def identifier(self) -> str:
		if self == HashingAlgorithm.SHA512:
			return "6"
		if self == HashingAlgorithm.BCRYPT:
			return "2b"
		raise ValueError(f"Unsupported hashing algorithm: {self!r}")

	@classmethod
	def from_identifier(cls, identifier: str) -> HashingAlgorithm:
		if identifier == "6":
			return HashingAlgorithm.SHA512
		if identifier in ("2a", "2b", "2y"):
			return HashingAlgorithm.BCRYPT
		raise ValueError(f"Unsupported hashing algorithm {identifier!r}")


def create_password_hash(
	password: str,
	*,
	algorithm: HashingAlgorithm = HashingAlgorithm.BCRYPT,
	rounds: int | None = None,
	format: PasswordHashFormat = PasswordHashFormat.SHADOW,
) -> str:
	"""
	Encode a password using the specified algorithm and return a hash string.
	"""
	encoded_password = password.encode("utf-8")
	if len(encoded_password) > 64:
		# Max for bcrypt is 72 bytes
		raise ValueError("Password cannot be longer than 64 bytes")

	if algorithm == HashingAlgorithm.SHA512:
		if format != PasswordHashFormat.SHADOW:
			raise ValueError("SHA512 only supported with SHADOW format")
		salt = crypt_r.mksalt(method=crypt_r.METHOD_SHA512, rounds=rounds or 500_000)
		return crypt_r.crypt(password, salt=salt)

	if algorithm == HashingAlgorithm.BCRYPT:
		if format != PasswordHashFormat.SHADOW:
			raise ValueError("BCRYPT only supported with SHADOW format")
		salt = bcrypt.gensalt(rounds=rounds or 12)
		return bcrypt.hashpw(encoded_password, salt).decode("utf-8")

	if algorithm == HashingAlgorithm.PBKDF2_SHA512:
		if format != PasswordHashFormat.GRUB:
			raise ValueError("PBKDF2_SHA512 only supported with GRUB format")

		salt = os.urandom(16)
		rounds = int(rounds or 10_000)
		hash_bytes = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), os.urandom(16), rounds)
		return f"grub.pbkdf2.sha512.{rounds}.{binascii.hexlify(salt).decode().upper()}.{binascii.hexlify(hash_bytes).decode().upper()}"

	raise ValueError("Only 'SHA512', 'BCRYPT' and 'PBKDF2_SHA512' methods are supported")


def verify_password(password: str, hash: str) -> bool:
	"""
	Verify a password against a given hash string.
	"""
	if hash.count("$") < 3:
		raise ValueError("Invalid shadow hash format")

	identifier = hash.split("$", 2)[1]
	algorithm = HashingAlgorithm.from_identifier(identifier)
	if algorithm == HashingAlgorithm.SHA512:
		return crypt_r.crypt(password, hash) == hash

	if algorithm == HashingAlgorithm.BCRYPT:
		return bcrypt.checkpw(password.encode("utf-8"), hash.encode("utf-8"))

	raise ValueError("Only 'SHA512' and 'BCRYPT' methods are supported")
