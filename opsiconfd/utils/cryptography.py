# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
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
import secrets
from enum import StrEnum
from functools import lru_cache
from random import randbytes
from typing import Type, overload

import bcrypt
import crypt_r
from argon2 import DEFAULT_HASH_LENGTH as ARGON2_DEFAULT_HASH_LENGTH
from argon2 import DEFAULT_MEMORY_COST as ARGON2_DEFAULT_MEMORY_COST
from argon2 import DEFAULT_PARALLELISM as ARGON2_DEFAULT_PARALLELISM
from argon2 import DEFAULT_RANDOM_SALT_LENGTH as ARGON2_DEFAULT_SALT_LENGTH
from argon2 import DEFAULT_TIME_COST as ARGON2_DEFAULT_TIME_COST
from argon2 import PasswordHasher
from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret as argon2_hash_secret
from Crypto.Cipher import AES
from Crypto.Cipher._mode_gcm import GcmMode
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from opsiconfd.config import config
from opsiconfd.logging import logger, secret_filter

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
	return ciphertext, key_salt, mac_tag, bytes(cipher.nonce)


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
			return value
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
				return result.decode("utf-8")
			return result
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
	ARGON2ID = "ARGON2ID"

	@classmethod
	def _missing_(cls, value: object) -> HashingAlgorithm:
		value = str(value).upper().replace("-", "_")
		for member in cls:
			if member.value == value:
				return member
		raise ValueError(f"{value!r} is not a valid {cls.__name__}")

	def identifier(self) -> str:
		if self == HashingAlgorithm.ARGON2ID:
			return "argon2id"
		if self == HashingAlgorithm.SHA512:
			return "6"
		if self == HashingAlgorithm.BCRYPT:
			return "2b"
		raise ValueError(f"Unsupported hashing algorithm: {self!r}")

	@classmethod
	def from_identifier(cls, identifier: str) -> HashingAlgorithm:
		if identifier == "argon2id":
			return HashingAlgorithm.ARGON2ID
		if identifier == "6":
			return HashingAlgorithm.SHA512
		if identifier in ("2a", "2b", "2y"):
			return HashingAlgorithm.BCRYPT
		raise ValueError(f"Unsupported hashing algorithm {identifier!r}")


def create_password_hash(
	password: str,
	*,
	algorithm: HashingAlgorithm = HashingAlgorithm.ARGON2ID,
	rounds: int | None = None,
	format: PasswordHashFormat = PasswordHashFormat.SHADOW,
	generate_salt: bool = True,
) -> str:
	"""
	Encode a password using the specified algorithm and return a hash string.
	"""
	encoded_password = password.encode("utf-8")
	if len(encoded_password) > 64:
		# Max for bcrypt is 72 bytes
		raise ValueError("Password cannot be longer than 64 bytes")
	if not isinstance(algorithm, HashingAlgorithm):
		algorithm = HashingAlgorithm(algorithm)
	if rounds is not None:
		rounds = int(rounds)
	if not isinstance(format, PasswordHashFormat):
		format = PasswordHashFormat(format)

	if algorithm == HashingAlgorithm.ARGON2ID:
		if format != PasswordHashFormat.SHADOW:
			raise ValueError("ARGON2ID only supported with SHADOW format")
		return argon2_hash_secret(
			secret=password.encode("utf-8"),
			salt=os.urandom(ARGON2_DEFAULT_SALT_LENGTH) if generate_salt else b"................",
			time_cost=ARGON2_DEFAULT_TIME_COST,
			memory_cost=ARGON2_DEFAULT_MEMORY_COST,
			parallelism=ARGON2_DEFAULT_PARALLELISM,
			hash_len=ARGON2_DEFAULT_HASH_LENGTH,
			type=Argon2Type.ID,
		).decode("ascii")

	if algorithm == HashingAlgorithm.SHA512:
		if format != PasswordHashFormat.SHADOW:
			raise ValueError("SHA512 only supported with SHADOW format")
		rounds = rounds or 5000
		salt = (
			crypt_r.mksalt(
				method=crypt_r.METHOD_SHA512,  # ty: ignore[unresolved-attribute]
				rounds=rounds,
			)
			if generate_salt
			else f"$6$rounds={rounds}$................$"
		)
		return crypt_r.crypt(password, salt=salt)

	if algorithm == HashingAlgorithm.BCRYPT:
		if format != PasswordHashFormat.SHADOW:
			raise ValueError("BCRYPT only supported with SHADOW format")
		rounds = rounds or 12
		salt = bcrypt.gensalt(rounds=rounds) if generate_salt else f"$2b${rounds}$......................$".encode("utf-8")
		return bcrypt.hashpw(encoded_password, salt).decode("utf-8")

	if algorithm == HashingAlgorithm.PBKDF2_SHA512:
		if format != PasswordHashFormat.GRUB:
			raise ValueError("PBKDF2_SHA512 only supported with GRUB format")

		salt = os.urandom(16) if generate_salt else b"................"
		rounds = rounds or 10_000
		hash_bytes = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, rounds)
		return f"grub.pbkdf2.sha512.{rounds}.{binascii.hexlify(salt).decode().upper()}.{binascii.hexlify(hash_bytes).decode().upper()}"

	raise ValueError(f"Only 'SHA512', 'BCRYPT' and 'PBKDF2_SHA512' methods are supported, not {algorithm!r}")


def get_password_hash_algorithm(hash: str) -> HashingAlgorithm:
	"""
	Get the hashing algorithm used for a given hash string.
	"""
	if hash.count("$") < 3:
		raise ValueError("Invalid shadow hash format")

	identifier = hash.split("$", 2)[1]
	return HashingAlgorithm.from_identifier(identifier)


def verify_password(password: str, hash: str, algorithm: HashingAlgorithm | None = None) -> bool:
	"""
	Verify a password against a given hash string.
	"""
	if not algorithm:
		algorithm = get_password_hash_algorithm(hash)

	if algorithm == HashingAlgorithm.ARGON2ID:
		hasher = PasswordHasher()
		try:
			return hasher.verify(hash, password)
		except Exception:
			return False

	if algorithm == HashingAlgorithm.SHA512:
		return crypt_r.crypt(password, hash) == hash

	if algorithm == HashingAlgorithm.BCRYPT:
		return bcrypt.checkpw(password.encode("utf-8"), hash.encode("utf-8"))

	raise ValueError("Only 'SHA512' and 'BCRYPT' methods are supported")


def create_token_hash(token: str) -> str:
	if len(token) != 64:
		raise ValueError("Token must be 64 characters long")
	return create_password_hash(token, algorithm=HashingAlgorithm.SHA512, rounds=1000, generate_salt=False)


def create_auth_token() -> tuple[str, str]:
	"""
	Create a new authentication token and return the token and its hash.
	"""
	token = secrets.token_hex(32)
	secret_filter.add_secrets(token)
	token_hash = create_token_hash(token)
	secret_filter.add_secrets(token_hash)
	return token, token_hash
