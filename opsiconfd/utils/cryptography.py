# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
utils
"""

from __future__ import annotations

import base64
import re
import secrets
from enum import StrEnum
from functools import lru_cache
from random import randbytes
from typing import overload

from Crypto.Cipher import AES
from Crypto.Cipher._mode_gcm import GcmMode
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from opsi.crypt.hash import PasswordHashAlgorithm, hash_password

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
def decrypt(value: str, *, return_type: type[str] = ..., ignore_unencrypted: bool = False) -> str: ...


@overload
def decrypt(value: str, *, return_type: type[bytes], ignore_unencrypted: bool = False) -> bytes: ...


def decrypt(value: str, *, return_type: type[str | bytes] = str, ignore_unencrypted: bool = False) -> str | bytes:
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


def create_token_hash(token: str) -> str:
	if len(token) != 64:
		raise ValueError("Token must be 64 characters long")
	return hash_password(token, algorithm=PasswordHashAlgorithm.SHA512, rounds=1000, generate_salt=False)


def create_auth_token() -> tuple[str, str]:
	"""
	Create a new authentication token and return the token and its hash.
	"""
	token = secrets.token_hex(32)
	secret_filter.add_secrets(token)
	token_hash = create_token_hash(token)
	secret_filter.add_secrets(token_hash)
	return token, token_hash
