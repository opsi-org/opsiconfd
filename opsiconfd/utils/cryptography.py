# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
utils
"""

from Crypto.Cipher import AES, Blowfish
from Crypto.Cipher._mode_gcm import GcmMode
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


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
