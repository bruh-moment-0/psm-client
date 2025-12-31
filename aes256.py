# The AES-256-GCM and Argon2id code of Private Safe Messaging Client
# Copyright (C) 2025  bruh-moment-0

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.



from argon2.low_level import hash_secret_raw, Type # argon2id for AES256GCM
from Crypto.Cipher import AES # AES256GCM
from Crypto.Random import get_random_bytes # salt/nonce for AES256GCM
import secrets
import base64

from typing import Tuple, Union, Optional

SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32

def keygen(length_bytes: int = 32) -> bytes:
    key_bytes = secrets.token_bytes(length_bytes)
    return key_bytes

def keydecode(key_b64: str) -> bytes:
    return base64.b64decode(key_b64)

def _to_bytes(s: str | bytes) -> bytes:
    return s.encode("utf-8") if isinstance(s, str) else s

def password2key_argon2id(password: Union[str, bytes], salt: bytes) -> bytes:
    return hash_secret_raw(secret=_to_bytes(password), salt=salt, time_cost=3, memory_cost=65536, parallelism=1, hash_len=KEY_LENGTH, type=Type.ID,)

def encryptAESGCM(password: Union[str, bytes], data: bytes, human: bool) -> Tuple[str, str, str, str]:
    salt = get_random_bytes(SALT_LENGTH)
    nonce = get_random_bytes(NONCE_LENGTH)
    if human:
        key = password2key_argon2id(password, salt)
    else:
        key = _to_bytes(password)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    blob = ciphertext + tag
    return (base64.b64encode(ciphertext).decode(), base64.b64encode(tag).decode(), base64.b64encode(salt).decode(), base64.b64encode(nonce).decode())

def decryptAESGCM(password: Union[str, bytes], ciphertext_b64: str, tag_b64: str, salt_b64: str, nonce_b64: str, human: bool) -> bytes:
    ciphertext = base64.b64decode(ciphertext_b64)
    tag = base64.b64decode(tag_b64)
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    if human:
        key = password2key_argon2id(password, salt)
    else:
        key = _to_bytes(password)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
