from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from quantum import oqs, encap, decap # custom
from data import b642byte, byte2b64, str2byte # custom
from aes256 import encryptAESGCM, decryptAESGCM # custom
from typing import Tuple
import os

def hkdf_function(shared_secret_bytes: bytes, salt: bytes, info: bytes = b"psm-hkdf-ver2") -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(shared_secret_bytes)

def encapsulate_shared_secret(kemobj: oqs.KeyEncapsulation, receiver_public_key_b64: str) -> Tuple[str, bytes]:
    publickey = b642byte(receiver_public_key_b64)
    ciphertext, sharedsecret = encap(kemobj, publickey)
    return byte2b64(ciphertext), sharedsecret

def decapsulate_shared_secret(kemobj: oqs.KeyEncapsulation, ciphertext_b64: str) -> bytes:
    ciphertext = b642byte(ciphertext_b64)
    sharedsecret = decap(kemobj, ciphertext)
    return sharedsecret

def encrypt_message_payload(sharedsecret: bytes, message: str) -> Tuple[str, str, str, str, str]:
    salt = os.urandom(32)
    key = hkdf_function(sharedsecret, salt=salt)
    (payload_ciphertext_b64, payload_tag_b64, payload_salt_b64, payload_nonce_b64) = encryptAESGCM(key, str2byte(message), human=False)
    return payload_ciphertext_b64, payload_tag_b64, payload_salt_b64, payload_nonce_b64, byte2b64(salt)

def decrypt_message_payload(sharedsecret: bytes, payload_ciphertext_b64: str, payload_tag_b64: str, payload_salt_b64: str, payload_nonce_b64: str, salt_b64: str) -> bytes:
    key = hkdf_function(sharedsecret, salt=b642byte(salt_b64))
    message = decryptAESGCM(key, payload_ciphertext_b64, payload_tag_b64, payload_salt_b64, payload_nonce_b64, human=False)
    return message