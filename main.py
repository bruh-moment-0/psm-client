# oh boy oh boy here we go.
# api was 100x easier than this shit
# or atleast thats my speculation ofc

from link import * # custom lib for link/url control
from data import * # custom lib for file control

from pqcrypto.kem.ml_kem_512 import generate_keypair, encrypt, decrypt # kyber
from cryptography.hazmat.primitives.asymmetric import ed25519 # ed25519
from cryptography.hazmat.primitives import serialization # ed25519 shit
from argon2.low_level import hash_secret_raw, Type # argon2id for AES256GCM
from Crypto.Random import get_random_bytes # salt/nonce for AES256GCM
from typing import Tuple, Dict, Any, Union
from pydantic import BaseModel
from Crypto.Cipher import AES # AES256GCM
import requests # we gonna use this ALOT
import secrets # for 256 bit key gen
import time

SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32
KDF_ITERATIONS = 100_000

# === Schemas ===
class UserClassRegisterModel(BaseModel):
    username: str
    publickey_kyber: str
    publickey_ed25519: str

# === Functions ===
def post(url: str, json: Dict[str, Any]) -> Dict[str, Any]:
    return requests.post(url, json=json).json()

def get(url: str) -> Dict[str, Any]:
    return requests.get(url).json()

# === Cryptography ===
def keygen(length_bytes: int = 32) -> str:
    key_bytes = secrets.token_bytes(length_bytes)
    return base64.b64encode(key_bytes).decode("utf-8")

def keydecode(key_b64: str) -> bytes:
    return base64.b64decode(key_b64)

def _to_bytes(s: str | bytes) -> bytes:
    return s.encode("utf-8") if isinstance(s, str) else s

def encryptAESGCM(data: str, password: Union[str, bytes]) -> Tuple[str, str, str]:
    salt = get_random_bytes(SALT_LENGTH)
    nonce = get_random_bytes(NONCE_LENGTH)
    key = hash_secret_raw(
        secret=_to_bytes(password),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=KEY_LENGTH,
        type=Type.ID,
    )
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode("utf-8"))
    blob = ciphertext + tag
    return (
        base64.b64encode(blob).decode(),
        base64.b64encode(salt).decode(),
        base64.b64encode(nonce).decode(),
    )

def decryptAESGCM(blob_b64: str, password: Union[str, bytes], salt_b64: str, nonce_b64: str) -> str:
    blob = base64.b64decode(blob_b64)
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    key = hash_secret_raw(
        secret=_to_bytes(password),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=KEY_LENGTH,
        type=Type.ID,
    )
    tag = blob[-16:]
    ct = blob[:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode("utf-8")

# === Helpers ===
def create_skey(username: str, password: str) -> str:
    key = keygen()
    blob, salt, iv = encryptAESGCM(key, password)
    data = {
        "username": username,
        "enc": {
            "blob": blob,
            "salt": salt,
            "iv": iv
        },
        "app": "psm-client",
        "type": "skey",
        "ver": VERSION,
        "stamp": time.time()
    }
    writejson(os.path.join(USERDIR, f"{username}_client-V1.skey.json"), data)
    return key

def create_user(username: str, password: str) -> Dict[str, Any]:
    if os.path.exists(os.path.join(USERDIR, f"{username}_client-V1.skey.json")) and os.path.exists(os.path.join(USERDIR, f"{username}_client-V1.json")):
        raise RuntimeError(f"registration failed: user exists on the clients storage")
    key = keydecode(create_skey(username, password))
    publickey_kyber, privatekey_kyber = generate_keypair()
    privatekey_ed25519 = ed25519.Ed25519PrivateKey.generate()
    publickey_ed25519 = privatekey_ed25519.public_key()
    privatekey_ed25519_b64 = byte2b64(privatekey_ed25519.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()))
    privatekey_kyber_b64 = byte2b64(privatekey_kyber)
    (privatekey_ed25519_b64_blob, privatekey_ed25519_b64_salt, privatekey_ed25519_b64_nonce) = encryptAESGCM(privatekey_ed25519_b64, key)
    (privatekey_kyber_b64_blob, privatekey_kyber_b64_salt, privatekey_kyber_b64_nonce) = encryptAESGCM(privatekey_kyber_b64, key)
    data = {
        "username": username,
        "privatekey_ed25519": {
            "blob": privatekey_ed25519_b64_blob,
            "salt": privatekey_ed25519_b64_salt,
            "nonce": privatekey_ed25519_b64_nonce,
        },
        "publickey_ed25519": byte2b64(publickey_ed25519.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)),
        "privatekey_kyber": {
            "blob": privatekey_kyber_b64_blob,
            "salt": privatekey_kyber_b64_salt,
            "nonce": privatekey_kyber_b64_nonce,
        },
        "publickey_kyber": byte2b64(publickey_kyber),
        "skeypath": os.path.join(USERDIR, f"{username}_client-V1.skey.json")
    }
    u = UserClassRegisterModel(username=username, publickey_kyber=data["publickey_kyber"], publickey_ed25519=data["publickey_ed25519"])
    resp = post(APIURL + AUTH_REGISTER, u.model_dump())
    if not resp.get("ok"):
        raise RuntimeError(f"registration failed: {resp}")
    resp = get(APIURL + GET_USER + username)
    if not resp.get("ok"):
        raise RuntimeError(f"registration failed: {resp}")
    data["ver"] = resp["data"]["ver"]
    data["usertype"] = resp["data"]["usertype"]
    data["creation"] = resp["data"]["creation"]
    writejson(os.path.join(USERDIR, f"{username}_client-V1.json"), data)
    data["privatekey_ed25519_obj"] = privatekey_ed25519 # pyright: ignore[reportArgumentType]
    data["publickey_ed25519_obj"] = publickey_ed25519 # pyright: ignore[reportArgumentType]
    return data

"""
def load_user(username: str) -> Dict[str, Any]:
    with open(os.path.join(USERDIR, f"{username}_client-V1.json"), "r") as f:
        data = json.load(f)
    data = {
        "priv_obj": ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["private_key"])),
        "pub_obj": ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(data["public_key"]))
    }
    return data
"""

print(create_user("john", "super-secret-password!"))