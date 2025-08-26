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
import warnings
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
def get_challenge(username):
    r = requests.post(APIURL + AUTH_CHALLENGE, json={"username": username})
    r.raise_for_status()
    j = r.json()
    return j["challenge_id"], j["challenge"]

def respond_challenge(user, challenge_str: str):
    sig_bytes = user['privatekey_ed25519_obj'].sign(challenge_str.encode())
    return base64.b64encode(sig_bytes).decode()

def get_token(username, challenge_id, signature):
    r = requests.post(APIURL + AUTH_RESPOND, json={
        "username": username,
        "challenge_id": challenge_id,
        "signature": signature
    })
    r.raise_for_status()
    return r.json()

def create_skey(username: str, password: str) -> str:
    key = keygen()
    blob, salt, nonce = encryptAESGCM(key, password)
    data = {
        "username": username,
        "enc": {
            "blob": blob,
            "salt": salt,
            "nonce": nonce
        },
        "app": "psm-client",
        "type": "skey",
        "ver": VERSION,
        "stamp": time.time()
    }
    writejson(os.path.join(USERDIR, f"{username}_client-V1.skey.json"), data)
    return key

def load_skey(username: str, password: str) -> str:
    data = readjson(os.path.join(USERDIR, f"{username}_client-V1.skey.json"))
    if data["app"] != "psm-client":
        raise RuntimeError(f"skey load failed: wrong app")
    if data["type"] != "skey":
        raise RuntimeError(f"skey load failed: wrong type")
    if data["ver"] != VERSION:
        warnings.warn("skey load warn: app version mismatch", RuntimeWarning)
    if time.time() - data["stamp"] > 60 * 60 * 24 * 14:
        warnings.warn("skey load warn: skey is older than 14 days", RuntimeWarning)
    return decryptAESGCM(data["enc"]["blob"], password, data["enc"]["salt"], data["enc"]["nonce"])

def create_user(username: str, password: str) -> Dict[str, Any]:
    if os.path.exists(os.path.join(USERDIR, f"{username}_client-V1.skey.json")) or os.path.exists(os.path.join(USERDIR, f"{username}_client-V1.json")):
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
        "privatekey_ed25519_enc": {
            "blob": privatekey_ed25519_b64_blob,
            "salt": privatekey_ed25519_b64_salt,
            "nonce": privatekey_ed25519_b64_nonce,
        },
        "publickey_ed25519_b64": byte2b64(publickey_ed25519.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)),
        "privatekey_kyber_enc": {
            "blob": privatekey_kyber_b64_blob,
            "salt": privatekey_kyber_b64_salt,
            "nonce": privatekey_kyber_b64_nonce,
        },
        "publickey_kyber_b64": byte2b64(publickey_kyber),
        "skeypath": os.path.join(USERDIR, f"{username}_client-V1.skey.json")
    }
    u = UserClassRegisterModel(username=username, publickey_kyber=data["publickey_kyber_b64"], publickey_ed25519=data["publickey_ed25519_b64"])
    resp = requests.post(APIURL + AUTH_REGISTER, json=u.model_dump()).json()
    if not resp.get("ok"):
        raise RuntimeError(f"registration failed: {resp}")
    resp = requests.get(APIURL + GET_USER + username).json()
    if not resp.get("ok"):
        raise RuntimeError(f"registration failed: {resp}")
    data["ver"] = VERSION
    data["usertype"] = resp["data"]["usertype"]
    data["creation"] = resp["data"]["creation"]
    writejson(os.path.join(USERDIR, f"{username}_client-V1.json"), data)
    data["privatekey_ed25519_obj"] = privatekey_ed25519 # pyright: ignore[reportArgumentType]
    data["publickey_ed25519_obj"] = publickey_ed25519 # pyright: ignore[reportArgumentType]
    return data

def load_user(username: str, password: str) -> Dict[str, Any]:
    if not os.path.exists(os.path.join(USERDIR, f"{username}_client-V1.skey.json")) or not os.path.exists(os.path.join(USERDIR, f"{username}_client-V1.json")):
        raise RuntimeError(f"loading failed: clients files dont exist on the clients storage")
    key = load_skey(username, password)
    data = readjson(os.path.join(USERDIR, f"{username}_client-V1.json"))
    if data["ver"] != VERSION:
        warnings.warn("skey load warn: app version mismatch", RuntimeWarning)
    privatekey_ed25519_b64 = decryptAESGCM(data["privatekey_ed25519_enc"]["blob"], keydecode(key), data["privatekey_ed25519_enc"]["salt"], data["privatekey_ed25519_enc"]["nonce"])
    privatekey_kyber_b64 = decryptAESGCM(data["privatekey_kyber_enc"]["blob"], keydecode(key), data["privatekey_kyber_enc"]["salt"], data["privatekey_kyber_enc"]["nonce"])
    publickey_ed25519 = data["publickey_ed25519_b64"]
    publickey_kyber = data["publickey_kyber_b64"]
    resp = requests.get(APIURL + GET_USER + username).json()
    if not resp.get("ok"):
        raise RuntimeError(f"loading failed: {resp}")
    data["privatekey_ed25519_obj"] = ed25519.Ed25519PrivateKey.from_private_bytes(b642byte(privatekey_ed25519_b64))
    data["publickey_ed25519_obj"] = ed25519.Ed25519PublicKey.from_public_bytes(b642byte(publickey_ed25519))
    data["privatekey_kyber"] = b642byte(privatekey_kyber_b64)
    data["publickey_kyber"] = b642byte(publickey_kyber)
    return data

def create_token(userdata: Dict[str, Any]):
    cid, challenge = get_challenge(userdata["username"])
    sig = respond_challenge(userdata, challenge)   # pass only the string
    tokens = get_token(userdata["username"], cid, sig)
    r = requests.get(APIURL + AUTH_PROTECTED, headers={"Authorization": f"Bearer {tokens['access_token']}"}).json()
    data = {
        "tokens": tokens,
        "exp": r["exp"]
    }
    return data

try:
    udc = create_user("john", "super-secret-password!")
    print(udc)
    print("\n"*5)
except Exception as e:
    print(f"error: {e}")

try:
    udl = load_user("john", "super-secret-password!")
    print(udl)
    print("\n"*5)
    tok = create_token(udl)
    print(tok)
except Exception as e:
    print(f"error: {e}")
