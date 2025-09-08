# oh boy oh boy here we go.
# api was 100x easier than this shit
# or atleast thats my speculation ofc

from link import * # custom lib for link/url control
from data import * # custom lib for file control

from fastapi import FastAPI, Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from pqcrypto.kem.ml_kem_512 import generate_keypair, encrypt, decrypt # kyber
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ed25519 # ed25519
from cryptography.hazmat.primitives import serialization # ed25519 shit
from argon2.low_level import hash_secret_raw, Type # argon2id for AES256GCM
from Crypto.Random import get_random_bytes # salt/nonce for AES256GCM
from typing import Tuple, Dict, Any, Union, Optional
from pydantic import BaseModel
from Crypto.Cipher import AES # AES256GCM
import webbrowser
import requests # we gonna use this ALOT
import warnings
import secrets # for 256 bit key gen
import time

SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32
KDF_ITERATIONS = 100_000
TOKEN_BUFFER_TIME = 60 # get new token 60 seconds before expiration
BASEDIR = os.path.abspath(os.path.dirname(__file__))
STATICDIR = os.path.join(BASEDIR, "static")
TEMPLATESDIR = os.path.join(BASEDIR, "templates")

app = FastAPI()
app.mount("/static", StaticFiles(directory=STATICDIR), name="static")
templates = Jinja2Templates(directory=TEMPLATESDIR)

# === Schemas ===
class UserClassRegisterModel(BaseModel):
    username: str
    publickey_kyber: str
    publickey_ed25519: str

class MessageSendModel(BaseModel):
    messageid: str
    sender: str
    reciever: str
    sender_pk: str
    reciever_pk: str
    ciphertext: str
    payload: str

class MessageGetModel(BaseModel):
    messageid: str
    sendertoken: str

class MessageIDGENModel(BaseModel):
    sender: str
    sendertoken: str
    reciever: str
    update: bool

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

# === Token Management ===
def check_token_expiration(token: str) -> Optional[int]:
    try:
        headers = {"Authorization": f"Bearer {token}"}
        r = requests.get(APIURL + AUTH_PROTECTED, headers=headers)
        if r.status_code == 200:
            response = r.json()
            return response.get("exp")
        return None
    except:
        return None

def is_token_expiring_soon(token: str) -> bool:
    exp_time = check_token_expiration(token)
    if exp_time is None:
        return True
    return time.time() + TOKEN_BUFFER_TIME >= exp_time

def ensure_valid_token(user_data: Dict[str, Any], current_token: str = None) -> str: # pyright: ignore[reportArgumentType]
    if current_token and not is_token_expiring_soon(current_token):
        return current_token
    token_data = create_token(user_data)
    return token_data["tokens"]["access_token"]

def make_authenticated_request(method: str, url: str, user_data: Dict[str, Any], current_token: str = None, **kwargs) -> requests.Response: # pyright: ignore[reportArgumentType]
    token = ensure_valid_token(user_data, current_token)
    headers = kwargs.get('headers', {})
    headers["Authorization"] = f"Bearer {token}"
    kwargs['headers'] = headers
    if method.upper() == 'GET':
        response = requests.get(url, **kwargs)
    elif method.upper() == 'POST':
        response = requests.post(url, **kwargs)
    else:
        raise ValueError(f"Unsupported HTTP method: {method}")
    if response.status_code == 401:
        print("Token failed or expired. Forcing a new token and retrying once...")
        fresh_token = ensure_valid_token(user_data, None) # pyright: ignore[reportArgumentType]
        headers["Authorization"] = f"Bearer {fresh_token}"
        kwargs['headers'] = headers
        if method.upper() == 'GET':
            response = requests.get(url, **kwargs)
        elif method.upper() == 'POST':
            response = requests.post(url, **kwargs)
    return response

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
    sig = respond_challenge(userdata, challenge) # pass only the string
    tokens = get_token(userdata["username"], cid, sig)
    r = requests.get(APIURL + AUTH_PROTECTED, headers={"Authorization": f"Bearer {tokens['access_token']}"}).json()
    data = {
        "tokens": tokens,
        "exp": r["exp"]
    }
    return data

# === Messaging Functions ===
def _derive_symmetric_key(shared_secret_bytes: bytes, info: bytes = b"psm-session-key") -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32, # 256-bit key for ChaCha20-Poly1305
        salt=None, # optional; None is fine, but i will supply a per-session salt in the payload or something idk
        info=info,
    )
    return hkdf.derive(shared_secret_bytes)

def encapsulate_shared_secret(receiver_public_key_b64: str) -> Tuple[str, str]:
    pk = b642byte(receiver_public_key_b64)
    ct, ss = encrypt(pk)
    return byte2b64(ct), byte2b64(ss)

def decapsulate_shared_secret(private_key_bytes: bytes, ciphertext_b64: str) -> str:
    ct = b642byte(ciphertext_b64)
    ss = decrypt(private_key_bytes, ct)
    return byte2b64(ss)

def get_user_info(username: str, user_data: Dict[str, Any], token: str = None) -> Dict[str, Any]: # pyright: ignore[reportArgumentType]
    r = make_authenticated_request("GET", APIURL + GET_USER + username, user_data, token)
    r.raise_for_status()
    return r.json()

def generate_message_id(sender: str, receiver: str, user_data: Dict[str, Any], token: str = None, update: bool = True) -> str: # pyright: ignore[reportArgumentType]
    data = {
        "sender": sender,
        "reciever": receiver,
        "update": update
    }
    r = make_authenticated_request("GET", APIURL + MSG_GET_ID, user_data, token, params=data)
    r.raise_for_status()
    response = r.json()
    if not response.get("ok"):
        raise RuntimeError(f"Failed to generate message ID: {response}")
    return response["msgid"]

def create_shared_secret(sender_private_key: bytes, receiver_public_key: str) -> str:
    receiver_public_key_bytes = b642byte(receiver_public_key)
    shared_secret = decrypt(sender_private_key, receiver_public_key_bytes)
    return byte2b64(shared_secret)

def encrypt_message_payload(message: str, shared_secret_b64: str) -> str:
    shared_secret_bytes = b642byte(shared_secret_b64)
    key = _derive_symmetric_key(shared_secret_bytes)
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = aead.encrypt(nonce, message.encode("utf-8"), associated_data=None)
    combined = nonce + ciphertext
    return base64.b64encode(combined).decode("utf-8")

def decrypt_message_payload(encrypted_payload_b64: str, shared_secret_b64: str) -> str:
    shared_secret_bytes = b642byte(shared_secret_b64)
    key = _derive_symmetric_key(shared_secret_bytes)
    combined = base64.b64decode(encrypted_payload_b64)
    nonce = combined[:12]
    ciphertext = combined[12:]
    aead = ChaCha20Poly1305(key)
    plaintext = aead.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext.decode("utf-8")

def send_message(sender_data: Dict[str, Any], receiver_username: str, payload: str, token: str = None) -> Dict[str, Any]: # pyright: ignore[reportArgumentType]
    receiver_info = get_user_info(receiver_username, sender_data, token)
    if not receiver_info.get("ok"):
        raise RuntimeError(f"Failed to get receiver info: {receiver_info}")
    receiver_public_key = receiver_info["data"]["publickey_kyber"]
    message_id = generate_message_id(sender_data["username"], receiver_username, sender_data, token)
    ciphertext_b64, shared_secret_b64 = encapsulate_shared_secret(receiver_public_key)
    encrypted_payload = encrypt_message_payload(payload, shared_secret_b64)
    msg_data = {
        "messageid": message_id,
        "sender": sender_data["username"],
        "sendertoken": token,
        "reciever": receiver_username,
        "sender_pk": sender_data["publickey_kyber_b64"],
        "reciever_pk": receiver_public_key,
        "ciphertext": ciphertext_b64,
        "payload": encrypted_payload
    }
    r = make_authenticated_request("POST", APIURL + MSG_SEND, sender_data, token, json=msg_data)
    r.raise_for_status()
    response = r.json()
    if not response.get("ok"):
        raise RuntimeError(f"Failed to send message: {response}")
    return {
        "message_id": message_id,
        "status": "sent",
        "timestamp": response.get("timestamp"),
        "token_exp": response.get("tokenexp"),
        "sender": sender_data["username"],
        "reciever": receiver_username,
        "sender_pk": sender_data["publickey_kyber_b64"],
        "reciever_pk": receiver_public_key,
        "payload": payload
    }

def send_message_persistent_storage(userdata: Dict[str, Any], sender_data: Dict[str, Any], receiver_username: str, message: str, token: str = None) -> Dict[str, Any]: # pyright: ignore[reportArgumentType]
    send_data = send_message(sender_data, receiver_username, message, token)
    b64kyberprivate = byte2b64(userdata["privatekey_kyber"])
    payload = encrypt_message_payload(send_data["payload"], b64kyberprivate) # this does feel cursed to do...
    send_data["payload"] = payload
    messagefp = os.path.join(MESSAGEDIR, f"{send_data['message_id']}-msg-V1-CLIENT.json")
    writejson(messagefp, send_data)
    return {
        "message_id": send_data["message_id"],
        "status": "sent",
        "timestamp": send_data["timestamp"],
        "token_exp": send_data["token_exp"],
        "sender": sender_data["username"],
        "reciever": receiver_username
    }

def get_message(message_id: str, user_data: Dict[str, Any], token: str = None) -> Dict[str, Any]: # pyright: ignore[reportArgumentType]
    params = {"sendertoken": token}
    r = requests.get(APIURL + MSG_GET + message_id, params=params)
    r.raise_for_status()
    response = r.json()
    if not response.get("ok"):
        raise RuntimeError(f"Failed to get message: {response}")
    m = response["message"]
    if m["reciever"] != user_data["username"]:
        # sender is trying to get this text, so we gonna use the existing one
        messagefp = os.path.join(MESSAGEDIR, f"{message_id}-msg-V1-CLIENT.json")
        local_send_data = readjson(messagefp)
        b64kyberprivate = byte2b64(user_data["privatekey_kyber"])
        plaintext = decrypt_message_payload(local_send_data["payload"], b64kyberprivate)
        return {
            "message_id": local_send_data["message_id"],
            "sender": local_send_data["sender"],
            "receiver": local_send_data["reciever"],
            "message": plaintext,
            "timestamp": local_send_data["timestamp"],
            "token_exp": local_send_data["token_exp"]
        }
    else:
        ciphertext_b64 = m["ciphertext"]
        shared_secret_b64 = decapsulate_shared_secret(user_data["privatekey_kyber"], ciphertext_b64)
        plaintext = decrypt_message_payload(m["payload"], shared_secret_b64)
        return {
            "message_id": m["messageid"],
            "sender": m["sender"],
            "receiver": m["reciever"],
            "message": plaintext,
            "timestamp": m.get("timestamp"),
            "token_exp": response.get("tokenexp")
        }

# === client web server ===
@app.get("/", response_class=HTMLResponse)
async def homeUI(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "version": VERSION})

@app.get("/login", response_class=HTMLResponse)
async def loginUI(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login-send")
async def login_send(username: str = Form(...), password: str = Form(...)):
    # for now just gonna return the info
    return {"username": username, "password": password}

if __name__ == "__main__":
    import uvicorn
    port = 8080
    uvicorn.run(app, host="0.0.0.0", port=port)
    webbrowser.open_new(f"http://localhost:{port}")

# === testing ===
if __name__ == "__main__":
    # Test user creation and loading
    try:
        udc = create_user("john", "super-secret-password!")
        print("User created successfully")
        print(f"Username: {udc['username']}")
        print(f"Public Key (Kyber): {udc['publickey_kyber_b64']}...")
        print("\n"*2)
    except Exception as e:
        print(f"User creation error: {e}")
    try:
        udc = create_user("alice", "super-secret-password!")
        print("User created successfully")
        print(f"Username: {udc['username']}")
        print(f"Public Key (Kyber): {udc['publickey_kyber_b64'][:50]}...")
        print("\n"*2)
    except Exception as e:
        print(f"User creation error: {e}")

    try:
        udl = load_user("john", "super-secret-password!")
        print("User loaded successfully")
        print(f"Username: {udl['username']}")
        print(f"User Type: {udl['usertype']}")
        
        # Test token creation
        tok = create_token(udl)
        print(f"Token created successfully")
        print(f"Token expires at: {tok['exp']}")
        print("\n"*2)
        
        # Test messaging workflow with automatic token management
        print("Testing messaging workflow with automatic token management...")
        try:
            user_data = load_user("john", "super-secret-password!")
            token_data = create_token(user_data)
            token = token_data["tokens"]["access_token"]
            print(f"Authenticated as: {user_data['username']}")
            print(f"Initial token expires at: {token_data['exp']}")
            receiver = "alice"
            message = "Hello Alice! This is an encrypted message with automatic token management."
            print(f"\nSending message to {receiver}...")
            send_result = send_message(user_data, receiver, message, token)
            print(f"Message sent! ID: {send_result['message_id']}")
            print(f"Token expires at: {send_result['token_exp']}")
            print(f"\nRetrieving message {send_result['message_id']}...")
            alice_data = load_user("alice", "super-secret-password!")
            alice_token_data = create_token(alice_data)
            alice_token = alice_token_data["tokens"]["access_token"]
            retrieved_message = get_message(send_result['message_id'], alice_data, alice_token)
            print(f"Retrieved message: {retrieved_message['message']}")
            print(f"From: {retrieved_message['sender']}")
            print(f"Timestamp: {retrieved_message['timestamp']}")
            print(f"\nChecking token expiration...")
            exp_time = check_token_expiration(token)
            if exp_time:
                print(f"Token expires at: {exp_time}")
                print(f"Will expire soon: {is_token_expiring_soon(token)}")
            else:
                print("Token is invalid")
        except Exception as e:
            print(f"Error in messaging workflow: {e}")
        
    except Exception as e:
        print(f"User loading/messaging error: {e}")
