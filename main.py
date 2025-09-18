# oh boy oh boy here we go.
# api was 100x easier than this shit
# or atleast thats my speculation ofc

from link import * # custom lib for link/url control
from data import * # custom lib for file control

from fastapi import FastAPI, Request, HTTPException, Form, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 # main encryption
from pqcrypto.kem.ml_kem_512 import generate_keypair, encrypt, decrypt # kyber
from cryptography.hazmat.primitives.asymmetric import ed25519 # ed25519
from cryptography.hazmat.primitives import serialization # ed25519 shit
from cryptography.hazmat.primitives.kdf.hkdf import HKDF # to do something i forgot right now
from typing import Tuple, Dict, Any, Union, Optional # making pylance happy i guess
from argon2.low_level import hash_secret_raw, Type # argon2id for AES256GCM
from cryptography.hazmat.primitives import hashes # hkdf stuff
from Crypto.Random import get_random_bytes # salt/nonce for AES256GCM

from pydantic import BaseModel
from urllib.parse import quote # to make text url friendly
from Crypto.Cipher import AES # AES256GCM
import webbrowser # to open the webbrowser
import requests # we gonna use this ALOT
import warnings
import secrets # for 256 bit key gen
import socket
import time

# importing the whole pypi ass

SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32
KDF_ITERATIONS = 100_000
TOKEN_BUFFER_TIME = 60 # get new token 60 seconds before expiration
BASEDIR = os.path.abspath(os.path.dirname(__file__))
STATICDIR = os.path.join(BASEDIR, "static")
TEMPLATESDIR = os.path.join(BASEDIR, "templates")

# i have no idea what these do but they make shit work so yes yes
scrolled_text_data: list[dict] = [] # shared buffer
connections: list[WebSocket] = [] # connected clients

userdat = None
tok = None
app = FastAPI()
app.mount("/static", StaticFiles(directory=STATICDIR), name="static")
templates = Jinja2Templates(directory=TEMPLATESDIR)

# === Functions ===
def messageformatter(username: str, message: str, timestamp: str) -> dict:
    try:
        dt = datetime.datetime.fromisoformat(timestamp)
        formatted = f"[{dt.strftime('%d/%m/%Y %H:%M:%S')}] {username} > {message}"
    except:
        dt = 0
        formatted = "null"
    return {"timestamp": dt, "formatted": formatted}

# === Schemas ===
class UserClassRegisterModel(BaseModel):
    username: str
    publickey_kyber: str
    publickey_ed25519: str

class MessageSendModel(BaseModel):
    messageid: str
    sender: str
    receiver: str
    sender_pk: str
    receiver_pk: str
    ciphertext: str
    payload: str
    sendertoken: str

class MessageGetModel(BaseModel):
    messageid: str
    sendertoken: str

class MessageIDGENModel(BaseModel):
    sender: str
    sendertoken: str
    receiver: str
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

def _derive_symmetric_key(shared_secret_bytes: bytes, info: bytes = b"psm-session-key") -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32, # 256-bit key for ChaCha20-Poly1305
        salt=None, # optional; None is fine, but i will supply a per-session salt in the payload or something idk
        # this shit lowkey sucks ass but i have gotten so far to give up now
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

def ensure_valid_token(userdata: Dict[str, Any], current_token: str = None) -> str: # pyright: ignore[reportArgumentType]
    if current_token and not is_token_expiring_soon(current_token):
        return current_token
    token_data = create_token(userdata)
    return token_data["tokens"]["access_token"]

def make_authenticated_request(method: str, url: str, userdata: Dict[str, Any], current_token: str = None, **kwargs) -> requests.Response: # pyright: ignore[reportArgumentType]
    token = ensure_valid_token(userdata, current_token)
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
        fresh_token = ensure_valid_token(userdata, None) # pyright: ignore[reportArgumentType]
        headers["Authorization"] = f"Bearer {fresh_token}"
        kwargs['headers'] = headers
        if method.upper() == 'GET':
            response = requests.get(url, **kwargs)
        elif method.upper() == 'POST':
            response = requests.post(url, **kwargs)
    return response

def get_challenge(username):
    r = requests.post(APIURL + AUTH_CHALLENGE, json={"username": username})
    r.raise_for_status()
    j = r.json()
    return j["challenge_id"], j["challenge"]

def respond_challenge(user, challenge_str: str):
    sig_bytes = user["user"]['privatekey_ed25519_obj'].sign(challenge_str.encode())
    return base64.b64encode(sig_bytes).decode()

def get_token(username, challenge_id, signature):
    r = requests.post(APIURL + AUTH_RESPOND, json={
        "username": username,
        "challenge_id": challenge_id,
        "signature": signature
    })
    r.raise_for_status()
    return r.json()

def create_token(userdata: Dict[str, Any]):
    cid, challenge = get_challenge(userdata["user"]["username"])
    sig = respond_challenge(userdata, challenge) # pass only the string
    tokens = get_token(userdata["user"]["username"], cid, sig)
    r = requests.get(APIURL + AUTH_PROTECTED, headers={"Authorization": f"Bearer {tokens['access_token']}"}).json()
    data = {
        "tokens": tokens,
        "exp": r["exp"]
    }
    return data

# === Helpers ===
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
    try:
        return decryptAESGCM(data["enc"]["blob"], password, data["enc"]["salt"], data["enc"]["nonce"])
    except Exception as e:
        raise RuntimeError(f"decryption failed: {e}, password might be wrong or file might be corrupted")

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
        "user": {
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
        },
        "messages": {}
    }
    u = UserClassRegisterModel(username=username, publickey_kyber=data["publickey_kyber_b64"], publickey_ed25519=data["publickey_ed25519_b64"])
    resp = requests.post(APIURL + AUTH_REGISTER, json=u.model_dump()).json()
    if not resp.get("ok"):
        raise RuntimeError(f"registration failed: {resp}")
    resp = requests.get(APIURL + GET_USER + username).json()
    if not resp.get("ok"):
        raise RuntimeError(f"registration failed: {resp}")
    data["user"]["ver"] = VERSION
    data["user"]["usertype"] = resp["data"]["usertype"]
    data["user"]["creation"] = resp["data"]["creation"]
    writejson(os.path.join(USERDIR, f"{username}_client-V1.json"), data)
    data["user"]["privatekey_ed25519_obj"] = privatekey_ed25519 # pyright: ignore[reportArgumentType]
    data["user"]["publickey_ed25519_obj"] = publickey_ed25519 # pyright: ignore[reportArgumentType]
    return data

def load_user(username: str, password: str) -> Dict[str, Any]:
    if not os.path.exists(os.path.join(USERDIR, f"{username}_client-V1.skey.json")) or not os.path.exists(os.path.join(USERDIR, f"{username}_client-V1.json")):
        raise RuntimeError("loading failed: clients files dont exist on the clients storage")
    key = load_skey(username, password)
    data = readjson(os.path.join(USERDIR, f"{username}_client-V1.json"))
    if data["user"]["ver"] != VERSION:
        warnings.warn("skey load warn: app version mismatch", RuntimeWarning)
    privatekey_ed25519_b64 = decryptAESGCM(data["user"]["privatekey_ed25519_enc"]["blob"], keydecode(key), data["user"]["privatekey_ed25519_enc"]["salt"], data["user"]["privatekey_ed25519_enc"]["nonce"])
    privatekey_kyber_b64 = decryptAESGCM(data["user"]["privatekey_kyber_enc"]["blob"], keydecode(key), data["user"]["privatekey_kyber_enc"]["salt"], data["user"]["privatekey_kyber_enc"]["nonce"])
    publickey_ed25519 = data["user"]["publickey_ed25519_b64"]
    publickey_kyber = data["user"]["publickey_kyber_b64"]
    resp = requests.get(APIURL + GET_USER + username).json()
    if not resp.get("ok"):
        raise RuntimeError(f"loading failed: {resp}")
    data["user"]["privatekey_ed25519_obj"] = ed25519.Ed25519PrivateKey.from_private_bytes(b642byte(privatekey_ed25519_b64))
    data["user"]["publickey_ed25519_obj"] = ed25519.Ed25519PublicKey.from_public_bytes(b642byte(publickey_ed25519))
    data["user"]["privatekey_kyber"] = b642byte(privatekey_kyber_b64)
    data["user"]["publickey_kyber"] = b642byte(publickey_kyber)
    data["user"]["key"] = key
    return data

# === Messaging Functions ===
# > creates "Cryptography" header
# > puts messaging encryption uhnder a diffrent header
# shit ass programming time
# (update on 18/09/2025 fixed this shit ass programming skill issue)

def get_user_info(username: str, userdata: Dict[str, Any], token: str = None) -> Dict[str, Any]: # pyright: ignore[reportArgumentType]
    r = make_authenticated_request("GET", APIURL + GET_USER + username, userdata, token)
    r.raise_for_status()
    return r.json()

def generate_message_id(sender: str, receiver: str, userdata: Dict[str, Any], token: str = None, update: bool = True) -> str: # pyright: ignore[reportArgumentType]
    data = {
        "sender": sender,
        "receiver": receiver,
        "update": update
    }
    r = make_authenticated_request("GET", APIURL + MSG_GET_ID, userdata, token, params=data)
    r.raise_for_status()
    response = r.json()
    if not response.get("ok"):
        raise RuntimeError(f"Failed to generate message ID: {response}")
    return response["msgid"]

def send_message(userdata: Dict[str, Any], receiver_username: str, payload: str, token: str = None) -> Dict[str, Any]: # pyright: ignore[reportArgumentType]
    receiver_info = get_user_info(receiver_username, userdata, token)
    if not receiver_info.get("ok"):
        raise RuntimeError(f"Failed to get receiver info: {receiver_info}")
    receiver_public_key = receiver_info["data"]["publickey_kyber"]
    message_id = generate_message_id(userdata["user"]["username"], receiver_username, userdata, token)
    ciphertext_b64, shared_secret_b64 = encapsulate_shared_secret(receiver_public_key)
    encrypted_payload = encrypt_message_payload(payload, shared_secret_b64)
    msg_data = {
        "messageid": message_id,
        "sender": userdata["user"]["username"],
        "sendertoken": token,
        "receiver": receiver_username,
        "sender_pk": userdata["user"]["publickey_kyber_b64"],
        "receiver_pk": receiver_public_key,
        "ciphertext": ciphertext_b64,
        "payload": encrypted_payload
    }
    r = make_authenticated_request("POST", APIURL + MSG_SEND, userdata, token, json=msg_data)
    r.raise_for_status()
    response = r.json()
    if not response.get("ok"):
        raise RuntimeError(f"Failed to send message: {response}")
    return {
        "message_id": message_id,
        "status": "sent",
        "timestamp": response.get("timestamp"),
        "token_exp": response.get("tokenexp"),
        "sender": userdata["user"]["username"],
        "receiver": receiver_username,
        "sender_pk": userdata["user"]["publickey_kyber_b64"],
        "receiver_pk": receiver_public_key,
        "payload": payload,
        "shared_secret_b64_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT": shared_secret_b64 # i think this might be important gang :sob: :wilted-rose:
    }

# shit ass function name, how long even this shit is??
def send_message_persistent_storage(userdata: Dict[str, Any], receiver_username: str, message: str, token: str = None) -> Dict[str, Any]: # pyright: ignore[reportArgumentType]
    send_data = send_message(userdata, receiver_username, message, token)
    payload = encrypt_message_payload(send_data["payload"], send_data["shared_secret_b64_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT"]) # well this is cursed as shit... but it should work better than the older one!!!
    userkey = userdata["user"]["key"]
    userfile = os.path.join(USERDIR, f"{userdata['user']['username']}_client-V1.skey.json")
    userfiledata = readjson(userfile)
    (blob, salt, nonce) = encryptAESGCM(send_data["shared_secret_b64_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT"], userkey)
    # i mean we are buildidng in such way if the users "shared_secret_b64_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT" is exposed also the reciever is in danger
    # but wait, even if it gets leaked that message could be read by the attackers? so no needto use another key? also this is high entropy so shouldnt be a problem?
    # gang i might lowkey have no idea what the fucking shit i am doing bruh
    userfiledata["messages"][send_data['message_id']] = {
        "blob": blob,
        "salt": salt,
        "nonce": nonce
    }
    send_data["payload"] = payload
    messagefp = os.path.join(MESSAGEDIR, f"{send_data['message_id']}-msg-V1-CLIENT.json")
    writejson(userfile, userfiledata)
    writejson(messagefp, send_data)
    return {
        "message_id": send_data["message_id"],
        "status": "sent",
        "timestamp": send_data["timestamp"],
        "token_exp": send_data["token_exp"],
        "sender": userdata["user"]["username"],
        "receiver": receiver_username
    }

def get_message(message_id: str, userdata: Dict[str, Any], token: str = None) -> Dict[str, Any]: # pyright: ignore[reportArgumentType]
    params = {"sendertoken": token}
    r = requests.get(APIURL + MSG_GET + message_id, params=params)
    r.raise_for_status()
    response = r.json()
    if not response.get("ok"):
        raise RuntimeError(f"Failed to get message: {response}")
    m = response["message"]
    if m["receiver"] != userdata["user"]["username"]:
        # sender is trying to get this text, so we gonna use the existing one
        messagefp = os.path.join(MESSAGEDIR, f"{message_id}-msg-V1-CLIENT.json")
        userfile = os.path.join(USERDIR, f"{userdata['user']['username']}_client-V1.skey.json")
        userfiledata = readjson(userfile)
        userkey = userdata["user"]["key"]
        shared_secret_b64_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT = decryptAESGCM(userfiledata["messages"][message_id]["blob"], userkey, userfiledata["messages"][message_id]["salt"], userfiledata["messages"][message_id]["nonce"])
        # yes super optimized code best out there
        local_send_data = readjson(messagefp)
        plaintext = decrypt_message_payload(local_send_data["payload"], shared_secret_b64_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT)
        return {
            "message_id": local_send_data["message_id"],
            "sender": local_send_data["sender"],
            "receiver": local_send_data["receiver"],
            "message": plaintext,
            "timestamp": local_send_data["timestamp"],
            "token_exp": local_send_data["token_exp"]
        }
    else:
        ciphertext_b64 = m["ciphertext"]
        shared_secret_b64 = decapsulate_shared_secret(userdata["user"]["privatekey_kyber"], ciphertext_b64)
        plaintext = decrypt_message_payload(m["payload"], shared_secret_b64)
        return {
            "message_id": m["messageid"],
            "sender": m["sender"],
            "receiver": m["receiver"],
            "message": plaintext,
            "timestamp": m["timestamp"],
            "token_exp": response["tokenexp"]
        }

# === client web server shit ===
@app.exception_handler(RuntimeError)
async def runtime_error_exception_handler(request: Request, exc: RuntimeError):
    error_message = quote(str(exc))
    referer = request.headers.get("referer", "/")
    if "?" in referer:
        redirect_url = f"{referer}&error={error_message}"
    else:
        redirect_url = f"{referer}?error={error_message}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)

@app.get("/", response_class=HTMLResponse)
async def homeUI(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "version": VERSION})

@app.get("/login", response_class=HTMLResponse)
async def loginUI(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login-send")
async def login_send(username: str = Form(...), password: str = Form(...)):
    global userdat
    userdat = load_user(username, password)
    return RedirectResponse(url="/main", status_code=302)

@app.get("/register", response_class=HTMLResponse)
async def registerUI(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register-send")
async def register_send(username: str = Form(...), password: str = Form(...)):
    global userdat
    userdat = create_user(username, password)
    return RedirectResponse(url="/login", status_code=302)

@app.get("/main", response_class=HTMLResponse)
async def mainUI(request: Request):
    global userdat
    global tok
    if not userdat:
        return RedirectResponse(url="/login", status_code=302)
    if not tok:
        tok = create_token(userdat)
    return templates.TemplateResponse("main.html", {"request": request, "version": VERSION, "username": userdat["username"]})

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    global userdat
    global tok
    await ws.accept()
    connections.append(ws)
    # send initial contents
    await ws.send_json({"lines": [entry["formatted"] for entry in sorted(scrolled_text_data, key=lambda x: x["timestamp"])]}) # pyright: ignore[reportArgumentType]
    try:
        while True:
            jsondata = await ws.receive_json()
            action = jsondata.get("action")
            username = jsondata.get("username")
            message = jsondata.get("message", "")
            access_token_str = tok["tokens"]["access_token"]  # pyright: ignore[reportOptionalSubscript]
            if action == "send":
                messagedata = send_message_persistent_storage(userdat, username, message, access_token_str)  # pyright: ignore[reportArgumentType]
                if messagedata["status"] != "sent":
                    raise RuntimeError("message couldn't be sent")
                timestamp = messagedata["timestamp"]
                entry = messageformatter(userdat["username"], message, timestamp) # pyright: ignore[reportOptionalSubscript]
                scrolled_text_data.append(entry)
            elif action == "get":
                scrolled_text_data.clear()
                messageid = generate_message_id(userdat["username"], username, userdat, access_token_str, update=False)  # pyright: ignore[reportArgumentType, reportOptionalSubscript]
                counter = int(messageid.split("-")[1])
                usershash = messageid.split("-")[0]
                for msgnum in range(1, counter + 1):
                    msgid = f"{usershash}-{msgnum}"
                    messagedata = get_message(msgid, userdat, access_token_str)  # pyright: ignore[reportArgumentType]
                    plaintext = messagedata["message"]
                    sender = messagedata["sender"]
                    timestamp = messagedata["timestamp"]
                    print(timestamp)
                    entry = messageformatter(sender, plaintext, timestamp)
                    scrolled_text_data.append(entry)
            # sorting before sending
            sorted_lines = [entry["formatted"] for entry in sorted(scrolled_text_data, key=lambda x: x["timestamp"])] # pyright: ignore[reportArgumentType]
            for conn in connections:
                await conn.send_json({"lines": sorted_lines})
    except WebSocketDisconnect:
        connections.remove(ws)
        scrolled_text_data.clear()

def portused(port, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0

if __name__ == "__main__":
    import uvicorn
    port = 8080
    while portused(port):
        port += 1
    webbrowser.open_new(f"http://localhost:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port)