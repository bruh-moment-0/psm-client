# oh boy oh boy here we go.
# api was 100x easier than this shit
# or atleast thats my speculation ofc

# custom libs
from quantum import oqs, sign_obj_create, kem_obj_create, create_key_pair, sign, verify, encap, decap
from aes256 import keygen, encryptAESGCM, decryptAESGCM # AES256-GCM custom lib
from link import * # custom lib for link/url control
from data import * # custom lib for file control

from fastapi import FastAPI, Request, HTTPException, Form, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from cryptography.hazmat.primitives.kdf.hkdf import HKDF # to do something i forgot right now
from typing import Tuple, Dict, Any, Optional # making pylance happy i guess
from cryptography.hazmat.primitives import hashes # hkdf stuff

from pydantic import BaseModel
from urllib.parse import quote # to make text url friendly

from urllib.parse import urlparse
import webbrowser # to open the webbrowser
import requests # we gonna use this ALOT
import datetime
import warnings
import socket
import time

# importing the whole pypi ass

if NOTREADY:
    print("code is NOTREADY for usage for now, due to security concerns. please use an older version until this version is fixed.")
    print("issue: get persistent writes shared secret")
    print(f"current version: {VERSION}")
    print("reminder, THIS FAILSAFE ONLY ACTIVATES IF THERE IS A BIG SECURITY PROBLEM!!!")
    # exit(1)


KDF_ITERATIONS = 100_000
TOKEN_BUFFER_TIME = 60 # get new token 60 seconds before expiration
BASEDIR = os.path.abspath(os.path.dirname(__file__))
STATICDIR = os.path.join(BASEDIR, "static")
TEMPLATESDIR = os.path.join(BASEDIR, "templates")

# i have no idea what these do but they make shit work so yes yes
tok: Optional[Dict[str, Any]] = None # token
scrolled_text_data: list[dict] = [] # shared buffer
connections: list[WebSocket] = [] # connected clients

userdat = None
tok = None
app = FastAPI()
app.mount("/static", StaticFiles(directory=STATICDIR), name="static")
templates = Jinja2Templates(directory=TEMPLATESDIR)

# === Functions ===
def messageformatter(username: str, message: str, timestamp: str, timezone: int) -> dict:
    try:
        dt = datetime.datetime.fromisoformat(timestamp)
        dt = dt + datetime.timedelta(hours=timezone)
        formatted = f"[{dt.strftime('%d/%m/%Y %H:%M:%S')}] {username} > {message}"
    except Exception as e:
        dt = datetime.datetime.min
        formatted = f"[unknown-time] {username} > {message}"
        warnings.warn(f"WARNING: sorting failed on 'messageformatter': {e}, data: {username} {message} {timestamp}")
    return {"timestamp": dt, "formatted": formatted}

# === Schemas ===
class MessageSendModel(BaseModel):
    messageid: str
    sender: str
    receiver: str
    sender_pk: str
    receiver_pk: str
    ciphertext: str
    payload_ciphertext: str
    payload_tag: str
    payload_salt: str
    payload_nonce: str
    sendertoken: str
    hkdfsalt: str

class MessageGetModel(BaseModel):
    messageid: str
    sendertoken: str

class MessageIDGENModel(BaseModel):
    sender: str
    sendertoken: str
    receiver: str
    update: bool

class UserClassModel(BaseModel):
    username: str
    publickey_kyber: str
    publickey_token: str
    publickey_connection: str

class TokenStart(BaseModel):
    username: str

class TokenFinish(BaseModel):
    username: str
    challenge_id: str
    signature: str

class UserClassRegisterModel(BaseModel):
    username: str
    publickey_kyber: str
    publickey_token: str
    publickey_connection: str

# === Cryptography ===
def _derive_symmetric_key(shared_secret_bytes: bytes, salt: bytes, info: bytes = b"psm-session-key") -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32, # 256-bit key for ChaCha20-Poly1305
        salt=salt, # salt is added
        # this shit lowkey sucks ass but i have gotten so far to give up now
        info=info,
    )
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
    key = _derive_symmetric_key(sharedsecret, salt=salt)
    (payload_ciphertext_b64, payload_tag_b64, payload_salt_b64, payload_nonce_b64) = encryptAESGCM(key, str2byte(message), human=False)
    return payload_ciphertext_b64, payload_tag_b64, payload_salt_b64, payload_nonce_b64, byte2b64(salt)

def decrypt_message_payload(sharedsecret: bytes, payload_ciphertext_b64: str, payload_tag_b64: str, payload_salt_b64: str, payload_nonce_b64: str, salt_b64: str) -> bytes:
    key = _derive_symmetric_key(sharedsecret, salt=b642byte(salt_b64))
    message = decryptAESGCM(key, payload_ciphertext_b64, payload_tag_b64, payload_salt_b64, payload_nonce_b64, human=False)
    return message

# === Token Management ===
def connection_signer_header(userdata: Dict[str, Any], method: str, url: str, body_dict: dict) -> str:
    # create signature for X-Connection-Signature header
    if not userdata or not userdata.get("ram", {}).get("connection_sign_obj"):
        return "None"
    parsed = urlparse(url)
    path = parsed.path
    # create deterministic signing payload
    sign_payload = {
        "method": method.upper(),
        "path": path,
        "body": body_dict
    }
    connection_signer = userdata["ram"]["connection_sign_obj"]
    sign_str = json.dumps(sign_payload, sort_keys=True, separators=(',', ':'))
    signature = byte2b64(sign(connection_signer, str2byte(sign_str)))
    return signature

def make_request(userdata: Dict[str, Any], method: str, url: str, **kwargs) -> requests.Response:
    headers = kwargs.pop('headers', {}).copy()
    body_dict = kwargs.get('json', {})
    if body_dict:  # sign if there's a body
        signature = connection_signer_header(userdata, method, url, body_dict)
        headers['X-Connection-Signature'] = signature
    kwargs['headers'] = headers
    response = requests.request(method.upper(), url, **kwargs)
    response.raise_for_status()
    return response

def check_tokenexpiration(userdata, token: str) -> Optional[int]:
    try:
        headers = {"Authorization": f"Bearer {token}"}
        r = make_request(userdata, "GET", APIURL + AUTH_PROTECTED, headers=headers)
        if r.status_code == 200:
            response = r.json()
            return response.get("exp")
        return None
    except:
        return None

def is_tokenexpiring_soon(userdata, token: str) -> bool:
    exp_time = check_tokenexpiration(userdata, token)
    if exp_time is None:
        return True
    return time.time() + TOKEN_BUFFER_TIME >= exp_time

def ensure_valid_token(userdata: Dict[str, Any], current_token: str = None) -> str: # pyright: ignore[reportArgumentType]
    global tok
    if current_token and not is_tokenexpiring_soon(userdata, current_token):
        return current_token
    tok = create_token(userdata) # UPDATE GLOBAL TOK HERE
    return tok["tokens"]["access_token"]

def make_authenticated_request(method: str, url: str, userdata: Dict[str, Any], current_token: str = None, **kwargs) -> requests.Response: # pyright: ignore[reportArgumentType]
    global tok
    token = ensure_valid_token(userdata, current_token)
    headers = kwargs.get('headers', {})
    headers["Authorization"] = f"Bearer {token}"
    kwargs['headers'] = headers
    if method in ["GET", "POST"]:
        response = make_request(userdata, method, url, **kwargs)
    else:
        raise ValueError(f"Unsupported HTTP method: {method}")
    if response.status_code == 401:
        print("token failed or expired. forcing a new token and retrying once...")
        fresh_token = ensure_valid_token(userdata, None) # pyright: ignore[reportArgumentType]
        headers["Authorization"] = f"Bearer {fresh_token}"
        kwargs['headers'] = headers
        response = make_request(userdata, method, url, **kwargs)
    response.raise_for_status()
    return response

def get_current_token(userdata: Dict[str, Any]) -> str:
    global tok
    if not tok:
        tok = create_token(userdata)
        return tok["tokens"]["access_token"]
    current_token = tok["tokens"]["access_token"]
    return ensure_valid_token(userdata, current_token)

def get_challenge(userdata: Dict[str, Any], username: str)  -> Tuple[str, str]:
    response = make_request(userdata, "POST", url=APIURL+AUTH_CHALLENGE, json={"username": username}).json()
    return response["challenge_id"], response["challenge"]

def respond_challenge(userdata: Dict[str, Any], challenge_str: str):
    sign_obj = userdata["ram"]["sign_token_obj"]
    sig_bytes = sign(sign_obj, str2byte(challenge_str))
    return byte2b64(sig_bytes)

def get_token(userdata: Dict[str, Any], username: str, challenge_id, signature):
    return make_request(userdata, "POST", url=APIURL+AUTH_RESPOND, json={"username": username, "challenge_id": challenge_id, "signature": signature}).json()

def create_token(userdata: Dict[str, Any]) -> Dict[str, str]:
    cid, challenge = get_challenge(userdata, userdata["user"]["username"])
    sig = respond_challenge(userdata, challenge) # pass only the string
    tokens = get_token(userdata, userdata["user"]["username"], cid, sig)
    r = requests.get(APIURL + AUTH_PROTECTED, headers={"Authorization": f"Bearer {tokens['access_token']}"}).json()
    data = {
        "tokens": tokens,
        "exp": r["exp"]
    }
    return data

def create_skey(username: str, password: str) -> bytes:
    key = keygen()
    ciphertext, tag, salt, nonce = encryptAESGCM(password=password, data=key, human=True)
    data = {
        "username": username,
        "enc": {
            "ciphertext": ciphertext,
            "tag": tag,
            "salt": salt,
            "nonce": nonce
        },
        "app": "psm-client",
        "type": "skey",
        "ver": VERSION,
        "stamp": time.time()
    }
    writejson(os.path.join(USERDIR, f"{username}_client-V2.skey.json"), data)
    return key

def load_skey(username: str, password: str) -> bytes:
    data = readjson(os.path.join(USERDIR, f"{username}_client-V2.skey.json"))
    if data["app"] != "psm-client":
        raise RuntimeError(f"skey load failed: wrong app")
    if data["type"] != "skey":
        raise RuntimeError(f"skey load failed: wrong type")
    if data["ver"] != VERSION:
        warnings.warn("skey load warn: app version mismatch", RuntimeWarning)
    if time.time() - data["stamp"] > 60 * 60 * 24 * 14:
        warnings.warn("skey load warn: skey is older than 14 days", RuntimeWarning)
    try:
        return decryptAESGCM(password=password, ciphertext_b64=data["enc"]["ciphertext"], tag_b64=data["enc"]["tag"], salt_b64=data["enc"]["salt"], nonce_b64=data["enc"]["nonce"], human=True)
    except Exception as e:
        raise RuntimeError(f"decryption failed: {e}, password might be wrong or file might be corrupted")

def create_user(username: str, password: str, tz: int) -> Dict[str, Any]:
    if os.path.exists(os.path.join(USERDIR, f"{username}_client-V2.json")):
        raise RuntimeError(f"registration failed: user exists on the clients storage")
    key = create_skey(username, password)
    kemobj = kem_obj_create()
    signobjtoken = sign_obj_create()
    signobjconnection = sign_obj_create()
    publickey_kyber, privatekey_kyber = create_key_pair(kemobj)
    publickey_sign_token, privatekey_sign_token = create_key_pair(signobjtoken)
    publickey_sign_connection, privatekey_sign_connection = create_key_pair(signobjconnection)
    publickey_kyber_b64 = byte2b64(publickey_kyber)
    publickey_sign_token_b64 = byte2b64(publickey_sign_token)
    publickey_sign_connection_b64 = byte2b64(publickey_sign_connection)
    (privatekey_kyber_ciphertext, privatekey_kyber_tag, privatekey_kyber_salt, privatekey_kyber_nonce) = encryptAESGCM(key, privatekey_kyber, human=False)
    (privatekey_sign_token_ciphertext, privatekey_sign_token_tag, privatekey_sign_token_salt, privatekey_sign_token_nonce) = encryptAESGCM(key, privatekey_sign_token, human=False)
    (privatekey_sign_connection_ciphertext, privatekey_sign_connection_tag, privatekey_sign_connection_salt, privatekey_sign_connection_nonce) = encryptAESGCM(key, privatekey_sign_connection, human=False)
    u = UserClassRegisterModel(username=username, publickey_kyber=publickey_kyber_b64, publickey_token=publickey_sign_token_b64, publickey_connection=publickey_sign_connection_b64)
    response = make_request(userdata={}, method="POST", url=APIURL + AUTH_REGISTER, json=u.model_dump()).json()
    if not response.get("ok"):
        raise RuntimeError(f"registration failed: {response}")
    response = requests.get(APIURL + GET_USER + username).json()
    if not response.get("ok"):
        raise RuntimeError(f"registration failed: {response}")
    data = {
        "user": {
            "username": username,
            "ver": VERSION,
            "usertype": response["data"]["usertype"],
            "creation": response["data"]["creation"],
            "tz": tz,
            "keys": {
                "publickey_kyber_b64": publickey_kyber_b64,
                "publickey_sign_token_b64": publickey_sign_token_b64,
                "publickey_sign_connection_b64": publickey_sign_connection_b64,
                "privatekey_kyber": {
                    "ciphertext": privatekey_kyber_ciphertext,
                    "tag": privatekey_kyber_tag,
                    "salt": privatekey_kyber_salt,
                    "nonce": privatekey_kyber_nonce
                },
                "privatekey_sign_token": {
                    "ciphertext": privatekey_sign_token_ciphertext,
                    "tag": privatekey_sign_token_tag,
                    "salt": privatekey_sign_token_salt,
                    "nonce": privatekey_sign_token_nonce
                },
                "privatekey_sign_connection": {
                    "ciphertext": privatekey_sign_connection_ciphertext,
                    "tag": privatekey_sign_connection_tag,
                    "salt": privatekey_sign_connection_salt,
                    "nonce": privatekey_sign_connection_nonce
                }
            },
            "skeypath": os.path.join(USERDIR, f"{username}_client-V2.skey.json")
        },
        "messages": {}
    }
    if os.path.exists(os.path.join(USERDIR, "userslist-V2.json")):
        current = readjson(os.path.join(USERDIR, "userslist-V2.json"))
        try:
            current["users"].append(username)
            current["contacts"][username] = []
            current["contacts"][username].append(username)
        except:
            current["users"] = []
            current["users"].append(username)
            current["contacts"] = {}
            current["contacts"][username] = []
            current["contacts"][username].append(username)
    else:
        current = {"users": [username]}
    writejson(os.path.join(USERDIR, f"{username}_client-V2.json"), data)
    writejson(os.path.join(USERDIR, "userslist-V2.json"), current)
    return data

def load_user(username: str, password: str) -> Dict[str, Any]:
    if not os.path.exists(os.path.join(USERDIR, f"{username}_client-V2.skey.json")) or not os.path.exists(os.path.join(USERDIR, f"{username}_client-V2.json")):
        raise RuntimeError("loading failed: clients files dont exist on the clients storage")
    response = make_request(userdata={}, method="GET", url=APIURL + GET_USER + username).json()
    if not response.get("ok"):
        raise RuntimeError(f"loading failed: {resp}")
    key = load_skey(username, password)
    data = readjson(os.path.join(USERDIR, f"{username}_client-V2.json"))
    if data["user"]["ver"] != VERSION:
        warnings.warn("skey load warn: app version mismatch", RuntimeWarning)
    privatekey_kyber = decryptAESGCM(key, data["user"]["keys"]["privatekey_kyber"]["ciphertext"], data["user"]["keys"]["privatekey_kyber"]["tag"], data["user"]["keys"]["privatekey_kyber"]["salt"], data["user"]["keys"]["privatekey_kyber"]["nonce"], human=False)
    privatekey_sign_token = decryptAESGCM(key, data["user"]["keys"]["privatekey_sign_token"]["ciphertext"], data["user"]["keys"]["privatekey_sign_token"]["tag"], data["user"]["keys"]["privatekey_sign_token"]["salt"], data["user"]["keys"]["privatekey_sign_token"]["nonce"], human=False)
    privatekey_sign_connection = decryptAESGCM(key, data["user"]["keys"]["privatekey_sign_connection"]["ciphertext"], data["user"]["keys"]["privatekey_sign_connection"]["tag"], data["user"]["keys"]["privatekey_sign_connection"]["salt"], data["user"]["keys"]["privatekey_sign_connection"]["nonce"], human=False)
    publickey_kyber = b642byte(data["user"]["keys"]["publickey_kyber_b64"])
    publickey_sign_token = b642byte(data["user"]["keys"]["publickey_sign_token_b64"])
    publickey_sign_connection = b642byte(data["user"]["keys"]["publickey_sign_connection_b64"])
    kyber_obj = kem_obj_create(privkey=privatekey_kyber)
    sign_token_obj = sign_obj_create(privkey=privatekey_sign_token)
    connection_sign_obj = sign_obj_create(privkey=privatekey_sign_connection)
    data["ram"] = {}
    data["ram"]["publickey_kyber"] = publickey_kyber
    data["ram"]["publickey_sign_token"] = publickey_sign_token
    data["ram"]["publickey_sign_connection"] = publickey_sign_connection
    data["ram"]["privatekey_kyber"] = privatekey_kyber
    data["ram"]["privatekey_sign_token"] = privatekey_sign_token
    data["ram"]["privatekey_sign_connection"] = privatekey_sign_connection
    data["ram"]["kyber_obj"] = kyber_obj
    data["ram"]["sign_token_obj"] = sign_token_obj
    data["ram"]["connection_sign_obj"] = connection_sign_obj
    data["ram"]["key"] = key
    return data

# === Messaging Functions ===
# > creates "Cryptography" header
# > puts messaging encryption under a diffrent header
# shit ass programming time
# (update on 18/09/2025 fixed this shit ass programming skill issue)
def generate_message_id(sender: str, receiver: str, userdata: Dict[str, Any], token: str = None, update: bool = True) -> str: # pyright: ignore[reportArgumentType]
    idgen = MessageIDGENModel(sender=sender, sendertoken=token, receiver=receiver, update=update)
    response = make_authenticated_request("POST", APIURL + MSG_GET_ID, userdata, token, json=idgen.model_dump()).json()
    if not response.get("ok"):
        raise RuntimeError(f"Failed to generate message ID: {response}")
    return response["msgid"]

# shit ass function name, how long even this shit is??
# edit (04/11/2025): well this doesnt looks so bad rigth now isnt it
def send_message_persistent_storage(userdata: Dict[str, Any], receiver_username: str, payload: str, token: str = None) -> Dict[str, Any]: # pyright: ignore[reportArgumentType]
    receiver_info = make_authenticated_request("GET", APIURL + GET_USER + receiver_username, userdata, token).json()
    if not receiver_info.get("ok"):
        raise RuntimeError(f"Failed to get receiver info: {receiver_info}")
    message_id = generate_message_id(userdata["user"]["username"], receiver_username, userdata, token)
    if not receiver_username == userdata["user"]["username"]:
        receiver_public_key = receiver_info["data"]["publickey_kyber"]
        ciphertext_b64, sharedsecret = encapsulate_shared_secret(userdata["ram"]["kyber_obj"], receiver_public_key)
        payload_ciphertext_b64, payload_tag_b64, payload_salt_b64, payload_nonce_b64, hkdfsalt = encrypt_message_payload(sharedsecret, payload)
        messagemodel = MessageSendModel(messageid=message_id, sender=userdata["user"]["username"], sendertoken=token, receiver=receiver_username,
                                        sender_pk=userdata["user"]["keys"]["publickey_kyber_b64"], receiver_pk=receiver_public_key, ciphertext=ciphertext_b64,
                                        payload_ciphertext=payload_ciphertext_b64, payload_tag=payload_tag_b64, payload_salt= payload_salt_b64,
                                        payload_nonce=payload_nonce_b64, hkdfsalt=hkdfsalt)
        response = make_authenticated_request("POST", APIURL + MSG_SEND, userdata, token, json=messagemodel.model_dump()).json()
        if not response.get("ok"):
            raise RuntimeError(f"failed to send message: {response}")
        senddata = {
            "status": "sent",
            "message_id": message_id,
            "timestamp": response.get("timestamp"),
            "tokenexp": response.get("tokenexp"),
            "sender": userdata["user"]["username"],
            "receiver": receiver_username,
            "sender_pk": userdata["user"]["keys"]["publickey_kyber_b64"],
            "receiver_pk": receiver_public_key,
            "hkdfsalt": hkdfsalt,
            "ciphertext": ciphertext_b64,
            "encrypted_payload_for_storage_ciphertext": payload_ciphertext_b64,
            "encrypted_payload_for_storage_payload_tag": payload_tag_b64,
            "encrypted_payload_for_storage_payload_salt": payload_salt_b64,
            "encrypted_payload_for_storage_payload_nonce": payload_nonce_b64,
            "shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT": sharedsecret # i think this might be important gang :sob: :wilted-rose:
        }
    else:
        sharedsecret = keygen()
        payload_ciphertext_b64, payload_tag_b64, payload_salt_b64, payload_nonce_b64, hkdfsalt = encrypt_message_payload(sharedsecret, payload)
        senddata = {
            "status": "local",
            "message_id": message_id,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tokenexp": 0,
            "sender": userdata["user"]["username"],
            "receiver": receiver_username,
            "sender_pk": userdata["user"]["keys"]["publickey_kyber_b64"],
            "receiver_pk": userdata["user"]["keys"]["publickey_kyber_b64"],
            "hkdfsalt": hkdfsalt,
            "ciphertext": 0,
            "encrypted_payload_for_storage_ciphertext": payload_ciphertext_b64,
            "encrypted_payload_for_storage_payload_tag": payload_tag_b64,
            "encrypted_payload_for_storage_payload_salt": payload_salt_b64,
            "encrypted_payload_for_storage_payload_nonce": payload_nonce_b64,
            "shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT": sharedsecret
        }
    userkey = userdata["ram"]["key"]
    userfile = os.path.join(USERDIR, f"{userdata['user']['username']}_client-V2.json")
    userfiledata = readjson(userfile)
    (sharedsecret_local_ciphertext, sharedsecret_local_tag, sharedsecret_local_salt, sharedsecret_local_nonce) = encryptAESGCM(userkey, senddata["shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT"], human=False)
    # i mean we are buildidng in such way if the users "shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT" is exposed also the reciever is in danger
    # but wait, even if it gets leaked that message could be read by the attackers? so no need to use another key? also this is high entropy so shouldnt be a problem?
    # gang i might lowkey have no idea what the fucking shit i am doing bruh
    userfiledata["messages"][senddata['message_id']] = {
        "local_ciphertext": sharedsecret_local_ciphertext,
        "local_tag": sharedsecret_local_tag,
        "local_salt": sharedsecret_local_salt,
        "local_nonce": sharedsecret_local_nonce
    }
    senddata.pop("shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT")
    messagefp = os.path.join(MESSAGEDIR, f"{senddata['message_id']}-msg-V2-CLIENT.json")
    writejson(userfile, userfiledata)
    writejson(messagefp, senddata)
    return {
        "status": "sent",
        "message_id": senddata["message_id"],
        "timestamp": senddata["timestamp"],
        "tokenexp": senddata["tokenexp"],
        "sender": userdata["user"]["username"],
        "receiver": receiver_username
    }

def get_message_persistent_storage2(message_id: str, userdata: Dict[str, Any], username: str, token: str = None) -> Dict[str, Any]: # pyright: ignore[reportArgumentType]
    messagefp = os.path.join(MESSAGEDIR, f"{message_id}-msg-V2-CLIENT.json")
    userfile = os.path.join(USERDIR, f"{userdata['user']['username']}_client-V2.json")
    userfiledata = readjson(userfile)
    userkey = userdata["ram"]["key"]
    if not username == userdata["user"]["username"]:
        params = {"sendertoken": token}
        response = make_authenticated_request("GET", APIURL + MSG_GET + message_id, userdata, token, params=params).json()
        if not response.get("ok"):
            raise RuntimeError(f"failed to get message: {response}")
        response_message = response["message"]
        userkey = userdata["ram"]["key"]
        if os.path.exists(messagefp):
            # we are trying to read a existing, saved, local file OR
            # sender is trying to get this text, so we gonna use the existing one
            shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT = decryptAESGCM(userkey, userfiledata["messages"][message_id]["local_ciphertext"], userfiledata["messages"][message_id]["local_tag"], userfiledata["messages"][message_id]["local_salt"], userfiledata["messages"][message_id]["local_nonce"], human=False)
            local_send_data = readjson(messagefp)
            plaintext = byte2str(decrypt_message_payload(shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT, local_send_data["encrypted_payload_for_storage_ciphertext"], local_send_data["encrypted_payload_for_storage_payload_tag"], local_send_data["encrypted_payload_for_storage_payload_salt"], local_send_data["encrypted_payload_for_storage_payload_nonce"], local_send_data["hkdfsalt"]))
            return {
                "message_id": local_send_data["message_id"],
                "status": "get",
                "sender": local_send_data["sender"],
                "receiver": local_send_data["receiver"],
                "message": plaintext,
                "timestamp": local_send_data["timestamp"],
                "tokenexp": local_send_data["tokenexp"]
            }
        else:
            shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT = decapsulate_shared_secret(userdata["ram"]["kyber_obj"], response_message["ciphertext"])
            plaintext = byte2str(decrypt_message_payload(shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT, response_message["payload_ciphertext"], response_message["payload_tag"], response_message["payload_salt"], response_message["payload_nonce"], response_message["hkdfsalt"]))
            (local_ciphertext, local_tag, local_salt, local_nonce) = encryptAESGCM(userkey, shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT, human=False)
            userfiledata["messages"][message_id] = {
                "local_ciphertext": local_ciphertext,
                "local_tag": local_tag,
                "local_salt": local_salt,
                "local_nonce": local_nonce
            }
            messagefp = os.path.join(MESSAGEDIR, f"{message_id}-msg-V2-CLIENT.json")
            writejson(userfile, userfiledata)
            local_send_data = {
                "status": "recieved",
                "timestamp": response_message["timestamp"],
                "tokenexp": response["tokenexp"],
                "sender": response_message["sender"],
                "receiver": response_message["receiver"],
                "sender_pk": response_message["sender_pk"],
                "receiver_pk": response_message["receiver_pk"],
                "message_id": message_id,
                "hkdfsalt": response_message["hkdfsalt"],
                "encrypted_payload_for_storage_ciphertext": response_message["payload_ciphertext"],
                "encrypted_payload_for_storage_payload_tag": response_message["payload_tag"],
                "encrypted_payload_for_storage_payload_salt": response_message["payload_salt"],
                "encrypted_payload_for_storage_payload_nonce": response_message["payload_nonce"]
            }
            writejson(messagefp, local_send_data)
            return {
                "message_id": message_id,
                "status": "get",
                "message": plaintext,
                "timestamp": response_message["timestamp"],
                "sender": response_message["sender"],
                "tokenexp": response["tokenexp"],
                "message_id_server": response_message["messageid"],
                "receiver": response_message["receiver"],
            }
    else:
        shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT = decryptAESGCM(userkey, userfiledata["messages"][message_id]["local_ciphertext"], userfiledata["messages"][message_id]["local_tag"], userfiledata["messages"][message_id]["local_salt"], userfiledata["messages"][message_id]["local_nonce"], human=False)
        local_send_data = readjson(messagefp)
        plaintext = byte2str(decrypt_message_payload(shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT, local_send_data["encrypted_payload_for_storage_ciphertext"], local_send_data["encrypted_payload_for_storage_payload_tag"], local_send_data["encrypted_payload_for_storage_payload_salt"], local_send_data["encrypted_payload_for_storage_payload_nonce"], local_send_data["hkdfsalt"]))
        return {
            "message_id": local_send_data["message_id"],
            "status": "get",
            "sender": local_send_data["sender"],
            "receiver": local_send_data["receiver"],
            "message": plaintext,
            "timestamp": local_send_data["timestamp"],
            "tokenexp": local_send_data["tokenexp"]
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
    return templates.TemplateResponse("index.html", {"request": request, "version": VERSION, "apiurl": APIURL})

@app.get("/login", response_class=HTMLResponse)
async def loginUI(request: Request):
    options = readjson(os.path.join(USERDIR, "userslist-V2.json")).get("users")
    if not options:
        return RedirectResponse(url="/register", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "version": VERSION, "apiurl": APIURL, "options": options})

@app.post("/login-send")
async def login_send(username: str = Form(...), password: str = Form(...)):
    global userdat
    userdat = load_user(username, password)
    return RedirectResponse(url="/main", status_code=302)

@app.get("/register", response_class=HTMLResponse)
async def registerUI(request: Request):
    options = readjson(os.path.join(USERDIR, "userslist-V2.json")).get("users", ["no users on disk"])
    return templates.TemplateResponse("register.html", {"request": request, "version": VERSION, "apiurl": APIURL, "options": options})

@app.post("/register-send")
async def register_send(username: str = Form(...), password: str = Form(...), timezone: str = Form(...)):
    global userdat
    userdat = create_user(username, password, int(timezone))
    return RedirectResponse(url="/login", status_code=302)

@app.get("/contacts/{username}")
async def get_contacts(username: str):
    data = readjson(os.path.join(USERDIR, "userslist-V2.json"))
    contacts = data.get("contacts", {}).get(username, [])
    return JSONResponse({"contacts": contacts})

@app.post("/contacts/add")
async def add_contact(username: str = Form(...), new_contact: str = Form(...)):
    data = readjson(os.path.join(USERDIR, "userslist-V2.json"))
    contacts = data.setdefault("contacts", {}).setdefault(username, [])
    if new_contact not in contacts:
        contacts.append(new_contact)
        writejson(os.path.join(USERDIR, "userslist-V2.json"), data)
    return JSONResponse({"contacts": contacts})

@app.post("/contacts/delete")
async def delete_contact(username: str = Form(...), del_contact: str = Form(...)):
    data = readjson(os.path.join(USERDIR, "userslist-V2.json"))
    contacts = data.get("contacts", {}).get(username, [])
    if del_contact in contacts:
        contacts.remove(del_contact)
        writejson(os.path.join(USERDIR, "userslist-V2.json"), data)
    return JSONResponse({"contacts": contacts})

@app.get("/main", response_class=HTMLResponse)
async def mainUI(request: Request):
    global userdat
    global tok
    if not userdat:
        return RedirectResponse(url="/login", status_code=302)
    get_current_token(userdat)
    contacts_dict = readjson(os.path.join(USERDIR, "userslist-V2.json")).get("contacts", {})
    contacts = contacts_dict.get(userdat["user"]["username"], [])
    return templates.TemplateResponse("main.html", {"request": request, "version": VERSION, "username": userdat["user"]["username"], "apiurl": APIURL, "contacts": contacts})

@app.get("/settings", response_class=HTMLResponse)
async def settingsUI(request: Request):
    global userdat
    global tok
    if not userdat:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("settings.html", {"request": request, "version": VERSION, "username": userdat["user"]["username"], "apiurl": APIURL})

@app.get("/logout", response_class=HTMLResponse)
async def logoutUI(request: Request):
    global userdat
    global tok
    userdat = None
    tok = None
    return RedirectResponse(url="/login", status_code=302)

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    global userdat
    global tok
    messages = {}
    await ws.accept()
    connections.append(ws)
    await ws.send_json({"lines": [entry["formatted"] for entry in sorted(scrolled_text_data, key=lambda x: x["timestamp"])]})
    try:
        while True:
            jsondata = await ws.receive_json()
            start = time.time()
            action = jsondata.get("action")
            username = jsondata.get("username", None)
            message = jsondata.get("message", "")
            access_token_str = get_current_token(userdat) # pyright: ignore[reportArgumentType]
            if action == "send":
                messagedata = send_message_persistent_storage(userdat, username, message, access_token_str) # pyright: ignore[reportArgumentType]
                if messagedata["status"] != "sent":
                    raise RuntimeError("message couldn't be sent")
                pass
            elif action == "get":
                if username is not None:
                    scrolled_text_data.clear()
                    messageid = generate_message_id(userdat["user"]["username"], username, userdat, access_token_str, update=False) # pyright: ignore[reportArgumentType, reportOptionalSubscript]
                    counter = int(messageid.split("-")[1])
                    usershash = messageid.split("-")[0]
                    for msgnum in range(1, counter + 1):
                        msgid = f"{usershash}-{msgnum}"
                        if not messages.get(msgid):
                            messagedata = get_message_persistent_storage2(msgid, userdat, username, access_token_str) # pyright: ignore[reportArgumentType]
                            messages[msgid] = messagedata
                        else:
                            messagedata = messages[msgid]
                        plaintext = messagedata["message"]
                        sender = messagedata["sender"]
                        timestamp = messagedata["timestamp"]
                        entry = messageformatter(sender, plaintext, timestamp, timezone=userdat["user"]["tz"]) # pyright: ignore[reportOptionalSubscript]
                        scrolled_text_data.append(entry)
            try:
                sorted_lines = [entry["formatted"] for entry in sorted(scrolled_text_data, key=lambda x: x["timestamp"])]
            except Exception as e:
                sorted_lines = [entry["formatted"] for entry in scrolled_text_data]
                sorted_lines.append("sorting failed, see logs")
                warnings.warn(f"message sorting failed, skipping sorting: {e}", RuntimeWarning)
            stop = time.time()
            token_exp = tok.get("exp", 0) if tok else 0
            time_until_exp = max(0, token_exp - time.time())
            apistat = [
                f"api url: {APIURL} is alive: {apiTunnelAlive()}", 
                f"last action took {(stop-start)*1000:.0f} ms, updates per second: {(1/(stop-start+0.001)):.2f}",
                f"token expires in: {time_until_exp:.0f}s",
                "MOTD: Have a nice day!"
            ]
            for conn in connections:
                await conn.send_json({
                    "lines": sorted_lines,
                    "apistat": apistat,
                })
    except WebSocketDisconnect:
        connections.remove(ws)
        scrolled_text_data.clear()

def portused(port, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0

if __name__ == "__main__":
    import uvicorn
    while True:
        port = PORT_BASE
        while portused(port):
            if MULTIPLE_PORTS:
                port += 1
            else:
                print(f"port {port} is used. Another instance is running. please run this script again when port {PORT_BASE} is available")
                _ = input("press enter to exit: ")
                exit(1)
        webbrowser.open_new(f"http://localhost:{port}") # lowkey takes longer to init the server startup so its right before it
        try:
            uvicorn.run(app, host="0.0.0.0", port=port)
            break
        except:
            print(f"port {port} is used, trying another...")
            continue