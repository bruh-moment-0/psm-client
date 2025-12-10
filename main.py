# oh boy oh boy here we go.
# api was 100x easier than this shit
# or atleast thats my speculation ofc

# custom libs
from const import * # constants
from quantum import sign_obj_create, kem_obj_create, create_key_pair # post quantum custom lib based on liboqs-python
# if you are reading this you acknowledge that liboqs-python is fire but installing it is ass.
from aes256 import keygen, encryptAESGCM, decryptAESGCM # AES256-GCM custom lib
from encrypt import * # custom lib for encryption
from data import * # custom lib for file control
from connect import * # custom lib for connecting
from fastapi import FastAPI, Request, Form, status, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

# from cryptography.hazmat.primitives.kdf.hkdf import HKDF # to do something i forgot right now
from typing import Dict, Any # making pylance happy i guess
# from cryptography.hazmat.primitives import hashes # hkdf stuff

from pydantic import BaseModel

from urllib.parse import urlencode, urlparse, parse_qs, urlunparse, quote, unquote
from zoneinfo import ZoneInfo
from io import BytesIO
import webbrowser # to open the webbrowser
import datetime
import hashlib
import warnings
import socket
import time

# all this just to get the path of a file :wilted-rose:
import wx # gui system
import asyncio # for async gui
from concurrent.futures import ThreadPoolExecutor # for threading the gui

# importing the whole pypi ass

if NOTREADY:
    print("code is NOT READY for usage for now, due to security concerns. please use an older version until this version is fixed.")
    print("current issue: None")
    print(f"current version: {VERSION}")
    print("REMINDER, THIS FAILSAFE ONLY ACTIVATES IF THERE IS A BIG SECURITY PROBLEM!")
    print("DO NOT TAMPER THE CODE TO BYPASS THIS!")
    _ = input("press ENTER to exit")
    exit(1)
else:
    print("system init complete. please wait...")

BASEDIR = os.path.abspath(os.path.dirname(__file__))
STATICDIR = os.path.join(BASEDIR, "static")
TEMPLATESDIR = os.path.join(BASEDIR, "templates")

# i have no idea what these do but they make shit work so yes yes
scrolled_text_data: list[dict] = [] # shared buffer
connections: list[WebSocket] = [] # connected clients

executor = ThreadPoolExecutor(max_workers=4)
userdat = {}
tok = None
app = FastAPI()
app.mount("/static", StaticFiles(directory=STATICDIR), name="static")
templates = Jinja2Templates(directory=TEMPLATESDIR)

# === Schemas ===
class MessageSendModel(BaseModel):
    messageid: str
    sender: str
    receiver: str
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

# === Helper Functions ===
def get_filepath_sync(title: str) -> str:
    try:
        app = wx.App(False)
        dialog = wx.FileDialog(
            None,
            message=title,
            defaultDir="",
            defaultFile="",
            wildcard="All files (*.*)|*.*",
            style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST
        )
        dialog.SetWindowStyle(dialog.GetWindowStyle() | wx.STAY_ON_TOP)
        filepath = ""
        if dialog.ShowModal() == wx.ID_OK:
            filepath = dialog.GetPath()
        dialog.Destroy()
        app.Destroy()
        return filepath
    except Exception as e:
        print(f"file dialog error: {e}")
        return ""

async def get_filepath_async(title: str) -> str:
    loop = asyncio.get_event_loop()
    filepath = await loop.run_in_executor(executor, get_filepath_sync, title)
    return filepath

def get_timezone_offset_hours(tz_name: str) -> float:
    now = datetime.datetime.now(ZoneInfo(tz_name))
    offset = now.utcoffset()
    if offset is None:
        return 0.0
    return offset.total_seconds() / 3600

def messageformatter(username: str, message: str, timestamp: str, timezone: int) -> dict:
    try:
        dt = datetime.datetime.fromisoformat(timestamp)
        dt = dt + datetime.timedelta(hours=timezone)
        formatted = dt.strftime('%d/%m/%Y %H:%M:%S')
    except Exception as e:
        dt = datetime.datetime.min
        formatted = "unknown-time"
        warnings.warn(f"WARNING: sorting failed on 'messageformatter': {e}, data: {username} {message} {timestamp}")
    return {"sender": username, "message": message, "timestamp": timestamp, "formatted_time": formatted}

def generate_message_id_local(username: str, update: bool) -> str:
    chathash = hashlib.sha256("LOCAL".join([username, username]).encode()).hexdigest()
    counter_file = os.path.join(MESSAGECOUNTERDIR, f"{chathash}-V1.json")
    if os.path.exists(counter_file):
        data = readjson(counter_file)
        counter = data.get("counter", 0)
    else:
        data = {"user": username, "counter": 0}
        counter = 0
    if update:
        counter += 1
        data["counter"] = counter
        writejson(counter_file, data)
    return f"{chathash}-{counter}"

# === User Management Functions ===
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

def create_user(username: str, password: str, tz: float) -> Dict[str, Any]:
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
    response = make_request(userdata={}, method="GET", url=APIURL + GET_USER + username).json()
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
    try:
        response = make_request(userdata={}, method="GET", url=APIURL + GET_USER + username).json()
    except Exception as e:
        raise RuntimeError(e)
    if not response.get("ok"):
        raise RuntimeError(f"loading failed: {resp}")
    key = load_skey(username, password)
    data = readjson(os.path.join(USERDIR, f"{username}_client-V2.json"))
    if data["user"]["ver"] != VERSION:
        warnings.warn("skey load warn: app version mismatch", RuntimeWarning)
    privatekey_kyber = decryptAESGCM(
        key,
        data["user"]["keys"]["privatekey_kyber"]["ciphertext"],
        data["user"]["keys"]["privatekey_kyber"]["tag"],
        data["user"]["keys"]["privatekey_kyber"]["salt"],
        data["user"]["keys"]["privatekey_kyber"]["nonce"],
        human=False
    )
    privatekey_sign_token = decryptAESGCM(
        key,
        data["user"]["keys"]["privatekey_sign_token"]["ciphertext"],
        data["user"]["keys"]["privatekey_sign_token"]["tag"],
        data["user"]["keys"]["privatekey_sign_token"]["salt"],
        data["user"]["keys"]["privatekey_sign_token"]["nonce"],
        human=False
    )
    privatekey_sign_connection = decryptAESGCM(
        key,
        data["user"]["keys"]["privatekey_sign_connection"]["ciphertext"],
        data["user"]["keys"]["privatekey_sign_connection"]["tag"],
        data["user"]["keys"]["privatekey_sign_connection"]["salt"],
        data["user"]["keys"]["privatekey_sign_connection"]["nonce"],
        human=False
    )
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
def generate_message_id(sender: str, receiver: str, userdata: Dict[str, Any], token: str = "", update: bool = True) -> str:
    if sender == receiver:
        return generate_message_id_local(sender, update)
    else:
        idgen = MessageIDGENModel(sender=sender, sendertoken=token, receiver=receiver, update=update)
        response = make_authenticated_request("POST", APIURL + MSG_GET_ID, userdata, token, json=idgen.model_dump()).json()
        if not response.get("ok"):
            raise RuntimeError(f"Failed to generate message ID: {response}")
        return response["msgid"]

# shit ass function name, how long even this shit is??
# edit (04/11/2025): well this doesnt looks so bad rigth now isnt it
# edit 2 (11/11/2025): changed the name because ts gonna be so hard to manage
def send_message_ps(userdata: Dict[str, Any], receiver_username: str, payload: Dict[str, Any], token: str = "") -> Dict[str, Any]:
    # ps stands for persistent storage
    if not receiver_username == userdata["user"]["username"]:
        receiver_info = make_authenticated_request("GET", APIURL + GET_USER + receiver_username, userdata, token).json()
        if not receiver_info.get("ok"):
            raise RuntimeError(f"Failed to get receiver info: {receiver_info}")
        message_id = generate_message_id(userdata["user"]["username"], receiver_username, userdata, token, update=True)
        receiver_public_key = receiver_info["data"]["publickey_kyber"]
        ciphertext_b64, sharedsecret = encapsulate_shared_secret(userdata["ram"]["kyber_obj"], receiver_public_key)
        payload_ciphertext_b64, payload_tag_b64, payload_salt_b64, payload_nonce_b64, hkdfsalt = encrypt_message_payload(sharedsecret, jsondump(payload))
        messagemodel = MessageSendModel(messageid=message_id, sender=userdata["user"]["username"], sendertoken=token, receiver=receiver_username,
                                        ciphertext=ciphertext_b64, payload_ciphertext=payload_ciphertext_b64, payload_tag=payload_tag_b64,
                                        payload_salt=payload_salt_b64, payload_nonce=payload_nonce_b64, hkdfsalt=hkdfsalt)
        response = make_authenticated_request("POST", APIURL + MSG_SEND, userdata, token, json=messagemodel.model_dump()).json()
        if not response.get("ok"):
            raise RuntimeError(f"failed to send message: {response}")
        senddata = {
            "status": "sent",
            "message_id": message_id,
            "timestamp": payload["timestamp"],
            "tokenexp": response.get("tokenexp"),
            "sender": userdata["user"]["username"],
            "receiver": receiver_username,
            "hkdfsalt": hkdfsalt,
            "ciphertext": ciphertext_b64,
            "encrypted_payload_for_storage_ciphertext": payload_ciphertext_b64,
            "encrypted_payload_for_storage_payload_tag": payload_tag_b64,
            "encrypted_payload_for_storage_payload_salt": payload_salt_b64,
            "encrypted_payload_for_storage_payload_nonce": payload_nonce_b64,
            "shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT": sharedsecret # i think this might be important gang :sob: :wilted-rose:
        }
    else:
        message_id = generate_message_id(userdata["user"]["username"], userdata["user"]["username"], userdata, token="", update=True)
        sharedsecret = keygen()
        payload_ciphertext_b64, payload_tag_b64, payload_salt_b64, payload_nonce_b64, hkdfsalt = encrypt_message_payload(sharedsecret, jsondump(payload))
        senddata = {
            "status": "local",
            "message_id": message_id,
            "timestamp": payload["timestamp"],
            "tokenexp": 0,
            "sender": userdata["user"]["username"],
            "receiver": receiver_username,
            "hkdfsalt": hkdfsalt,
            "ciphertext": 0,
            "encrypted_payload_for_storage_ciphertext": payload_ciphertext_b64,
            "encrypted_payload_for_storage_payload_tag": payload_tag_b64,
            "encrypted_payload_for_storage_payload_salt": payload_salt_b64,
            "encrypted_payload_for_storage_payload_nonce": payload_nonce_b64,
            "shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT": sharedsecret
        }
    userkey = userdata["ram"]["key"]
    hkdfsalt = os.urandom(32)
    deriveduserkey = hkdf_function(userkey, hkdfsalt)
    userfile = os.path.join(USERDIR, f"{userdata['user']['username']}_client-V2.json")
    userfiledata = readjson(userfile)
    (sharedsecret_local_ciphertext, sharedsecret_local_tag, sharedsecret_local_salt, sharedsecret_local_nonce) = encryptAESGCM(deriveduserkey, senddata["shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT"], human=False)
    userfiledata["messages"][senddata['message_id']] = {
        "hkdfsalt_key": byte2b64(hkdfsalt),
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

def get_message_ps(message_id: str, userdata: Dict[str, Any], username: str, token: str = ""):
    messagefp = os.path.join(MESSAGEDIR, f"{message_id}-msg-V2-CLIENT.json")
    userfile = os.path.join(USERDIR, f"{userdata['user']['username']}_client-V2.json")
    userfiledata = readjson(userfile)
    userkey = userdata["ram"]["key"]
    if not username == userdata["user"]["username"]:
        if os.path.exists(messagefp):
            # we are trying to read a existing, saved, local file OR
            # sender is trying to get this text, so we gonna use the existing one
            deriveduserkey = hkdf_function(userkey, userfiledata["messages"][message_id]["hkdfsalt"])
            shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT = decryptAESGCM(
                deriveduserkey,
                userfiledata["messages"][message_id]["local_ciphertext"],
                userfiledata["messages"][message_id]["local_tag"],
                userfiledata["messages"][message_id]["local_salt"],
                userfiledata["messages"][message_id]["local_nonce"],
                human=False
            )
            local_send_data = readjson(messagefp)
            payload = jsonload(byte2str(decrypt_message_payload(
                shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT,
                local_send_data["encrypted_payload_for_storage_ciphertext"],
                local_send_data["encrypted_payload_for_storage_payload_tag"],
                local_send_data["encrypted_payload_for_storage_payload_salt"],
                local_send_data["encrypted_payload_for_storage_payload_nonce"],
                local_send_data["hkdfsalt"]
            )))
            return {
                "status": "get",
                "message_id": message_id,
                "payload": payload,
                "receiver": local_send_data["receiver"],
                "sender": local_send_data["sender"],
                "tokenexp": local_send_data["tokenexp"]
            }
        else:
            params = {"sendertoken": token}
            response = make_authenticated_request("GET", APIURL + MSG_GET + message_id, userdata, token, params=params).json()
            if not response.get("ok"):
                raise RuntimeError(f"failed to get message: {response}")
            response_message = response["message"]
            shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT = decapsulate_shared_secret(userdata["ram"]["kyber_obj"], response_message["ciphertext"])
            payload = jsonload(byte2str(decrypt_message_payload(
                shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT,
                response_message["payload_ciphertext"],
                response_message["payload_tag"],
                response_message["payload_salt"],
                response_message["payload_nonce"],
                response_message["hkdfsalt"]
            )))
            hkdfsalt = os.urandom(32)
            deriveduserkey = hkdf_function(userkey, hkdfsalt)
            (local_ciphertext, local_tag, local_salt, local_nonce) = encryptAESGCM(deriveduserkey, shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT, human=False)
            userfiledata["messages"][message_id] = {
                "hkdfsalt": hkdfsalt,
                "local_ciphertext": local_ciphertext,
                "local_tag": local_tag,
                "local_salt": local_salt,
                "local_nonce": local_nonce
            }
            messagefp = os.path.join(MESSAGEDIR, f"{message_id}-msg-V2-CLIENT.json")
            writejson(userfile, userfiledata)
            local_send_data = {
                "status": "get",
                "tokenexp": response["tokenexp"],
                "sender": response_message["sender"],
                "receiver": response_message["receiver"],
                "message_id": message_id,
                "hkdfsalt": response_message["hkdfsalt"],
                "encrypted_payload_for_storage_ciphertext": response_message["payload_ciphertext"],
                "encrypted_payload_for_storage_payload_tag": response_message["payload_tag"],
                "encrypted_payload_for_storage_payload_salt": response_message["payload_salt"],
                "encrypted_payload_for_storage_payload_nonce": response_message["payload_nonce"]
            }
            writejson(messagefp, local_send_data)
            return {
                "status": "get",
                "message_id": message_id,
                "payload": payload,
                "receiver": response_message["receiver"],
                "sender": response_message["sender"],
                "tokenexp": response["tokenexp"],
            }
    else:
        deriveduserkey = hkdf_function(userkey, userfiledata["messages"][message_id]["hkdfsalt"])
        shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT = decryptAESGCM(
            deriveduserkey,
            userfiledata["messages"][message_id]["local_ciphertext"],
            userfiledata["messages"][message_id]["local_tag"],
            userfiledata["messages"][message_id]["local_salt"],
            userfiledata["messages"][message_id]["local_nonce"],
            human=False
        )
        local_send_data = readjson(messagefp)
        payload = jsonload(byte2str(decrypt_message_payload(
            shared_secret_DO_NOT_SHARE_SUPER_SECRET_ULTRA_IMPORTANT,
            local_send_data["encrypted_payload_for_storage_ciphertext"],
            local_send_data["encrypted_payload_for_storage_payload_tag"],
            local_send_data["encrypted_payload_for_storage_payload_salt"],
            local_send_data["encrypted_payload_for_storage_payload_nonce"],
            local_send_data["hkdfsalt"]
        )))
        return {
                "status": "get",
                "message_id": local_send_data["message_id"],
                "payload": payload,
                "receiver": local_send_data["receiver"],
                "sender": local_send_data["sender"],
                "tokenexp": local_send_data["tokenexp"],
            }

def send_text_message_ps(userdata: Dict[str, Any], receiver_username: str, message: str, token: str = "") -> Dict[str, Any]:
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    payload = {"type": "text", "message": message, "timestamp": timestamp}
    return send_message_ps(userdat, receiver_username, payload, token)

def get_text_message_ps(message_id: str, userdata: Dict[str, Any], username: str, token: str = ""):
    messagedict = get_message_ps(message_id, userdata, username, token)
    payload = messagedict["payload"]
    sender = messagedict["sender"]
    msgtype = payload["type"]
    message = payload["message"]
    timestamp = payload["timestamp"]
    return {
        "sender": sender,
        "timestamp": timestamp,
        "message": message
    }

def send_file_message_ps(userdata: Dict[str, Any], receiver_username: str, fp: str, filetype: str, token: str = ""):
    print("send file not implemented yet")
    return {"status": "error"}

# === client web server shit ===
warnings.filterwarnings("ignore", category=DeprecationWarning)
@app.on_event("startup") # i wasnt able to un-deprecate this...
async def startup():
    templates.env.filters['url_decode'] = unquote

@app.exception_handler(RuntimeError)
async def runtime_error_exception_handler(request: Request, exc: RuntimeError):
    error_message = quote(str(exc))
    referer = request.headers.get("referer", "/")
    parsed = urlparse(referer)
    query = parse_qs(parsed.query)
    query.pop("error", None)
    query["error"] = [error_message]
    new_query = urlencode(query, doseq=True)
    redirect_url = urlunparse(parsed._replace(query=new_query))
    return RedirectResponse(
        url=redirect_url,
        status_code=status.HTTP_303_SEE_OTHER
    )

# EXAMPLE, does not work for now
@app.get("/download")
async def download_file():
    content = b"example byte file that was generated on the fly"
    buffer = BytesIO(content)  # put text into memory buffer
    # return as a downloadable file
    return StreamingResponse(buffer, media_type="application/octet-stream", headers={"Content-Disposition": 'attachment; filename="generated.txt"'})

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
    userdat = create_user(username, password, get_timezone_offset_hours(timezone))
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
    if userdat == {}:
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
    userdat = {}
    tok = None
    return RedirectResponse(url="/login", status_code=302)

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    global userdat
    global tok
    messages = {}
    await ws.accept()
    connections.append(ws)
    await ws.send_json({"lines": [entry for entry in sorted(scrolled_text_data, key=lambda x: x["timestamp"])]})
    try:
        while True:
            jsondata = await ws.receive_json()
            start = time.time()
            action = jsondata.get("action")
            username = jsondata.get("username", None)
            message = jsondata.get("message", "")
            try:
                access_token_str = get_current_token(userdat)
            except Exception as e:
                await ws.send_json({"error": f"Token error: {str(e)}"})
                continue
            if action == "send":
                messagedata = send_text_message_ps(userdata=userdat, receiver_username=username, message=message, token=access_token_str)
                if messagedata["status"] != "sent":
                    raise RuntimeError("message couldn't be sent")
            elif action == "sendf":
                fp = await get_filepath_async(title="select file to send")
                if fp:
                    messagedata = send_file_message_ps(userdat, username, fp, "file", access_token_str)
                    if messagedata["status"] != "sent":
                        raise RuntimeError("message couldn't be sent")
            elif action == "get":
                if username is not None:
                    scrolled_text_data.clear()
                    messageid = generate_message_id(userdat["user"]["username"], username, userdat, access_token_str, update=False)
                    counter = int(messageid.split("-")[1])
                    usershash = messageid.split("-")[0]
                    for msgnum in range(1, counter + 1):
                        msgid = f"{usershash}-{msgnum}"
                        if not messages.get(msgid):
                            messagedata = get_text_message_ps(msgid, userdat, username, access_token_str)
                            messages[msgid] = messagedata
                        else:
                            messagedata = messages[msgid]
                        try:
                            plaintext = messagedata["message"]
                            message_obj = jsonload(plaintext)
                        except (json.JSONDecodeError, KeyError):
                            # UNBOUND
                            message_obj = {"type": "message", "content": plaintext} # pyright: ignore[reportPossiblyUnboundVariable]
                        sender = messagedata["sender"]
                        timestamp = messagedata["timestamp"]
                        entry = messageformatter(sender, message_obj, timestamp, timezone=userdat["user"]["tz"]) # pyright: ignore[reportArgumentType]
                        scrolled_text_data.append(entry)
            try:
                sorted_lines = [entry for entry in sorted(scrolled_text_data, key=lambda x: x["timestamp"])]
            except Exception as e:
                sorted_lines = [entry for entry in scrolled_text_data]
                sorted_lines.append({"type": "error", "content": "sorting failed, see logs", "timestamp": time.time()})
                warnings.warn(f"message sorting failed, skipping sorting: {e}", RuntimeWarning)
            stop = time.time()
            token_exp = check_tokenexpiration(userdat, access_token_str)
            token_exp = token_exp if token_exp != None else 0
            time_until_exp = max(0, token_exp - time.time())
            time_until_exp = "now" if time_until_exp == 0 else f"{time_until_exp:.0f}s"
            apistat = [
                f"api url: {APIURL} is alive: {apiTunnelAlive()}", 
                f"last action took {(stop-start)*1000:.0f} ms, updates per second: {(1/(stop-start+0.001)):.2f}",
                f"token expires in: {time_until_exp}",
                "MOTD: Have a nice day!"
            ]
            dead_connections = []
            for conn in connections:
                try:
                    await conn.send_json({
                        "lines": sorted_lines,
                        "apistat": apistat,
                    })
                except Exception as e:
                    print(f"Dead connection detected: {e}")
                    dead_connections.append(conn)
            for dead_conn in dead_connections:
                if dead_conn in connections:
                    connections.remove(dead_conn)  
    except WebSocketDisconnect:
        if ws in connections:
            connections.remove(ws)
        scrolled_text_data.clear()
    except Exception as e:
        print(f"WebSocket error: {e}")
        if ws in connections:
            connections.remove(ws)

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