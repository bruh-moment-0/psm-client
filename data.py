# data.py but for clients!

from typing import Any
import base64
import json # you guessed it, the best db ever
import os

# Normally False but if this is set to True, better leave it be True...
# ONLY FOR REALLY IMPORTANT SECURITY PROBLEMS
NOTREADY = False

VERSION = "CLIENT V1.10.3 WIP (built 20:15 GMT+0 14/10/2025)"
BASEDIR = os.path.abspath(os.path.dirname(__file__))
STORAGEDIR = os.path.join(BASEDIR, "storage")
FILESDIR = os.path.join(STORAGEDIR, "files")
USERDIR = os.path.join(STORAGEDIR, "users")
MESSAGEDIR = os.path.join(STORAGEDIR, "messages")
os.makedirs(STORAGEDIR, exist_ok=True)
os.makedirs(FILESDIR, exist_ok=True)
os.makedirs(USERDIR, exist_ok=True)
os.makedirs(MESSAGEDIR, exist_ok=True)

def b64encodeUrlSafe(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode()

def b64decodeUrlSafe(s: str) -> bytes:
    return base64.urlsafe_b64decode(s)

def str2byte(text: str) -> bytes:
    byte = text.encode('utf-8')
    return byte

def byte2str(bytetext: bytes) -> str:
    text = bytetext.decode('utf-8')
    return text

def byte2b64(bytetext: bytes) -> str:
    return base64.b64encode(bytetext).decode()

def b642byte(b64text: str) -> bytes:
    return base64.b64decode(b64text.encode())

def writejson(filepath: str, data: Any, indent: int = 4) -> None:
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent)

def readjson(filepath: str) -> dict:
    if not os.path.exists(filepath):
        print(f"FP: {filepath} does not exist, readjson")
        data = {}
        writejson(filepath, data)
        return data
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)