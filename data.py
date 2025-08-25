# data.py but for clients!

from typing import Any
import datetime # i normally go with time but thats just not cool as this
import base64
import json # "in json we believe" - json cult /s
import os

VERSION = "CLI V1.1.1 INDEV (built 14:00 25/08/2025)"
BASEDIR = os.path.abspath(os.path.dirname(__file__))
USERDIR = os.path.join(BASEDIR, "users")

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

def writejson(filepath: str, data: Any, indent: int = 4) -> None:
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent)

def readjson(filepath: str) -> dict:
    if not os.path.exists(filepath):
        data = {}
        writejson(filepath, data)
        return data
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)