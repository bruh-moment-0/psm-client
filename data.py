# The file management system code of Private Safe Messaging Client
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



# data.py but for clients!
from const import * # constants
from typing import Any
import base64
import json # you guessed it, the best db ever
import zlib
import os

VERSION = "CLIENT V2.2.1 (built 9:00 GMT+0 31/12/2025)"
BASEDIR = os.path.abspath(os.path.dirname(__file__))
STORAGEDIR = os.path.join(BASEDIR, "storage")
FILESDIR = os.path.join(STORAGEDIR, "files")
USERDIR = os.path.join(STORAGEDIR, "users")
MESSAGEDIR = os.path.join(STORAGEDIR, "messages")
MESSAGECOUNTERDIR = os.path.join(MESSAGEDIR, "localcounter")

os.makedirs(STORAGEDIR, exist_ok=True)
os.makedirs(FILESDIR, exist_ok=True)
os.makedirs(USERDIR, exist_ok=True)
os.makedirs(MESSAGEDIR, exist_ok=True)
os.makedirs(MESSAGECOUNTERDIR, exist_ok=True)

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

def jsonload(text: str) -> dict:
    return json.loads(text)

def jsondump(obj: dict) -> str:
    return json.dumps(obj)

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

# these namings might be bad as fuck but i give no shit
# writes normal data compressed
def write_compress_disk(filepath: str, data: bytes, compress: bool) -> None:
    if compress:
        data = zlib.compress(data, level=6)
    with open(filepath, "wb") as f:
        f.write(data)

# reads compressed data and returns the normal data
def read_compress_disk(filepath: str, compress: bool) -> bytes:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"{filepath} does not exist")
    with open(filepath, "rb") as f:
        data = f.read()
    if compress:
        data = zlib.decompress(data)
    return data

# writes a file from a compressed data but the output file is normal
def write_compress_return(filepath: str, compressed_data: bytes) -> None:
    raw_bytes = zlib.decompress(compressed_data)
    with open(filepath, "wb") as f:
        f.write(raw_bytes)

# reads a file normally but returns a compressed data
def read_compress_return(filepath: str) -> bytes:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"{filepath} does not exist")
    with open(filepath, "rb") as f:
        raw_bytes = f.read()
    return zlib.compress(raw_bytes, level=6)

def localfilelimit(filepath: str) -> bool:
    if not os.path.isfile(filepath):
        print(f"FP: {filepath} does not exist, localfilelimit")
        raise FileNotFoundError("file not found")
    return not os.path.getsize(filepath) > FILESIZELIMIT

def get_extension(filepath: str) -> str:
    return os.path.splitext(filepath)[1]

def get_name(filepath: str) -> str:
    return os.path.splitext(os.path.basename(filepath))[0]

def json2b64(data: dict) -> str:
    json_str = json.dumps(data)
    return byte2b64(json_str.encode())

def b642json(b64text: str) -> dict:
    json_str = b642byte(b64text).decode()
    return json.loads(json_str)

def str2b64(text: str) -> str:
    return byte2b64(text.encode())

def b642str(b64text: str) -> str:
    return b642byte(b64text).decode()
