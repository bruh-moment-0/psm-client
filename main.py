# oh boy oh boy here we go.
# api was 100x easier than this shit
# or atleast thats my speculation ofc

import json # you guessed it, the best db ever
import requests # we gonna use this ALOT
from pydantic import BaseModel
from link import * # custom lib for link/url control
from data import * # custom lib for file control
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# === Schemas ===
class UserClassModelCLI(BaseModel):
    username: str
    publickey_kyber: str
    publickey_ed25519: str

class UserClassModelAPI(BaseModel):
    username: str
    publickey_kyber: str
    publickey_ed25519: str

# === Functions ===
def post(url, json):
    resp = requests.post(url, json=json)
    return resp.json()

def create_user(username):
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    data = {
        "username": username,
        "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "private_key": priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ).hex(),
        "public_key": pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex(),
    }
    with open(os.path.join(USERDIR, f"{username}_challenge.json"), "w") as f:
        json.dump(data, f, indent=2)
    data["priv_obj"] = priv
    data["pub_obj"] = pub
    return data

def load_user(username):
    with open(os.path.join(USERDIR, f"{username}_challenge.json"), "r") as f:
        data = json.load(f)
    data = {
        "priv_obj": ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["private_key"])),
        "pub_obj": ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(data["public_key"]))
    }
    return data