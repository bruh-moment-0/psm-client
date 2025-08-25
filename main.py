# oh boy oh boy here we go.
# api was 100x easier than this shit
# or atleast thats my speculation ofc

import json # you guessed it, the best db ever
import requests # we gonna use this ALOT
from pydantic import BaseModel
from link import * # custom lib for link/url control

# === Schemas ===
class UserClassModel(BaseModel):
    username: str
    publickey_kyber: str
    publickey_ed25519: str

# === Functions ===
def post(url, json):
    resp = requests.post(url, json=json)
    return resp.json()



user = UserClassModel(username="alice", publickey_kyber="abcd1234...hex...", publickey_ed25519="deadbeef...hex...")

resp = post("http://localhost:8000/auth/register", user.dict())
print(resp)
