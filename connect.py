# The internet requests code of Private Safe Messaging Client
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



from link import * # custom
from quantum import sign
from data import str2byte, byte2b64
from typing import Tuple, Dict, Any, Optional
import requests
import time

tok: Optional[Dict[str, Any]] = None # token

def make_request(userdata: Dict[str, Any], method: str, url: str, **kwargs) -> requests.Response:
    headers = kwargs.pop('headers', {}).copy()
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

def is_tokenexpiring_soon(userdata, token: str, token_exp_time_override: int = 0) -> bool:
    if token_exp_time_override == 0 or token_exp_time_override == None:
        exp_time = check_tokenexpiration(userdata, token)
    else:
        exp_time = token_exp_time_override
    if exp_time is None:
        return True
    return time.time() + TOKEN_BUFFER_TIME >= exp_time

def ensure_valid_token(userdata: Dict[str, Any], current_token: str = "") -> Tuple[str, int | None]:
    global tok
    token_exp = check_tokenexpiration(userdata, current_token)
    if current_token and not is_tokenexpiring_soon(userdata, current_token, token_exp_time_override=token_exp): # pyright: ignore[reportArgumentType]
        return current_token, token_exp
    tok = create_token(userdata)
    return tok["tokens"]["access_token"], tok["exp"]

def make_authenticated_request(method: str, url: str, userdata: Dict[str, Any], current_token: str = "", **kwargs) -> requests.Response:
    global tok
    token, _ = ensure_valid_token(userdata, current_token)
    headers = kwargs.get('headers', {})
    headers["Authorization"] = f"Bearer {token}"
    kwargs['headers'] = headers
    if method in ["GET", "POST"]:
        response = make_request(userdata, method, url, **kwargs)
    else:
        raise ValueError(f"Unsupported HTTP method: {method}")
    if response.status_code == 401:
        print("token failed or expired. forcing a new token and retrying once...")
        fresh_token, _ = ensure_valid_token(userdata, "")
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
    token, _ = ensure_valid_token(userdata, current_token)
    return token

def get_challenge(userdata: Dict[str, Any], username: str) -> Tuple[str, str]:
    response = make_request(userdata, "POST", url=APIURL+AUTH_CHALLENGE, json={"username": username}).json()
    return response["challenge_id"], response["challenge"]

def respond_challenge(userdata: Dict[str, Any], challenge_str: str):
    sign_obj = userdata["ram"]["sign_token_obj"]
    sig_bytes = sign(sign_obj, str2byte(challenge_str))
    return byte2b64(sig_bytes)

def get_token(userdata: Dict[str, Any], username: str, challenge_id, signature):
    return make_request(userdata, "POST", url=APIURL+AUTH_RESPOND, json={"username": username, "challenge_id": challenge_id, "signature": signature}).json()

def create_token(userdata: Dict[str, Any]) -> Dict[str, Any]:
    cid, challenge = get_challenge(userdata, userdata["user"]["username"])
    sig = respond_challenge(userdata, challenge)
    tokens = get_token(userdata, userdata["user"]["username"], cid, sig)
    r = requests.get(APIURL + AUTH_PROTECTED, headers={"Authorization": f"Bearer {tokens['access_token']}"}).json()
    data = {
        "tokens": tokens,
        "exp": r["exp"]
    }
    return data
