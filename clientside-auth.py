import os, json, requests
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

SERVER = "http://127.0.0.1:8000"
USER = "alice"
USERFILE = f"client_users/{USER}.json"

os.makedirs("client_users", exist_ok=True)

def load_or_create_user():
    if os.path.exists(USERFILE):
        with open(USERFILE, "r") as f:
            data = json.load(f)
            # recreate key objects from hex
            data['priv_obj'] = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data['private_key']))
            data['pub_obj'] = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(data['public_key']))
            return data

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    data = {
        "username": USER,
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

    # save **only hex strings**, not Python objects
    with open(USERFILE, "w") as f:
        json.dump(data, f, indent=2)

    # create objects for in-memory use
    data['priv_obj'] = priv # pyright: ignore[reportArgumentType]
    data['pub_obj'] = pub # pyright: ignore[reportArgumentType]

    print("[+] Created new Ed25519 keys")
    return data


def get_challenge(username):
    r = requests.post(f"{SERVER}/auth/challenge", json={"username": username})
    r.raise_for_status()
    j = r.json()
    return j["challenge_id"], j["challenge"]

def respond_challenge(user, challenge_str: str):
    sig = user['priv_obj'].sign(challenge_str.encode())
    return sig.hex()

def get_token(username, challenge_id, signature):
    r = requests.post(f"{SERVER}/auth/respond", json={
        "username": username,
        "challenge_id": challenge_id,
        "signature": signature
    })
    r.raise_for_status()
    return r.json()


if __name__ == "__main__":
    user = load_or_create_user()

    cid, challenge = get_challenge(USER)
    print(f"[CLIENT] Challenge ID: {cid}")
    print(f"[CLIENT] Challenge: {challenge}")

    sig = respond_challenge(user, challenge)   # pass only the string
    tokens = get_token(USER, cid, sig)

    print(f"[CLIENT] Tokens: {tokens}")
    r = requests.get(f"{SERVER}/protected",
                     headers={"Authorization": f"Bearer {tokens['access_token']}"})
    print(r.json())
