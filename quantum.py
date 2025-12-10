# quantum.py for post quantum functions
# 02/11/2025

from typing import Optional, Tuple, Any
from data import BASEDIR
import os

def file_exists(path):
    return os.path.isfile(path)

def remove_file(path):
    os.remove(path)

firstbootflag = os.path.join(BASEDIR, "firstboot.flag")
requirements = os.path.join(BASEDIR, "requirements.txt")
if file_exists(firstbootflag):
    print("Thank you for using Private Safe Messaging.")
    print("In the first startup, there will be many operations, which will happen now.")
    print("This will not happen again if you do not remove the _oqs folder.")
    print("While setting up, do NOT close this window, or your installation might get corrupted!")
    print("When the setup is over, the program will continue as normal.")
    print("Press ENTER to acknowledge.")
    _ = input("")
    remove_file(firstbootflag)
    print("installing dependencies.")
    os.system(f"pip install -r {requirements}")
    print("installed dependencies.")
    print("installing liboqs-python...")
    os.system("git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python")
    os.system("cd liboqs-python && pip install .")
    print("ok, liboqs-python is ready! calling oqs...")

import oqs # pyright: ignore[reportMissingImports]

# sign algos:
# print(oqs.get_enabled_sig_mechanisms())
# kem algos:
# print(oqs.get_enabled_kem_mechanisms())

ML_DSA_ALGO = "ML-DSA-65" # ML-DSA-44, ML-DSA-65, ML-DSA-87
KEM_ALGO = "Kyber768" # ("Kyber512", "Kyber768", "Kyber1024")

def sign_obj_create(privkey: Optional[bytes] = None) -> oqs.Signature:
    sig = oqs.Signature(ML_DSA_ALGO, secret_key=privkey)
    return sig

def kem_obj_create(privkey: Optional[bytes] = None) -> oqs.KeyEncapsulation:
    kem_obj = oqs.KeyEncapsulation(KEM_ALGO, secret_key=privkey)
    return kem_obj

def create_key_pair(obj: Any) -> Tuple[bytes, bytes]:
    pubkey: bytes = obj.generate_keypair()
    privkey: bytes = obj.export_secret_key()
    return pubkey, privkey

def sign(sign_obj: oqs.Signature, message: bytes) -> bytes:
    signature: bytes = sign_obj.sign(message)
    return signature

def verify(sign_obj: oqs.Signature, message: bytes, signature: bytes, pubkey: bytes) -> bool:
    valid: bool = sign_obj.verify(message, signature, pubkey)
    return valid

def encap(kem_obj: oqs.KeyEncapsulation, pubkey: bytes) -> Tuple[bytes, bytes]:
    ciphertext, sharedsecret = kem_obj.encap_secret(pubkey)
    return ciphertext, sharedsecret

def decap(kem_obj: oqs.KeyEncapsulation, ciphertext: bytes) -> bytes:
    sharedsecret: bytes = kem_obj.decap_secret(ciphertext)
    return sharedsecret