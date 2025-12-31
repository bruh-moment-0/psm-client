# quantum.py for post quantum functions (02/11/2025)
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



from typing import Optional, Tuple, Any
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
