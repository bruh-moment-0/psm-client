from const import * # constants
import requests
import warnings

if not DEMOMODE:
    try:
        resp = requests.get(URLBASE + "url.txt")
    except:
        warnings.warn("WARNING: UNSAFE ADAPTER WILL BE INITIATED BECAUSE OF NETWORK-LEVEL PROBLEMS." \
        "THIS ADAPTER IS NOT SAFE AND IS VULNERABLE TO MITM ATTACKS. YOUR ONLY LINE OF DEFENSE IS YOUR ENCRYPTION ALGORITHMS AND KEYS." \
        "DO NOT SHARE ANY FILES FROM /storage.", RuntimeWarning)
        print("\nWARNING: AN UNSAFE ADAPTER WILL BE INITIATED BECAUSE OF NETWORK-LEVEL PROBLEMS.")
        print("THIS ADAPTER IS NOT SAFE AND IS VULNERABLE TO MAN-IN-THE-MIDDLE ATTACKS.")
        print("YOUR ONLY LINE OF DEFENSE IS YOUR ENCRYPTION ALGORITHMS AND YOUR KEYS.")
        print("DO NOT SHARE ANY FILES FROM /storage.")
        print("\nUSER, IT IS NOW TIME FOR YOU TO MAKE A CHOICE.")
        print("\nTHE RISKS OF PROCEEDING ARE AS FOLLOWS:")
        print("MAN-IN-THE-MIDDLE (MITM) ATTACKS")
        print("TRAFFIC INTERCEPTION AND EAVESDROPPING")
        print("FAKE SERVERS IMPERSONATING REAL ONES")
        print("TAMPERED OR MALICIOUS RESPONSES")
        print("PASSWORDS, TOKENS, AND DATA BEING STOLEN")
        print("EXECUTING MALICIOUS PAYLOADS WITHOUT DETECTION")
        print("\nIF YOU PROCEED, THIS MODULE WILL DISABLE ALL SSL/TLS SECURITY.")
        print("\nIF YOU UNDERSTAND THE RISKS AND WANT TO CONTINUE, PRESS ENTER BELOW.")
        print("IF YOU DO NOT WANT TO USE THIS APPLICATION IN AN UNSAFE STATE, PRESS Ctrl+C OR CLOSE THE PROGRAM NOW.")
        input()
        import unsafeadapter # unsafe fallback to bypass CA failures
        resp = requests.get(URLBASE + "url.txt")
    APIURL = resp.text.strip() + "/"
else:
    APIURL = "http://127.0.0.1:8000/"

def apiTunnelAlive():
    try:
        test = requests.get(APIURL, timeout=5)
        if test.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        return False

AUTH_REGISTER = "auth/register"
AUTH_CHALLENGE = "auth/challenge"
AUTH_RESPOND = "auth/respond"
AUTH_PROTECTED = "auth/protected"
AUTH_REMOVE = "auth/remove"
MSG_SEND = "api/message/send"
MSG_GET = "api/message/get/"
MSG_GET_ID = "api/message/genid"
GET_USER = "api/user/"