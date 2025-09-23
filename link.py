import requests
import warnings

# default:
# DEMOMODE = False
DEMOMODE = True

_URLBASE = "https://raw.githubusercontent.com/bruh-moment-0/psm-url/refs/heads/main/url.txt"

if not DEMOMODE:
    try:
        resp = requests.get(_URLBASE)
    except:
        warnings.warn(
            "WARNING: UNSAFE ADAPTER IS INITIATED BECAUSE OF NETWORK LEVEL PROBLEMS. WARNING, THIS ADAPTER IS NOT SAFE AND IS VULNERABLE TO MITM ATTACKS. YOUR ONLY LINE OF DEFENCE IS THE ENCRYPTION ALGORITHMS AND YOUR KEYS. DO NOT SHARE ANY FILES FROM /storage"
        , RuntimeWarning)
        import unsafeadapter # worst adapter ever but fixes CA problems and other unsafe connection caused bugs
        # best way to fight something unsafe is to do something more unsafe i guess
        resp = requests.get(_URLBASE)
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
MSG_GET = "api/message/get/" # {messageid}
MSG_GET_ID = "api/message/genid"

GET_USER = "api/user/" # {username}