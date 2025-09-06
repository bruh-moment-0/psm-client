import requests

# default:
# DEMOMODE = False
DEMOMODE = True

_URLBASE = "https://raw.githubusercontent.com/bruh-moment-0/psm-url/refs/heads/main/url.txt"
resp = requests.get(_URLBASE)
APIURL = resp.text.strip() if not DEMOMODE else "http://127.0.0.1:8000/"

def apiTunnelAlive():
    try:
        test = requests.get(APIURL, timeout=5)
        if test.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        return False

AUTH_REGISTER = "/auth/register" # used
AUTH_CHALLENGE = "/auth/challenge" # used
AUTH_RESPOND = "/auth/respond" # used
AUTH_PROTECTED = "/auth/protected" # used

MSG_SEND = "/api/message/send"
MSG_GET = "/api/message/get/" # {messageid}
MSG_GET_ID = "/api/message/genid"

GET_USER = "/api/user/" # {username}