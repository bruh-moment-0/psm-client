import requests

_URLBASE = "https://raw.githubusercontent.com/bruh-moment-0/psm-url/refs/heads/main/url.txt"
resp = requests.get(_URLBASE)
APIURL = resp.text.strip()

def apiTunnelAlive():
    try:
        test = requests.get(APIURL, timeout=5)
        if test.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        return False

AUTH_REGISTER = "/auth/register"
AUTH_CHALLENGE = "/auth/challenge"
AUTH_RESPOND = "/auth/respond"
AUTH_PROTECTED = "/auth/protected"

MSG_SEND = "/api/message/send"
MSG_GET = "/api/message/get/{messageid}"
MSG_GET_ID = "/api/message/genid"

GET_USER = "/api/user/{username}"