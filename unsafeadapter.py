# WARNING, THIS ADAPTER IS NOT SAFE AND IS VULNERABLE TO MITM ATTACKS.
# DO NOT USE THIS IF NOT ABSOLUTELY NECESSARY!!!

import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
import ssl
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class UnsafeAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

session = requests.Session()
session.mount("https://", UnsafeAdapter())
requests.get = session.get
requests.post = session.post