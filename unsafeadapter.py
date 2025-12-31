# The unsafe internet adapter code of Private Safe Messaging Client
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



# WARNING, THIS ADAPTER IS NOT SAFE AND IS VULNERABLE TO MITM ATTACKS.
# DO NOT USE THIS IF NOT ABSOLUTELY NECESSARY!!!

# NOTICE TO READER: this is only activated if your internet connection is being controlled (school, library networks etc.) and disable all cert failsafes
# which allows the IT managers to be able to read the requests. however, the critical information is still being encrypted and is safe. without this,
# requests in those limited networks dont sadly work.

import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
import ssl
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TotallyUnsafeAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs["ssl_context"] = ctx
        kwargs["assert_hostname"] = False
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs["ssl_context"] = ctx
        kwargs["assert_hostname"] = False
        return super().proxy_manager_for(*args, **kwargs)

# globally replace HTTPS adapter
session = requests.Session()
session.mount("https://", TotallyUnsafeAdapter())

requests.get = session.get
requests.post = session.post
requests.request = session.request
