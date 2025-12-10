# CONSTANTS FOR PRIVATE SAFE MESSAGING
# DO NOT MODIFY IF YOU DONT KNOW WHAT YOU ARE DOING

# for almost all python files
# version
VERSION = "CLIENT V2.2.0 (built 11:10 GMT+0 28/11/2025)"

# for link.py, hashchecker.py
# default:
# DEMOMODE = False
# used only when the api is tested locally.
DEMOMODE = False

# for main.py
# default:
# MULTIPLE_PORTS = False
# allows multiple port checking.
MULTIPLE_PORTS = True

# for main.py
# default:
# PORT_BASE = 8080
# the default port
PORT_BASE = 8080

# for link.py and hashchecker.py
# for getting the api url and hashes
URLBASE = "https://raw.githubusercontent.com/bruh-moment-0/psm-util/refs/heads/main/"

# for main.py
# Normally False but if this is set to True, better leave it be True...
# ONLY FOR REALLY IMPORTANT SECURITY PROBLEMS
# DO NOT CHANGE THIS IF ITS SET TO TRUE.
NOTREADY = False

# for data.py
# file size limit of 1 MB
# do not change this with the hopes of sending bigger files, server will still decline it
# so this is purely client side handling
FILESIZELIMIT = 1 * 1024 * 1024

# for connect.py
# how much the token lasts
# do not change this, its in sync with the server
TOKEN_BUFFER_TIME = 60