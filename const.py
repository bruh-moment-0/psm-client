# constants of Private Safe Messaging Client
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



# CONSTANTS FOR PRIVATE SAFE MESSAGING
# DO NOT MODIFY IF YOU DONT KNOW WHAT YOU ARE DOING

# for link.py
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

# for link.py
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
