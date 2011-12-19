"""
onetimepass module is designed to work for one-time passwords - HMAC-based and
time-based. It is compatible with Google Authenticator application and
applications based on it.

@version: 0.1
@author: Tomasz Jaskowski
@contact: http://github.com/tadeck
@license: GNU Lesser General Public License (LGPL)
"""

import hmac
import base64
import struct
import hashlib
import time

__author__ = "Tomasz Jaskowski <tadeck@gmail.com>"
__date__ = "18 December 2011"
__version__ = "0.1"
__version_info__ = (0, 1)
__license__ = "GNU Lesser General Public License (LGPL)"


def get_hotp_token(secret, intervals_no):
    """Get HMAC-based one-time password on the basis of given secret and
    interval number.

    Keyword arguments:
    secret          -- the base32-encoded string acting as secret key
    intervals_no    -- interval number used for generating different tokens, it
    is incremented with each use

    >>> get_hotp_token('MZXW633PN5XW6MZX', 1)
    448400
    >>> get_hotp_token('MZXW633PN5XW6MZX', 2)
    656122
    """
    key = base64.b32decode(secret)
    msg = struct.pack(">Q", intervals_no)
    hmac_digest = hmac.new(key, msg, hashlib.sha1).digest()
    o = ord(hmac_digest[19]) & 15
    token_base = struct.unpack(">I", hmac_digest[o:o + 4])[0] & 0x7fffffff
    token = token_base % 1000000
    return token


def get_totp_token(secret):
    """Get time-based one-time password on the basis of given secret and time.

    Keyword arguments:
    secret  -- the base32-encoded string acting as secret key

    >>> get_hotp_token('MZXW633PN5XW6MZX', int(time.time())//30) == \
        get_totp_token('MZXW633PN5XW6MZX')
    True
    """
    return get_hotp_token(secret, intervals_no=int(time.time()) // 30)

__all__ = [
    'get_hotp_token',
    'get_totp_token'
]
