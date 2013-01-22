"""
onetimepass module is designed to work for one-time passwords - HMAC-based and
time-based. It is compatible with Google Authenticator application and
applications based on it.

@version: 0.1.2
@author: Tomasz Jaskowski
@contact: http://github.com/tadeck
@license: GNU Lesser General Public License (LGPL)

>>> secret = 'MFRGGZDFMZTWQ2LK'
>>> get_hotp(secret, 1) == 765705
True
>>> get_hotp(secret, 1, as_string=True) == '765705'
True
>>> valid_hotp(get_hotp(secret, 123), secret)
123
>>> valid_hotp(get_hotp(secret, 123), secret, last=123)
False
>>> valid_totp(get_totp(secret), secret)
True
>>> valid_totp(get_totp(secret)+1, secret)
False
>>> valid_hotp(get_totp(secret), secret)
False
>>> valid_totp(get_hotp(secret, 1), secret)
False
"""

import hmac
import base64
import struct
import hashlib
import time

__author__ = "Tomasz Jaskowski <tadeck@gmail.com>"
__date__ = "22 January 2013"
__version__ = "0.1.2"
__version_info__ = (0, 1, 2)
__license__ = "GNU Lesser General Public License (LGPL)"


def _is_possible_token(token):
    """Determines if given value is acceptable as a token. Used when validating
    tokens.

    Currently allows only numeric tokens no longer than 6 chars.

    >>> _is_possible_token(123456)
    True
    >>> _is_possible_token('123456')
    True
    >>> _is_possible_token('abcdef')
    False
    >>> _is_possible_token('12345678')
    False
    """
    return str(token).isdigit() and len(str(token)) <= 6


def get_hotp(secret, intervals_no, as_string=False):
    """Get HMAC-based one-time password on the basis of given secret and
    interval number.

    Keyword arguments:
    secret          -- the base32-encoded string acting as secret key
    intervals_no    -- interval number used for generating different tokens, it
    is incremented with each use
    as_string       -- True if result should be padded string, False otherwise

    >>> get_hotp('MFRGGZDFMZTWQ2LK', intervals_no=1)
    765705
    >>> get_hotp('MFRGGZDFMZTWQ2LK', intervals_no=2)
    816065
    >>> get_hotp('MFRGGZDFMZTWQ2LK', intervals_no=2, as_string=True)
    '816065'
    """
    try:
        key = base64.b32decode(secret)
    except (TypeError):
        raise TypeError('Incorrect secret')
    msg = struct.pack(">Q", intervals_no)
    hmac_digest = hmac.new(key, msg, hashlib.sha1).digest()
    try:
        o = ord(hmac_digest[19]) & 15
    except TypeError as e:
        """ We're likely running on Python 3 and don't need to do ord()"""
        o = hmac_digest[19] & 15
    token_base = struct.unpack(">I", hmac_digest[o:o + 4])[0] & 0x7fffffff
    token = token_base % 1000000
    if as_string:
        return '{:06d}'.format(token)
    else:
        return token


def get_totp(secret, as_string=False):
    """Get time-based one-time password on the basis of given secret and time.

    Keyword arguments:
    secret       -- the base32-encoded string acting as secret key
    as_string    -- True if result should be padded string, False otherwise

    >>> get_hotp('MFRGGZDFMZTWQ2LK', int(time.time())//30) == \
        get_totp('MFRGGZDFMZTWQ2LK')
    True
    >>> get_hotp('MFRGGZDFMZTWQ2LK', int(time.time())//30) == \
        get_totp('MFRGGZDFMZTWQ2LK', as_string=True)
    False
    """
    interv_no = int(time.time()) // 30
    return get_hotp(secret, intervals_no=interv_no, as_string=as_string)


def valid_hotp(token, secret, last=1, trials=1000):
    """Check if given token is valid for given secret. Return interval number
    that was successful, or False if not found.

    Keyword arguments:
    token     -- token being checked
    secret    -- secret for which token is checked
    last      -- last used interval (start checking with next one)
    trials    -- number of intervals to check after 'last'

    >>> secret = 'MFRGGZDFMZTWQ2LK'
    >>> valid_hotp(713385, secret, last=1, trials=5)
    4
    >>> valid_hotp(865438, secret, last=1, trials=5)
    False
    >>> valid_hotp(713385, secret, last=4, trials=5)
    False
    """
    if not _is_possible_token(token):
        return False
    for i in xrange(last + 1, last + trials + 1):
        if get_hotp(secret=secret, intervals_no=i) == int(token):
            return i
    return False


def valid_totp(token, secret):
    """Check if given token is valid time-based one-time password for given
    secret.

    Keyword arguments:
    token    -- token which is being checked
    secret   -- secret for which the token is being checked

    >>> secret = 'MFRGGZDFMZTWQ2LK'
    >>> token = get_totp(secret)
    >>> valid_totp(token, secret)
    True
    >>> valid_totp(token+1, secret)
    False
    >>> token = get_totp(secret, as_string=True)
    >>> valid_totp(token, secret)
    True
    >>> valid_totp(token+'1', secret)
    False
    """
    return _is_possible_token(token) and int(token) == get_totp(secret)

__all__ = [
    'get_hotp',
    'get_totp',
    'valid_hotp',
    'valid_totp'
]
