"""
onetimepass module is designed to work for one-time passwords - HMAC-based and
time-based. It is compatible with Google Authenticator application and
applications based on it.

@version: 1.0.1
@author: Tomasz Jaskowski
@contact: http://github.com/tadeck
@license: MIT

>>> secret = b'MFRGGZDFMZTWQ2LK'
>>> get_hotp(secret, 1) == 765705
True
>>> get_hotp(secret, 1, as_string=True) == b'765705'
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

import base64
import hashlib
import hmac
import six
import struct
import time

__author__ = 'Tomasz Jaskowski <tadeck@gmail.com>'
__date__ = '31 July 2015'
__version_info__ = (1, 0, 1)
__version__ = '%s.%s.%s' % __version_info__
__license__ = 'MIT'


def _is_possible_token(token, token_length=6):
    """Determines if given value is acceptable as a token. Used when validating
    tokens.

    Currently allows only numeric tokens no longer than 6 chars.

    :param token: token value to be checked
    :type token: int or str
    :param token_length: allowed length of token
    :type token_length: int
    :return: True if can be a candidate for token, False otherwise
    :rtype: bool

    >>> _is_possible_token(123456)
    True
    >>> _is_possible_token(b'123456')
    True
    >>> _is_possible_token(b'abcdef')
    False
    >>> _is_possible_token(b'12345678')
    False
    """
    if not isinstance(token, bytes):
        token = six.b(str(token))
    return token.isdigit() and len(token) <= token_length


def get_hotp(
        secret,
        intervals_no,
        as_string=False,
        casefold=True,
        digest_method=hashlib.sha1,
        token_length=6,
):
    """
    Get HMAC-based one-time password on the basis of given secret and
    interval number.

    :param secret: the base32-encoded string acting as secret key
    :type secret: str or unicode
    :param intervals_no: interval number used for getting different tokens, it
        is incremented with each use
    :type intervals_no: int
    :param as_string: True if result should be padded string, False otherwise
    :type as_string: bool
    :param casefold: True (default), if should accept also lowercase alphabet
    :type casefold: bool
    :param digest_method: method of generating digest (hashlib.sha1 by default)
    :type digest_method: callable
    :param token_length: length of the token (6 by default)
    :type token_length: int
    :return: generated HOTP token
    :rtype: int or str

    >>> get_hotp(b'MFRGGZDFMZTWQ2LK', intervals_no=1)
    765705
    >>> get_hotp(b'MFRGGZDFMZTWQ2LK', intervals_no=2)
    816065
    >>> result = get_hotp(b'MFRGGZDFMZTWQ2LK', intervals_no=2, as_string=True)
    >>> result == b'816065'
    True
    """
    if isinstance(secret, six.string_types):
        # It is unicode, convert it to bytes
        secret = secret.encode('utf-8')
    # Get rid of all the spacing:
    secret = secret.replace(b' ', b'')
    try:
        key = base64.b32decode(secret, casefold=casefold)
    except (TypeError):
        raise TypeError('Incorrect secret')
    msg = struct.pack('>Q', intervals_no)
    hmac_digest = hmac.new(key, msg, digest_method).digest()
    ob = hmac_digest[19] if six.PY3 else ord(hmac_digest[19])
    o = ob & 15
    token_base = struct.unpack('>I', hmac_digest[o:o + 4])[0] & 0x7fffffff
    token = token_base % (10 ** token_length)
    if as_string:
        # TODO: should as_string=True return unicode, not bytes?
        return six.b('{{:0{}d}}'.format(token_length).format(token))
    else:
        return token


def get_totp(
        secret,
        as_string=False,
        digest_method=hashlib.sha1,
        token_length=6,
        interval_length=30,
        clock=None,
):
    """Get time-based one-time password on the basis of given secret and time.

    :param secret: the base32-encoded string acting as secret key
    :type secret: str
    :param as_string: True if result should be padded string, False otherwise
    :type as_string: bool
    :param digest_method: method of generating digest (hashlib.sha1 by default)
    :type digest_method: callable
    :param token_length: length of the token (6 by default)
    :type token_length: int
    :param interval_length: length of TOTP interval (30 seconds by default)
    :type interval_length: int
    :param clock: time in epoch seconds to generate totp for, default is now
    :type clock: int
    :return: generated TOTP token
    :rtype: int or str

    >>> get_hotp(b'MFRGGZDFMZTWQ2LK', int(time.time())//30) == \
        get_totp(b'MFRGGZDFMZTWQ2LK')
    True
    >>> get_hotp(b'MFRGGZDFMZTWQ2LK', int(time.time())//30) == \
        get_totp(b'MFRGGZDFMZTWQ2LK', as_string=True)
    False
    """
    if clock is None:
        clock = time.time()
    interv_no = int(clock) // interval_length
    return get_hotp(
        secret,
        intervals_no=interv_no,
        as_string=as_string,
        digest_method=digest_method,
        token_length=token_length,
    )


def valid_hotp(
        token,
        secret,
        last=1,
        trials=1000,
        digest_method=hashlib.sha1,
        token_length=6,
):
    """Check if given token is valid for given secret. Return interval number
    that was successful, or False if not found.

    :param token: token being checked
    :type token: int or str
    :param secret: secret for which token is checked
    :type secret: str
    :param last: last used interval (start checking with next one)
    :type last: int
    :param trials: number of intervals to check after 'last'
    :type trials: int
    :param digest_method: method of generating digest (hashlib.sha1 by default)
    :type digest_method: callable
    :param token_length: length of the token (6 by default)
    :type token_length: int
    :return: interval number, or False if check unsuccessful
    :rtype: int or bool

    >>> secret = b'MFRGGZDFMZTWQ2LK'
    >>> valid_hotp(713385, secret, last=1, trials=5)
    4
    >>> valid_hotp(865438, secret, last=1, trials=5)
    False
    >>> valid_hotp(713385, secret, last=4, trials=5)
    False
    """
    if not _is_possible_token(token, token_length=token_length):
        return False
    for i in six.moves.xrange(last + 1, last + trials + 1):
        token_candidate = get_hotp(
            secret=secret,
            intervals_no=i,
            digest_method=digest_method,
            token_length=token_length,
        )
        if token_candidate == int(token):
            return i
    return False


def valid_totp(
        token,
        secret,
        digest_method=hashlib.sha1,
        token_length=6,
        interval_length=30,
        clock=None,
        window=0,
):
    """Check if given token is valid time-based one-time password for given
    secret.

    :param token: token which is being checked
    :type token: int or str
    :param secret: secret for which the token is being checked
    :type secret: str
    :param digest_method: method of generating digest (hashlib.sha1 by default)
    :type digest_method: callable
    :param token_length: length of the token (6 by default)
    :type token_length: int
    :param interval_length: length of TOTP interval (30 seconds by default)
    :type interval_length: int
    :param clock: time in epoch seconds to generate totp for, default is now
    :type clock: int
    :param window: compensate for clock skew, number of intervals to check on
        each side of the current time. (default is 0 - only check the current
        clock time)
    :type window: int (positive)
    :return: True, if is valid token, False otherwise
    :rtype: bool

    >>> secret = b'MFRGGZDFMZTWQ2LK'
    >>> token = get_totp(secret)
    >>> valid_totp(token, secret)
    True
    >>> valid_totp(token+1, secret)
    False
    >>> token = get_totp(secret, as_string=True)
    >>> valid_totp(token, secret)
    True
    >>> valid_totp(token + b'1', secret)
    False
    """
    if _is_possible_token(token, token_length=token_length):
        if clock is None:
            clock = time.time()
        for w in range(-window, window+1):
            if int(token) == get_totp(
                secret,
                digest_method=digest_method,
                token_length=token_length,
                interval_length=interval_length,
                clock=int(clock)+(w*interval_length)
            ):
                return True
    return False

__all__ = [
    'get_hotp',
    'get_totp',
    'valid_hotp',
    'valid_totp'
]
