"""
Tests for ``onetimepass`` module
"""
import six
import time
from unittest import TestCase

from onetimepass import (
    _is_possible_token, get_hotp, get_totp, valid_hotp, valid_totp,
)


class PreliminaryChecksTestCase(TestCase):
    """
    Test for assessing potential validity of tokens, aimed at limiting data
    processing to validating only non-malformed tokens.
    """
    def test_is_possible_token_helper(self):
        """
        Checks ``_is_possible_token`` helper method for valid behaviour
        """
        # Properly formatted tokens:
        # integer
        self.assertTrue(_is_possible_token(123456))
        # bytes
        self.assertTrue(_is_possible_token(b'123456'))
        # unicode
        self.assertTrue(_is_possible_token(six.u('123456')))

        # token with invalid characters
        self.assertFalse(_is_possible_token(b'abcdef'))
        # token being too long
        self.assertFalse(_is_possible_token(b'12345678'))

        # similar cases as above, but for unicode
        self.assertFalse(_is_possible_token(six.u('abcdef')))
        self.assertFalse(_is_possible_token(six.u('12345678')))


class HotpGenerationTestCase(TestCase):
    """
    Test generating HOTP tokens.
    """
    def test_hotp_generation_from_bytes_secret(self):
        """
        Test simple generation of HOTP token
        """
        # Simple generation from bytes
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertEqual(get_hotp(secret, 1), 765705)

    def test_hotp_generation_from_unicode_secret(self):
        """
        Check if HOTP is properly generated for unicode secrets
        """
        # Simple generation from unicode
        secret = six.u('MFRGGZDFMZTWQ2LK')
        self.assertEqual(get_hotp(secret, 1), 765705)

    def test_returning_hotp_as_string(self):
        """
        Check if properly returns string when asked
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertEqual(get_hotp(secret, 1, as_string=True), b'765705')

    def test_generation_for_different_intervals(self):
        """
        Check if the HOTP changes with different intervals properly
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertEqual(get_hotp(secret, intervals_no=1), 765705)
        self.assertEqual(get_hotp(secret, intervals_no=2), 816065)

        self.assertEqual(
            get_hotp(secret, intervals_no=2, as_string=True),
            b'816065',
        )


class HotpValidityTestCase(TestCase):
    """
    Check valid_hotp() function
    """
    def test_checking_hotp_validity_without_range(self):
        """
        Check if validating HOTP without giving any interval works properly
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertTrue(valid_hotp(get_hotp(secret, 123), secret))

    def test_checking_hotp_validity_for_unicode_secret(self):
        """
        Validity check should also work if secret passed to valid_hotp is
        unicode.
        """
        secret = six.u('MFRGGZDFMZTWQ2LK')
        self.assertTrue(valid_hotp(get_hotp(secret, 123), secret))

    def test_validating_correct_hotp_after_exhaustion(self):
        """
        Validating token created for old interval number should fail
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        # Act as if the given token was created for previous interval
        self.assertFalse(valid_hotp(get_hotp(secret, 123), secret, last=123))

    def test_validating_correct_totp_as_hotp(self):
        """
        Check if valid TOTP will work as HOTP - should not work, unless for
        very big interval number (matching Unix epoch timestamp)
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertFalse(valid_hotp(get_totp(secret), secret))

    def test_retrieving_proper_interval_from_validator(self):
        """
        Check, if returns valid interval when checking the valid HOTP
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        totp = 713385
        result = valid_hotp(totp, secret, last=1, trials=5)
        # Should be 4, as HOTP is valid for 4th interval
        self.assertEqual(result, 4)
        # Re-generate HOTP for this specific interval and check again
        self.assertEqual(get_hotp(secret, intervals_no=4), totp)

    def test_hotp_for_range_preceding_match(self):
        """
        Check behaviour of validation of values that precede the proper
        interval value
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertFalse(valid_hotp(713385, secret, last=1, trials=2))


class TotpGenerationTestCase(TestCase):
    """
    TOTP generation test
    """
    def test_generating_current_totp_and_validating(self):
        """
        Check if TOTP generated for current time is the same as manually
        created HOTP for proper interval
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        hotp = get_hotp(secret=secret, intervals_no=int(time.time())//30,)
        totp = get_totp(secret=secret)
        self.assertEqual(hotp, totp)

    def test_generating_current_totp_as_string(self):
        """
        Check if the TOTP also works seamlessly when generated as string
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        hotp = get_hotp(
            secret=secret,
            intervals_no=int(time.time())//30,
            as_string=True,
        )
        totp = get_totp(secret=secret, as_string=True)
        self.assertEqual(hotp, totp)


class TotpValidityTestCase(TestCase):
    """
    TOTP token validation checks
    """
    def test_validating_totp_for_same_secret(self):
        """
        Check if validating TOTP generated for the same secret works
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertTrue(valid_totp(get_totp(secret), secret))

    def test_validating_invalid_totp_for_same_secret(self):
        """
        Test case when the same secret is used, but the token differs
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertFalse(valid_totp(get_totp(secret)+1, secret))

    def test_validating_correct_hotp_as_totp(self):
        """
        Check if valid TOTP will work as HOTP - should not work, unless for
        very big interval number (matching Unix epoch timestamp)
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        self.assertFalse(valid_totp(get_hotp(secret, 1), secret))
