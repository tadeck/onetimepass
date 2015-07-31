"""
Tests for ``onetimepass`` module
"""
import six
import time
import timecop
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

    def test_variable_length_in_possible_tokens(self):
        """
        Check if length is respected when verifying tokens
        """
        # When default is length of 6:
        self.assertFalse(_is_possible_token(1234567))
        # Longer version:
        self.assertTrue(_is_possible_token(1234567, token_length=7))
        # Shorter version, when longer is allowed:
        self.assertTrue(_is_possible_token(123456, token_length=7))
        # Invalid token with correct length:
        self.assertFalse(_is_possible_token('abcdefg', token_length=7))


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

    def test_ignoring_spaces_in_secret(self):
        """
        Check if spaces are skipped during generation of the token
        """
        def chunks(original, size):
            """
            Split original string into chunks sized as requested in ``size``
            parameter. Returns iterator yielding single chunks.
            Similar to: http://stackoverflow.com/a/312464/548696
            :param original: original string (almost any iterable really)
            :type original: str or unicode
            :param size: requested size of chunks
            :type size: int
            """
            for i in six.moves.range(0, len(original), size):
                yield original[i:i+size]

        # Simple generation without spaces:
        secret = 'MFRGGZDFMZTWQ2LK'
        # Simple generation with spaces:
        secret_with_spaces = ' '.join(chunks(secret, 3))
        # Check if was properly sliced:
        self.assertEqual(5, secret_with_spaces.count(' '))

        # Both spaceless secret and secret with spaces should give the same
        self.assertEqual(
            get_hotp(secret, 1),
            get_hotp(secret_with_spaces, 1),
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
        with timecop.freeze(time.time()):
            hotp = get_hotp(secret=secret, intervals_no=int(time.time())//30,)
            totp = get_totp(secret=secret)
            self.assertEqual(hotp, totp)

    def test_generating_current_totp_as_string(self):
        """
        Check if the TOTP also works seamlessly when generated as string
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with timecop.freeze(time.time()):
            hotp = get_hotp(
                secret=secret,
                intervals_no=int(time.time())//30,
                as_string=True,
            )
            totp = get_totp(secret=secret, as_string=True)
            self.assertEqual(hotp, totp)

    def test_generating_totp_at_specific_clock(self):
        """
        check if the totp can be generated for a specific clock
        which is basically the same as hotp
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with timecop.freeze(time.time()):
            hotp = get_hotp(secret=secret, intervals_no=int(time.time())//30,)
            totp = get_totp(secret=secret, clock=None)
            self.assertEqual(hotp, totp)

            # hotp intervals minus 1
            hotp = get_hotp(
                secret=secret,
                intervals_no=int(time.time())//30-1,
            )
            # totp 30 seconds in the past
            totp = get_totp(secret=secret, clock=(int(time.time())-30))
            self.assertEqual(hotp, totp)

    def test_validating_totp_with_a_window(self):
        """
        validate if a totp token falls within a certain window
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with timecop.freeze(time.time()):
            totp = get_totp(secret=secret, clock=(int(time.time()-30)))
            self.assertFalse(valid_totp(totp, secret))
            self.assertTrue(valid_totp(totp, secret, window=1))

            totp = get_totp(secret=secret, clock=(int(time.time()+30)))
            self.assertFalse(valid_totp(totp, secret))
            self.assertTrue(valid_totp(totp, secret, window=1))

            totp = get_totp(secret=secret, clock=(int(time.time()-60)))
            self.assertFalse(valid_totp(totp, secret))
            self.assertFalse(valid_totp(totp, secret, window=1))
            self.assertTrue(valid_totp(totp, secret, window=2))


class TotpValidityTestCase(TestCase):
    """
    TOTP token validation checks
    """
    def test_validating_totp_for_same_secret(self):
        """
        Check if validating TOTP generated for the same secret works
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with timecop.freeze(time.time()):
            self.assertTrue(valid_totp(get_totp(secret), secret))

    def test_validating_invalid_totp_for_same_secret(self):
        """
        Test case when the same secret is used, but the token differs
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with timecop.freeze(time.time()):
            self.assertFalse(valid_totp(get_totp(secret)+1, secret))

    def test_validating_correct_hotp_as_totp(self):
        """
        Check if valid TOTP will work as HOTP - should not work, unless for
        very big interval number (matching Unix epoch timestamp)
        """
        secret = b'MFRGGZDFMZTWQ2LK'
        with timecop.freeze(time.time()):
            self.assertFalse(valid_totp(get_hotp(secret, 1), secret))
