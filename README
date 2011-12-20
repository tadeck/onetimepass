What is OneTimePass
-------------------

OneTimePass (actually `onetimepass`) is a module for generating one-time
passwords, namely HOTPs (HMAC-based one-time passowords) and TOTPs (time-based
one-time passwords). They are used eg. within Google Authenticator application
for Android or iPhone.

How to use OneTimePass
----------------------

You can use this module in the following way:

1. Install module (download it into your application's directory or into modules
directory)
2. To get time-based token you invoke it like that:

        my_token = get_totp_token('MZXW633PN5XW6MZX')

3. To get HMAC-based token you invoke it like that:

        my_token = get_hotp_token('MZXW633PN5XW6MZX', intervals_no=3)

    where `intervals_no` is the number of the current trial (if checking on the
server, you have to check several values, higher than the last successful one,
determined for previous successful authentications).
