import hmac
import hashlib
import struct

# Copyright (C) 2011, Matteo Panella. All rights reserved.
#
# This software is licensed under the same terms as the original
# Java reference code in RFC 4226.
#
# This is a work derived from OATH HOTP Algorithm.
#
# The author makes no representations concerning either
# the merchantability of this software or the suitability of this
# software for any particular purpose.
#
# It is provided "as is" without express or implied warranty
# of any kind and THE AUTHOR EXPRESSLY DISCLAIMS ANY
# WARRANTY OR LIABILITY OF ANY KIND relating to this software.
#
# These notices must be retained in any copies of any part of this
# documentation and/or software.

# Copyright notice for original Java code:
# Copyright (C) 2004, OATH.  All rights reserved.
#
# License to copy and use this software is granted provided that it
# is identified as the "OATH HOTP Algorithm" in all material
# mentioning or referencing this software or this function.
#
# License is also granted to make and use derivative works provided
# that such works are identified as
#  "derived from OATH HOTP algorithm"
# in all material mentioning or referencing the derived work.
#
# OATH (Open AuTHentication) and its members make no
# representations concerning either the merchantability of this
# software or the suitability of this software for any particular
# purpose.
#
# It is provided "as is" without express or implied warranty
# of any kind and OATH AND ITS MEMBERS EXPRESSaLY DISCLAIMS
# ANY WARRANTY OR LIABILITY OF ANY KIND relating to this software.
#
# These notices must be retained in any copies of any part of this
# documentation and/or software.

__all__ = ['hotp']

# Checksum algorithm defined in RFC4226
_doubleDigits = (0, 2, 4, 6, 8, 1, 3, 5, 7, 9)
def _calcChecksum(num, digits):
    doubleDigit = True
    total = 0
    while digits > 0:
        digits -= 1
        digit = num % 10
        num /= 10
        if doubleDigit:
            digit = _doubleDigits[digit]
        total += digit
        doubleDigit = not doubleDigit
    result = total % 10
    if result > 0:
        result = 10 - result
    return result

def hotp(secret, movingFactor, codeDigits=6, addChecksum=False, truncationOffset=None):
    """
    Perform RFC4226 HOTP generation from given secret (shared secret) and movingFactor.

    secret: the shared secret
    movingFactor: a counter, current time or other value that changes on a per-use basis (64 bit integer)
    codeDigits: number of digits in the OTP, not including the checksum (if any)
    addChecksum: True if a checksum digit should be appended to the OTP, False otherwise (default: False)
    truncationOffset: the offset into the MAC output to begin truncation. If this value is out of the
                      range 0 .. 15 or is None, then dynamic truncation will be used.
    Returns a numeric string in base 10 (the OTP).

    Test vectors (RFC4226, Appendix D):
    >>> hotp("12345678901234567890", 0)
    '755224'
    >>> hotp("12345678901234567890", 1)
    '287082'
    >>> hotp("12345678901234567890", 2)
    '359152'
    >>> hotp("12345678901234567890", 3)
    '969429'
    >>> hotp("12345678901234567890", 4)
    '338314'
    >>> hotp("12345678901234567890", 5)
    '254676'
    >>> hotp("12345678901234567890", 6)
    '287922'
    >>> hotp("12345678901234567890", 7)
    '162583'
    >>> hotp("12345678901234567890", 8)
    '399871'
    >>> hotp("12345678901234567890", 9)
    '520489'
    """
    digits = codeDigits + 1 if addChecksum else codeDigits
    movingFactor = struct.pack('!q', movingFactor)
    hs = hmac.new(secret, movingFactor, hashlib.sha1).digest()
    if truncationOffset is None or truncationOffset < 0 or truncationOffset > 15:
        # Perform dynamic truncation (per RFC4226)
        # The offset is taken from the lowest 4 bits of hs[19]
        truncationOffset = ord(hs[19]) & 0xf

    # Starting from the offset, 4 bytes are extracted and converted to an
    # unsigned 32 bit integer (big endian) and then masked with 7fffffff
    bin_code = struct.unpack('!I', hs[truncationOffset:truncationOffset+4])[0] & 0x7fffffff
    # OTP is the value modulo 10^codeDigits
    otp = bin_code % 10**codeDigits
    if addChecksum:
        otp = (otp * 10) + _calcChecksum(otp, codeDigits)
    result = '%d' % (otp,)
    return '0' * (digits - len(result)) + result

