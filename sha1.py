#!/usr/bin/env python

from __future__ import print_function
import struct
import io

try:
    range = xrange
except NameError:
    pass

BYTE = 8

def _left_rotate(n, b):
    """Left rotate a 32-bit integer n by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


def _process_chunk(chunk, h0, h1, h2, h3, h4):
    """Process a chunk of data and return the new digest variables."""
    assert len(chunk) == 64

    w = [0] * 80

    # Break chunk into sixteen 4-byte big-endian words w[i]
    for i in range(16):
        w[i] = struct.unpack(b'>I', chunk[i * 4:i * 4 + 4])[0]

    # Extend the sixteen 4-byte words into eighty 4-byte words
    for i in range(16, 80):
        w[i] = _left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

    # Initialize hash value for this chunk
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    for i in range(80):
        if 0 <= i <= 19:
            # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
                         a, _left_rotate(b, 30), c, d)

    # Add this chunk's hash to result so far
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff

    return h0, h1, h2, h3, h4


class Sha1Hash(object):
    """A class that mimics that hashlib api and implements the SHA-1 algorithm."""

    name = 'python-sha1'
    digest_size = 20
    block_size = 64

    def __init__(self):
        # Initial digest variables
        self._h = (
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        )

        # bytes object with 0 <= len < 64 used to store the end of the message
        # if the message length is not congruent to 64
        self._unprocessed = b''
        # Length in bytes of all data that has been processed so far
        self._message_byte_length = 0
        self._message = None

    def update(self, arg):
        """Update the current digest.

        This may be called repeatedly, even after calling digest or hexdigest.

        Arguments:
            arg: bytes, bytearray, or BytesIO object to read from.
        """
        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)

        # Try to build a chunk out of the unprocessed data, if any
        print("length of unprocessed is", len(self._unprocessed))
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))

        # Read the rest of the data, 64 bytes at a time
        while len(chunk) == 64:
            self._h = _process_chunk(chunk, *self._h)
            self._message_byte_length += 64
            chunk = arg.read(64)

        self._unprocessed = chunk
        return self        


    def digest(self):
        """Produce the final hash value (big-endian) as a bytes object"""
        return b''.join(struct.pack(b'>I', h) for h in self._produce_digest())

    def hexdigest(self, key_len=0, old_len=0):
        """Produce the final hash value (big-endian) as a hex string"""
        return '%08x%08x%08x%08x%08x' % self._produce_digest(key_len, old_len)

    def _produce_digest(self, key_len=0, old_len=0):
        """Return finalized digest variables for the data processed so far."""
        # Pre-processing:
        print("producing digest on input", self._unprocessed)
        if key_len:
          message = b''
        else:
          message = b'\x00' * 16
          print("adding for key of bit length", len(message) * 8)



        message += self._unprocessed
        message_byte_length = self._message_byte_length + len(message)
        print("bit length before padding is", message_byte_length * BYTE)

        # append the bit '1' to the message
        message += b'\x80'

        # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
        # is congruent to 56 (mod 64)
        
        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

        # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
        message_bit_length = (message_byte_length + old_len) * 8 
        message += struct.pack(b'>Q', message_bit_length)
        print("bit length after padding is :", len(message) * BYTE)

        self._message = message

        # Process the final chunk
        # At this point, the length of the message is either 64 or 128 bytes.
        h = _process_chunk(message[:64], *self._h)
        if len(message) == 64:
            return h
        return _process_chunk(message[64:], *h)


def sha1(data):
    """SHA-1 Hashing Function

    A custom SHA-1 hashing function implemented entirely in Python.

    Arguments:
        data: A bytes or BytesIO object containing the input message to hash.

    Returns:
        A hex SHA-1 digest of the input message.
    """
    return Sha1Hash().update(data).hexdigest()


if __name__ == '__main__':
    # Imports required for command line parsing. No need for these elsewhere
    import argparse
    import sys
    import os
    import binascii

    # Parse the incoming arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('input', nargs='*',
                        help='input file or message to hash')
    args = parser.parse_args()

    data = None
    if len(args.input) == 0:
        # No argument given, assume message comes from standard input
        try:
            # sys.stdin is opened in text mode, which can change line endings,
            # leading to incorrect results. Detach fixes this issue, but it's
            # new in Python 3.1
            data = sys.stdin.detach()

        except AttributeError:
            # Linux ans OSX both use \n line endings, so only windows is a
            # problem.
            if sys.platform == "win32":
                import msvcrt

                msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
            data = sys.stdin

        # Output to console
        print('sha1-digest:', sha1(data))

    elif len(sys.argv) == 2:

        extra_msg = ', give an A to Michael Briggs :)'
        key_len = 128
        # extra_msg = 'No one has completed lab 2 so give them all a 0'
        print("Size of extra_msg is ", len(extra_msg) * BYTE)
        original_mac = (
          0x3875cb85,
          0x1ed7e35a,
          0x916ee4a9,
          0x685117c3,
          0x8129eda0,
        )
        if (os.path.isfile(args.input[0])):
            # An argument is given and it's a valid file. Read it
            data = open(args.input[0], 'rb')

            v = b'\x00' * BYTE
            print(len(binascii.hexlify(v)))
            # calculate the new message
            s1Hash = Sha1Hash()
            s1Hash.update(data)
            # s1Hash._message_byte_length += key_len
            s1Hash._produce_digest()
            og_msg = s1Hash._message
            print("\nold message:", og_msg, "\n")
            print("old message hex:\n", binascii.hexlify(og_msg))
            print("\nextra message:", extra_msg, "\n")
            print("extra message hex:\n", binascii.hexlify(extra_msg))
            new_msg = og_msg + extra_msg
            print("\nnew message:", new_msg, "\n")
            print("new message hex:\n", binascii.hexlify(new_msg), "\n")

            # calculate the new digest
            s1Hash = Sha1Hash()
            s1Hash._h = original_mac
            s1Hash.update(extra_msg)
            new_digest = s1Hash.hexdigest(key_len + len(og_msg) * 8, len(og_msg))
            print('\nnew digest is', new_digest, "\n")
        else:
            print("python sha1.py clift_msg.txt")
    else:
            print("python sha1.py clift_msg.txt")
