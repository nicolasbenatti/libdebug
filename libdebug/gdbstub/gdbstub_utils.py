#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import socket
import math

from libdebug.gdbstub.gdbstub_constants import (
    GDBStubFeature
)


def send_ack(sck: socket):
    """Sends an acknowledgement to the stub."""
    sck.send(b'+')

def send_nack(sck: socket):
    """Sends a non-acknowledgement to the stub."""
    sck.send(b'-')

def prepare_stub_packet(data: bytes):
    """Prepares a valid GDB stub packet starting from some payload.
    See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Overview.html#Overview for protocol info.
    """
    payload = b'$' + data + b'#'
    payloadv = [bytes([b]) for b in data]
    checksum = 0

    for b in payloadv:
        checksum = checksum + ord(b)
    checksum = checksum % 256

    # NOTE: Checksum is 1 Byte, but must be expressed as a 2-digit hex literal
    return payload + bytes(f"{checksum:02x}", "ascii")

def get_supported_features() -> bytes:
    """Builds a string containing all the supported stub features
    that can be probed (i.e. that you should expect in the stub reply).
    """
    res = b""
    for feat in GDBStubFeature:
        res += feat.value + b"+;"

    return res

def memtox(data: bytes):
    """Encodes binary data escaping not allowed characters.
    See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Overview.html#Binary-Data for more info.
    """
    encoded = bytearray()
    
    for b in data:
        if b in [ord(b'#'), ord(b'$'), ord(b'*'), ord(b'}')]:
            encoded.append(b'}')
            encoded.append(b ^ 0x20)
        else:
            encoded.append(b)
    
    return encoded

def xtomem(data: bytes):
    """Decodes binary data that has been escaped by the stub."""
    decoded = bytearray()
    
    i = 0
    while i < len(data):
        if data[i] == ord(b'}'):
            decoded.append(data[i+1] ^ 0x20)
            i += 1
        else:
            decoded.append(data[i])
        i += 1

    return decoded

def int2hexbstr(n: int, nbytes: int = 0) -> bytes:
    """Converts an integer into a Byte-converted hexstring.

    Args:
        n (int): the number to convert.
        nbytes (int, optional): number of Bytes of the output string. Defaults to 0 (= not specified).
    """
    return bytes(f"{n:0{2*nbytes}x}", 'ascii')

def hexbstr2int_le(hexstr: bytes) -> int:
    """Converts a little-endian hex bytestring into an integer number.
    
    Args:
        bytes (bytes): the hex bystestring in little-endian ordering.
    """
    nbytes = len(hexstr)
    if nbytes not in [8, 16]:
        raise ValueError(f"Cannot convert {int(nbytes/2)}-Byte hex literal to integer: supported widths are 4 and 8 Bytes")

    res = bytearray.fromhex(str(hexstr, 'ascii'))
    res.reverse()

    return int(''.join(f"{n:02x}" for n in res), 16)

def int2hexbstr_le(n: int, nbytes: int) -> bytes:
    """Converts an integer to a little-endian hex bytestring.

    Args:
        n (int): the number to convert.
        nbytes (int): number of Bytes of the output string. Supported value are 4 and 8.
    """
    if nbytes not in [4, 8]:
        raise ValueError(f"Cannot convert {math.ceil(math.log(n)):d}-Byte integer to little-endian hexstring: supported widths are 4 and 8 Bytes")

    hexstr = int2hexbstr(n, nbytes)
    res = bytearray.fromhex(str(hexstr, 'ascii'))
    res.reverse()

    return bytes(''.join(f"{n:02x}" for n in res), 'ascii')

def str2hex(s: str):
    """Converts a string into another string containing its
    ASCII hexadecimal representation.
    
    Args:
        s (str): the string to convert.
    """
    if len(s) == 0:
        raise ValueError("Cannot convert empty string to hex representation")

    return s.encode('ascii').hex()

def bstr2hex(buf: bytes):
    """Converts a binary string into another one containing its hex-encoded bytes.
    
    Args:
        buf (bytes): the binary string to convert.
    """
    if len(buf) == 0:
        raise ValueError("Cannot convert bytestring to hex representation")

    return bytes(''.join([f"{b:x}" for b in buf]), 'ascii')