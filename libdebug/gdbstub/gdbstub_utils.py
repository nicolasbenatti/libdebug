#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import socket
import math
import errno

from libdebug.gdbstub.gdbstub_callbacks_helper import gdb_stub_callback_provider
from libdebug.liblog import liblog
from libdebug.gdbstub.gdbstub_constants import (
    GDBSTUB_MAX_PAYLOAD_LEN,
    GDBSTUB_ORDINARY_PACKET_INITIAL_BYTE,
    GDBSTUB_REPLY_UNSUPPORTED,
    GDBSTUB_command_semantics,
    GDBSTUB_qemu_support_matrix,
    GDBStubFeature,
    GDBStubCommand
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

def send_stub_packet(stub: socket, data: bytes, session_enabled_feats: list[GDBStubFeature]):
    """Sends a packet to the GDB stub.
    See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Overview.html#Overview for protocol info.
    
    Args:
        stub (socket): Connection to the stub.
        data (bytes): Data to send.
        session_enabled_feats (list): List of features enabled in the current session.
    
    Raises:
        RuntimeError: The packet is not supported in the current session.
    """
    command = None
    for cmd in GDBStubCommand:
        if data.startswith(cmd):
            command = cmd
            break
    else:
        # NOTE: we should never reach this but, just to be sure...
        raise ValueError(f"Command not supported by libdebug: \'{command}\'")

    # Get the feature from which the current command depends
    if command in GDBSTUB_command_semantics.keys():
        command_feature = GDBSTUB_command_semantics[command]
        if command_feature not in session_enabled_feats:
            min_qemu_version = GDBSTUB_qemu_support_matrix[command_feature]
            raise ValueError(f"Command not supported in the current session: \'{command}\'. QEMU >= {min_qemu_version} required.")
    else:
        liblog.debugger(f"Command \'{command}\' relies on a feature that cannot be probed")

    stub.send(prepare_stub_packet(data))

def receive_stub_packet(stub: socket, cmd: str):
    """Receives a packet from the GDB stub.
    See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Overview.html#Overview for protocol info.

    Args:
        stub (socket): Connection to the stub.
        data (bytes): Data to send.

    Returns:
        Tuple (stub_reply, is_cmd_supported -> bool)
    """
    # Receive ACK/NACK
    ack = stub.recv(1)
    if ack == b'-':
        # If NAK received, return empty buffer
        # NOTE: this should never happen with TCP sockets
        return bytes()

    resp = stub.recv(GDBSTUB_MAX_PAYLOAD_LEN)
    if len(resp) == 0:
        raise RuntimeError("Got empty reply, connection is probably closed")
    if resp[0] == ord(GDBSTUB_ORDINARY_PACKET_INITIAL_BYTE):
        send_ack(stub)
    
    # Handle errors and unsupported commands
    if resp == GDBSTUB_REPLY_UNSUPPORTED:
        liblog.debugger(f"GDBSTUB: unsupported command \'{cmd}\'")
        return bytes(), False
    elif resp[1] == ord(b'E'):
        errcode = int(resp[1:3], 10)
        liblog.error(f"GDBSTUB: received error code \'{errcode}\' [{errno.errorcode[errcode]}]")
        return b"E: " + errno.errorcode[errcode], True

    # Extract data (or just strip control Bytes if callback not available)
    callback = gdb_stub_callback_provider(cmd)
    data = callback(resp)

    return data, True

def get_supported_features() -> bytes:
    """Builds a string containing all the supported stub features
    that can be probed (i.e. that you should expect in the stub reply).
    """
    res = b""
    for feat in GDBStubFeature:
        res += feat.value + b"+;"

    return res

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