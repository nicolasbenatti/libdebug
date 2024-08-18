#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import socket

from libdebug.gdb_stub.gdb_stub_callbacks_helper import gdb_stub_callback_provider


def send_ack(sck: socket):
    sck.send(b'+')

def send_nack(sck: socket):
    sck.send(b'-')

def prepare_stub_packet(data: bytes):
    """Prepares a valid GDB stub packet starting from payload.
    See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Overview.html#Overview for info"""
    payload = b'$' + data + b'#'
    payloadv = [bytes([b]) for b in data]
    checksum = 0

    for b in payloadv:
        checksum = checksum + ord(b)
    checksum = checksum % 256
    hexum = hex(checksum)

    # NOTE: checksum is 1 Byte, but must be expressed as a 2-digit hex number
    return payload + bytes(hexum[2:4], "ascii")

def receive_stub_packet(cmd: str, sck: socket):
    """Handles the reception of a packet from GDB stub.
    See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Overview.html#Overview for info"""
    # receive ACK/NACK
    ack = sck.recv(1)
    if ack == b'-':
        # if NAK received, return empty buffer
        # NOTE: this should never happen if we use
        #       TCP sockets
        return bytes()

    resp = sck.recv(3000)
    send_ack(sck)

    # extract data (or just strip control bytes if callback
    # not available)
    callback = gdb_stub_callback_provider(cmd)
    print(callback)
    data = callback(resp)

    return data