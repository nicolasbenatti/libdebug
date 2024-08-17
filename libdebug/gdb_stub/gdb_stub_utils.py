#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import socket


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

def receive_stub_packet(sck: socket):
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

    # strip control bytes & checksum
    resp = resp[1 : -3]

    return resp