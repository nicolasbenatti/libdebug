#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

class GdbStubCallbacks:
    """A class that provides callbacks for the most common commands of GDB stub.
    The callbacks are meant to be called upon reception of a packet and allow to 
    interpret its content in order to extract meaningful data
    
    e.g. the command `qC` returns current thread id, in the format
    `QCp<pid>.<tid>`, the callback will return an object with
    `pid` and `tid` properties."""

    @staticmethod
    def default_callback(resp: bytes):
        """Default callback: just strip control bytes & checksum."""
        return resp[1 : -3]

    @staticmethod
    def qc_callback(resp: bytes):
        """Extracts information from the `qC` reply.
        tid: process TID
        pid: process PID"""
        resp = GdbStubCallbacks.default_callback(resp)
        
        pid_tid = lambda: None
        if b'p' in resp:
            resp = resp[3:]
            tmp = resp.split(b'.')
            pid_tid.pid = int(tmp[0], 16)
            pid_tid.tid = int(tmp[1], 16)
        else:
            resp = resp[2:]
            resp.tid = int(resp, 16)
            resp.pid = None

        return pid_tid