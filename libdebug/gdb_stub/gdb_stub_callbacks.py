#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.gdb_stub.gdb_stub_constants import StubFeatures


class GdbStubCallbacks:
    """A class that provides callbacks for the most common commands of GDB stub.
    The callbacks are meant to be called upon reception of a packet and allow to 
    interpret its content in order to extract meaningful data.
    
    e.g. the command `qC` returns current thread id, in the format
    `QCp<pid>.<tid>`, the callback will return an object with
    `pid` and `tid` properties."""

    @staticmethod
    def default_callback(resp: bytes):
        """Default callback: just strip control bytes & checksum.
        
        Args:
            resp (bytes): The stub reply."""
        return resp[1 : -3]

    @staticmethod
    def qc_callback(resp: bytes):
        """Extracts information from the `qC` reply.
        
        Args:
            resp (bytes): The stub reply.

        Returns:
            tid (int): Thread ID.
            pid (int): Process ID.
        """
        escaped = GdbStubCallbacks.default_callback(resp)

        # Add attributes on-the-fly with lambdas
        pid_tid = lambda: None
        if b'p' in escaped:
            escaped = escaped[3:]
            tmp = escaped.split(b'.')
            pid_tid.pid = int(tmp[0], 16)
            pid_tid.tid = int(tmp[1], 16)
        else:
            escaped = escaped[2:]
            pid_tid.tid = int(escaped, 16)
            pid_tid.pid = None

        return pid_tid
    
    @staticmethod
    def qsupported_callback(resp: bytes):
        """Extracts information about stub's supported features.
        
        Args:
            resp (bytes): The stub reply.
        """
        escaped = GdbStubCallbacks.default_callback(resp)
        remote_feats = escaped.split(b';')[1:] # Discard `PacketSize`
        
        supported_feats = [feat.value for feat in StubFeatures]
        for feat in supported_feats:
            if feat+b'+' not in remote_feats:
                raise RuntimeError(f"Stub doesn't support the following feature: {str(feat)}")
