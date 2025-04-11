#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.gdbstub.gdbstub_constants import GDBStubFeature

class GdbStubCallbacks:
    """A class that provides callbacks for the most common commands of GDB stub.
    The callbacks are meant to be called upon reception of a packet and allow to 
    interpret its content in order to extract meaningful data.
    
    e.g. the command `qC` returns current thread id, in the format
    `QCp<pid>.<tid>`, the callback will return an object with
    `pid` and `tid` properties.
    """

    @staticmethod
    def default_callback(resp: bytes):
        """Default callback: just strip control bytes & checksum.
        
        Args:
            resp (bytes): The raw stub reply.
        """
        return resp[1 : -3]

    @staticmethod
    def qc_callback(resp: bytes):
        """Extracts information from the `qC` reply.
        
        Args:
            resp (bytes): The raw stub reply.

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
    def qsupported_callback(resp: bytes) -> list[GDBStubFeature]:
        """Extracts information about stub's supported features.
        
        Args:
            resp (bytes): The raw stub reply.
        
        Returns:
            A list of enabled features, so that they can be disabled
            at runtime.
        """
        escaped = GdbStubCallbacks.default_callback(resp)
        remote_feats = escaped.split(b';')[1:] # Discard `PacketSize`
        
        supported_feats = [feat.value for feat in GDBStubFeature]
        enabled_feats = []
        for feat in supported_feats:
            if feat+b'+' in remote_feats:
                enabled_feats.append(feat)

        return enabled_feats

    def qexec_file_read_callback(resp: bytes):
        """Extracts the full path of the remote running program.
        
        Args:
            resp (bytes): The raw stub reply.
        """
        escaped = GdbStubCallbacks.default_callback(resp)
        
        # strip initial 'l' indicating "no more data to read"
        return escaped[1:]

    def vcont_callback(resp: bytes):
        """Extracts information from a stop reply packet.
        See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Stop-Reply-Packets.html#Stop-Reply-Packets for details.

        Args:
            resp (bytes): The raw stub reply.
        """
        escaped = GdbStubCallbacks.default_callback(resp)
        bundle = lambda: None
        bundle.msgtype = escaped[0]
        if bundle.msgtype == ord(b'T'):
            bundle.signal = int(escaped[1:3])
            additional_info = escaped[3:].split(b';')[0:-1]
            bundle.is_syscall_trap = False
            bundle.is_breakpoint_trap = False
            for infopair in additional_info:
                n, r = infopair.split(b':')
                if n == b'thread':
                    bundle.pid, bundle.tid = [int(el, 16) for el in r[1:].split(b'.')]
                elif n == b'syscall_entry' or n == b'syscall_return':
                    bundle.is_syscall_trap = True
                    bundle.syscall_number = int(r, 16)
            if not bundle.is_syscall_trap:
                bundle.is_breakpoint_trap = True

        elif bundle.msgtype == ord(b'W'):
            bundle.status = int(escaped[1:3], 16)
        elif bundle.msgtype == ord(b'X'):
            bundle.signal = int(escaped[1:3], 16)
        elif bundle.msgtype == ord(b'W'):
            bundle.signal = int(escaped[1:3], 16)
            bundle.tid = int(escaped[4:], 16)

        return bundle

    def vfile_open_callback(resp: bytes):
        """Extracts the file descriptor of the requested file.
        
        Args:
            resp (bytes): The raw stub reply.
        """
        escaped = GdbStubCallbacks.default_callback(resp)
        
        return escaped[1:]
    
    def vfile_pread_callback(resp: bytes):
        """Extracts content of the requested file.
        
        Args:
            resp (bytes): The raw stub reply.
        """
        escaped = GdbStubCallbacks.default_callback(resp)

        bundle = lambda: None
        bundle.nbytes = int(escaped[1:escaped.index(b';')], 16)
        bundle.data = escaped[escaped.index(b';')+1:]
        return bundle