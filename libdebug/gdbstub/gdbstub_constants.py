#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from enum import Enum

GDBSTUB_DEFAULT_PORT = 3333
GDBSTUB_MAX_PACKET_LEN = 4096 # Bytes
GDBSTUB_MAX_PAYLOAD_LEN = GDBSTUB_MAX_PACKET_LEN - 5 # Not counting delimiters and checksum
GDBSTUB_ORDINARY_PACKET_INITIAL_BYTE = b'$'
GDBSTUB_NOTIFICATION_PACKET_INITIAL_BYTE = b'%'
GDBSTUB_REPLY_UNSUPPORTED = b'$#00'

GDBSTUB_MAIN_TARGET_DESCRIPTION_FILENAME = "target.xml"

class GDBStubCommand(bytes, Enum):
    """Supported commands."""
    GDBSTUB_GET_SUPPORTED_FEATS = b"qSupported:"
    GDBSTUB_GET_PID_TID = b"qC"
    GDBSTUB_HALT_REASON = b"?"
    GDBSTUB_TDESCR_READ = b"qXfer:features:read:"
    GDBSTUB_EXECFILE_READ = b"qXfer:exec-file:read:"
    GDBSTUB_REG_READ_ALL = b"g"
    GDBSTUB_REG_WRITE = b"P"
    GDBSTUB_MEM_READ = b"m"
    GDBSTUB_MEM_WRITE = b"M"
    GDBSTUB_SET_SW_BP = b"Z0,"
    GDBSTUB_SET_HW_BP = b"Z1,"
    GDBSTUB_UNSET_SW_BP = b"z0,"
    GDBSTUB_UNSET_HW_BP = b"z1,"
    GDBSTUB_CONTINUE = b"vCont;c:"
    GDBSTUB_STEP = b"vCont;s:"
    GDBSTUB_KILL = b"vKill;"
    GDBSTUB_VFILE_SETFS = b"vFile:setfs:"
    GBSTUB_VFILE_OPEN = b"vFile:open:"
    GDBSTUB_VFILE_PREAD = b"vFile:pread:"

class GDBStubFeature(bytes, Enum):
    """Supported features. Features can be either query commands or indications on stub's capabilities (e.g. threading support).
    See https://sourceware.org/gdb/current/onlinedocs/gdb.html/General-Query-Packets.html#qSupported for a comprehensive list."""
    GDBSTUB_TDESCR_READ_FEATURE = b"qXfer:features:read"
    GDBSTUB_EXECFILE_READ_FEATURE = b'qXfer:exec-file:read'
    GDBSTUB_VCONT_FEATURE = b"vContSupported"
    GDBSTUB_MULTIPROC_FEATURE = b"multiprocess"
    GDBSTUB_CATCH_SYSCALLS = b"QCatchSyscalls"
