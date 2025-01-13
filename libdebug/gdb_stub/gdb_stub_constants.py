#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from enum import Enum

MAX_PACKET_LEN = 4096 # Bytes
MAX_PAYLOAD_LEN = MAX_PACKET_LEN - 5 # Not counting delimiters and checksum

MAIN_TARGET_DESCRIPTION_FILENAME = "target.xml"

class StubCommands(bytes, Enum):
    """Supported commands."""

    GET_SUPPORTED_FEATS = b"qSupported:"
    GET_PID_TID = b"qC"
    HALT_REASON = b"?"
    TDESCR_READ = b"qXfer:features:read:"
    REG_READ_ALL = b"g"
    REG_WRITE = b"P"
    MEM_READ = b"m"
    MEM_WRITE = b"M"
    SET_SW_BP = b"Z0,"
    SET_HW_BP = b"Z1,"
    UNSET_SW_BP = b"z0,"
    UNSET_HW_BP = b"z1,"
    CONTINUE = b"vCont;c:"
    STEP = b"vConst;s:"
    KILL = b"vKill;"

class StubFeatures(bytes, Enum):
    """Supported features; Features can be either query commands or indications on stub's capabilities (e.g. threading support).
    See https://sourceware.org/gdb/current/onlinedocs/gdb.html/General-Query-Packets.html#qSupported for a comprehensive list."""

    TDESCR_READ_FEATURE = b"qXfer:features:read"
    EXECFILE_READ_FEATURE = b'qXfer:exec-file:read'
    VCONT_FEATURE = b"vContSupported"
    MULTIPROC_FEATURE = b"multiprocess"
