#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.gdbstub.gdbstub_callbacks import GdbStubCallbacks
from libdebug.gdbstub.gdbstub_constants import GDBStubCommands


def gdb_stub_callback_provider(last_cmd: bytes):
    """Returns the right callback based on what's the last received packet."""
    # Extract command type
    for supported_cmd in GDBStubCommands:
        if last_cmd.startswith(supported_cmd.value):
            prefix = supported_cmd.value
            break
    else:
        prefix = b""

    match prefix:
        case GDBStubCommands.GDBSTUB_GET_SUPPORTED_FEATS:
            return GdbStubCallbacks.qsupported_callback
        case GDBStubCommands.GDBSTUB_EXECFILE_READ:
            return GdbStubCallbacks.qexec_file_read_callback
        case GDBStubCommands.GBSTUB_VFILE_OPEN:
            return GdbStubCallbacks.vfile_open_callback
        case GDBStubCommands.GDBSTUB_VFILE_PREAD:
            return GdbStubCallbacks.vfile_pread_callback
        case GDBStubCommands.GDBSTUB_GET_PID_TID:
            return GdbStubCallbacks.qc_callback
        case GDBStubCommands.GDBSTUB_CONTINUE | GDBStubCommands.GDBSTUB_STEP:
            return GdbStubCallbacks.vcont_callback
        case _:
            return GdbStubCallbacks.default_callback