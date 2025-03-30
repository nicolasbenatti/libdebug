#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.gdb_stub.gdb_stub_callbacks import GdbStubCallbacks
from libdebug.gdb_stub.gdb_stub_constants import StubCommands


def gdb_stub_callback_provider(last_cmd: bytes):
    """Returns the right callback based on what's the last received packet."""
    # Extract command type
    for supported_cmd in StubCommands:
        if last_cmd.startswith(supported_cmd.value):
            prefix = supported_cmd.value
            break
    else:
        prefix = b""

    match prefix:
        case StubCommands.GET_SUPPORTED_FEATS:
            return GdbStubCallbacks.qsupported_callback
        case StubCommands.EXECFILE_READ:
            return GdbStubCallbacks.qexec_file_read_callback
        case StubCommands.GET_PID_TID:
            return GdbStubCallbacks.qc_callback
        case _:
            return GdbStubCallbacks.default_callback