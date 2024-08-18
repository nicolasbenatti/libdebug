#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.gdb_stub.gdb_stub_callbacks import GdbStubCallbacks
from libdebug.utils.libcontext import libcontext


def gdb_stub_callback_provider(last_cmd: str):
    """Returns the right callback based on what's the last received packet."""
    match last_cmd:
        case b'qC':
            return GdbStubCallbacks.qc_callback
        case _:
            return GdbStubCallbacks.default_callback