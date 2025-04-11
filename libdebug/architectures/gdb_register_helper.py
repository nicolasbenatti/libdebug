#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.architectures.amd64.amd64_gdb_register_holder import (
    Amd64GdbRegisterHolder,
)
from libdebug.data.register_holder import GdbRegisterHolder
from libdebug.gdbstub.register_parser import RegisterInfo
from libdebug.utils.libcontext import libcontext


def gdb_register_holder_provider(
    register_file: object,
    register_info: dict[str, RegisterInfo],
    register_blob: bytearray
) -> GdbRegisterHolder:
    """Returns an instance of the register holder to be used by the `_InternalDebugger` class."""
    architecture = libcontext.arch

    match architecture:
        case "amd64":
            return Amd64GdbRegisterHolder(register_file, register_info, register_blob)
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")

