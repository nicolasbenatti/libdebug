#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.architectures.amd64.amd64_gdb_register_holder import Amd64RegisterInfoParser
from libdebug.gdb_stub.register_parser import RegisterInfoParser
from libdebug.utils.libcontext import libcontext


def register_parser_provider() -> RegisterInfoParser:
    """Returns an instance of the register information parser to be used by the `GdbStubInterface` class."""
    architecture = libcontext.arch

    match architecture:
        case "amd64":
            return Amd64RegisterInfoParser()
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")

