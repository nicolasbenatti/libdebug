#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from typing import Callable

from libdebug.architectures.amd64.amd64_ptrace_register_holder import (
    Amd64PtraceRegisterHolder,
)
from libdebug.data.register_holder import PtraceRegisterHolder
from libdebug.utils.libcontext import libcontext


def ptrace_register_holder_provider(
    register_file: object,
    getter: Callable[[], object] | None = None,
    setter: Callable[[object], None] | None = None,
) -> PtraceRegisterHolder:
    """Returns an instance of the register holder to be used by the `_InternalDebugger` class."""
    architecture = libcontext.arch

    match architecture:
        case "amd64":
            return Amd64PtraceRegisterHolder(register_file)
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")
