#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.architectures.amd64.amd64_gdb_hw_bp_helper import (
    Amd64GdbHardwareBreakpointManager,
)
from libdebug.architectures.ptrace_hardware_breakpoint_manager import (
    PtraceHardwareBreakpointManager,
)
from libdebug.state.thread_context import ThreadContext
from libdebug.utils.libcontext import libcontext


def gdb_hardware_breakpoint_manager_provider(
    thread: ThreadContext,
) -> PtraceHardwareBreakpointManager:
    """Returns an instance of the hardware breakpoint manager to be used by the `_InternalDebugger` class."""
    architecture = libcontext.arch

    match architecture:
        case "amd64":
            return Amd64GdbHardwareBreakpointManager(thread)
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")
