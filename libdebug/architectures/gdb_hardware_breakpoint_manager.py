#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Nicolas Benatti. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.state.thread_context import ThreadContext
from libdebug.architectures.hardware_breakpoint_manager import HardwareBreakpointManager
from libdebug.state.debugging_context import DebuggingContext


class GdbHardwareBreakpointManager(HardwareBreakpointManager):
    """An architecture-independent interface for managing hardware breakpoints,
    specific to the `gdbstub` debugging backend.

    Attributes:
        thread (ThreadContext): The target thread.
        context (DebuggingContext): The global debugging context, used to communicate with GDB stub.
        breakpoint_count (int): The number of hardware breakpoints set.
    """

    def __init__(
        self,
        thread: ThreadContext,
    ):
        super().__init__(thread)