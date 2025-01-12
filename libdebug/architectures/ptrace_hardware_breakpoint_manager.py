#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from typing import Callable

from libdebug.state.thread_context import ThreadContext
from libdebug.architectures.hardware_breakpoint_manager import HardwareBreakpointManager


class PtraceHardwareBreakpointManager(HardwareBreakpointManager):
    """An architecture-independent interface for managing hardware breakpoints,
    specifically for the `ptrace` debugging backend.

    Attributes:
        thread (ThreadContext): The target thread.
        peek_user (callable): A function that reads a number of bytes from the target thread registers.
        poke_user (callable): A function that writes a number of bytes to the target thread registers.
        breakpoint_count (int): The number of hardware breakpoints set.
    """

    def __init__(
        self,
        thread: ThreadContext,
        peek_user: Callable[[int, int], int],
        poke_user: Callable[[int, int, int], None],
    ):
        super().__init__(thread)
        self.peek_user = peek_user
        self.poke_user = poke_user
