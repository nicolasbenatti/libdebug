#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from abc import ABC, abstractmethod

from libdebug.data.breakpoint import Breakpoint
from libdebug.state.thread_context import ThreadContext


class HardwareBreakpointManager(ABC):
    """Base class for managing hardware breakpoints.
    This is both architecture and debug-interface independent.

    Attributes:
        thread (ThreadContext): The target thread.
        breakpoint_count (int): The number of hardware breakpoints set.
    """

    def __init__(
        self,
        thread: ThreadContext,
    ):
        self.thread = thread
        self.breakpoint_count = 0

    @abstractmethod
    def install_breakpoint(self, bp: Breakpoint):
        """Installs a hardware breakpoint at the provided location."""
        pass

    @abstractmethod
    def remove_breakpoint(self, bp: Breakpoint):
        """Removes a hardware breakpoint at the provided location."""
        pass

    @abstractmethod
    def available_breakpoints(self) -> int:
        """Returns the number of available hardware breakpoint registers."""
        pass
