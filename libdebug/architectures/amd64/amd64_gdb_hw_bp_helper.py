#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.architectures.gdb_hardware_breakpoint_manager import (
    GdbHardwareBreakpointManager,
)
from libdebug.data.breakpoint import Breakpoint
from libdebug.liblog import liblog
from libdebug.state.thread_context import ThreadContext
from libdebug.gdbstub.gdbstub_utils import (
    prepare_stub_packet,
    receive_stub_packet,
    int2hexbstr
)
from libdebug.state.debugging_context import provide_context

AMD64_DBREGS_COUNT = 4


class Amd64GdbHardwareBreakpointManager(GdbHardwareBreakpointManager):
    """A hardware breakpoint manager for the amd64 architecture,
    specifically for the `GDB` debugging backend.

    Attributes:
        thread (ThreadContext): The target thread.
        breakpoint_count (int): The number of hardware breakpoints set.
        context (DebuggingContext): The global debugging context, used to communicate with GDB stub.
        breakpoint_registers (dict[str, Breakpoint]): A dictionary holding the current
                                                      breakpoint (if any) associated with the register.
    """

    def __init__(
        self,
        thread: ThreadContext,
    ):
        super().__init__(thread)
        self.context = provide_context(self)

    def install_breakpoint(self, bp: Breakpoint):
        """Installs a hardware breakpoint at the provided location."""
        if self.breakpoint_count >= AMD64_DBREGS_COUNT:
            raise RuntimeError("No more hardware breakpoints available.")

        len = int2hexbstr(bp.length if bp.length > 1 else 0)

        cmd = b'Z1,'+int2hexbstr(bp.address)+b','+len
        self.context.debugging_interface.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.context.debugging_interface.stub)

        if resp == b'OK':
            liblog.debugger(f"Hardware breakpoint installed at address %#x" % bp.address) 
        else:
            raise RuntimeError(f"Cannot insert hw breakpoint at address %#x" % bp.address)

        self.breakpoint_count += 1

    def remove_breakpoint(self, bp: Breakpoint):
        """Removes a hardware breakpoint at the provided location."""
        if self.breakpoint_count <= 0:
            raise RuntimeError("No more hardware breakpoints to remove.")

        len = int2hexbstr(bp.length if bp.length > 1 else 0)

        cmd = b'z1,'+int2hexbstr(bp.address)+b','+len
        self.context.debugging_interface.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.context.debugging_interface.stub)

        if resp == b'OK':
            liblog.debugger(f"Removed hardware breakpoint at address %#x" % bp.address) 
        else:
            raise RuntimeError(f"Cannot remove hw breakpoint at address %#x" % bp.address)

        self.breakpoint_count -= 1

    def available_breakpoints(self) -> int:
        """Returns the number of available hardware breakpoint registers."""
        return AMD64_DBREGS_COUNT - self.breakpoint_count
