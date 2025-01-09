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
from libdebug.gdb_stub.gdb_stub_utils import (
    prepare_stub_packet,
    receive_stub_packet
)
from libdebug.state.debugging_context import DebuggingContext

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
        context: DebuggingContext
    ):
        super().__init__(thread, context)

    def install_breakpoint(self, bp: Breakpoint):
        """Installs a hardware breakpoint at the provided location."""
        if self.breakpoint_count >= AMD64_DBREGS_COUNT:
            raise RuntimeError("No more hardware breakpoints available.")

        if bp.length > 1:
            len = bytes(hex(bp.length), 'ascii')[2:]
        else:
            len = b'0'

        cmd = b'Z1,'+bytes(hex(bp.address), 'ascii')+b','+len
        self.context.debugging_interface.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.context.debugging_interface.stub)
        print(resp)

        if resp == b'OK':
            liblog.debugger(f"Hardware breakpoint installed at address %#x" % bp.address) 
        else:
            raise RuntimeError(f"Cannot insert hw breakpoint at address %#x" % bp.address)

        self.breakpoint_count += 1

    def remove_breakpoint(self, bp: Breakpoint):
        """Removes a hardware breakpoint at the provided location."""
        if self.breakpoint_count <= 0:
            raise RuntimeError("No more hardware breakpoints to remove.")

        if bp.length > 1:
            len = bytes(hex(bp.length), 'ascii')[2:]
        else:
            len = b'0'

        cmd = b'z1,'+bytes(hex(bp.address), 'ascii')+b','+len
        self.context.debugging_interface.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.context.debugging_interface.stub)
        print(resp)

        if resp == b'OK':
            liblog.debugger(f"Removed hardware breakpoint at address %#x" % bp.address) 
        else:
            raise RuntimeError(f"Cannot remove hw breakpoint at address %#x" % bp.address)

        self.breakpoint_count -= 1

    def available_breakpoints(self) -> int:
        """Returns the number of available hardware breakpoint registers."""
        return AMD64_DBREGS_COUNT - self.breakpoint_count
