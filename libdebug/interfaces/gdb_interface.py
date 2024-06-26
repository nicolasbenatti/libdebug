#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import errno
import os
import signal
import pty
from time import sleep
import tty
from pathlib import Path
import socket

from libdebug.architectures.register_helper import register_holder_provider
from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_map import MemoryMap
from libdebug.data.register_holder import RegisterHolder
from libdebug.data.syscall_hook import SyscallHook
from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.liblog import liblog
from libdebug.state.debugging_context import (
    context_extend_from,
    link_context,
    provide_context,
)
from libdebug.state.debugging_context import DebuggingContext
from libdebug.state.thread_context import ThreadContext
from libdebug.utils import posix_spawn
from libdebug.utils.debugging_utils import normalize_and_validate_address
from libdebug.utils.elf_utils import get_entry_point
from libdebug.utils.pipe_manager import PipeManager
from libdebug.utils.process_utils import (
    disable_self_aslr,
    get_process_maps,
    invalidate_process_cache,
)


QEMU_LOCATION = str(
    (Path("/") / "usr" / "bin" / "qemu-x86_64").resolve()
)

if hasattr(os, "posix_spawn"):
    from os import posix_spawn, POSIX_SPAWN_CLOSE, POSIX_SPAWN_DUP2
else:
    from libdebug.utils.posix_spawn import (
        posix_spawn,
        POSIX_SPAWN_CLOSE,
        POSIX_SPAWN_DUP2,
    )


class GdbStubInterface(DebuggingInterface):
    """The interface used by `_InternalDebugger` to communicate with the `gdb` debugging backend."""

    context: DebuggingContext
    """The debugging context."""

    # hardware_bp_helpers: dict[int, PtraceHardwareBreakpointManager]
    """The hardware breakpoint managers (one for each thread)."""

    process_id: int | None
    """The process ID of the QEMU instance"""

    stub: socket
    """The socket used to connect to the stub"""

    GDB_STUB_PORT: int
    """Default port of the QEMU gdbstub"""

    def __init__(self):
        super().__init__()

        self.context = provide_context(self)

        self.GDB_STUB_PORT = 5000

        if not self.context.aslr_enabled:
            disable_self_aslr()

        self.process_id = 0

        self.hardware_bp_helpers = {}

        self.reset()

    def run(self):
        """Runs the specified process."""
        argv = self.context.argv
        env = self.context.env
        env["QEMU_GDB"] = "5000"

        liblog.debugger("Running %s", argv)

        # Creating pipes for stdin, stdout, stderr
        self.stdin_read, self.stdin_write = os.pipe()
        self.stdout_read, self.stdout_write = pty.openpty()
        self.stderr_read, self.stderr_write = pty.openpty()

        # Setting stdout, stderr to raw mode to avoid terminal control codes interfering with the
        # output
        tty.setraw(self.stdout_read)
        tty.setraw(self.stderr_read)

        child_pid = posix_spawn(
            QEMU_LOCATION,
            [QEMU_LOCATION] + argv,
            env,
            file_actions=[
                # (POSIX_SPAWN_CLOSE, self.stdin_write),
                # (POSIX_SPAWN_CLOSE, self.stdout_read),
                # (POSIX_SPAWN_CLOSE, self.stderr_read),
                # (POSIX_SPAWN_DUP2, self.stdin_read, 0),
                # (POSIX_SPAWN_DUP2, self.stdout_write, 1),
                # (POSIX_SPAWN_DUP2, self.stderr_write, 2),
                # (POSIX_SPAWN_CLOSE, self.stdin_read),
                # (POSIX_SPAWN_CLOSE, self.stdout_write),
                # (POSIX_SPAWN_CLOSE, self.stderr_write),
            ],
            setpgroup=0,
        )

        self.process_id = child_pid
        self.context.process_id = child_pid
        self.context.pipe_manager = self._setup_pipe()
        
        # don't connect to qemu too fast, the stub may not be there yet
        # TODO: better handling
        sleep(0.1)

        # connect to the stub
        self.stub = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.stub.connect(("localhost", self.GDB_STUB_PORT))
        stub_info = self.stub.getpeername()
        print(f"connected to GDB stub at %s:%s" % (stub_info[0], stub_info[1]))

    def cont(self):
        """Continues the execution of the process."""
        # Enable all breakpoints if they were disabled for a single step
        # changed = []

        # for bp in self.context.breakpoints.values():
        #     bp._disabled_for_step = False
        #     if bp._changed:
        #         changed.append(bp)
        #         bp._changed

        # for bp in changed:
        #     if bp.enabled:
        #         self.set_breakpoint(bp, insert=False)
        #     else:
        #         self.unset_breakpoint(bp, delete=False)

        self.stub.send(b"c")
    
    def reset(self):
        pass

    def _set_options(self):
        pass

    def _trace_self(self):
        pass

    def attach(self, pid: int):
        """Attaches to the specified process.

        Args:
            port (int): the port at which the stub is listening.
        """
        # TODO: when attaching to a process with GDB stub, we actually specify
        # the port at which the stub is listening to, not the PID.
        
        self.stub = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.stub.connect(("localhost", self.GDB_STUB_PORT))
        except Exception as e:
            raise Exception("Error when connecting to GDB stub")
        stub_info = self.stub.getpeername()
        self.process_id = pid
        self.context.process_id = pid
        print(f"connected to GDB stub at %s:%s" % (stub_info[0], stub_info[1]))

    def kill(self):
        # terminate emulated process
        self.stub.send(b"k")
        self.stub.close()
        # terminate QEMU instance
        os.kill(self.process_id, signal.SIGKILL)

    def step(self, thread: ThreadContext):
        pass

    def step_until(self, thread: ThreadContext, address: int, max_steps: int):
        pass

    def _setup_pipe(self):
        try:
            os.close(self.stdin_read)
            os.close(self.stdout_write)
            os.close(self.stderr_write)
        except Exception as e:
            # TODO: custom exception
            raise Exception("Closing fds failed: %r" % e)
        return PipeManager(self.stdin_write, self.stdout_read, self.stderr_read)

    def _setup_parent(self, continue_to_entry_point: bool):
        pass

    def get_register_holder(self, thread_id: int) -> RegisterHolder:
        pass

    def wait(self) -> bool:
        pass

    def migrate_to_gdb(self):
        pass

    def migrate_from_gdb(self):
        pass

    def maps(self) -> list[MemoryMap]:
        pass

    def set_breakpoint(self, breakpoint: Breakpoint):
        pass

    def unset_breakpoint(self, breakpoint: Breakpoint):
        pass

    def set_syscall_hook(self, hook: SyscallHook):
        pass

    def unset_syscall_hook(self, hook: SyscallHook):
        pass

    def peek_memory(self, address: int) -> int:
        pass

    def poke_memory(self, address: int, data: int):
        pass
    