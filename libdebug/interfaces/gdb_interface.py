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

from libdebug.architectures.gdb_hardware_breakpoint_manager import (
    GdbHardwareBreakpointManager,
)
from libdebug.architectures.gdb_hardware_breakpoint_provider import (
    gdb_hardware_breakpoint_manager_provider,
)
from libdebug.architectures.register_helper import register_holder_provider
from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_map import MemoryMap
from libdebug.data.register_holder import RegisterHolder
from libdebug.architectures.amd64.amd64_gdb_register_holder import Amd64GdbRegisterHolder
from libdebug.gdb_stub.register_parser_helper import register_parser_provider
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
from libdebug.gdb_stub.gdb_stub_utils import (
    send_ack,
    prepare_stub_packet,
    receive_stub_packet,
    int2hexbstr
)
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
    """The interface used by `_InternalDebugger` to communicate with the `GDB` debugging backend."""

    context: DebuggingContext
    """The debugging context."""

    hardware_bp_helpers: dict[int, GdbHardwareBreakpointManager]
    """The hardware breakpoint managers (one for each thread)."""

    process_id: int | None
    """The process ID of the QEMU instance"""

    stub: socket
    """The socket used to connect to the stub"""

    GDB_STUB_PORT: int
    """Default port of the QEMU gdbstub"""

    syscall_hooks_enabled: bool
    """Whether syscall hooks are enabled for the current context or not."""

    is_attached_process: bool
    """Whether libdebug was attached to a running stub or directly spawned the QEMU instance"""

    def __init__(self):
        super().__init__()

        self.context = provide_context(self)

        self.GDB_STUB_PORT = 5000

        if not self.context.aslr_enabled:
            disable_self_aslr()

        self.process_id = 0

        self.hardware_bp_helpers = {}

        self.reset()

    def reset(self):
        """Resets the state of the interface."""
        # TODO
        pass

    def _set_options(self):
        """Sets the tracer options."""
        pass

    def _trace_self(self):
        """Traces the current process."""
        pass

    def run(self):
        """Runs the specified process."""
        self.is_attached_process = False

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
                (POSIX_SPAWN_CLOSE, self.stdin_write),
                (POSIX_SPAWN_CLOSE, self.stdout_read),
                (POSIX_SPAWN_CLOSE, self.stderr_read),
                (POSIX_SPAWN_DUP2, self.stdin_read, 0),
                (POSIX_SPAWN_DUP2, self.stdout_write, 1),
                (POSIX_SPAWN_DUP2, self.stderr_write, 2),
                (POSIX_SPAWN_CLOSE, self.stdin_read),
                (POSIX_SPAWN_CLOSE, self.stdout_write),
                (POSIX_SPAWN_CLOSE, self.stderr_write),
            ],
            setpgroup=0,
        )

        """ self.process_id = child_pid
        self.context.process_id = child_pid """
        self.context.pipe_manager = self._setup_pipe()
        
        # Don't connect to qemu too fast, the stub may not be there yet
        # TODO: better handling
        sleep(0.1)

        # Connect to the stub
        self.stub = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.stub.connect(("localhost", self.GDB_STUB_PORT))
        stub_info = self.stub.getpeername()
        print(f"Connected to GDB stub at %s:%s" % (stub_info[0], stub_info[1]))
        send_ack(self.stub)

        # Enable supported features
        cmd = b'qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+'
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)

        cmd = b'qC'
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)
        self.process_id = resp.pid
        self.context.process_id = resp.pid
        thread_id = resp.tid

        cmd = b'qXfer:features:read:target.xml:0,ffb'
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)

        offset = b'0'
        data = b''
        nbytes = 0
        # TODO: We may not want a fixed no. of iterations
        for i in range(4):
            cmd = b'qXfer:features:read:i386-64bit.xml:'+offset+b',ffb'
            self.stub.send(prepare_stub_packet(cmd))
            resp = receive_stub_packet(cmd, self.stub)
            # Strip initial 'm' (part of payload)
            data += resp[1:]
            
            nbytes += len(resp)-1
            offset = int2hexbstr(nbytes)

        data = data.decode('ascii')

        register_parser = register_parser_provider()
        register_info = register_parser.parse(data)
        
        self.register_new_thread(thread_id, register_info)

    def attach(self, port: int):
        """Attaches to the specified process.

        Args:
            port (int): the port at which the stub is listening.
        """
        # TODO: When attaching to a process with GDB stub, we actually specify
        # the port at which the stub is listening to, not the PID.
        
        self.is_attached_process = True
        self.stub = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.stub.connect(("localhost", self.GDB_STUB_PORT))
        except Exception as e:
            raise Exception("Error when connecting to GDB stub, maybe QEMU is down?")
        stub_info = self.stub.getpeername()
        self.context.process_id = port
        print(f"Connected to GDB stub at %s:%s" % (stub_info[0], stub_info[1]))

        # Enable supported features
        cmd = b'qSupported:multiprocess+;swbreak+;hwbreak+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+'
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)

        cmd = b'qC'
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)
        self.process_id = resp.pid
        self.context.process_id = resp.pid
        thread_id = resp.tid

        cmd = b'qXfer:features:read:target.xml:0,ffb'
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)

        offset = b'0'
        data = b''
        nbytes = 0
        # TODO: We may not want a fixed no. of iterations
        for i in range(4):
            cmd = b'qXfer:features:read:i386-64bit.xml:'+offset+b',ffb'
            self.stub.send(prepare_stub_packet(cmd))
            resp = receive_stub_packet(cmd, self.stub)
            # Strip initial 'm' (part of payload)
            data += resp[1:]
            
            nbytes += len(resp)-1
            offset = int2hexbstr(nbytes)

        data = data.decode('ascii')

        register_parser = register_parser_provider()
        register_info = register_parser.parse(data)

        self.register_new_thread(thread_id, register_info)

    def kill(self):
        """Instantly terminates the process."""
        assert self.process_id is not None

        cmd = b'vKill;'+int2hexbstr(self.process_id)
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)
        if resp == b"OK":
            self.stub.close()
            if self.is_attached_process == False:
                # Wait for the child QEMU instance to terminate
                os.waitpid(self.process_id, 0)

    def cont(self):
        """Continues the execution of the process."""
        # Enable all breakpoints if they were disabled for a single step
        changed = []

        for bp in self.context.breakpoints.values():
            bp._disabled_for_step = False
            if bp._changed:
                changed.append(bp)
                bp._changed

        for bp in changed:
            if bp.enabled:
                self.set_breakpoint(bp, insert=False)
            else:
                self.unset_breakpoint(bp, delete=False)

        cmd = b"vCont;c"
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)

    def step(self, thread: ThreadContext):
        """Executes a single instruction of the process."""
        # TODO
        pass

    def step_until(self, thread: ThreadContext, address: int, max_steps: int):
        """Executes instructions of the specified thread until the specified address is reached.

        Args:
            thread (ThreadContext): The thread to step.
            address (int): The address to reach.
            max_steps (int): The maximum number of steps to execute.
        """
        # TODO
        pass

    def _setup_pipe(self):
        """
        Sets up the pipe manager for the child process.

        Close the read end for stdin and the write ends for stdout and stderr
        in the parent process since we are going to write to stdin and read from
        stdout and stderr
        """
        try:
            os.close(self.stdin_read)
            os.close(self.stdout_write)
            os.close(self.stderr_write)
        except Exception as e:
            # TODO: Custom exception
            raise Exception("Closing fds failed: %r" % e)
        return PipeManager(self.stdin_write, self.stdout_read, self.stderr_read)

    def _setup_parent(self, continue_to_entry_point: bool):
        """
        Sets up the parent process after the child process has been created or attached to.
        """
        pass

    def get_register_holder(self, thread_id: int) -> RegisterHolder:
        """Returns the current value of all the available registers.
        Note: the register holder should then be used to automatically setup getters and setters for each register.
        """
        raise RuntimeError("This method should never be called.")

    def wait(self) -> bool:
        # TODO
        pass

    def migrate_to_gdb(self):
        """Migrates the current process to GDB."""
        pass

    def migrate_from_gdb(self):
        """Migrates the current process from GDB."""
        pass

    def register_new_thread(self, new_thread_id: int, register_info: list):
        """Registers a new thread."""
        register_file = self._fetch_register_file(register_info)
        
        # TODO: Integrate with `register_holder_provider` method
        register_holder = Amd64GdbRegisterHolder(register_file, register_info)

        with context_extend_from(self):
            thread = ThreadContext.new(new_thread_id, register_holder)

        link_context(thread, self)

        self.context.insert_new_thread(thread)
        thread_hw_bp_helper = gdb_hardware_breakpoint_manager_provider(thread, self.context)
        self.hardware_bp_helpers[new_thread_id] = thread_hw_bp_helper

        # For any hardware breakpoints, we need to reapply them to the new thread
        for bp in self.context.breakpoints.values():
            if bp.hardware:
                thread_hw_bp_helper.install_breakpoint(bp)

    def _fetch_register_file(self, register_info: list):
        """Query the stub and fetch value of registers"""
        cmd = b'g'
        self.stub.send(prepare_stub_packet(cmd))
        reg_blob = receive_stub_packet(cmd, self.stub)

        # Slice the chunk with a 64bit stride to get
        # register values
        register_file = lambda: None
        for reg in register_info:
            stride = int((reg.size / 8) * 2)
            offset = reg.offset * 2
            slice = reg_blob[offset : offset+stride]
            value = int(slice, 16)
            setattr(register_file, reg.name, value)

        return register_file

    def unregister_thread(self, thread_id: int):
        """Unregisters a thread."""
        self.context.set_thread_as_dead(thread_id)

        # Remove the hardware breakpoint manager for the thread
        self.hardware_bp_helpers.pop(thread_id)

    def _set_sw_breakpoint(self, breakpoint: Breakpoint):
        """Sets a software breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to set.
        """
        cmd = b'Z0,'+int2hexbstr(breakpoint.address)+b',0'
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)

        if resp != b'OK':
            raise RuntimeError(f"Cannot insert breakpoint at address %#x" % breakpoint.address)

    def _unset_sw_breakpoint(self, breakpoint: Breakpoint):
        """Unsets a software breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to unset.
        """
        cmd = b'z0,'+int2hexbstr(breakpoint.address)+b',0'
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)

        if resp != b'OK':
            raise RuntimeError(f"Cannot remove breakpoint at address %#x" % breakpoint.address)

    def set_breakpoint(self, breakpoint: Breakpoint, insert: bool = True):
        """Sets a breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to set.
        """
        if breakpoint.hardware:
            for helper in self.hardware_bp_helpers.values():
                helper.install_breakpoint(breakpoint)
        else:
            # NOTE: GDB remote protocol offers no way to enable breakpoints.
            # Therefore, enabling == inserting
            self._set_sw_breakpoint(breakpoint)

        if insert:
            self.context.insert_new_breakpoint(breakpoint)

    def unset_breakpoint(self, breakpoint: Breakpoint, delete: bool = True):
        """Restores the breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to unset.
        """
        if breakpoint.hardware:
            for helper in self.hardware_bp_helpers.values():
                helper.remove_breakpoint(breakpoint)
        else:
            # NOTE: GDB remote protocol offers no way to disable breakpoints.
            # Therefore, disabling == removing
            self._unset_sw_breakpoint(breakpoint)

        if delete:
            self.context.remove_breakpoint(breakpoint)

    def set_syscall_hook(self, hook: SyscallHook):
        """Sets a syscall hook.

        Args:
            hook (SyscallHook): The syscall hook to set.
        """
        # TODO
        pass

    def unset_syscall_hook(self, hook: SyscallHook):
        """Unsets a syscall hook.

        Args:
            hook (SyscallHook): The syscall hook to unset.
        """
        # TODO
        pass

    def peek_memory(self, address: int) -> int:
        """Reads the memory at the specified address."""
        cmd = b'm'+int2hexbstr(address)+b',8w'
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)

        if resp == b'E22' or resp == b'E14':
            raise RuntimeError(f"Cannot read memory at address %#x" % address)

        return int(resp, 16)

    def poke_memory(self, address: int, data: int):
        """Writes the memory at the specified address."""
        cmd = b'M'+int2hexbstr(address)+b',8w:'+int2hexbstr(data)
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)

        if resp == b'E22' or resp == b'E14':
            raise RuntimeError(f"Cannot write memory at address %#x" % address)

    def maps(self) -> list[MemoryMap]:
        """Returns the memory maps of the process."""
        assert self.process_id is not None

        # NOTE: QEMU gdbstub implementation doesn't currently support
        # reading memory maps from a process/thread. Therefore return a
        # dummy map so not to make already existing logic fail
        start = 0x0000000000000000
        end = 0xffffffffffffffff
        permissions = "rwxp"
        size = end
        int_offset = 0x00000000
        backing_file = ""
        return [MemoryMap(start, end, permissions, size, int_offset, backing_file)]
