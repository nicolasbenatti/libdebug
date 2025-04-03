#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import errno
import os
import signal
import psutil
import pty
from time import sleep
import tty
from pathlib import Path
import socket
from xml.parsers import expat

from libdebug.architectures.gdb_hardware_breakpoint_manager import (
    GdbHardwareBreakpointManager
)
from libdebug.architectures.gdb_hardware_breakpoint_provider import (
    gdb_hardware_breakpoint_manager_provider
)
from libdebug.architectures.register_helper import register_holder_provider
from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_map import MemoryMap
from libdebug.gdb_stub.gdb_stub_status_handler import GdbStubStatusHandler
from libdebug.data.register_holder import GdbRegisterHolder
from libdebug.architectures.amd64.amd64_gdb_register_holder import Amd64GdbRegisterHolder
from libdebug.gdb_stub.gdb_stub_constants import (
    GDBStubCommands,
    GDBStubReplies,
    GDBSTUB_MAIN_TARGET_DESCRIPTION_FILENAME
)
from libdebug.gdb_stub.register_parser_helper import register_parser_provider
from libdebug.gdb_stub.register_parser import RegisterInfo
from libdebug.data.syscall_hook import SyscallHook
from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.liblog import liblog
from libdebug.state.debugging_context import (
    context_extend_from,
    link_context,
    provide_context
)
from libdebug.state.debugging_context import DebuggingContext
from libdebug.state.thread_context import ThreadContext
from libdebug.utils import posix_spawn
from libdebug.gdb_stub.gdb_stub_utils import (
    send_ack,
    prepare_stub_packet,
    receive_stub_packet,
    get_supported_features,
    int2hexbstr,
    int2hexbstr_le,
    hexbstr2int_le,
    bstr2hex
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

    register_holder: GdbRegisterHolder = None
    """Tells the interface how to parse the register blob coming from the stub."""

    qemu_pid: int | None
    """The process ID of the QEMU instance."""

    remote_process_id: int | None
    """The process ID of the debugged process."""

    stub: socket = None
    """The socket used to connect to the stub."""

    parser: expat.XMLParserType = None
    """Target description file parser."""

    GDB_STUB_PORT: int
    """Default port of the QEMU gdbstub."""

    syscall_hooks_enabled: bool
    """Whether syscall hooks are enabled for the current context or not."""

    is_attached_process: bool
    """Whether libdebug was attached to a running stub or directly spawned the QEMU instance."""

    executable_path: str
    """Absolute path of the program running on the stub."""

    last_reply: object
    """The last reply we got from the stub."""    

    def __init__(self):
        super().__init__()

        self.context = provide_context(self)

        self.GDB_STUB_PORT = 5000

        # Disable namespace processing to avoid issues
        self.parser = expat.ParserCreate('ascii', None)

        self.qemu_pid = 0
        self.remote_process_id = 0

        self.hardware_bp_helpers = {}

        self.reset()

    def reset(self):
        """Resets the state of the interface."""
        self.hardware_bp_helpers.clear()
        self.syscall_hooks_enabled = False
        if self.stub != None:
            self.stub.close()
            self.stub = None
        self.qemu_pid = 0
        self.remote_process_id = 0

    def _fetch_target_description(self, filename: str):
        """Reads a target description from the remote process.
        See https://sourceware.org/gdb/current/onlinedocs/gdb.html/General-Query-Packets.html#qXfer-read for more info."""
        offset = b'0'
        data = b''
        resp = b''
        nbytes = 0
        while resp != b'l':
            cmd = b'qXfer:features:read:'+bytes(filename, 'ascii')+b':'+offset+b',ffb'
            self.stub.send(prepare_stub_packet(cmd))
            resp = receive_stub_packet(cmd, self.stub)
            # Strip initial 'm'/'l'
            data += resp[1:]
            
            nbytes += len(resp)-1
            offset = int2hexbstr(nbytes)

        return data.decode('ascii')

    def _parse_main_target_description(self, data: str): 
        """Parses the main target description file.
        
        Returns: the filename of the architecture-dependent description file.
        """
        arch_tdesc_filename = ""
        is_first_tag = False
        
        # Expat is an event-driven parser, so we need
        # to define callbacks
        def tag_start_handler(tag, attrs):
            nonlocal arch_tdesc_filename
            nonlocal is_first_tag
            if is_first_tag == False and tag == "xi:include":
                is_first_tag = True
                arch_tdesc_filename = attrs["href"]

        self.parser.StartElementHandler = tag_start_handler
        self.parser.Parse(data)

        return arch_tdesc_filename

    def _fetch_elf_file(self, fd: str): 
        """Reads the content of the remote process' executable file."""
        offset = b'0'
        data = b''
        resp = b''
        nbytes = -1
        
        # Read 2KiB chunks
        cmd = b'vFile:pread:'+int2hexbstr(int(fd))+b",800,"+offset   
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)
        
        while resp.nbytes != 0:
            data += resp.data
            nbytes += resp.nbytes
            offset = int2hexbstr(nbytes)
            
            cmd = b'vFile:pread:'+int2hexbstr(int(fd))+b",800,"+offset   
            self.stub.send(prepare_stub_packet(cmd))
            resp = receive_stub_packet(cmd, self.stub)
        
        return data
    
    def _should_disconnect(self, resp: bytes):
        """Check whether the remote process is not running anymore after a client command (continue/step/step_until)
        
        Args:
            resp (bytes): The escaped stub reply.
        """
        if resp.msgtype == ord(b'W'):
            liblog.debugger(f"GDBSTUB: remote process exited with status {int(resp.status)}")
            self.reset()
            return True
        elif resp.msgtype == ord(b'X'):
            liblog.debugger(f"GDBSTUB: remote process terminated with signal {int(resp.signal)}")
            self.reset()
            return True
        elif resp.msgtype == b'N':
            liblog.debugger("GDBSTUB: process is alive, but no running threads")
            self.reset()
            return True
        
        return False

    def _get_qemu_instance_pid(self, port: int):
        """Looks for the PID of the qemu instance listening on the specified port
        
        Args:
            port (int): The port on which qemu gdbstub is listening on.
        """
        assert self.is_attached_process is True

        connections = psutil.net_connections()
        for conn in connections:
            p = conn.laddr.port
            if conn.status == "LISTEN" and p == port:
                return conn.pid
        else:
            raise RuntimeError("Cannot find pid of QEMU instance")

    def _download_executable(self, executable_path):
        liblog.debugger("Executable file is not on local machine, downloading...")
        cmd = b"vFile:setfs:0"
        self.stub.send(prepare_stub_packet(cmd))
        receive_stub_packet(cmd, self.stub)

        cmd = b"vFile:open:"+bstr2hex(executable_path)+b",0,0"
        self.stub.send(prepare_stub_packet(cmd))
        fd = receive_stub_packet(cmd, self.stub)

        elf = self._fetch_elf_file(int(fd))
        remote_exec_path = os.getcwd()+"/../../remote_binaries/"+remote_exec_path.split("/")[-1]
        with open(remote_exec_path, "wb") as f:
            f.write(elf)
            f.close()
        liblog.debugger("DONE")

        return remote_exec_path

    def run(self):
        """Runs the specified process."""
        self.is_attached_process = False
        # Setup gdbstub wait status handler after debugging_context has been properly initialized
        with context_extend_from(self):
            self.status_handler = GdbStubStatusHandler()

        argv = self.context.argv
        env = self.context.env
        env["QEMU_GDB"] = str(self.GDB_STUB_PORT)

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

        self.qemu_pid = child_pid
        self.context.process_id = child_pid
        self.context.pipe_manager = self._setup_pipe()
        
        # Don't connect to qemu too fast, the stub may not be there yet
        # TODO: better handling?
        sleep(0.1)

        # Connect to the stub
        self.stub = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.stub.connect(("localhost", self.GDB_STUB_PORT))
        stub_info = self.stub.getpeername()
        print(f"Connected to GDB stub at %s:%s" % (stub_info[0], stub_info[1]))
        send_ack(self.stub)

        # Enable supported features
        cmd = b'qSupported:'+get_supported_features()+b'swbreak+;hwbreak+'
        self.stub.send(prepare_stub_packet(cmd))
        receive_stub_packet(cmd, self.stub)

        cmd = b"QCatchSyscalls:1"
        self.stub.send(prepare_stub_packet(cmd))
        receive_stub_packet(cmd, self.stub)
        
        cmd = b'qC'
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)
        self.remote_process_id = resp.pid
        self.context.process_id = resp.pid
        thread_id = resp.tid

        # Fetch target description of the remote process
        main_tdesc = self._fetch_target_description(GDBSTUB_MAIN_TARGET_DESCRIPTION_FILENAME)
        tdesc_filename = self._parse_main_target_description(main_tdesc)
        tdesc = self._fetch_target_description(tdesc_filename)

        register_parser = register_parser_provider()
        registers_info = register_parser.parse(tdesc)
        
        self.register_new_thread(thread_id, registers_info)
        
        cmd = b"qXfer:exec-file:read:"+ int2hexbstr(self.remote_process_id) +b":0,ffb"
        self.stub.send(prepare_stub_packet(cmd))
        elf_fname = receive_stub_packet(cmd, self.stub)
        self.executable_path = elf_fname.decode('ascii')

    def attach(self, port: int):
        """Attaches to the specified process.

        Args:
            port (int): The port at which the stub is listening.
        """
        self.is_attached_process = True
        # Setup gdbstub wait status handler after debugging_context has been properly initialized
        with context_extend_from(self):
            self.status_handler = GdbStubStatusHandler()
        
        # Creating pipes for stdin, stdout, stderr
        self.stdin_read, self.stdin_write = os.pipe()
        self.stdout_read, self.stdout_write = pty.openpty()
        self.stderr_read, self.stderr_write = pty.openpty()
        
        # Setting stdout, stderr to raw mode to avoid terminal control codes interfering with the
        # output
        tty.setraw(self.stdout_read)
        tty.setraw(self.stderr_read)
        
        self.stub = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.stub.connect(("localhost", self.GDB_STUB_PORT))
        except Exception as e:
            raise Exception("Error when connecting to GDB stub, is QEMU running?")
        stub_info = self.stub.getpeername()
        print(f"Connected to GDB stub at {stub_info[0]}:{stub_info[1]}")
        
        self.qemu_pid = self._get_qemu_instance_pid(port)
        self.context.pipe_manager = self._setup_pipe()
        print(f"PID of qemu instance is {self._get_qemu_instance_pid(port)}")

        # Enable supported features
        cmd = b'qSupported:'+get_supported_features()+b'swbreak+;hwbreak+'
        self.stub.send(prepare_stub_packet(cmd))
        receive_stub_packet(cmd, self.stub)

        cmd = b"QCatchSyscalls:1"
        self.stub.send(prepare_stub_packet(cmd))
        receive_stub_packet(cmd, self.stub)

        cmd = b'qC'
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)
        self.remote_process_id = resp.pid
        self.context.process_id = resp.pid
        thread_id = resp.tid

        # Fetch target description of the remote process
        main_tdesc = self._fetch_target_description(GDBSTUB_MAIN_TARGET_DESCRIPTION_FILENAME)
        tdesc_filename = self._parse_main_target_description(main_tdesc)
        tdesc = self._fetch_target_description(tdesc_filename)

        register_parser = register_parser_provider()
        registers_info = register_parser.parse(tdesc)

        self.register_new_thread(thread_id, registers_info)

        cmd = b"qXfer:exec-file:read:"+int2hexbstr(self.remote_process_id)+b":0,ffb"
        self.stub.send(prepare_stub_packet(cmd))
        remote_elf_path = receive_stub_packet(cmd, self.stub)

        # if the remote is on another machine, try to download the executable
        if not os.path.exists(remote_elf_path):
            local_elf_path = remote_elf_path = self._download_executable(remote_elf_path)
        else:
            local_elf_path = remote_elf_path
        self.executable_path = local_elf_path.decode('ascii')

    def kill(self):
        """Instantly terminates the process."""
        assert self.remote_process_id is not None

        cmd = b'vKill;'+int2hexbstr(self.remote_process_id)
        self.stub.send(prepare_stub_packet(cmd))
        resp = receive_stub_packet(cmd, self.stub)
        if resp == b"OK":
            self.stub.close()
            if self.is_attached_process == False:
                # Wait for the child QEMU instance to terminate
                os.waitpid(self.qemu_pid, 0)

    def cont(self):
        """Continues the execution of the process."""
        if self.stub is None:
            raise RuntimeError("Not connected to any stub, quitting...")

        for thread in self.context.threads: 
            self.step(thread)
        
        # Enable all breakpoints if they were disabled for a single step
        changed = []

        for bp in self.context.breakpoints.values():
            bp._disabled_for_step = False
            if bp._changed:
                changed.append(bp)
                bp._changed = False

        for bp in changed:
            if bp.enabled:
                self.set_breakpoint(bp, insert=False)
            else:
                self.unset_breakpoint(bp, delete=False)

        for hook in self.context.syscall_hooks.values():
            if hook.enabled:
                self.syscall_hooks_enabled = True
                break
        else:
            self.syscall_hooks_enabled = False

        # Flush register updates in all threads
        for thread in self.context.threads:
            self._update_register_file(thread.registers)

        cmd = b"vCont;c:p"+int2hexbstr(self.remote_process_id)+b'.-1'
        self.stub.send(prepare_stub_packet(cmd))
        self.last_reply = receive_stub_packet(cmd, self.stub)
        if self._should_disconnect(self.last_reply):
            return

        # Update registers for all threads
        for thread in self.context.threads:
            regfile, thread.registers.register_blob = self._fetch_register_file(thread.registers.register_info)
            for item, val in regfile.__dict__.items():
                setattr(thread.registers.register_file, item, val)
                #print(f"%s %#16x %#16x" % (item, val, thread.registers.get_most_recent_value(item)))
            thread.registers.flush(thread)

    def step(self, thread: ThreadContext):
        """Executes a single instruction of the process."""
        if self.stub is None:
            raise RuntimeError("Not connected to any stub, quitting...")
        
        # Disable all breakpoints for the single step
        for bp in self.context.breakpoints.values():
            bp._disabled_for_step = True

        # Flush register updates from the context.
        self._update_register_file(thread.registers)

        cmd = b'vCont;s:p'+int2hexbstr(self.remote_process_id)+b'.'+int2hexbstr(thread.thread_id)
        self.stub.send(prepare_stub_packet(cmd))
        self.last_reply = receive_stub_packet(cmd, self.stub)
        if self._should_disconnect(self.last_reply):
            return

        # Update registers in the thread context
        regfile, thread.registers.register_blob = self._fetch_register_file(thread.registers.register_info)
        for item, val in regfile.__dict__.items():
            setattr(thread.registers.register_file, item, val)
            #print(f"%s %#16x %#16x" % (item, val, thread.registers.get_most_recent_value(item)))
        thread.registers.flush(thread)

    def step_until(self, thread: ThreadContext, address: int, max_steps: int):
        """Executes instructions of the specified thread until the specified address is reached.

        Args:
            thread (ThreadContext): The thread to step.
            address (int): The address to reach.
            max_steps (int): The maximum number of steps to execute. -1 means unlimited.
        """
        if self.stub is None:
            raise RuntimeError("Not connected to any stub, quitting...")

        # Disable all breakpoints for the single step
        for bp in self.context.breakpoints.values():
            bp._disabled_for_step = True

        step_count = 0
        while max_steps == -1 or step_count < max_steps:
            prv_ip = thread.rip

            self.step(thread)
            if thread.rip == address:
                break

            # Step again because we hit a hw breakpoint
            # NOTE: in QEMU user mode hw and sw breakpoints
            # are treated the same way, so shouldn't be an issue
            if thread.rip == prv_ip:
                continue

            step_count += 1

    def _setup_pipe(self):
        """
        Sets up the pipe manager for the child process.

        Close the read end for stdin and the write ends for stdout and stderr
        in the parent process since we are going to write to stdin and read from
        stdout and stderr
        """
        if self.is_attached_process:
            self.stdin_write = "/tmp/libdebug_fifo"
            #os.mkfifo(self.stdin_write)
            self.stdout_read = f"/proc/{self.qemu_pid}/fd/1"
            self.stderr_read = f"/proc/{self.qemu_pid}/fd/2"
        else:
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

    def get_register_holder(self, thread_id: int) -> GdbRegisterHolder:
        """Returns the current value of all the available registers.
        Note: the register holder should then be used to automatically setup getters and setters for each register.
        """
        raise RuntimeError("This method should never be called.")

    def wait(self) -> bool:
        """Waits for the process to stop. Returns True if the wait has to be repeated."""
        repeat = self.status_handler._handle_status_change() 

        return repeat

    def migrate_to_gdb(self):
        """Migrates the current process to GDB."""
        raise RuntimeError("This method should never be called.")

    def migrate_from_gdb(self):
        """Migrates the current process from GDB."""
        raise RuntimeError("This method should never be called.")

    def register_new_thread(self, new_thread_id: int, registers_info: dict[str, RegisterInfo]):
        """Registers a new thread."""
        register_file, register_blob = self._fetch_register_file(registers_info)
        
        # TODO: Integrate with `register_holder_provider` method
        self.register_holder = Amd64GdbRegisterHolder(register_file, registers_info, register_blob)
        with context_extend_from(self):
            thread = ThreadContext.new(new_thread_id, self.register_holder)

        link_context(thread, self)

        self.context.insert_new_thread(thread)
        with context_extend_from(self):
            thread_hw_bp_helper = gdb_hardware_breakpoint_manager_provider(thread)
        self.hardware_bp_helpers[new_thread_id] = thread_hw_bp_helper

        # For any hardware breakpoints, we need to reapply them to the new thread
        for bp in self.context.breakpoints.values():
            if bp.hardware:
                thread_hw_bp_helper.install_breakpoint(bp)

    def _fetch_register_file(self, registers_info: dict[str, RegisterInfo]):
        """Queries the stub and fetches value of registers."""
        cmd = b'g'
        self.stub.send(prepare_stub_packet(cmd))
        register_blob = receive_stub_packet(cmd, self.stub)
        # Slice the blob to get register values
        register_file = lambda: None
        for _, reg in registers_info.items():
            stride = int(reg.size * 2)
            offset = reg.offset * 2
            slice = register_blob[offset : offset+stride]
            if b'x' in slice:
                value = 0x0
            else:
                value = hexbstr2int_le(slice)
            setattr(register_file, reg.name, value)

        return register_file, bytearray(register_blob)

    def _update_register_file(self, register_holder: GdbRegisterHolder):
        """Sends updated register values to the stub."""
        for _, reg in self.register_holder.register_info.items():
            reg_val = getattr(register_holder.register_file, reg.name)
            if reg_val != register_holder.get_most_recent_value(reg.name):
                cmd = b'P'+int2hexbstr(reg.index)+b'='+int2hexbstr_le(reg_val, reg.size)
                self.stub.send(prepare_stub_packet(cmd))
                resp = receive_stub_packet(cmd, self.stub)
                if resp != b"OK":
                    raise RuntimeError("Cannot send updated registers to the target process.")

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
        self.context.insert_new_syscall_hook(hook)

    def unset_syscall_hook(self, hook: SyscallHook):
        """Unsets a syscall hook.

        Args:
            hook (SyscallHook): The syscall hook to unset.
        """
        self.context.remove_syscall_hook(hook)

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
        assert self.remote_process_id is not None

        # NOTE: QEMU gdbstub implementation doesn't currently support
        # reading memory maps from a process/thread. Therefore return a
        # dummy map so not to break existing logic
        start = 0x0000000000000000
        end = 0xffffffffffffffff
        permissions = "rwxp"
        size = end
        int_offset = 0x00000000
        backing_file = self.executable_path
        return [MemoryMap(start, end, permissions, size, int_offset, backing_file)]
