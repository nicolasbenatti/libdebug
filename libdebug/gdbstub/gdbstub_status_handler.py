from libdebug.state.debugging_context import provide_context
from libdebug.liblog import liblog

class GdbStubStatusHandler:
    def __init__(self):
        self.context = provide_context(self)
        self.gdbstub_interface = self.context.debugging_interface

    def _handle_trap(self, thread_id: int) -> bool:
        """Manage actions to do when the process enters/exits a syscall
        
        Args:
            thread_id (int): The thread which received the event
        
        Returns:
            True, indicating that the process should proceed because it has
            not reach the breakpoint yet.
        """
        if thread_id == -1:
            # If the stub yields a -1 tid, it means we didn't enable
            # multiprocess. This tho should never happen because in
            # those cases we'd have 1 thread with tid = pid
            return False

        for thread in self.context.threads:
            active_bps = {}
            for bp in self.context.breakpoints.values():
                if bp.enabled and not bp._disabled_for_step:
                    active_bps[bp.address] = bp
            
            ip = thread.rip
            bp = None
            if ip in active_bps:
                # NOTE: there is currently no distinction
                # between hw and sw breakpoints in qemu user-mode
                bp = self.context.breakpoints[ip]
            
            if bp:
                bp.hit_count += 1

                if bp.callback:
                    thread._in_background_op = True
                    bp.callback(thread, bp)
                    thread._in_background_op = False
                return False
        
        return False

    def _handle_syscall(self, thread_id: int, syscall_number: int) -> bool:
        """Manage actions to do when the process enters/exits a syscall
        
        Args:
            thread_id (int): The thread which received the event
        
        Returns:
            True, indicating that the process should proceed because it has
            not reach the breakpoint yet.
        """
        thread = self.context.get_thread_by_id(thread_id)

        """ if not hasattr(thread, "syscall_number"):
            # This is another spurious trap, we don't know what to do with it
            print("CIAONE")
            return False """

        #syscall_number = thread.syscall_number

        if syscall_number not in self.context.syscall_hooks:
            # This is a syscall we don't care about
            # Resume the execution
            return True

        hook = self.context.syscall_hooks[syscall_number]

        if not hook.enabled:
            # The hook is disabled, skip it
            return True 

        thread._in_background_op = True

        if not hook._has_entered:
            # The syscall is being entered
            liblog.debugger(
                "Syscall %d entered on thread %d", syscall_number, thread_id
            )

            if hook.on_enter:
                hook.on_enter(thread, syscall_number)
            hook._has_entered = True
        else:
            # The syscall is being exited
            liblog.debugger("Syscall %d exited on thread %d", syscall_number, thread_id)

            if hook.on_exit:
                hook.on_exit(thread, syscall_number)
            hook._has_entered = False

            # Increment the hit count only if the syscall was exited
            hook.hit_count += 1

        # TODO: I don't think this is needed for gdbstub, at least
        # when it is operating in synchronous mode
        thread._in_background_op = False

        return True
    
    def _handle_status_change(self) -> bool:
        """Handle a change in the status of a traced process. Return True if the process should start waiting again."""
        repeat = 0
        stub_reply = self.gdbstub_interface.last_reply
        for thread in self.context.threads:
            if stub_reply.msgtype == ord(b'T'):
                if stub_reply.is_syscall_trap:
                    print("the program stopped at a syscall")
                    repeat |= self._handle_syscall(thread.thread_id, stub_reply.syscall_number)
                elif stub_reply.is_breakpoint_trap:
                    print("the program stopped at a breakpoint")
                    repeat |= self._handle_trap(thread.thread_id)
        
        return repeat