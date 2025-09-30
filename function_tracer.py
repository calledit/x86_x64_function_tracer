#!/bin/env python

"""
A Windows x64 function call tracer using WinAppDbg, Keystone, and a helper DLL (calltracer.dll).

This script can start or attach to a target process, inject a DLL, and hook functions listed
in the PE's .pdata (runtime function table). It also patches CALL instructions to trace
inter-function calls, printing a readable call/return log similar to:

    enter: draw_cubedx11_19
      call: nr_1 draw_cubedx11_31 from draw_cubedx11_19
      enter: draw_cubedx11_31
        exit: draw_cubedx11_31
      called: nr_1  from draw_cubedx11_19
    ...

Functionality is intentionally preserved from the original version; this revision adds:
- Typing annotations
- Docstrings
- Clearer comments
- Spelling fixes in identifiers, strings, and comments

Requirements:
    pip install git+https://github.com/MarioVilas/winappdbg.git
    pip install pefile
    pip install keystone-engine
    pip install capstone==6.0.0a4

Note: Run on Windows. Requires debug privileges and x64 target processes.
"""

from winappdbg import win32
from winappdbg.debug import System
from winappdbg.debug import Debug
import sys
import ctypes
import ctypes.wintypes as wintypes
import pefile
import os
import json
import time
import struct
from functools import partial
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from typing import Dict, List, Tuple, Optional, Callable, Any

# -----------------------------
# Globals / State
# -----------------------------

# External breakpoints mapped by address to callback
external_breakpoints: Dict[int, Callable[[Any], None]] = {}

# Loaded module base addresses by basename (e.g., "kernel32")
loaded_modules: Dict[str, int] = {}

# Exported functions from calltracer.dll resolved to absolute addresses
call_tracer_dll_func: Dict[str, int] = {}

# Per-thread replacement return addresses for MinHook trampolines
# Structure: ret_replacements[tid][jump_table_addr] = [return_addr_stack]
ret_replacements: Dict[int, Dict[int, List[int]]] = {}

# Queue of (assembly_str, callback) to inject and execute
asm_code_to_run: List[Tuple[str, Optional[Callable[[Any], None]]]] = []

# Control flags / addresses
allocate_and_inject_dll: bool = True
in_loading_phase: bool = True
is_in_injected_code: bool = False
code_injection_address: Optional[int] = None
register_save_address: Optional[int] = None
shell_code_address: Optional[int] = None
shell_code_address_offset: int = 20  # Start at 20 arbitrarily to keep some space free.

# PE / function metadata (.pdata)
pdata: Optional[bytes] = None
pdata_functions: List[Tuple[int, int, int, int]] = []
pdata_function_ids: Dict[int, str] = {}
exe_entry_address: int = 0

# Simple call stack for pretty printing
call_stack: List[str] = []

# Functions (addresses) we plan to hook via MinHook (in calltracer.dll)
# Each entry: (target_fn_addr, enter_callback, exit_callback)
functions_to_hook: List[Tuple[int, Callable[[Any], None], Callable[[Any], None]]] = []

# Initialize Keystone for x64.
ks = Ks(KS_ARCH_X86, KS_MODE_64)


# -----------------------------
# Helpers
# -----------------------------

def start_or_attach_debugger(argv: List[str]) -> None:
    """Start or attach the debugger to the given executable.

    If only one argument is given, we try to attach to any running process with
    that filename. Otherwise, we start a new process using the argv list.
    """
    debug_obj = Debug(on_debug_event, bKillOnExit=True)
    try:
        aSystem = System()
        aSystem.request_debug_privileges()
        aSystem.scan_processes()
        pid: Optional[int] = None

        # Find any running executable
        if len(argv) == 1:
            executable = argv[0]
            for (process, name) in debug_obj.system.find_processes_by_filename(executable):
                pid = process.get_pid()

        # If there was no running instance of the executable, start it
        if pid is None:
            print("start:", argv)
            debug_obj.execv(argv)
        else:
            debug_obj.attach(pid)

        # Debug loop
        debug_obj.loop()

    finally:
        debug_obj.stop()


def get_base_name(filename: str) -> str:
    """Return lowercase filename without extension from a Windows path."""
    dname = filename.split("\\")[-1]
    basic_name = dname.split(".")[0].lower()
    return basic_name


def asm(CODE: str, address: int = 0) -> bytes:
    """Assemble x64 code at the given address using Keystone."""
    encoding, count = ks.asm(CODE, address)
    return bytes(encoding)


def read_ptr(process: Any, address: int) -> int:
    """Read an 8-byte pointer from the target process memory at address."""
    data = process.read(address, 8)
    return struct.unpack("<Q", data)[0]


def allocate_mem_and_inject_dll(event: Any, process: Any, pid: int, address_close_to_code: int) -> None:
    """Allocate remote memory regions and inject the helper DLL."""
    global register_save_address, code_injection_address, shell_code_address

    # VirtualAllocEx signature configuration
    ctypes.windll.kernel32.VirtualAllocEx.argtypes = [
        wintypes.HANDLE,  # hProcess
        ctypes.c_void_p,  # lpAddress
        ctypes.c_size_t,  # dwSize
        wintypes.DWORD,   # flAllocationType
        wintypes.DWORD,   # flProtect
    ]

    process_handle = process.get_handle()

    # Allocate small utility region (writable)
    ctypes.windll.kernel32.VirtualAllocEx.restype = ctypes.c_ulonglong
    remote_memory = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, 1000, 0x3000, 0x04)
    if not remote_memory:
        raise Exception(f"Failed to allocate memory in target process: {ctypes.WinError()}")

    # Allocate large RX region for shellcode near code
    size = 0x100000
    base_ask_addr = address_close_to_code - size * 5
    preferred_address = base_ask_addr
    base_injection_addr = ctypes.windll.kernel32.VirtualAllocEx(
        process_handle, ctypes.c_void_p(preferred_address), size, 0x3000, 0x40
    )
    if base_injection_addr == 0:
        print("Could not allocate jump table; this can be somewhat random. Please try again.")
        sys.exit(0)

    shell_code_address = base_injection_addr

    # Allocate register-save area (writable)
    register_save_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, 4096, 0x3000, 0x04)
    if not register_save_address:
        print(f"Failed to allocate register_save_address in target process: {ctypes.WinError()}")
        sys.exit(0)

    # Allocate secondary RX region for injected stub code
    base_ask_addr = address_close_to_code - size * 10
    preferred_address = base_ask_addr

    code_injection_address = ctypes.windll.kernel32.VirtualAllocEx(
        process_handle, ctypes.c_void_p(preferred_address), 0x100000, 0x3000, 0x40
    )
    if not code_injection_address:
        print(f"Failed to allocate code_injection_address in target process: {ctypes.WinError()}")
        sys.exit(0)

    # Inject helper DLL with MinHook-based hooks
    run_loadlibrary_in_process(process_handle, process, "calltracer.dll")

    # Now that we have all the instructions, add a breakpoint on the entry point
    event.debug.break_at(pid, exe_entry_address, exe_entry)

    process.close_handle()


def min_hooked_entry_hook(ujump_table_address: int, callback: Callable[[Any], None], event: Any) -> None:
    """Breakpoint handler for function entry via MinHook trampoline wrapper."""
    thread = event.get_thread()
    tid = thread.get_tid()

    if tid not in ret_replacements:
        ret_replacements[tid] = {ujump_table_address: []}
    if ujump_table_address not in ret_replacements[tid]:
        ret_replacements[tid][ujump_table_address] = []

    process = event.get_process()
    context = thread.get_context()
    stack_pointer = context["Rsp"]
    return_address = read_ptr(process, stack_pointer)

    ret_replacements[tid][ujump_table_address].append(return_address)
    callback(event)


def min_hooked_exit_hook(ujump_table_address: int, callback: Callable[[Any], None], event: Any) -> None:
    """Breakpoint handler for function exit; returns to original address and calls callback."""
    tid = event.get_tid()
    original_return_address = ret_replacements[tid][ujump_table_address].pop()
    event.get_thread().set_pc(original_return_address)
    callback(event)


def min_hooked_function(jump_table_address: int, enter_callback: Callable[[Any], None], exit_callback: Callable[[Any], None], event: Any) -> None:
    """Executed after MinHook finishes hooking a function."""
    thread = event.get_thread()
    context = thread.get_context()
    result = context["Rax"]

    if result != 0:
        print("failed to hook function:", jump_table_address)
        sys.exit()

    process = event.get_process()
    address_to_trampoline = process.read(shell_code_address, 8)
    address_to_trampoline = struct.unpack("<Q", address_to_trampoline)[0]
    print("min_hooked_function:", result, "addr:", address_to_trampoline)

    second_interrupt = jump_table_address + (24 - 2)
    # Tracking assembly: adds a breakpoint before and after the real function.
    # Saves the return address, modifies it to point to the post-call int3, then jumps.
    asmm = (
        "int 3;"
        "push rax;"
        "mov rax, [RIP + 22];"
        "mov [RSP+0x8], rax;"
        "pop rax;"
        "jmp [RIP + 0x2];"
        "int 3"
    )
    jump_code = asm(asmm, jump_table_address) + struct.pack("<Q", address_to_trampoline) + struct.pack("<Q", second_interrupt)

    external_breakpoints[jump_table_address + 2] = partial(min_hooked_entry_hook, jump_table_address, enter_callback)
    external_breakpoints[second_interrupt + 2] = partial(min_hooked_exit_hook, jump_table_address, exit_callback)
    process.write(jump_table_address, jump_code)


def min_hook_enabled(event: Any) -> None:
    thread = event.get_thread()
    context = thread.get_context()
    result = context["Rax"]
    print("min_hook_enabled:", result)


def hook_functions() -> None:
    """Queue MinHook setup calls for all functions_to_hook and queue a global enable."""
    global shell_code_address_offset

    hook_function = call_tracer_dll_func["hook_function"]
    enable_function = call_tracer_dll_func["enable_hooks"]

    for target_fn_addr, enter_callback, exit_callback in functions_to_hook:
        print("hook", target_fn_addr, "using:", call_tracer_dll_func["hook_function"]) 
        jump_table_address = (shell_code_address or 0) + shell_code_address_offset
        shell_code_address_offset += 50  # ~50 bytes per entry is usually enough

        asm_code_to_run.append((
            f"mov rcx, 0x{target_fn_addr:016X};"
            f"mov rdx, 0x{jump_table_address:016X};"
            f"mov r8, 0x{(shell_code_address or 0):016X};"
            f"mov rax, 0x{hook_function:016X};"
            "call rax",
            partial(min_hooked_function, jump_table_address, enter_callback, exit_callback),
        ))

    # Enable hooks once all are queued
    if len(functions_to_hook) != 0:
        print("enable func_location:", enable_function)
        asmm = (
            "mov r11, rsp;"
            # Stack alignment considerations omitted per original code
            f"mov rax, 0x{enable_function:016X};"
            "call rax;"
            "mov rsp, r11;"
        )
        asm_code_to_run.append((asmm, min_hook_enabled))


def deal_with_breakpoint(event: Any, process: Any, pid: int, tid: int, address: int) -> bool:
    """Handle breakpoint and injection state machine."""
    global in_loading_phase, is_in_injected_code

    inject_ok = False
    if address in external_breakpoints or (in_loading_phase and address == exe_entry_address):
        inject_ok = True

    if len(asm_code_to_run) != 0 and not is_in_injected_code and inject_ok:
        asmd, code_done_callback = asm_code_to_run.pop(0)
        break_point_location = address

        # For WinAppDbg breakpoints (event.debug.break_at), address points to the 0xCC byte; for others, it's the next instruction.
        if address != exe_entry_address:
            break_point_location -= 1

        code_address = inject_assembly(process, asmd, break_point_location, code_done_callback)
        is_in_injected_code = True

        # Disable entry breakpoint so it isn't copied while running MinHook
        event.debug.dont_break_at(pid, exe_entry_address)
        event.get_thread().set_pc(code_address)
        return True

    if in_loading_phase and is_in_injected_code:
        # Re-enable breakpoint so it triggers next time
        event.debug.break_at(pid, exe_entry_address)

    if len(asm_code_to_run) == 0 and in_loading_phase and not is_in_injected_code and inject_ok:
        print("Loading phase done; disabling entry breakpoint")
        event.debug.dont_break_at(pid, exe_entry_address)
        in_loading_phase = False

    if address in external_breakpoints:
        callb = external_breakpoints[address]
        callb(event)
        return True
    else:
        print("unknown break_point called", tid, address)

    return False


def hook_calls(process: Any, event: Any, pid: int) -> None:
    """Disassemble functions and patch CALLs to insert call-site tracing breakpoints."""
    # Cache to avoid repeated disassembly of large binaries
    disassembled_functions: List[List[Tuple[int, int, str, str]]] = []
    disassembled_cache_file = exe_basic_name + "_instructions_cache.json"
    save_cache = False

    if os.path.exists(disassembled_cache_file) and time.time() - os.path.getmtime(disassembled_cache_file) < 12 * 3600:
        with open(disassembled_cache_file, "r") as f:
            disassembled_functions = json.load(f)

    for function_start_addr, function_end_addr, unwind_info_addr, pdata_ordinal in pdata_functions:
        function_id = get_function_id(function_start_addr)

        # Queue MinHook entry/exit wrapping for this function
        functions_to_hook.append(
            (
                function_start_addr,
                partial(function_enter_break_point, function_id, function_start_addr),
                partial(function_exit_break_point, function_id, function_start_addr),
            )
        )

        # Disassemble and patch CALL instructions in the function body
        if len(disassembled_functions) > pdata_ordinal:
            instructions = disassembled_functions[pdata_ordinal]
        else:
            instcode = process.read(function_start_addr, function_end_addr - function_start_addr)
            instructions = process.disassemble_string(function_start_addr, instcode)
            disassembled_functions.append(instructions)
            save_cache = True

        insert_break_at_calls(event, pid, instructions, function_id)

    if save_cache:
        with open(disassembled_cache_file, "w") as f:
            json.dump(disassembled_functions, f)


def add_instruction_redirect(
    instruction_address_unused: int,
    instructions: List[Tuple[int, int, str, str]],
    process: Any,
    enter_callback: Callable[[Any], None],
    exit_callback: Callable[[Any], None],
) -> Tuple[Optional[int], int]:
    """Patch a single instruction (typically CALL) to redirect into shellcode that wraps it with int3 breakpoints.

    Returns (jump_to_address, break_point_entry). jump_to_address is None/False on failure.
    """
    global shell_code_address_offset

    code: List[bytes] = []
    jump_to_address = (shell_code_address or 0) + shell_code_address_offset
    new_instruction_address = jump_to_address
    break_point_entry = -1
    jump_back_address: Optional[int] = None

    for instruction in instructions:
        instruction_address = instruction[0]
        instruction_len = instruction[1]
        instruction_asm = instruction[2]
        instruction_parts = instruction_asm.split(" ")

        # Where execution resumes after the original instruction
        jump_back_address = instruction_address + instruction_len

        insert_len = 0
        jump_type = "none"

        # Prefer full 5-byte JMP if possible, otherwise insert 1 byte (int3)
        if instruction_len >= 5:
            insert_len = 5
            jump_type = "normal"

            # Add entry breakpoint in the shellcode
            new_code = b"\xCC"
            code.append(new_code)
            new_instruction_address += len(new_code)
            break_point_entry = new_instruction_address

        elif instruction_len >= 2 and instruction_parts[0] in ("call",):
            insert_len = 1
            jump_type = "call"
        else:
            insert_len = 1
            jump_type = "1byte"

        extra_bytes = max(instruction_len - insert_len, 0)
        jmp_to_shellcode: Optional[bytes] = None
        asmm: Optional[str] = None

        if jump_type == "normal":
            asmm = f"jmp 0x{jump_to_address:x}" + (";nop" * extra_bytes)
        elif jump_type == "call":
            jmp_to_shellcode = b"\xCC" + (b"\x90" * extra_bytes)
            break_point_entry = instruction_address + 1
        elif jump_type == "1byte":
            jmp_to_shellcode = b"\xCC"
            break_point_entry = instruction_address + 1

        is_jump = instruction_asm.startswith("j")
        call_relocate = False

        # RIP-relative handling
        if "rip +" in instruction_asm or "rip -" in instruction_asm:
            print("Accounting for altered RIP", instruction_asm)
            diff = new_instruction_address - instruction[0]
            rip_address = f"rip - 0x{(diff & 0xFFFFFFFF):x}"
            instruction_asm = instruction_asm.replace("rip", rip_address)
        elif "rip" in instruction_asm:
            print("If instruction directly uses RIP in a non-relative way we can't move it")
            return False, break_point_entry

        if instruction_parts[0] in ("call", "jmp"):
            # Recompile jmps and calls
            if len(instruction_parts) == 2 and instruction_parts[1].startswith("0x"):
                # Absolute target; nothing to change
                print("static call/jmp")
                if instruction_parts[0] == "call":
                    call_relocate = True
            else:
                print("dynamic call/jmp")
                if instruction_parts[0] == "call":
                    call_relocate = True
        elif is_jump:
            print("complex jump will fail", instruction_asm)
            return False, break_point_entry
        elif instruction_parts[0] in ("cmp",):
            print("non-movable instruction", instruction_asm)
            return False, break_point_entry

        if asmm or jmp_to_shellcode is not None:
            if jmp_to_shellcode is None:
                print("write:", asmm, "at:", instruction_address, "jump_to_address:", jump_to_address, "diff:", jump_to_address - instruction_address)
                jmp_to_shellcode = asm(asmm, instruction_address)
            print("write:", asmm, "len:", len(jmp_to_shellcode), "at:", instruction_address)
            process.write(instruction_address, jmp_to_shellcode)
            # Register the breakpoint callback
            if jump_type == "normal":
                external_breakpoints[break_point_entry] = enter_callback
            else:
                external_breakpoints[break_point_entry] = partial(go_jump_breakpoint, jump_to_address, enter_callback)
        else:
            return False, break_point_entry

        # Append relocated original instruction to shellcode block
        new_code = asm(instruction_asm, new_instruction_address)
        code.append(new_code)
        new_instruction_address += len(new_code)
        break  # Only relocate the first instruction in list

    # Add exit breakpoint and final jump back to original flow
    code.append(b"\xCC")
    new_instruction_address += 1
    break_point_exit = new_instruction_address
    external_breakpoints[break_point_exit] = exit_callback

    last_jump_asm = f"jmp 0x{(jump_back_address or 0):x}"
    print("last_jump asm:", last_jump_asm)
    new_code = asm(last_jump_asm, new_instruction_address)
    code.append(new_code)
    new_instruction_address += len(new_code)

    shellcode = b"".join(code)
    shell_len = len(shellcode)

    shell_code_address_offset += shell_len + 20
    process.write(jump_to_address, shellcode)

    return jump_to_address, break_point_entry


def go_jump_breakpoint(jump_to_address: int, callback: Callable[[Any], None], event: Any) -> None:
    event.get_thread().set_pc(jump_to_address)
    callback(event)


def insert_break_at_calls(event: Any, pid: int, instructions: List[Tuple[int, int, str, str]], function_id: str) -> None:
    """Insert breakpoints at every CALL within a function's instruction list."""
    process = event.get_process()

    for instruction_num, instruction in enumerate(instructions):
        instruction_name = instruction[2].split(" ")[0]
        instruction_address = instruction[0]
        instruction_len = instruction[1]

        if instruction_name == "call":
            print("type: callback")
            call_num = 1  # We treat each encountered call as nr_1 in this simplified loop

            replace_instructions = [instruction]
            jump_to_address, break_point_entry = add_instruction_redirect(
                instruction_address,
                replace_instructions,
                process,
                partial(function_call_break_point, function_id, instruction_address, call_num, instruction),
                partial(function_called_break_point, function_id, instruction_address, call_num),
            )
            if not jump_to_address:
                print("could not create jump_table_entry")
                sys.exit()


def on_debug_event(event: Any, reduce_address: bool = False) -> None:
    """Main WinAppDbg event callback."""
    global exe_basic_name, loaded_modules, exe_entry_address, allocate_and_inject_dll

    pid = event.get_pid()
    tid = event.get_tid()
    process = event.get_process()
    bits = process.get_bits()
    address = event.get_thread().get_pc()

    name = event.get_event_name()
    code = event.get_event_code()

    # Exceptions
    if code == win32.EXCEPTION_DEBUG_EVENT:
        name = event.get_exception_description()
        exception_code = event.get_exception_code()

        if name == "Breakpoint":
            _ = deal_with_breakpoint(event, process, pid, tid, address)
            return

        print("non-breakpoint EXCEPTION_DEBUG_EVENT:", name, exception_code, address)
        return

    # Module load / process start
    if code in (win32.LOAD_DLL_DEBUG_EVENT, win32.CREATE_PROCESS_DEBUG_EVENT):
        filename = event.get_filename()
        basic_name = get_base_name(filename)
        pdb_name = os.path.join("pdbs", basic_name + ".pdb")

        base_addr = event.get_module_base()
        loaded_modules[basic_name] = base_addr

        # TODO: Load PDBs if available (not implemented)

        if basic_name == "kernel32":
            if allocate_and_inject_dll:
                allocate_mem_and_inject_dll(event, process, pid, exe_entry_address)
                allocate_and_inject_dll = False
                hook_calls(process, event, pid)

    if name == "Process creation event":
        filename = event.get_filename()
        basic = get_base_name(filename)
        exe_basic_name = basic
        base_addr = event.get_module_base()
        get_pdata(filename, base_addr, exe_basic_name)
        print("Process started", "exe_basic_name:", exe_basic_name, "pc:", address, "base_addr:", base_addr, "entry:", exe_entry_address)

    if name == "Thread creation event":
        try:
            process.scan_modules()
        except Exception:
            pass


# -----------------------------
# Trace printing callbacks
# -----------------------------

def function_enter_break_point(function_id: str, instruction_address: int, event: Any) -> None:
    thread = event.get_thread()
    pc = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()
    print("  " * len(call_stack) + "enter: " + function_id)


def function_exit_break_point(function_id: str, instruction_address: int, event: Any) -> None:
    thread = event.get_thread()
    pc = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()
    print("  " * (len(call_stack) + 1) + "exit: " + function_id)


def function_call_break_point(parent_function_id: str, instruction_address: int, call_num: int, instruction: Tuple[int, int, str, str], event: Any) -> None:
    thread = event.get_thread()
    pc = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()

    context = thread.get_context()
    target_addr = call_asm2addr(instruction, context, process)
    target_function_id = get_function_id(target_addr)

    call_stack.append("call " + target_function_id)
    print("  " * len(call_stack) + "call: nr_" + str(call_num) + " " + target_function_id + " from " + parent_function_id)


def function_called_break_point(parent_function_id: str, instruction_address: int, call_num: int, event: Any) -> None:
    thread = event.get_thread()
    pc = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()

    _called_function_id = call_stack.pop()
    print("  " * (len(call_stack) + 1) + "called: nr_" + str(call_num) + "  from " + parent_function_id)


# -----------------------------
# Address / PE helpers
# -----------------------------

def get_function_id(function_addr: int) -> str:
    """Return a stable id for a function based on module name plus offset, or .pdata id if known."""
    if function_addr in pdata_function_ids:
        return pdata_function_ids[function_addr]

    mod = get_module_from_address(function_addr)
    module_offset = function_addr - loaded_modules[mod]
    func_id = str(mod) + "+" + str(module_offset)
    return func_id


def get_module_from_address(address: int) -> Optional[str]:
    """Return module basename containing the given address by highest base <= address."""
    found_module: Optional[str] = None
    found_base = -1

    for module, base in loaded_modules.items():
        if base <= address and base > found_base:
            found_module = module
            found_base = base

    return found_module


def call_asm2addr(code: Tuple[int, int, str, str], context: Dict[str, int], process: Any) -> int:
    """Resolve a CALL target address from a disassembled instruction, given thread context."""
    asm_text = code[2]
    if "[" in asm_text:  # indirect call like call [rax+8] or RIP-relative
        mem_expr = asm_text.split("[", 1)[1].split("]", 1)[0].strip()
        mem_parts = mem_expr.split(" ")
        if len(mem_parts) != 1:
            reg, op, disp_str = mem_parts[0], mem_parts[1], mem_parts[2]
        else:
            reg, op, disp_str = mem_parts[0], "+", "0"
        reg = reg.capitalize()
        displacement = 0
        if op and disp_str:
            displacement = int(disp_str, 0)
            if op == "-":
                displacement = -displacement

        base_val = context[reg]

        # Since RIP counts per instruction, account for CALL length we haven't executed yet
        if reg == "Rip":
            base_val = code[0]
            base_val += code[1]

        effective_addr = base_val + displacement
        target_addr = read_ptr(process, effective_addr)

    else:
        label = asm_text.split(" ")[1]

        if label.startswith("0x"):
            target_addr = int(label, 16)
            return target_addr

        reg = label.capitalize()
        # Direct register-based call like "call rax"
        if reg in context:
            target_addr = context[reg]
        else:
            raise ValueError("resolve_label error", code[2], label)

    return target_addr


def deal_with_injection_callback(callback: Callable[[Any], None], save_place: int, event: Any) -> None:
    global is_in_injected_code
    del external_breakpoints[save_place]
    callback(event)
    is_in_injected_code = False


def inject_assembly(process: Any, code: str, return_address: int, code_done_callback: Optional[Callable[[Any], None]] = None) -> int:
    """Inject assembly that saves/restores full register state, executes `code`, then returns.

    The injected block ends with an int3 so we can flip the is_in_injected_code flag.
    """
    if register_save_address is None or code_injection_address is None:
        raise RuntimeError("Injection regions not allocated.")

    save_place = code_injection_address
    assembly1 = f"""
    pushfq
    sub   rsp, 8
    push rax; push rcx; push rdx; push rbx
    push rbp; push rsi; push rdi
    push r8;  push r9;  push r10; push r11
    push r12; push r13; push r14; push r15
    mov eax, 0x0D
    xor ecx, ecx
    cpuid
    movabs rbx, 0x{register_save_address:016X}
    xsave64 [rbx]
    {code}
    """

    if code_done_callback is not None:
        assembly1 += ";int 3;"
    else:
        sys.exit(
            "Not implemented: you need to specify a callback so we can know when we're out of the injected code."
        )

    shellcode1 = asm(assembly1, save_place)

    save_place += len(shellcode1)
    if code_done_callback is not None:
        external_breakpoints[save_place] = partial(deal_with_injection_callback, code_done_callback, save_place)

    assembly2 = f"""
    movabs rbx, 0x{register_save_address:016X}
    xrstor64 [rbx]
    pop r15; pop r14; pop r13; pop r12
    pop r11; pop r10; pop r9;  pop r8
    pop rdi; pop rsi; pop rbp; pop rbx
    pop rdx; pop rcx; pop rax
    add   rsp, 8
    popfq
    jmp [RIP]
    """
    shellcode2 = asm(assembly2, save_place) + struct.pack("<Q", return_address)

    shellcode = shellcode1 + shellcode2
    process.write(code_injection_address, shellcode)
    return code_injection_address


# -----------------------------
# DLL injection helpers
# -----------------------------

def run_loadlibrary_in_process(h_process: int, process: Any, dll_path: str) -> None:
    """Write dll_path to target and call LoadLibraryA via injected assembly."""
    dll_path_bytes = dll_path.encode("ascii") + b"\x00"

    ctypes.windll.kernel32.VirtualAllocEx.restype = ctypes.c_ulonglong
    name_remote_memory = ctypes.windll.kernel32.VirtualAllocEx(h_process, None, 1000, 0x3000, 0x04)
    if not name_remote_memory:
        raise Exception(f"Failed to allocate memory in target process: {ctypes.WinError()}")

    process.write(name_remote_memory, dll_path_bytes)

    kernel32 = process.get_module_by_name("kernel32.dll")
    load_library_addr = kernel32.resolve("LoadLibraryA")

    asm_code_to_run.append((
        f"sub rsp, 0x20;mov rcx, 0x{name_remote_memory:016X};mov rax, 0x{load_library_addr:016X};call rax;add rsp, 0x20",
        partial(loaded_dll, dll_path),
    ))


def loaded_dll(dll_name: str, event: Any) -> None:
    thread = event.get_thread()
    context = thread.get_context()
    base_addr = context["Rax"]
    if base_addr != 0:
        print("Loaded injected dll:", dll_name)
        basename = os.path.basename(dll_name)
        basic_name, ext = os.path.splitext(basename)
        loaded_modules[basic_name] = base_addr

        if basic_name == "calltracer" and len(call_tracer_dll_func) == 0:
            pe = pefile.PE(dll_name)

            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        name = exp.name.decode()
                        rva = exp.address
                        virtual_address = base_addr + rva
                        call_tracer_dll_func[name] = virtual_address
                    else:
                        print("No export table found.")
                # Hook all functions listed in .pdata
                hook_functions()
    else:
        print("failed to load injected dll:", dll_name)
        sys.exit()


def exe_entry(event: Any) -> None:
    print("first instruction entered")
    on_debug_event(event, reduce_address=True)


def get_pdata(filen: str, base_addr: int, exe_basic_name: str) -> None:
    """Parse .pdata from file on disk and populate function ranges & IDs."""
    global pdata, pdata_functions, exe_entry_address, pdata_function_ids

    pe = pefile.PE(filen)
    exe_entry_address = pe.OPTIONAL_HEADER.AddressOfEntryPoint + base_addr
    functions: List[Tuple[int, int, int, int]] = []
    for section in pe.sections:
        if b".pdata" in section.Name:
            pdata_data = section.get_data()
            pdata = pdata_data

            # RUNTIME_FUNCTION entry: 12 bytes (Start, End, UnwindInfo), all RVAs
            entry_size = 12
            num_entries = len(pdata_data) // entry_size

            for i in range(num_entries):
                entry = pdata_data[i * entry_size : (i + 1) * entry_size]
                start_addr, end_addr, unwind_info_addr = struct.unpack("<III", entry)
                if start_addr == 0 and end_addr == 0:
                    break
                functions.append((start_addr + base_addr, end_addr + base_addr, unwind_info_addr, i))
                pdata_function_ids[start_addr + base_addr] = exe_basic_name + "_" + str(i)
            break

    pdata_functions = functions


# -----------------------------
# Entrypoint
# -----------------------------
if __name__ == "__main__":
    # If a process is already running we attach; otherwise we create it.
    start_or_attach_debugger(sys.argv[1:])
