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
disassembled_functions: List[List[Tuple[int, int, str, str]]] = []

# Simple call stack for pretty printing
call_stack: List[str] = []

# Functions (addresses) we plan to hook via MinHook (in calltracer.dll)
# Each entry: (target_fn_addr, enter_callback, exit_callback)
functions_to_hook: List[Tuple[int, Callable[[Any], None], Callable[[Any], None]]] = []

# Initialize Keystone for x64.
ks = Ks(KS_ARCH_X86, KS_MODE_64)


#Thread Storage
thread_storage_list_address = None
thread_storage_list_addresses = {}


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
            debug_obj.execv(argv, bBreakOnEntryPoint = False)
        else:
            debug_obj.attach(pid, bBreakOnEntryPoint = False)

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


def allocate_mem_and_inject_dll(event: Any, process: Any, pid: int, tid: int, address_close_to_code: int) -> None:
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
    size = 0x1000000
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
    

    process.close_handle()
    
    setup_thread_storage(process, True, tid = tid)


def min_hooked_entry_hook(ujump_table_address: int, callback: Callable[[Any], None], event: Any) -> None:
    """
    Breakpoint handler for function entry via MinHook trampoline wrapper.
    I am a bit afraid that this might get called multiple times as code in a function may jump bak to the first instruction.
    This is somewhat unlikly as the first few instructions are generally used to set up the stack and stuff like that.
    This may register to many return addreses when call stack optimizations are used. WIll probaly need a fix for that.
    Main "issue" is tail call optimization. min_hooked_entry_hook will execute even when it is jumped to and not called. ie part of tail call optimization.
    This means ret_replacements will keep growing and not get poped at tthe end. Making it out of sync with reality.
    """
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
    print("stack_pointer:", stack_pointer, 'return_address:', return_address)
    
    #print("saving return address:", return_address, ujump_table_address)

    ret_replacements[tid][ujump_table_address].append(return_address)
    callback(event)


def min_hooked_exit_hook(ujump_table_address: int, callback: Callable[[Any], None], event: Any) -> None:
    """Breakpoint handler for function exit; returns to original address and calls callback."""
    tid = event.get_tid()
    original_return_address = ret_replacements[tid][ujump_table_address].pop()
    #print("jumping to:", original_return_address, ujump_table_address)
    #event.get_thread().set_pc(original_return_address)
    callback(event)
    
def instrument_function(instructions, process, enter_callback):
    """Takes list of instrucitons for a fuction and hooks the function"""
    assert (len(instructions) != 0), "function cant be zero instructions long"
    function_addres = instructions[0][0]
    #print(instructions)
    clean_instructions(instructions, process, enter_callback)
    #exit(0)

def clean_instructions(instructions, process, enter_callback):
    global shell_code_address_offset, shell_code_address

    clean_code = []
    function_addres = instructions[0][0]
    function_id = get_function_id(function_addres)
    print("instrumenting:", function_id)
    new_location = shell_code_address + shell_code_address_offset
    new_instruction_address = new_location
    free_space = 0
    jump_asm = False
    
    #Add entry tracing
    clean = asm(f"int3", new_instruction_address)
    clean_code.append(clean)
    new_instruction_address += len(clean)
    external_breakpoints[new_location+1] = enter_callback
    
    for instruction in instructions:
        instruction_address = instruction[0]
        instruction_len = instruction[1]
        instruction_asm = instruction[2]
        instruction_parts = instruction_asm.split(" ")
        
        
        
        free_space += instruction_len
        
        #If a insctruction is int3 we cant move it cause other stuff may use it
        if instruction_asm == "int3":
            print("int3 already at address:", instruction_address)
            return

        # RIP-relative handling
        if "rip +" in instruction_asm or "rip -" in instruction_asm:
            print("Accounting for altered RIP", instruction_asm)
            diff = new_instruction_address - instruction[0]
            rip_address = instruction_address + instruction_len
            rip_address = f"{rip_address}"
            instruction_asm = instruction_asm.replace("rip", rip_address)
        
        clean = asm(instruction_asm, new_instruction_address)
        print('old:', instruction[2], 'new:', instruction_asm)
        clean_code.append(clean)
        new_instruction_address += len(clean)
        
        if free_space >= 5:
            extra_bytes = max(free_space - 5, 0)#jmp is 5 bytes long
            jump_asm = f"jmp {new_location}" + (";nop" * extra_bytes)
            break
    
    
    #Add jumping back to shell code
    jump_back_address = function_addres + free_space
    clean = asm(f"jmp {jump_back_address}", new_instruction_address)
    clean_code.append(clean)
    new_instruction_address += len(clean)
    
    shellcode = b"".join(clean_code)
    shell_len = len(shellcode)
    
    shell_code_address_offset += shell_len + 20
    #print(shell_code_address_offset)
    
    process.write(new_location, shellcode)
    
    #if the cleaing managed to get enogh bytes
    if jump_asm:
        print(jump_asm)
        jmp_to_shellcode = asm(jump_asm, function_addres)
        print('jump len:', free_space, len(jmp_to_shellcode))
    else:#else we use a breakpoint jump, we skip the first tracing breakpoint if we use this method
        external_breakpoints[function_addres+1] = partial(go_jump_breakpoint, new_location+1, enter_callback)
        extra_bytes = max(free_space - 1, 0)#0xCC is 1 bytes long
        jmp_to_shellcode = b"\xCC" + (b"\x90" * extra_bytes)
    
    process.write(function_addres, jmp_to_shellcode)
    print("wrote stuff")
    
        

def min_hooked_function(function_addres: int, jump_table_address: int, enter_callback: Callable[[Any], None], exit_callback: Callable[[Any], None], event: Any) -> None:
    """Executed after MinHook finishes hooking a function."""
    thread = event.get_thread()
    context = thread.get_context()
    result = context["Rax"]


    process = event.get_process()
    if result != 0:
        print("failed to hook function", get_function_id(function_addres), result, "using internal hook function")
        pdata_by_start = {
            start: (end, unwind, ordinal)
            for start, end, unwind, ordinal in pdata_functions
        }
        end, unwind, ordinal = pdata_by_start[function_addres]
        instrument_function(disassembled_functions[ordinal], process, enter_callback)
        return


    
    address_to_trampoline = process.read(shell_code_address, 8)
    address_to_trampoline = struct.unpack("<Q", address_to_trampoline)[0]
    print("min_hooked_function:", result, "addr:", address_to_trampoline)

    
    # Tracking assembly: adds a breakpoint before and after the real function.
    # Saves the return address, modifies it to point to the post-call int3, then jumps.
    asmm = (
        "int 3;" # triger interupt for tracing purpose and saving original return address
        "push rax;" # save value in rax
        "mov rax, [RIP + 20];" # fill rax with addres leading to code after trampoline jump
        "mov [RSP+0x8], rax;" # move the value in rax in to the stack (saving it as a return address), that way we return to the second interupt
        "pop rax;" # restore rax 
        "jmp [RIP];" # jump to address_to_trampoline
        #"int 3" # triger interupt for tracing purpose and returning to original location
    )
    
    
    
    enter_asm = (
        f"mov     rcx, {function_addres};"    # first argument 
        "mov     rdx, r15;"    # second argument return address saved in r15 by generate_clean_asm_func_call
        f"mov     rax, {call_tracer_dll_func['function_enter_trace_point']};"
        "call    rax;"
    )
    
    enter_func_call_code = asm(generate_clean_asm_func_call(enter_asm), jump_table_address)
    jump_write_address = jump_table_address + len(enter_func_call_code)
    
    
    exit_asm = (
        f"mov     rcx, {function_addres};"    # first argument 
        f"mov     rax, {call_tracer_dll_func['function_exit_trace_point']};"
        "call    rax;"
        "mov [r15], rax" #Restore the original return address that was given by function_exit_trace_point
    )
    exit_func_call_code = asm(generate_clean_asm_func_call(exit_asm), jump_table_address)
    
    final_jump_code = asm("jmp [rsp]", jump_table_address + len(exit_func_call_code))
    
    jcode = asm(asmm, jump_write_address)
    after_trampoline_jump = jump_write_address + len(jcode)+16
    jump_code = enter_func_call_code + jcode + struct.pack("<Q", address_to_trampoline) + struct.pack("<Q", after_trampoline_jump) + exit_func_call_code + b"\xCC" + final_jump_code
    
    final_breakpoint = len(jump_code)+jump_table_address - len(final_jump_code)

    external_breakpoints[jump_write_address + 2] = partial(min_hooked_entry_hook, jump_table_address, enter_callback)
    
    external_breakpoints[final_breakpoint] = partial(min_hooked_exit_hook, jump_table_address, exit_callback)
    process.write(jump_table_address, jump_code)


def min_hook_enabled(event: Any) -> None:
    thread = event.get_thread()
    context = thread.get_context()
    result = context["Rax"]
    print("min_hook_enabled:", result)
    
    
def ran_fun(event: Any) -> None:
    global is_in_injected_code
    thread = event.get_thread()
    context = thread.get_context()
    result = context["Rax"]
    print("ran_func:", context)
    is_in_injected_code = False
    #exit()
    
def start_fun(event: Any) -> None:
    thread = event.get_thread()
    context = thread.get_context()
    result = context["Rax"]
    print("start_fun:", context)


def submit_hook_function_list_for_injection() -> None:
    """Queue MinHook setup calls for all functions_to_hook and queue a global enable."""
    global shell_code_address_offset

    hook_function = call_tracer_dll_func["hook_function"]
    enable_function = call_tracer_dll_func["enable_hooks"]

    for target_fn_addr, enter_callback, exit_callback in functions_to_hook:
        print("hook", target_fn_addr, "using:", call_tracer_dll_func["hook_function"]) 
        jump_table_address = shell_code_address + shell_code_address_offset
        shell_code_address_offset += 800  # ~800 bytes per entry is usually enough

        asm_code_to_run.append((
            f"mov rcx, {target_fn_addr};"
            f"mov rdx, {jump_table_address};"
            f"mov r8, {shell_code_address};"
            f"mov rax, {hook_function};"
            "call rax",
            partial(min_hooked_function, target_fn_addr, jump_table_address, enter_callback, exit_callback),
        ))

    # Enable hooks once all are queued
    if len(functions_to_hook) != 0:
        print("enable func_location:", enable_function)
        asmm = (
            f"mov rax, {enable_function};"
            "call rax;"
        )
        asm_code_to_run.append((asmm, min_hook_enabled))


breakpoint_active = False
def deal_with_breakpoint(event: Any, process: Any, pid: int, tid: int, address: int) -> bool:
    """Handle breakpoint and injection state machine."""
    global in_loading_phase, is_in_injected_code, breakpoint_active

    #print("deal_with_breakpoint:", address, address == exe_entry_address)
    
    known_ = False
    if address in external_breakpoints:
        callb = external_breakpoints[address]
        known_ = True
    
    inject_ok = False
    if address in external_breakpoints or (in_loading_phase and address == exe_entry_address):
        inject_ok = True
        
        
    #print("inject_ok:", inject_ok, "known:", known_, "is_in_injected_code:", is_in_injected_code, 'in_loading_phase:', in_loading_phase, 'len:', len(asm_code_to_run))

    if len(asm_code_to_run) != 0 and not is_in_injected_code and inject_ok:
        print("jumping to injected code", len(asm_code_to_run))
        asmd, code_done_callback = asm_code_to_run.pop(0)
        break_point_location = address

        # For WinAppDbg breakpoints (event.debug.break_at), address points to the 0xCC byte; for others, it's the next instruction.
        if address != exe_entry_address:
            break_point_location -= 1

        code_address = inject_assembly(process, asmd, break_point_location, code_done_callback)
        is_in_injected_code = True

        # Disable entry breakpoint so it isn't copied while running MinHook
        breakpoint_active = False
        event.debug.dont_break_at(pid, exe_entry_address)
        event.get_thread().set_pc(code_address)
        return True
    
    before = is_in_injected_code
    if address in external_breakpoints:
        callb(event)

    if in_loading_phase and not is_in_injected_code and before and not breakpoint_active:
        print("Re-enable breakpoint so it triggers next time", len(asm_code_to_run))
        # Re-enable breakpoint so it triggers next time
        event.debug.break_at(pid, exe_entry_address)
        breakpoint_active = True

    if len(asm_code_to_run) == 0 and in_loading_phase and not is_in_injected_code and inject_ok:
        print("Loading phase done; disabling entry breakpoint")
        #if address != exe_entry_address:#You cant remove  breakpoint you are currently on
        event.debug.dont_break_at(pid, exe_entry_address)
        breakpoint_active = False
        in_loading_phase = False

    if known_:
        return True
    else:
        print("unknown break_point called", tid, address)

    return False


def hook_calls(process: Any, event: Any, pid: int) -> None:
    """Disassemble functions and patch CALLs to insert call-site tracing breakpoints."""
    global disassembled_functions
    # Cache to avoid repeated disassembly of large binaries
    
    disassembled_cache_file = exe_basic_name + "_instructions_cache.json"
    save_cache = False
    if len(disassembled_functions) == 0:
        if os.path.exists(disassembled_cache_file) and time.time() - os.path.getmtime(disassembled_cache_file) < 12 * 3600:
            with open(disassembled_cache_file, "r") as f:
                disassembled_functions = json.load(f)

    for function_start_addr, function_end_addr, unwind_info_addr, pdata_ordinal in pdata_functions:
        function_id = get_function_id(function_start_addr)
        DO_hook = True
        
        # Disassemble and patch CALL instructions in the function body
        if len(disassembled_functions) > pdata_ordinal:
            instructions = disassembled_functions[pdata_ordinal]
        else:
            instcode = process.read(function_start_addr, function_end_addr - function_start_addr)
            instructions = process.disassemble_string(function_start_addr, instcode)
            disassembled_functions.append(instructions)
            save_cache = True
        
        #if pdata_ordinal not in(122,):
        #instrument_function(instructions, process, partial(function_enter_break_point, function_id, function_start_addr))
        
        #print("ordinal:", pdata_ordinal)
        #if pdata_ordinal not in(122,) and pdata_ordinal < 120:
        insert_break_at_calls(event, pid, instructions, function_id, function_start_addr)
        
        #if pdata_ordinal == 168:
        #    break
        

    if save_cache:
        with open(disassembled_cache_file, "w") as f:
            json.dump(disassembled_functions, f)


def create_list_of_functions_to_hook() -> None:
    """Disassemble functions and patch CALLs to insert call-site tracing breakpoints."""
    global disassembled_functions
    # Cache to avoid repeated disassembly of large binaries
    
    disassembled_cache_file = exe_basic_name + "_instructions_cache.json"
    save_cache = False
    if len(disassembled_functions) == 0:
        if os.path.exists(disassembled_cache_file) and time.time() - os.path.getmtime(disassembled_cache_file) < 12 * 3600:
            with open(disassembled_cache_file, "r") as f:
                disassembled_functions = json.load(f)

    for function_start_addr, function_end_addr, unwind_info_addr, pdata_ordinal in pdata_functions:
        function_id = get_function_id(function_start_addr)
        DO_hook = True
        
        # Disassemble and patch CALL instructions in the function body
        if len(disassembled_functions) > pdata_ordinal:
            instructions = disassembled_functions[pdata_ordinal]
        else:
            instcode = process.read(function_start_addr, function_end_addr - function_start_addr)
            instructions = process.disassemble_string(function_start_addr, instcode)
            disassembled_functions.append(instructions)
            save_cache = True
        
        first_instruction = instructions[0][2]
        #VLC Does not like it when you move breakpoints
        if first_instruction in ('int3', 'ret'):
            #print("yes", instructions[0][2])
            DO_hook = False
            #exit()
        
        # Queue MinHook entry/exit wrapping for this function
        if DO_hook:
            functions_to_hook.append(
                (
                    function_start_addr,
                    partial(function_enter_break_point, function_id, function_start_addr),
                    partial(function_exit_break_point, function_id, function_start_addr),
                )
            )

    if save_cache:
        with open(disassembled_cache_file, "w") as f:
            json.dump(disassembled_functions, f)


def dud_func():
    pass

def add_instruction_redirect(
    function_address: int,
    instruction_address_unused: int,
    instructions: List[Tuple[int, int, str, str]],
    process: Any,
    enter_callback: Callable[[Any], None],
    exit_callback: Callable[[Any], None],
) -> Tuple[Optional[int], int]:
    """Patch a single instruction (typically CALL) to redirect into shellcode that wraps it with int3 breakpoints.

    Returns (jump_to_address, break_point_entry). jump_to_address is None/False on failure.
    """
    global shell_code_address_offset, shell_code_address

    code: List[bytes] = []
    jump_to_address = shell_code_address + shell_code_address_offset
    new_instruction_address = jump_to_address
    break_point_entry = -1
    jump_back_address: Optional[int] = None

    if len(instructions) != 0:
        instruction = instructions[0]
        instruction_address = instruction[0]
        instruction_len = instruction[1]
        instruction_asm = instruction[2]
        instruction_parts = instruction_asm.split(" ")

        # Where execution resumes after the original instruction
        jump_back_address = instruction_address + instruction_len

        insert_len = 0
        jump_type = "none"
        
        #function_call_trace_point(uint64_t function_address, uint64_t call_address, uint64_t return_address, uint64_t target_address)
        call_asm = (
            f"mov     rcx, {function_address};"    # first argument function_address
            f"mov     rdx, {instruction_address};"    # second argument call_address
            f"mov     r8, {instruction_address + instruction_len};"    # third arg return_address
            f"mov     r9, {function_address};"    # forth arg FIXXXMEEEEE add target address
            f"mov     rax, {call_tracer_dll_func['function_call_trace_point']};"
            "call    rax;"
        )
        
        call_func_call_code = asm(generate_clean_asm_func_call(call_asm), new_instruction_address)
        
        code.append(call_func_call_code)
        new_instruction_address += len(call_func_call_code)
        
        # Add entry breakpoint in the shellcode
        new_code = b"\xCC"
        code.append(new_code)
        new_instruction_address += len(new_code)
        break_point_entry = new_instruction_address

        # Prefer full 5-byte JMP if possible, otherwise insert 1 byte (int3)
        if instruction_len >= 5:
            insert_len = 5
            jump_type = "normal"
        elif instruction_len >= 2 and instruction_parts[0] in ("call",):#FIXMEEE whenever minhook moves these breakpoints shit stops working
            insert_len = 1
            jump_type = "call"
        else:#FIXMEEE whenever minhook moves these breakpoints shit stops working
            insert_len = 1
            jump_type = "1byte"

        extra_bytes = max(instruction_len - insert_len, 0)
        jmp_to_shellcode: Optional[bytes] = None
        asmm: Optional[str] = None
        jump_breakpoint = None
        if jump_type == "normal":
            asmm = f"jmp {jump_to_address}" + (";nop" * extra_bytes)
        elif jump_type == "call":
            jmp_to_shellcode = b"\xCC" + (b"\x90" * extra_bytes)
            jump_breakpoint = instruction_address + 1
        elif jump_type == "1byte":
            jmp_to_shellcode = b"\xCC"
            jump_breakpoint = instruction_address + 1

        is_jump = instruction_asm.startswith("j")
        call_relocate = False

        # RIP-relative handling
        if "rip +" in instruction_asm or "rip -" in instruction_asm:
            print("Accounting for altered RIP", instruction_asm)
            diff = new_instruction_address - instruction[0]
            rip_address = instruction_address + instruction_len
            rip_address = f"{rip_address}"
            instruction_asm = instruction_asm.replace("rip", rip_address)
        elif "rip" in instruction_asm:
            raise ValueError("If instruction directly uses RIP in a non-relative way we can't move it" + instruction_asm)
            return False, break_point_entry
        static = True
        if instruction_parts[0] in ("call", "jmp"):
            # Recompile jmps and calls
            if len(instruction_parts) == 2 and instruction_parts[1].startswith("0x"):
                # Absolute target; nothing to change
                print("static call/jmp")
                static = True
                if instruction_parts[0] == "call":
                    call_relocate = True
            else:
                print("dynamic call/jmp")
                static = False
                #return False, break_point_entry
                #return False, break_point_entry
                if instruction_parts[0] == "call":
                    call_relocate = True
        elif is_jump:
            print("complex jump will fail", instruction_asm)
            return False, break_point_entry
        elif instruction_parts[0] in ("cmp",):
            print("non-movable instruction", instruction_asm)
            return False, break_point_entry

        if asmm is not None or jmp_to_shellcode is not None:
            if jmp_to_shellcode is None:
                jmp_to_shellcode = asm(asmm, instruction_address)
            print(jump_type,'org:', instruction_asm, "(", instruction_len, ") write:", asmm, "bytes:", len(jmp_to_shellcode), "at:", instruction_address, "jump_to_address:", jump_to_address, "diff:", jump_to_address - instruction_address)
            
            
            if jump_breakpoint is not None:
                assert (jump_breakpoint not in external_breakpoints), "Overwriting old breakpoint"
                external_breakpoints[jump_breakpoint] = partial(go_jump_breakpoint, jump_to_address, dud_func)
            
            assert (break_point_entry not in external_breakpoints), "Overwriting old breakpoint"
            external_breakpoints[break_point_entry] = enter_callback
        else:
            raise ValueError("should never happen")
            return False, break_point_entry

        # If the function we are patching depends on the return address, problematicly this does not let us capture the return.
        if static and False: #This code path manually sets the return address to the real next instruciton then jumps to the function
            asd = "push rax;push rax;mov rax, [RIP + 12];mov [RSP+0x8], rax;pop rax;jmp [rip + 8];"
            new_code = asm(asd, new_instruction_address)

            code.append(new_code)
            new_instruction_address += len(new_code)
            
            #save the return position
            new_code = struct.pack("<Q", jump_back_address)
            code.append(new_code)
            new_instruction_address += len(new_code)
            
            #extract and sae the target function that we are trying to call
            target = int(instruction_parts[1], 16)
            new_code = struct.pack("<Q", target)
            code.append(new_code)
            new_instruction_address += len(new_code)
            
            print('function_id:', get_function_id(target))
            
            
        else:
            new_code = asm(instruction_asm, new_instruction_address)
            code.append(new_code)
            new_instruction_address += len(new_code)

    # Add exit breakpoint and final jump back to original flow
    code.append(b"\xCC")
    new_instruction_address += 1
    break_point_exit = new_instruction_address
    assert (break_point_exit not in external_breakpoints), "Overwriting old breakpoint"
    external_breakpoints[break_point_exit] = exit_callback
    
    
    #function_called_trace_point(uint64_t function_address, uint64_t call_address, uint64_t return_address);
    call_asm = (
        f"mov     rcx, {function_address};"    # first argument function_address
        f"mov     rdx, {instruction_address};"    # second argument call_address
        f"mov     r8, {instruction_address + instruction_len};"    # third arg return_address
        f"mov     rax, {call_tracer_dll_func['function_called_trace_point']};"
        "call    rax;"
    )
    
    call_func_called_code = asm(generate_clean_asm_func_call(call_asm), new_instruction_address)
    
    code.append(call_func_called_code)
    new_instruction_address += len(call_func_called_code)

    last_jump_asm = f"jmp {jump_back_address}"
    print("last_jump asm:", last_jump_asm)
    new_code = asm(last_jump_asm, new_instruction_address)
    code.append(new_code)
    new_instruction_address += len(new_code)

    shellcode = b"".join(code)
    shell_len = len(shellcode)

    shell_code_address_offset += shell_len + 20
    process.write(jump_to_address, shellcode)
    process.write(instruction_address, jmp_to_shellcode)

    return jump_to_address, break_point_entry


def go_jump_breakpoint(jump_to_address: int, callback: Callable[[Any], None], event: Any) -> None:
    print("go_jump_breakpoint", jump_to_address)
    event.get_thread().set_pc(jump_to_address)
    callback(event)


def insert_break_at_calls(event: Any, pid: int, instructions: List[Tuple[int, int, str, str]], function_id: str, function_address: int) -> None:
    """Insert breakpoints at every CALL within a function's instruction list."""
    process = event.get_process()
    
    call_num = 0
    for instruction_num, instruction in enumerate(instructions):
        instruction_name = instruction[2].split(" ")[0]
        instruction_address = instruction[0]
        instruction_len = instruction[1]

        if instruction_name == "call":
            print("type: callback")
            
            
            reg, indirect, offset = asm2regaddr(instruction)
            #To get the target value to the function_call_break_point() you would need to edit add_instruction_redirect() to take reg, indirect and offset and save/return the target value somehow 
            replace_instructions = [instruction]
            jump_to_address, break_point_entry = add_instruction_redirect(
                function_address,
                instruction_address,
                replace_instructions,
                process,
                partial(function_call_break_point, function_id, instruction_address, call_num, reg, indirect, offset),
                partial(function_called_break_point, function_id, instruction_address, call_num),
            )
            if not jump_to_address:
                print("could not create jump_table_entry for instruction", instruction, instructions)
                #break
                #exit(0)
                #sys.exit()
            call_num += 1


def on_debug_event(event: Any, reduce_address: bool = False) -> None:
    """Main WinAppDbg event callback."""
    global exe_basic_name, loaded_modules, exe_entry_address, allocate_and_inject_dll, breakpoint_active

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
                allocate_mem_and_inject_dll(event, process, pid, tid, exe_entry_address)
                allocate_and_inject_dll = False
                
                # Hook stuff
                create_list_of_functions_to_hook()
                
                
                # add a breakpoint on the entry point
                event.debug.break_at(pid, exe_entry_address, exe_entry)
                breakpoint_active = True

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
        setup_thread_storage(process, tid = tid)

def setup_thread_storage(process, Alocator_setup = False, tid = -99):
    global thread_storage_list_address
    
    process_handle = process.get_handle()
    if thread_storage_list_address is None:
        if Alocator_setup:
            print("allocate_thread mem", tid)
            thread_storage_list_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, 100000, 0x3000, 0x04)
            if not thread_storage_list_address:
                raise Exception(f"Failed to allocate memory in target process: {ctypes.WinError()}")
        else:
            print("alocator my not have been setup yet", tid)
            pass
            
    if thread_storage_list_address is not None and tid not in thread_storage_list_addresses:
        
        thread_storage_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, 20000, 0x3000, 0x04)
        print("setup storage for new thread", tid, thread_storage_address)
        if not thread_storage_address:
            raise Exception(f"Failed to allocate memory in target process: {ctypes.WinError()}")
        new_offeset = len(thread_storage_list_addresses) * (8 + 4)
        address_to_list_position = thread_storage_list_address + new_offeset
        
        list_entry = struct.pack("<I", tid) + struct.pack("<Q", thread_storage_address)
        
        process.write(address_to_list_position, list_entry)
        
        thread_storage_list_addresses[tid] = thread_storage_address
    
    process.close_handle()

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


def function_call_break_point(parent_function_id: str, instruction_address: int, call_num: int, reg, indirect, offset, event: Any) -> None:
    thread = event.get_thread()
    pc = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()

    context = thread.get_context()

    target_addr = get_targetaddr(reg, indirect, offset, context, process)
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
    
    
def get_targetaddr(reg, indirect, offset, context, process):
    """use info to get CALL target given thread context."""
    target_addr = offset
    if reg is not None:
        if reg in context:
            target_addr += context[reg]
        else:
            raise ValueError("Unkownn registry:", reg)
    if indirect:
        target_addr = read_ptr(process, target_addr)
    return target_addr

def asm2regaddr(code: Tuple[int, int, str, str]):
    """parse info needed to get CALL target address from a instruction, given thread context."""
    reg = None
    offset = 0
    indirect = False
    asm_text = code[2]
    if "[" in asm_text:  # indirect call like call [rax+8] or RIP-relative
        indirect = True
        mem_expr = asm_text.split("[", 1)[1].split("]", 1)[0].strip()
        mem_parts = mem_expr.split(" ")
        if len(mem_parts) != 1:
            reg, op, disp_str = mem_parts[0], mem_parts[1], mem_parts[2]
        else:
            reg, op, disp_str = mem_parts[0], "+", "0"
        reg = reg.capitalize()
        if op and disp_str:
            offset = int(disp_str, 0)
            if op == "-":
                offset = -offset
        

        # Since RIP counts per instruction, account for CALL length we haven't executed yet
        if reg == "Rip":
            base_val = code[0] + code[1]
            offset = base_val + offset
            reg = None

    else:
        label = asm_text.split(" ")[1]

        if label.startswith("0x"):
            target_addr = int(label, 16)
            return reg, indirect, target_addr

        reg = label.capitalize()

    return reg, indirect, offset

def deal_with_injection_callback(callback: Callable[[Any], None], save_place: int, event: Any) -> None:
    global is_in_injected_code
    del external_breakpoints[save_place]
    callback(event)
    is_in_injected_code = False

def deal_with_injection_callback_debug(callback: Callable[[Any], None], save_place: int, event: Any) -> None:
    global is_in_injected_code
    del external_breakpoints[save_place]
    callback(event)
    start_fun(event)
        

def strip_semicolon_comments(asm: str) -> str:
    """
    Remove everything from the first ';' to the end of the line for each line in `asm`.
    Preserves original line endings and leading indentation, trims trailing whitespace.
    """
    out_lines = []
    for line in asm.splitlines(True):  # keep line endings
        # find position of ';' before any newline characters
        # handle lines that may end with '\r\n' or '\n'
        if line.endswith('\r\n'):
            eol = '\r\n'
            body = line[:-2]
        elif line.endswith('\n'):
            eol = '\n'
            body = line[:-1]
        elif line.endswith('\r'):
            eol = '\r'
            body = line[:-1]
        else:
            eol = ''
            body = line

        idx = body.find(';')
        if idx != -1:
            body = body[:idx]

        # strip trailing whitespace from the kept part (but keep leading whitespace)
        body = body.rstrip()

        out_lines.append(body + eol)

    return ''.join(out_lines)
    
def generate_clean_asm_func_call(code, in_two_parts = False):
    global register_save_address, thread_storage_list_address
    assembly1 = strip_semicolon_comments("""
    ; ===== prologue: preserve flags & callee-saved registers =====
pushfq
sub   rsp, 8

; save callee-saved GPRs that we will use or clobber

push r15
mov r15, rsp
add r15, 24; save original return_address stack location in r15 fix ofset 24 caused by pushes
push rbp
push rsi
push rdi
push rax
push rcx
push rdx
push r8
push r9
push r10          ; r10 used as temp for alignment
push r11          ; r11 used for size/temp
push r12
push r13
push r14
push rbx



; Find thread storage from list

.find_current_thread_location:
    ; load current thread id (low 32 bits of GS:[0x48])
    mov     eax, dword ptr gs:[0x48]    ; EAX = current TID

    ; base pointer to the array
    movabs  rsi, """+str(thread_storage_list_address)+"""           ; RSI = array base

.loop:
    mov     edx, dword ptr [rsi]        ; EDX = entry.thread_id
    mov     rcx, qword ptr [rsi + 4]    ; RCX = entry.memory_location

    test    rcx, rcx
    je      .not_found                  ; if memory_location == 0,  end-of-list

    cmp     edx, eax
    je      .found                      ; match: return memory_location in RAX

    add     rsi, 12                     ; advance to next entry (12 bytes)
    jmp     .loop

    
.not_found:
    nop

.found:
    mov     rax, rcx                    ; return matching memory_location





mov r12, rax


; set mask: XCR0 -> EDX:EAX, ECX must be 0
xor  ecx, ecx
xgetbv

; save extended state; DO NOT use rdx as the memory base (EDX is mask upper)
xsave64 [r12]            ; (use xsaveopt if you detect support)
xor  ecx, ecx


; ===== prepare for making the actual code =====
; We must ensure RSP is 16-byte aligned at the CALL instruction and have 32 bytes shadow.

; Compute the adjustment needed to align RSP to 16 bytes:
; r10 currently saved on stack; we'll use r10 as temp for alignment value
; r11 currently holds alloc_size but we won't clobber it; use rax/rcx temporarily
mov  rax, rsp
and  rax, 15          ; rax = rsp % 16
xor  r10, r10         ; r10 = 0 (will store correction amount if any)
test rax, rax
je   .no_align_needed
mov  r10, 16
sub  r10, rax         ; r10 = (16 - (rsp & 15))
sub  rsp, r10         ; adjust stack to align to 16
.no_align_needed:
push r10
push r10
push r11
push r12

; Now allocate the 32-byte shadow space required by Windows x64 ABI
sub  rsp, 32
    """) + code.replace(";", "\n") +"\n"
    assembly2 = strip_semicolon_comments("""
    ; ===== after call: pop shadow and undo alignment correction =====
add  rsp, 32

pop r12
pop r11
pop r10
pop r10
test r10, r10
je   .no_align_restore
add  rsp, r10
.no_align_restore:

; ===== restore extended state =====
xor  ecx, ecx
xgetbv
xrstor64 [r12]        ; restore extended state from stack buffer


; ===== restore saved registers in reverse order =====

pop  rbx
pop  r14
pop  r13
pop  r12
pop  r11
pop  r10
pop  r9
pop  r8
pop  rdx
pop  rcx
pop  rax
pop  rdi
pop  rsi
pop  rbp
pop  r15


add  rsp, 8
popfq

""")
    if in_two_parts:
        return assembly1, assembly2
    return assembly1 + assembly2

def inject_assembly(process: Any, code: str, return_address: int, code_done_callback: Optional[Callable[[Any], None]] = None) -> int:
    """Inject assembly that saves/restores full register state, executes `code`, then returns.

    The injected block ends with an int3 so we can flip the is_in_injected_code flag.
    
    """
    
    dbg = True
    
    if code_injection_address is None:
        raise RuntimeError("Injection region not allocated.")

    save_place = code_injection_address
    assembly1, assembly2 = generate_clean_asm_func_call(code, in_two_parts = True )
    

    if code_done_callback is not None:
        if dbg:
            #pass
            assembly1 = "nop\nint3\n"+assembly1
            external_breakpoints[save_place+2] = start_fun
            #assembly1 += "int3\n"
        assembly1 += "int3"
    else:
        sys.exit(
            "Not implemented: you need to specify a callback so we can know when we're out of the injected code."
        )
        
    shellcode1 = asm(assembly1, save_place)
    #print("asm1", assembly1, process.disassemble_string(save_place, shellcode1), shellcode1)
    
    save_place += len(shellcode1)
    if code_done_callback is not None:
        if dbg:
            external_breakpoints[save_place] = partial(deal_with_injection_callback_debug, code_done_callback, save_place)
        else:
            external_breakpoints[save_place] = partial(deal_with_injection_callback, code_done_callback, save_place)
    if dbg:
        assembly2 += """
        int3
        nop
        jmp [RIP]
        """
    else:
        assembly2 += """
        jmp [RIP]
        """
    shellcode2 = asm(assembly2, save_place)
    #print("asm2", assembly2, process.disassemble_string(save_place, shellcode2), shellcode2)
    if dbg:
        external_breakpoints[save_place+len(shellcode2)-7] = ran_fun
    
    shellcode2 += struct.pack("<Q", return_address)

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
        f"mov rcx, {name_remote_memory};mov rax, {load_library_addr};call rax",
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
                        
                
                submit_hook_function_list_for_injection()
                
                # Hook all functions listed in .pdata
                #hook_functions(process, event, pid)
                
                process = event.get_process()
                pid = process.get_pid()
                hook_calls(process, event, pid)
                
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
