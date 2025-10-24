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
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KsError
from typing import Dict, List, Tuple, Optional, Callable, Any
import traceback
import random
import hook_lib
import locale

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

moved_instructions = {}
ref_instructions = {}

# Initialize Keystone for x64.
ks = Ks(KS_ARCH_X86, KS_MODE_64)

jump_breakpoints = []
jump_writes = []


#Thread Storage
thread_storage_list_address = None
thread_storage_list_addresses = {}
threads_to_setup = []
area_for_function_table = None
area_for_return_addr_linked_list = 3*8* 100000#this is how deap the recursion can be traced
area_for_tracing_results = 8*10000000
area_for_xsave64 = 12228 #we give xsave 8192 12228 to save its data
nr_of_prepared_alocations = 10


spawned = False
call_trace_dll_ready = False
load_dll_tid = -1
jumps = {}
max_thread_ids = 30000

os.makedirs('output', exist_ok=True)
out_file = None

call_map = []

exe_basic_name = None

forbid_break_point_jumps = False

do_call_tracing = True
redirect_return = False

call_exclusions = [
    #(2666, 0),
]

enter_exclusions = [
    #2666
]

function_exclusions = [
    2666, #NOTEPAD++
    5788, #NOTEPAD++
    5751, #NOTEPAD++
    5215, #NOTEPAD++
    8027, #NOTEPAD++
    5596, #NOTEPAD++

    ##SLOW
    2616,
    158,
    4725,
    5196,
    8977,
    5471
]


function_exclusions = []


# -----------------------------
# Helpers
# -----------------------------
def start_or_attach(argv: List[str]) -> None:
    """Start or attach to the given executable.

    """
    global spawned, exe_basic_name, out_file
    pid = None
    arg1 = sys.argv[1]
    
    if arg1.isdigit():
        pid = int(arg1)
    else:
        exe = arg1
        # Try to expand to absolute path if provided
        exe_path = exe
        if os.path.isabs(exe):
            exe_path = exe
        else:
            # leave as name (we will match by basename)
            exe_path = exe

        # 1) find running PIDs
        pids = hook_lib.get_pids_by_name(exe_path)
        if pids:
            if len(pids) > 1:
                print(f"Found {len(pids)} running process(es) named '{os.path.basename(exe_path)}': {pids} selecting first pid")
            pid = pids[0]
        else:
            print(f"No running process named '{os.path.basename(exe_path)}' found. Attempting to start it...")
            pid = hook_lib.try_start_executable(exe_path)
            spawned = True
    
    
    handle = hook_lib.get_handle(pid)
    
    executable_path = hook_lib.get_process_image_path(handle)
    mods = hook_lib.enumerate_modules(handle, do_until_sucess = True)
    #hook_lib.print_modules(mods)
    
    exe_basic_name = get_base_name(executable_path)
    out_file = os.path.abspath('output'+os.sep+exe_basic_name+'.trace')
    if os.path.exists(out_file):
        os.remove(out_file)
    
    base_addr = mods[executable_path]['base']

    
    get_pdata(executable_path, base_addr, exe_basic_name)
    
    allocate_mem_and_inject_dll(handle, exe_entry_address)
    
    on_calltrace_dll_ready(handle)
    #print(pdata_functions)
    


def get_base_name(filename: str) -> str:
    """Return lowercase filename without extension from a Windows path."""
    dname = filename.split("\\")[-1]
    basic_name = dname.split(".")[0].lower()
    return basic_name


def asm(CODE: str, address: int = 0) -> bytes:
    """Assemble x64 code at the given address using Keystone."""
    try:
        encoding, count = ks.asm(CODE, address)
    except KsError as e:
        # e.errno is a keystone error enum, e.count is # of statements assembled
        print(CODE, address)
        print(f"Keystone error: {e} (errno={getattr(e, 'errno', None)}, " f"count={getattr(e, 'count', None)})")
        traceback.print_stack()
        exit()
    return bytes(encoding)


def read_ptr(process: Any, address: int) -> int:
    """Read an 8-byte pointer from the target process memory at address."""
    data = process.read(address, 8)
    return struct.unpack("<Q", data)[0]

def allocate_close(process, address_close_to_code):
    process_handle = process.get_handle()
    size = 40
    
    adddress_close_by = None
    while adddress_close_by == None:
        adddress_close_by = ctypes.windll.kernel32.VirtualAllocEx(
            process_handle, ctypes.c_void_p(address_close_to_code), size, 0x3000, 0x40
        )
        address_close_to_code -= 4500
    if adddress_close_by == None:
        raise Exception("Could not allocate jump table; this can be somewhat random. Please try again.")
    process.close_handle()
    return adddress_close_by

def allocate_mem_and_inject_dll(process_handle, address_close_to_code: int) -> None:
    """Allocate remote memory regions and inject the helper DLL."""
    global register_save_address, code_injection_address, shell_code_address, thread_storage_list_address, alocated_thread_storages

    # VirtualAllocEx signature configuration
    ctypes.windll.kernel32.VirtualAllocEx.argtypes = [
        wintypes.HANDLE,  # hProcess
        ctypes.c_void_p,  # lpAddress
        ctypes.c_size_t,  # dwSize
        wintypes.DWORD,   # flAllocationType
        wintypes.DWORD,   # flProtect
    ]
    #print(address_close_to_code)
    #exit(0)

    # Allocate small utility region (writable)
    ctypes.windll.kernel32.VirtualAllocEx.restype = ctypes.c_ulonglong
    remote_memory = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, 1000, 0x3000, 0x04)
    if not remote_memory:
        raise Exception(f"Failed to allocate memory in target process: {ctypes.WinError()}")
    
    size = 0x20000000
    shell_code_address = 0
    while shell_code_address == 0:
        # Allocate large RX region for shellcode near code
        
        preferred_address = (address_close_to_code - size* random.randint(1, 3))
        shell_code_address = ctypes.windll.kernel32.VirtualAllocEx(
            process_handle, ctypes.c_void_p(preferred_address), size, 0x3000, 0x40
        )
        if shell_code_address == 0:
            print("Could not allocate jump table; this can be somewhat random. Please try again.")


    # Allocate register-save area (writable)
    register_save_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, 4096, 0x3000, 0x04)
    if register_save_address == 0:
        print(f"Failed to allocate register_save_address in target process: {ctypes.WinError()}")
        sys.exit(0)

    size = 0x10000000
    code_injection_address = 0
    while code_injection_address == 0:
        # Allocate secondary RX region for injected stub code
        preferred_address = address_close_to_code - size * random.randint(1, 20)

        code_injection_address = ctypes.windll.kernel32.VirtualAllocEx(
            process_handle, ctypes.c_void_p(preferred_address), 0x100000, 0x3000, 0x40
        )
        if code_injection_address == 0:
            print(f"Failed to allocate code_injection_address in target process: {ctypes.WinError()}")
    

    thread_storage_list_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, 8*max_thread_ids, 0x3000, 0x04)
    if thread_storage_list_address == 0:
        raise Exception(f"Failed to allocate memory in target process: {ctypes.WinError()}")
    
    
    alocated_thread_storages = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, nr_of_prepared_alocations*8, 0x3000, 0x04)
    if alocated_thread_storages == 0:
        raise Exception(f"Failed to allocate memory in target process: {ctypes.WinError()}")
    
    
    # Inject helper DLL with MinHook-based hooks
    run_loadlibrary_in_process(process_handle, "calltracer.dll") #FIXMEEE process
    
    
    
    
def setup_after_dll_loaded(process_handle):
    global register_save_address, code_injection_address, shell_code_address, thread_storage_list_address, restore_state_address, save_state_address, alocated_thread_storages, debug_func_address
    
    
    
    print("Set set_area_for_function_table")
    mem_size = str(area_for_function_table)
    asf = "sub rsp, 40\nmov     rcx, "+mem_size+"\nmovabs rax, "+str(call_tracer_dll_func['set_area_for_function_table'])+"\n\ncall rax\nadd rsp, 40\nret"
    injection_info = hook_lib.inject_asm(process_handle, asf)
    
    print("set out file:", out_file, "using dll function:", call_tracer_dll_func['set_output_file'])
    str_addr, alloc_size = hook_lib.alloc_and_write_remote(process_handle, out_file.encode(locale.getpreferredencoding()) + b'\x00', False)
    set_output_file_asm = "sub rsp, 40\nmovabs     rcx, "+str(str_addr)+"\nmovabs rax, "+str(call_tracer_dll_func['set_output_file'])+"\n\ncall rax\nadd rsp, 40\nret"
    hook_lib.inject_asm(process_handle, set_output_file_asm)
    
    
    #save state requires you to push 128 bytes to rsp before calling lea   rsp, [rsp-128]
    #Setup save sate and restore state functions
    
    #save state function
    save_state_asm = strip_semicolon_comments("""
; ===== prologue: preserve flags & callee-saved registers =====
pushfq
sub   rsp, 8

; save callee-saved GPRs that we will use or clobber
push r15
mov r15, rsp
add r15, 160; save original return_address stack location in r15 fix ofset 24 caused by earlier pushes and 128 from before call and 8 from the call

push rbp
push rsi
push rdi
push rax
push rcx
push rdx
push r8
push r9
push r10    
push r11
push r12
push r13
push r14
push rbx



; Find thread storage from list

.find_current_thread_location:
xor rdi,rdi
xor r11,r11
; load current thread id (low 32 bits of GS:[0x48])
xor rax,rax
mov     eax, dword ptr gs:[0x48]    ; EAX = current TID
xor r12,r12
lea r12, [rax*8] ; fix offset
; base pointer to the array
movabs  rsi, """+str(thread_storage_list_address)+"""           ; RSI = array base
add r12, rsi
mov rax, [r12]
test rax, rax
jnz .thread_memmory_is_alocated  ; jump if not zero (ZF = 0)

    ; not alocated - get allocation


    movabs rsi, """+str(alocated_thread_storages)+"""
    mov rcx, """+str(nr_of_prepared_alocations)+"""
    ; rsi = base, rcx = count
    ; clobbers: rdi, rax
    ; returns:  rdi = addres of value, rax = popped value (0 if none), ZF=1 if none

        mov     rdi, rsi              ; cursor = base
    .scan:
        test    rcx, rcx
        jz      .not_found

        xor     eax, eax              ; rax := 0 to swap into the slot
        xchg    rax, [rdi]            ; atomically: rax <- slot, slot <- 0
        test    rax, rax
        jnz     .found                ; got a non-zero, done

        add     rdi, 8                ; next qword
        dec     rcx
        jmp     .scan


    .not_found:
        int3 ; can never be allowed to happen
        xor     eax, eax

    .found:
        mov [r12], rax ; save new vale
        mov     r11, 1 ;set R11 so we store the extended registers we only do it if we need to as it is slow
        ;RDI is already set so alloc_thread_storage(uint64_t out_address) will be called further down



.thread_memmory_is_alocated:
mov r12, [r12]

;Check if trace memmory starts be become to big
xor r9, r9
mov r10, r12
add r10, """+str(area_for_xsave64 + area_for_function_table + area_for_return_addr_linked_list)+"""; get memory area for tracing

mov r8, [r10]   ;Retrive end on list that is saved in the first 64 bits

add r10 , """+str(area_for_tracing_results-1000)+"""
cmp r10, r8
ja  .size_ok 
    mov     r9, r12 ; We set r9 indicating that we need to empty the memory
    mov     r11, 1 ;set R11 so we store the extended registers we only do it if we need to as it is slow
.size_ok:


;IF r11 is not zero we need to save the extended state so we can call calling alloc_thread_storage
test    r11, r11
jz .skip_saving_extended_state
    ; set mask: XCR0 -> EDX:EAX, ECX must be 0
    xor  ecx, ecx
    xgetbv

    ; save extended state; DO NOT use rdx as the memory base (EDX is mask upper)
    xsave64 [r12]            ; (use xsaveopt if you detect support)
    xor  ecx, ecx

.skip_saving_extended_state:


; ===== prepare for making the actual code =====
; We must ensure RSP is 16-byte aligned at the CALL instruction and have 32 bytes shadow.

; Compute the adjustment needed to align RSP to 16 bytes:
; r10 currently saved on stack; we'll use r10 as temp for alignment value
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
push r15
push r11
push r12

; Now allocate the 32-byte shadow space required by Windows x64 ABI
sub  rsp, 32

test    RDI, RDI
jz .skip_alloc_thread_storage

    ;Alocate new thread storage rcx is alrady filled from 

    mov rcx, rdi ;set first arg
    movabs rax, """+str(call_tracer_dll_func['alloc_thread_storage'])+"""
    call rax

    ;Restore r15
    mov r15, [rsp+48]

.skip_alloc_thread_storage:

test    R9, R9
jz .skip_dump_trace

    ;dump saved traces

    mov rcx, r9 ;set first arg
    movabs rax, """+str(call_tracer_dll_func['dump_trace'])+"""
    call rax

    ;Restore r15
    mov r15, [rsp+48]

.skip_dump_trace:

jmp [r15 - 136] ;Jump back to return address of save call
    """)
    
    save_state_address = shell_code_address
    save_state_code = asm(save_state_asm, save_state_address)
    shell_code_address += len(save_state_code)
    hook_lib.write(process_handle, save_state_address, save_state_code, do_checks = False)
    
    
    
    
    
    debug_save_state_asm = strip_semicolon_comments("""

; ===== prologue: preserve flags & callee-saved registers =====
pushfq
sub   rsp, 8

; save callee-saved GPRs that we will use or clobber
push r15
mov r15, rsp
add r15, 160; save original return_address stack location in r15 fix ofset 24 caused by earlier pushes and 128 from before call and 8 from the call

push rbp
push rsi
push rdi
push rax
push rcx
push rdx
push r8
push r9
push r10    
push r11
push r12
push r13
push r14
push rbx



; Find thread storage from list

.find_current_thread_location:
xor rdi,rdi
xor r11,r11
; load current thread id (low 32 bits of GS:[0x48])
xor rax,rax
mov     eax, dword ptr gs:[0x48]    ; EAX = current TID
xor r12,r12
lea r12, [rax*8] ; fix offset
; base pointer to the array
movabs  rsi, """+str(thread_storage_list_address)+"""           ; RSI = array base
add r12, rsi
mov rax, [r12]
test rax, rax
jnz .thread_memmory_is_alocated  ; jump if not zero (ZF = 0)

    ; not alocated - get allocation


    movabs rsi, """+str(alocated_thread_storages)+"""
    mov rcx, """+str(nr_of_prepared_alocations)+"""
    ; rsi = base, rcx = count
    ; clobbers: rdi, rax
    ; returns:  rdi = addres of value, rax = popped value (0 if none), ZF=1 if none

        mov     rdi, rsi              ; cursor = base
    .scan:
        test    rcx, rcx
        jz      .not_found

        xor     eax, eax              ; rax := 0 to swap into the slot
        xchg    rax, [rdi]            ; atomically: rax <- slot, slot <- 0
        test    rax, rax
        jnz     .found                ; got a non-zero, done

        add     rdi, 8                ; next qword
        dec     rcx
        jmp     .scan


    .not_found:
        int3 ; can never be allowed to happen
        xor     eax, eax

    .found:
        mov [r12], rax ; save new vale
        mov     r11, 1 ;set R11 so we store the extended registers we only do it if we need to as it is slow
        ;RDI is already set so alloc_thread_storage(uint64_t out_address) will be called further down



.thread_memmory_is_alocated:
mov r12, [r12]

;Check if trace memmory starts be become to big
xor r9, r9
mov r10, r12
add r10, """+str(area_for_xsave64 + area_for_function_table + area_for_return_addr_linked_list)+"""; get memory area for tracing

mov r8, [r10]   ;Retrive end on list that is saved in the first 64 bits

add r10 , """+str(area_for_tracing_results-1000)+"""
cmp r10, r8
ja  .size_ok 
    mov     r9, r12 ; We set r9 indicating that we need to empty the memory
    mov     r11, 1 ;set R11 so we store the extended registers we only do it if we need to as it is slow
.size_ok:


;IF r11 is not zero we need to save the extended state so we can call calling alloc_thread_storage
test    r11, r11
jz .skip_saving_extended_state
    ; set mask: XCR0 -> EDX:EAX, ECX must be 0
    xor  ecx, ecx
    xgetbv

    ; save extended state; DO NOT use rdx as the memory base (EDX is mask upper)
    xsave64 [r12]            ; (use xsaveopt if you detect support)
    xor  ecx, ecx

.skip_saving_extended_state:


; ===== prepare for making the actual code =====
; We must ensure RSP is 16-byte aligned at the CALL instruction and have 32 bytes shadow.

; Compute the adjustment needed to align RSP to 16 bytes:
; r10 currently saved on stack; we'll use r10 as temp for alignment value
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
push r15
push r11
push r12

; Now allocate the 32-byte shadow space required by Windows x64 ABI
sub  rsp, 32

test    RDI, RDI
jz .skip_alloc_thread_storage

    ;Alocate new thread storage rcx is alrady filled from 

    mov rcx, rdi ;set first arg
    movabs rax, """+str(call_tracer_dll_func['alloc_thread_storage'])+"""
    call rax

    ;Restore r15
    mov r15, [rsp+48]

.skip_alloc_thread_storage:

test    R9, R9
jz .skip_dump_trace

    ;dump saved traces

    mov rcx, r9 ;set first arg
    movabs rax, """+str(call_tracer_dll_func['dump_trace'])+"""
    call rax

    ;Restore r15
    mov r15, [rsp+48]

.skip_dump_trace:

jmp [r15 - 136] ;Jump back to return address of save call
    """)
    
    debug_func_address = shell_code_address
    debug_save_state_code = asm(debug_save_state_asm, debug_func_address)
    shell_code_address += len(debug_save_state_code)
    hook_lib.write(process_handle, debug_func_address, debug_save_state_code, do_checks = False)
    
    
    #restore state function
    restore_state_asm = strip_semicolon_comments("""
    
; ===== after call: pop shadow and undo alignment correction =====

add  rsp, 40 ; Add 32 plus 8 cause we just did this call

pop r12
pop r11
pop r15

;Save the return address for this restore call
mov r10, [rsp-64]
mov [r15-136], r10

pop r10
test r10, r10
je   .no_align_restore
    add  rsp, r10
.no_align_restore:

test    r11, r11
jz .skip_restoring_extended_state

    ; ===== restore extended state =====
    xor  ecx, ecx
    xgetbv
    xrstor64 [r12]        ; restore extended state from stack buffer

.skip_restoring_extended_state:

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

lea   rsp, [rsp+136] ;restore rsp 128 cause we added that before call + 8 cause of this call
jmp [rsp - 136] ;jump to restore return address
""")
    
    restore_state_address = shell_code_address
    restore_state_code = asm(restore_state_asm, restore_state_address)
    shell_code_address += len(restore_state_code)
    hook_lib.write(process_handle, restore_state_address, restore_state_code, do_checks = False)

    
    
    print("setting up thread storage")
    
    #here we prealoacte memory for threads
    injection_info = None
    for stor_id in range(nr_of_prepared_alocations):
        hook_lib.inject_asm(process_handle, "sub rsp, 40\nmov     rcx, "+str(alocated_thread_storages + stor_id*8)+"\nmovabs rax, "+str(call_tracer_dll_func['alloc_thread_storage'])+"\n\ncall rax\nadd rsp, 40\nret")
    
    print("hooking executable")
    
    
    hook_calls(process_handle)
    



def get_function_containing(address):
    """
    Return the (function_start_addr, function_end_addr, unwind_info_addr, pdata_ordinal)
    tuple that contains the given address, or None if not found.
    """
    for entry in pdata_functions:
        function_start_addr, function_end_addr, _, _ = entry
        if function_start_addr <= address < function_end_addr:
            return entry
    return None
    


def hook_calls(process_handle) -> None:
    """Disassemble functions and patch CALLs to insert call-site tracing breakpoints."""
    global disassembled_functions, function_map
    # Cache to avoid repeated disassembly of large binaries
    
    
    
    disassembled_cache_file = exe_basic_name + "_instructions_cache.json"
    save_cache = False
    if len(disassembled_functions) == 0:
        if os.path.exists(disassembled_cache_file) and time.time() - os.path.getmtime(disassembled_cache_file) < 12 * 3600:
            with open(disassembled_cache_file, "r") as f:
                disassembled_functions = json.load(f)
    
    print("disassemble and index instructions", len(pdata_functions))
    for function_start_addr, function_end_addr, flags, pdata_ordinal in pdata_functions:
        function_id = get_function_id(function_start_addr)
        func_len = function_end_addr - function_start_addr
        print("disassemble:", function_id, "len:", func_len)
        
        # Disassemble and patch CALL instructions in the function body
        if len(disassembled_functions) > pdata_ordinal:
            instructions = disassembled_functions[pdata_ordinal]
        else:
            #try:
            instcode = hook_lib.read(process_handle, function_start_addr, func_len)
            instructions = hook_lib.disasm(function_start_addr, instcode)
            #except:
            #    instructions = [] #DEBUG shit for disasemble failures
            
            disassembled_functions.append(instructions)
            save_cache = True
        
        #try to find jumps so we know what jumps backward and to some extent where
        for instruction_num, instruction in enumerate(instructions):
            instruction_name = instruction[2].split(" ")[0]
            is_jump = instruction_name.startswith("j") or instruction_name.startswith("loop")
            
            if is_jump:
                reg, reg2, reg2_mult, indirect, offset = asm2regaddr(instruction)
                jump_to = None
                if reg is None:
                    jump_to = offset
                
                if offset not in jumps:
                    jumps[offset] = []
                jumps[offset].append(instruction)
    
    if save_cache:
        with open(disassembled_cache_file, "w") as f:
            json.dump(disassembled_functions, f, indent=2)
    
    print("instrument functions:", len(pdata_functions))
    do_init_at = 100
    #process.suspend() #FIXME we should suspend but process.suspend has a tendency to crash wen handling threads that just closed
    for function_start_addr, function_end_addr, flags, pdata_ordinal in pdata_functions:
        function_id = get_function_id(function_start_addr)
        
        doing_init = True
        #if do_init_at < pdata_ordinal: ## DEBUG
        #    doing_init = False         ## DEBUG
        #doing_init = False ## DEBUG
        
        if pdata_ordinal in enter_exclusions:
            doing_init = False
        
        #We dont trace initiation of funclets as the entry in to them might not mean a call was made
        if flags >= 4:
            doing_init = False
        
        function_map = {
            "ordinal": pdata_ordinal,
            "function_id":function_id,
            "function_start_addr": function_start_addr,
            "function_end_addr": function_end_addr,
            "flags": flags,
            "calls": []
        }
        
        if pdata_ordinal not in function_exclusions:
            instructions = disassembled_functions[pdata_ordinal]
            insert_break_at_calls(process_handle, instructions, function_id, function_start_addr, pdata_ordinal, doing_init)
        
        call_map.append(function_map)
        
    #process.resume()
    print("inserted tracers nr of calls:", len(call_map))
    
    map_file = "output\\"+exe_basic_name+'_map.json'
    with open(map_file, "w") as f:
            json.dump(call_map, f, indent=2)
            
    loaded_modules = hook_lib.enumerate_modules(process_handle, base_name = True)
    module_file = "output\\"+exe_basic_name+'_modules.json'
    with open(module_file, "w") as f:
            json.dump(loaded_modules, f, indent=2)
    
    #hook_lib.NtSuspendProcess(process_handle)
    for insert_location, jmp_to_shellcode in jump_writes:
        hook_lib.write(process_handle, insert_location, jmp_to_shellcode)
    #hook_lib.NtResumeProcess(process_handle)
    print("inserted calltracing")
    
    


def capstone_2_keystone(instruction_asm):
#fix differance betwen capstone and keystone asm
    instruction_asm = instruction_asm.replace('call ptr [', 'call qword ptr [')
    
    if instruction_asm.startswith("comisd "):
        instruction_asm = instruction_asm.replace(' xmmword ptr [', ' qword ptr [')
    
    if instruction_asm.startswith("call ptr cs:"):
        instruction_asm = instruction_asm.replace('call ptr cs:', 'call qword ptr ')
        
    if instruction_asm.startswith("call ptr "):
        instruction_asm = instruction_asm.replace('call ptr ', 'call qword ptr ')
    
    if instruction_asm.startswith("jmp ptr "):
        instruction_asm = instruction_asm.replace('jmp ptr ', 'jmp qword ptr ')
        
    
    
    return instruction_asm



def add_instruction_redirect(
    function_ordinal: int,
    function_address: int,
    is_init: bool,
    instructions: List[Tuple[int, int, str, str]],
    process_handle,
    call_num,
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
    
    closer_alocation = False
    excluded_calls = []
    for exclude_func_ordinal, exlude_call_num in call_exclusions:
        if exclude_func_ordinal == function_ordinal:
            excluded_calls.append(exlude_call_num)
    
    
    new_start_address = new_instruction_address
    
    assert len(instructions) != 0, "Cant move zero instructions"
    
    # The place jumping from
    insert_location = instructions[0][0]
    # Where execution resumes after the moved instructions
    jump_back_address = instructions[-1][0] + instructions[-1][1]
    
    instructions_len = 0
    instructions_asm = ""
    for instruciton_dat in instructions:
        instructions_len += instruciton_dat[1]
        instructions_asm += instruciton_dat[2]
    
    jump_distance = abs(jump_back_address-jump_to_address)
    
    insert_len = 0
    jump_type = "none"
    # Prefer full 5-byte JMP if possible, otherwise insert 1 byte (int3)
    if instructions_len >= 5:
        if jump_distance > 2147483647:
            closer_alocation = allocate_close(process, jump_back_address) # Have not botherd to move this to non winappdbg
            raise Exception("if you do double jumps the instructions we move might stop working")
            jump_distance2 = abs(jump_back_address - closer_alocation)
            if jump_distance2 > 2147483647:
                raise Exception("closer alocation not close enogh: "+ str(jump_distance2)+ " "+ str(jump_distance))
            hook_lib.write(process_handle, closer_alocation, asm("jmp [RIP]") + struct.pack("<Q", jump_to_address))
            if not closer_alocation:
                raise ValueError("cant jump that far ("+str(instructiosn_len)+"), from: " + str(jump_back_address) + " to: "+ str(jump_to_address) + " dist: "+str(jump_distance)+" best would be to alocate memmory closer")
        insert_len = 5
        jump_type = "normal"
    elif instructions_len >= 2:#FIXMEEE whenever minhook moves these breakpoints shit stops working
        insert_len = 1
        jump_type = "2byte"
    else:#FIXMEEE whenever minhook moves these breakpoints shit stops working
        insert_len = 1
        jump_type = "1byte"
    
    extra_bytes = max(instructions_len - insert_len, 0)
    jmp_to_shellcode: Optional[bytes] = None
    asmm: Optional[str] = None
    jump_breakpoint = None
    if jump_type == "normal":
        to_address = jump_to_address
        if closer_alocation:
            to_address = closer_alocation
        asmm = f"jmp {to_address}" + (";nop" * extra_bytes)
        jmp_to_shellcode = asm(asmm, insert_location)
    elif jump_type == "2byte":
        jmp_to_shellcode = b"\xCC" + (b"\x90" * extra_bytes)
        jump_breakpoint = insert_location
    elif jump_type == "1byte":
        jmp_to_shellcode = b"\xCC"
        jump_breakpoint = insert_location
    
    if forbid_break_point_jumps:
        if jump_type == "2byte" or jump_type == "1byte":
            print("trace of function "+str(function_ordinal)+" / call ignored due to needing breakpoint")
            raise Exception("TODO need to increment call num")
            return call_num
    
    if jump_breakpoint is not None:
        jump_breakpoints.append((jump_breakpoint, jump_to_address))
        hook_lib.inject_asm(process_handle, "sub rsp, 40\nmovabs     rcx, "+str(jump_breakpoint)+"\nmovabs     rdx, "+str(jump_to_address)+"\nmovabs rax, "+str(call_tracer_dll_func['add_jump_breakpoint'])+"\n\ncall rax\nadd rsp, 40\nret")

    
    print(jump_type,'org:', instructions_asm, "(", instructions_len, ") write:", asmm, "bytes:", len(jmp_to_shellcode), "at:", insert_location, "jump_to_address:", jump_to_address, "diff:", jump_distance)

    if is_init:
        print("we are inserting a call init capturer")
        # Tracking assembly: adds a breakpoint before and after the real function.
        # Saves the return address, modifies it to point to the post-call int3, then jumps.
        int3_bef = ""

        
        
        
        
        
        jump_table_address = new_instruction_address
        
        enter_asm1 = strip_semicolon_comments("""
        
add r12, """+str(area_for_xsave64)+"""

;Save tracing
mov r10, r12
add r10, """+str(area_for_function_table + area_for_return_addr_linked_list)+""" ; get memory area for tracing

mov r8, [r10]   ;Retrive end on list that is saved in the first 64 bits

mov     byte ptr [r8], 1 ;type 1 is function entry (1 byte)
mov     eax, dword ptr gs:[0x48]
mov     dword ptr [r8 + 1], eax ;save thread id (4 bytes)
mov     dword ptr [r8 + 5],  """+str(function_ordinal)+""";Save function ordinal(4 bytes)
rdtsc                 ; EDX:EAX = TSC
shl     rdx, 32       ; move high half up
or      rax, rdx      ; RAX = (EDX<<32) | EAX
mov     qword ptr [r8 + 9], rax ;save timestamp (8 bytes)

mov     qword ptr [r8 + 17], r15 ;save return address pointer/function entry rsp(8 bytes)
mov     rcx, [r15]              ;
mov     qword ptr [r8 + 25], rcx ;save return address (8 bytes) 
lea     r8, [r8+33]
mov [r10], r8



"""+("""

;Save return addres to linked list for later retrival on function exit
; This linked list can run out of memmory then it will crash TODO think about adding a check for this
mov r10, r12
mov rcx, r12

add r10, """+str(function_ordinal*8)+""" ; This fucntion top
add rcx, """+str(area_for_function_table)+""" ; Alocation top


mov  rdx, [r15] ; New Value (the return address saved in r15 by generate_clean_asm_func_call)


; Get top allocation and top entry
mov    rax, [r10]          ; rax = current_top_node_addr
mov   r8,  [rcx]          ; r8  = current_top_alocated_addr

test rax,rax
jnz .list_exists
;We dont have a list for this function we alocate a new one (The first node in the list will always be empty)
lea     r8, [r8+32]
mov     [rcx], r8
mov     rax, r8

.list_exists:

;See if next node is not allocated yet
mov   r11, [rax + 24]         ; r11 = node.next
test    r11, r11
jnz      .fill_new_entry

;Setup new entry at new location
;Alloc
lea     r11, [r8 + 32]
mov     [rcx], r11

;Set next value on old entry
mov [rax + 24], r11 ; node.next = r11

;Set previous value on new entry
mov   [r11 + 0], rax          ; newnode.previous = last_node
mov   qword ptr  [r11 + 24], 0 ; newnode.next = 0 



;Fill in value of entry
.fill_new_entry:
mov     [r11 + 8], rdx          ; newnode.value = value
mov     [r11 + 16], r15          ; newnode.value2 = value

;Save current_top_node_addr
mov     [r10], r11

    """ if redirect_return else ""))
    
        #lol = asm(enter_asm1, jump_table_address)
    
        enter_asm = enter_asm1

        
        enter_func_call_code = asm(generate_clean_asm_func_call(enter_asm, save_full=False), jump_table_address)
        #enter_func_call_code = b"" #asm("int3", jump_table_address) #Test with no tracing
        jump_write_address = jump_table_address + len(enter_func_call_code)
        
        
        #We redirect the return address to capture return, this is not invisible to the code so it may fail, if that is the case disable it
        #But that also means you wont be able to capture the return. You may be able to put breakpoints on all ret instructions but this will not catch tail calls.
        
        
        function_caller_asm = [
            int3_bef, # triger interupt for python tracing enter of function
            "push rax;" if redirect_return else "", # save value in rax
            "mov rax, [RIP + 20];" if redirect_return else "", # fill rax with addres leading to new_function_return_address
            "mov [RSP+8], rax;" if redirect_return else "", # move the value in rax in to the stack (saving it as a return address), that way we return to the second interupt
            "pop rax;" if redirect_return else "", # restore rax 
            "jmp [RIP];", # jump to new_function_start_address
        ]
        function_caller_asm = "\n".join(function_caller_asm)
        
        function_caller = asm(function_caller_asm, jump_write_address)
        new_function_return_address = jump_write_address + len(function_caller)+16
        
        if redirect_return:
            exit_asm1 = strip_semicolon_comments("""
add r12, """+str(area_for_xsave64)+"""

;Save tracing
mov r10, r12
add r10, """+str(area_for_function_table + area_for_return_addr_linked_list)+""" ; get memory area for tracing

mov r8, [r10]   ;Retrive end on list that is saved in the first 64 bits

mov     byte ptr [r8], 2 ;type 2 is function exit (1 byte)
mov     eax, dword ptr gs:[0x48]
mov     dword ptr [r8 + 1], eax ;save thread id (4 bytes)
mov     dword ptr [r8 + 5],  """+str(function_ordinal)+""";Save function ordinal(4 bytes)
rdtsc                 ; EDX:EAX = TSC
shl     rdx, 32       ; move high half up
or      rax, rdx      ; RAX = (EDX<<32) | EAX
mov     qword ptr [r8 + 9], rax ;save timestamp (8 bytes)
mov     qword ptr [r8 + 17], r15 ;save return address pointer(8 bytes)

lea     r8, [r8+25]
mov [r10], r8


;Load return address from linked list


add r12, """+str(function_ordinal*8)+"""



mov     r11, qword ptr [r12]       ; r11 = current top node

.loop:
    test    r11, r11
    jz      .pop_empty                  ; empty -> return 0

    mov     rdx, qword ptr [r11 + 16]   ; rdx = node->value2
    cmp     rdx, r15
    je      .match

    ; Not a match: pop and continue
    mov     r11, qword ptr [r11 + 0]    ; r11 = node->prev
    mov     qword ptr [r12], r11        ; update top
    jmp     .loop

.match:
    mov     rax, qword ptr [r11 + 8]    ; rax = node->value
    mov     r11, qword ptr [r11 + 0]    ; r11 = node->prev
    mov     qword ptr [r12], r11        ; update top
    jmp     .pop_done

.pop_empty:
    xor     rax, rax                    ; rax = 0
    int3 ; indication that something has gone teribly wrong

.pop_done:


mov     [r15-100], rax




        """)
        
            exit_asm = exit_asm1
            
            exit_func_call_code = asm("lea rsp, [rsp-8];"+generate_clean_asm_func_call(exit_asm, save_full=False), new_function_return_address)#We have just returned from a call so t onot clober the old return address that was just popped we decrement rsp by 8 before 
            final_jump_code = asm("lea rsp, [rsp+8];jmp [rsp-108]", new_function_return_address + len(exit_func_call_code))#Then we incremet by 8 after
            
            #exit_func_call_code = asm("lea rsp, [rsp-140];"+generate_clean_asm_func_call(exit_asm, extra_push=132, save_full=False), jump_table_address)#
            #final_jump_code = asm("lea rsp, [rsp+140];jmp [rsp-108]", jump_table_address + len(exit_func_call_code))#"ret"
        else:
           exit_func_call_code = b""
           final_jump_code = b""
        
        
        f_break = b""
            
        new_function_start_address = jump_table_address + len(enter_func_call_code) + len(function_caller) + 16 + len(exit_func_call_code) + len(final_jump_code)
        jump_code = enter_func_call_code + function_caller + struct.pack("<Q", new_function_start_address) + struct.pack("<Q", new_function_return_address) + exit_func_call_code + final_jump_code
        
        final_breakpoint = len(jump_code)+jump_table_address - len(final_jump_code)
        
        #print(len(jump_code))
        #exit()
        code.append(jump_code)
        new_instruction_address += len(jump_code)
        #process.write(jump_table_address, jump_code)

    for instruciton_dat in instructions:
        instruction_address = instruciton_dat[0]
        instruction_len = instruciton_dat[1]
        instruction_asm = capstone_2_keystone(instruciton_dat[2])
        instruction_parts = instruction_asm.split(" ")
        
        
        static_call = False
        
        rip_to = None
        contains_rip = False
        if "rip" in instruction_asm:
            contains_rip = True
            
        if instruction_parts[0] == "call":
            reg, reg2, reg2_mult, indirect, offset = asm2regaddr(instruciton_dat)
            
            call_info = {
                "address": instruction_address,
                "return_address": instruction_address + instruction_len,
                "asm": instruction_asm,
                "indirect": indirect,
            }
            if (reg is None or (reg is not None and reg.lower() == "rip")) and offset is not None:
                if not indirect:
                    rip_to = offset
                    call_info['target'] = rip_to
                else:
                    call_info['target_pointer'] = offset
                    try:
                        trg = read_ptr(process, offset)
                    except:
                        trg = None
                    call_info['target'] = trg
                    
        
        if instruction_parts[0] == "call" and call_num not in excluded_calls and do_call_tracing:

            
            #jump_back_address = instruction_address + instruction_len

            
            
            #Make sure we are using a tempreg that is not used
            reg_to_use = 'r9'
            if reg is not None:
                reg = reg.lower()
                if reg_to_use == reg:
                    reg_to_use = 'r8'
            if reg2 is not None:
                reg = reg.lower()
                if reg_to_use == reg:
                    reg_to_use = 'r10'
            if reg is not None:
                reg = reg.lower()
                if reg_to_use == reg:
                    reg_to_use = 'r11'
            
            
            target_resolver = get_target_asm_resolver(reg, reg2, reg2_mult, indirect, offset, reg_to_use)
            print("call info:", "nr:", call_num, "asm:", instruction_asm, "resolver:", target_resolver, "reg dat:", reg, reg2, reg2_mult, indirect, offset, reg_to_use, "new_addr:", new_instruction_address, "old_addr:", instruction_address)
            #exit()
            
            #DEBUG dfsdffdsfdds REMOVE WHEN DONE oct 7
            if reg is None and offset is not None and False:
                if indirect:
                    dsg_asm = (
                        f"call [{offset}]\n"
                        f"jmp {instruction_address+instruction_len}\n"
                    )
                else:
                    dsg_asm = (
                        f"call {offset}\n"
                        f"jmp {instruction_address+instruction_len}\n"
                    )

                    
                asms = asm(dsg_asm, new_instruction_address)
                inst = hook_lib.disasm(new_instruction_address, asms)
                disasem = inst[0][2]
                
                lreg, lreg2, lreg2_mult, lindirect, loffset = asm2regaddr(inst[0])
                print("dbg:", instruction_asm, disasem, lreg, lreg2, lreg2_mult, lindirect, loffset)
                
                
                dbg_call_code = asm(dsg_asm, new_instruction_address)
        
                
                code.append(dbg_call_code)
                new_instruction_address += len(dbg_call_code)
            
            save_target_asm = (
                "lea rsp, [rsp-8]\n" #make space on the stack where we will place the target address
                f"push {reg_to_use} \n" #Save r9
                "lea rsp, [rsp+16]\n"
                f"{target_resolver}\n" #fill r9 with target address # {target_resolver}
                f"mov [rsp-8], {reg_to_use}\n" #save r9 in the space we made on the stack
                "lea rsp, [rsp-16]\n"
                f"pop {reg_to_use}\n" #restore r9
                "\nlea rsp, [rsp+8]\n"
            )
            
            #call_asm = (
            #    f"movabs     rcx, {function_ordinal};"    # first argument function_address
            #    f"movabs     rdx, {instruction_address};"    # second argument call_address
            #    f"movabs     r8, {instruction_address + instruction_len};"    # third arg return_address
            #    f"mov     r9, [r15-8];"# forth arg target address # original rsp in rax, saved in r15 by generate_clean_asm_func_call the next value in the stack is filled in by save_target_asm which is what we reference here
            #    f"movabs     rax, {call_tracer_dll_func['function_call_trace_point']};"
            #)
            #print(call_asm)
            
            call_asm = strip_semicolon_comments("""
add r12, """+str(area_for_xsave64)+"""

;Save tracing
mov r10, r12
add r10, """+str(area_for_function_table + area_for_return_addr_linked_list)+""" ; get memory area for tracing

mov r8, [r10]   ;Retrive end on list that is saved in the first 64 bits

mov     byte ptr [r8], 3 ;type 3 is function call (1 byte)
mov     eax, dword ptr gs:[0x48]
mov     dword ptr [r8 + 1], eax ;save thread id (4 bytes)
mov     dword ptr [r8 + 5],  """+str(function_ordinal)+""";Save function ordinal(4 bytes)
rdtsc                 ; EDX:EAX = TSC
shl     rdx, 32       ; move high half up
or      rax, rdx      ; RAX = (EDX<<32) | EAX
mov     qword ptr [r8 + 9], rax ;save timestamp (8 bytes)

mov     dword ptr [r8 + 17], """+str(call_num)+""" ;save call num (4 bytes)
mov     rax, [r15] ;  arg target address # original rsp in rax, saved in r15 by save_target_asm
mov     qword ptr [r8 + 21], rax ;save raget_address (8 bytes)
lea     r8, [r8+29]
mov [r10], r8


            """)
            
            
            
            #asm(save_target_asm, new_instruction_address)
            
            
            
            #extra_pop = ""
            #save_target_asm = ""
            #call_asm = ""
            #extra_push = 0
            
            #print("target_asm", save_target_asm)
            #exit()
            
            call_func_call_code = asm(save_target_asm + generate_clean_asm_func_call(call_asm, save_full=False), new_instruction_address)
            #call_func_call_code = b""
            #exit()
            
            code.append(call_func_call_code)
            new_instruction_address += len(call_func_call_code)
            
        
            if reg is None and offset is not None:
                static_call = offset
                # RIP-relative handling
                
            
            
        
        else: #Not a call
            pass
        if True:
            # RIP-relative handling FIXMEE This wont handle a scenario like [rip + eax*1 + 123]
            if "rip +" in instruction_asm or "rip -" in instruction_asm:
                print("Accounting for altered RIP", instruction_asm)
                
                convs  = ""
                if "rip +" in instruction_asm:
                    sign = "+"
                elif "rip -" in instruction_asm:
                    sign = "-"
                    convs = "-"
                else:
                    raise ValueError("Not Implemnted")
                
                initial_part = instruction_asm.split("]")[0]
                arg_part = initial_part.split("[")[-1]
                parts = arg_part.split(" ")
                assert (len(parts) == 3), "only support [rip + 123] not what this is: "+instruction_asm
                off_str = convs + parts[-1]
                off = int(off_str, 16)
                diff = new_instruction_address - instruction_address
                instruct_off = off-diff
                if instruct_off > 2147483647:
                    raise Exception("altering: "+instruction_asm + "new offset to large")
                
                rip_to = instruction_address + instruction_len + off
                
                if instruct_off >= 0:
                    replace_arg = "rip + "+ str(instruct_off)
                else:
                    replace_arg = "rip "+ str(instruct_off)
                
                instruction_asm_test = instruction_asm.replace(arg_part, replace_arg)
                
                new_code = asm(instruction_asm_test, new_instruction_address)
                new_code_len = len(new_code)
                if instruction_len != new_code_len:
                    instruct_off -= (new_code_len - instruction_len)
                    if instruct_off >= 0:
                        replace_arg = "rip + "+ str(instruct_off)
                    else:
                        replace_arg = "rip "+ str(instruct_off)
                    instruction_asm_test = instruction_asm.replace(arg_part, replace_arg)
                    
                instruction_asm = instruction_asm_test

        
        is_jump = instruction_asm.startswith("j")
        
        if is_jump:
            reg, reg2, reg2_mult, indirect, offset = asm2regaddr(instruciton_dat)
            if (reg is None or (reg is not None and reg.lower() == "rip")) and offset is not None:
                rip_to = offset
        
        if is_jump and rip_to is not None and not indirect:
            if rip_to in pdata_function_ids:
                print("jump to function with address: "+ str(rip_to))
            else:
                ref_instructions[instruction_address] = rip_to
                #raise Exception("Trying to jump to non function: "+str(rip_to))
        #    raise Exception("complex jump will fail unless it is the final instruction: "+ instruction_asm)
        #elif instruction_parts[0] in ("cmp",):
        #    raise Exception("non-movable instruction (Should probably just remove this exception cmp is movable): "+ instruction_asm)


        if static_call and False:

            
            if indirect:
                asd = (
                #this might be the issue we are overwriting [rsp-8] and -16 and -24
                    "push rax;" #1. make space for return address on stack 
                    "push rax;" #2. save rax
                    "mov rax, [RIP + 30];" #3. fill rax with pointer to function address
                    "mov rax, [rax];" #4. fill rax with function address
                    "push rax;" #5. save function address
                    "pop rax;" # 6 decrese rsp but we still care about the function address we saved on the stack in step 5
                    "mov rax, [RIP + 10];" #7. fill rax with return address
                    "mov [RSP+0x8], rax;" #8. move return addess in rax to the place we made on the stack at step 1
                    "pop rax;" #9. restore rax 
                    "jmp [rsp - 16];" #10. jump to target function
                    )
            else:
                asd = (
                    "push rax;" #1. make space for return address on stack 
                    "push rax;" #2. save rax
                    "mov rax, [RIP + 12];" #3. fill rax with return address
                    "mov [RSP+0x8], rax;" #4. move return addess in rax to the place we made on the stack at step 1
                    "pop rax;" #5. restore rax 
                    "jmp [rip + 8];" # jump to target function
                    )
            
            new_code = asm(asd, new_instruction_address)

            code.append(new_code)
            new_instruction_address += len(new_code)
            
            #if the calle expects a certain return address set jump_back_address to True, Doing so means you cant track the return which is not good
            jump_diretly_back = False
            #save the return position
            if jump_diretly_back:
                new_code = struct.pack("<Q", jump_back_address)
            else:
                new_code = struct.pack("<Q", new_instruction_address+16)
            code.append(new_code)
            new_instruction_address += len(new_code)
            
            #save the target function/pointer that we are trying to call
            new_code = struct.pack("<Q", static_call)
            code.append(new_code)
            new_instruction_address += len(new_code)

        # If the function we are patching depends on the return address, problematicly this does not let us capture the return.
        elif static_call and False: #This code path manually sets the return address to the real next instruciton then jumps to the function
            asd = "push rax;push rax;mov rax, [RIP + 12];mov [RSP+0x8], rax;pop rax;jmp [rip + 8];"
            new_code = asm(asd, new_instruction_address)

            code.append(new_code)
            new_instruction_address += len(new_code)
            
            #save the return position
            raise Exception("we are now jumping to jump_back_addressthis only wors if this is the last instruction in the list we are moving, and it wont be tracing the return")
            new_code = struct.pack("<Q", jump_back_address)
            code.append(new_code)
            new_instruction_address += len(new_code)
            
            #save the target function that we are trying to call
            target = static_call
            new_code = struct.pack("<Q", target)
            code.append(new_code)
            new_instruction_address += len(new_code)
            
            print('function_id:', get_function_id(target))
            
            
        else:
            
                
             
            
            print("asm:", new_instruction_address, instruction_asm, "org:", instruciton_dat[2])
            new_code = asm(instruction_asm, new_instruction_address)
            new_len = len(new_code)
            if contains_rip and False:
                if instruction_len != new_len:
                    diff = abs(new_len - instruction_len)
                    if new_len > instruction_len:
                        raise Exception("new instruction longer than old RIP accounting will fail, len: "+ str(new_len)+" > "+str(instruction_len))
                    else:
                        raise Exception("new instruction shorter than old RIP accounting will fail, len: "+ str(new_len)+" < "+str(instruction_len) + " "+ instruction_asm)
            
            code.append(new_code)
            new_instruction_address += new_len
        
        
        if instruction_parts[0] == "call":
            if call_num not in excluded_calls and do_call_tracing:
                
                call_asm = strip_semicolon_comments("""
                add r12, """+str(area_for_xsave64)+"""

;Save tracing
mov r10, r12
add r10, """+str(area_for_function_table + area_for_return_addr_linked_list)+""" ; get memory area for tracing
;int1 ;DEBUGBS 
mov r8, [r10]   ;Retrive end on list that is saved in the first 64 bits

mov     byte ptr [r8], 4 ;type 4 is function called (1 byte)
mov     eax, dword ptr gs:[0x48]
mov     dword ptr [r8 + 1], eax ;save thread id (4 bytes)
mov     dword ptr [r8 + 5],  """+str(function_ordinal)+""";Save function ordinal(4 bytes)
rdtsc                 ; EDX:EAX = TSC
shl     rdx, 32       ; move high half up
or      rax, rdx      ; RAX = (EDX<<32) | EAX
mov     qword ptr [r8 + 9], rax ;save timestamp (8 bytes)

mov     dword ptr [r8 + 17], """+str(call_num)+""" ;save call num (4 bytes)
lea     r8, [r8+21]
mov [r10], r8

                """)
                
                call_func_called_code = asm(generate_clean_asm_func_call(call_asm, save_full=False), new_instruction_address)
                #call_func_called_code = b""
                
                code.append(call_func_called_code)
                new_instruction_address += len(call_func_called_code)
                
            
            call_info['call_num'] = call_num
            function_map['calls'].append(call_info)
            call_num += 1
        
        moved_instructions[instruction_address] = (new_start_address, new_instruction_address)
        
    last_jump_asm = f"jmp [RIP]"
    new_code = asm(last_jump_asm, new_instruction_address)+ struct.pack("<Q", jump_back_address)
    code.append(new_code)
    new_instruction_address += len(new_code)

    shellcode = b"".join(code)
    shell_len = len(shellcode)

    shell_code_address_offset += shell_len + 20
    hook_lib.write(process_handle, jump_to_address, shellcode, do_checks = False)
    jump_writes.append((insert_location, jmp_to_shellcode))
    

    return call_num


def find_jumps_to_address(address):
    """
    Return a list of all (offset, instruction) tuples where offset == address.
    """
    if address in jumps:
        return jumps[address]
    return []

def insert_break_at_calls(process_handle, instructions: List[Tuple[int, int, str, str]], function_id: str, function_address: int, function_ordinal: int, do_init: bool) -> None:
    """Insert breakpoints at every CALL within a function's instruction list."""
    global shell_code_address_offset
    
    func_id = get_function_id(function_address)
    
    #if function_address in (140697845009392,140697847417424 ):
    #    print("skip instrumenting function:", function_address, func_id)
    #    return
    print("instrumenting:", function_address, func_id)
    call_num = 0
    init_free_space = 0
    doing_init = do_init
    
    
    
    init_instructions = []
    call_replace_instructions = []
    num_instructions = len(instructions)
    for instruction_num, instruction in enumerate(instructions):
        instruction_name = instruction[2].split(" ")[0]
        instruction_address = instruction[0]
        instruction_len = instruction[1]
        
        is_jump = instruction_name.startswith("j") or instruction_name.startswith("loop")
        
        search_call = False
        
        if doing_init:
            do_relocation = False
            
            use_instruction = True
            #if instruction_name == "cmp":
            #    do_relocation = True # Test without things that are cmp
            #else:
            
                
            jump_instructions = find_jumps_to_address(instruction_address)
            if len(jump_instructions) != 0:
                if len(init_instructions) == 0: # if we are at the first instruction jumps are not an issue except that the function will be registerd more than one
                    print("jump_to_first_instruction:", jump_instructions)
                else:
                    do_relocation = True
                    use_instruction = False
                    print("jump_to_instruction_in_init: (skiping instruction)", jump_instructions)
            
            #loop instructions are short max 127 bytes so cant be moved
            if instruction_name.startswith("loop"):
                if len(init_instructions) == 0:
                    doing_init = False
                else:
                    use_instruction = False
                    do_relocation = True
            
            if instruction_name == "db":
                if len(init_instructions) == 0:
                    doing_init = False #if first instruction is not a instruction this is not a true function we just skip this
                else:
                    do_relocation = True
                    use_instruction = False
            
            if use_instruction:
                init_free_space += instruction_len
                init_instructions.append(instruction)
            
            if num_instructions-1 == instruction_num:#we are at the final instruction it is noew or never
                do_relocation = True
            
            #do_relocation = True #If something jumps in to one of the first few instructions uncomment this
            
            if is_jump: #jumps cant be relocated unless they are the final instruction
                do_relocation = True
            #    doing_init = False # Test without jumps
            
            #if "rip" in instruction[2]:
            #    doing_init = False # Test without things that contain RIP
            
            
            
            #if instruction_name == "cmp":
            #    doing_init = False # Test without things that are calls
            
            if init_free_space >= 5:#Issue here if the next instrcution is a call we could pick it up and stuff would be alot easier
                do_relocation = True
            
            if do_relocation and doing_init:
                doing_init = False
                print("relocating_init: ", init_instructions, "cur instruciton:", instruction[2])
                call_num = add_instruction_redirect(
                    function_ordinal,
                    function_address,
                    True,
                    init_instructions,
                    process_handle,
                    call_num,
                )
        else:
            call_replace_instructions.append(instruction)
            if instruction_name == "call" and do_call_tracing:
                search_call = True
        
            
        if search_call:
            
            replace_instructions = []
            free_space = 0
            for inst in reversed(call_replace_instructions):
                inst_name = inst[2].split(" ")[0]
                if inst_name == 'db' or inst_name.startswith("loop"):#we cant move db stuff we have no idea what they are and we cant move loops as they can only jmp 127 bytes(i guesss we could implment them as "dec rcx jnz .loop")
                    break
                free_space += inst[1]
                replace_instructions.append(inst)
                if free_space >= 5:
                    break
            call_replace_instructions = []
            replace_instructions = list(reversed(replace_instructions))
            #print("type: callback", instruction[2], instruction_address)
            
            #print(instruction)
            
            
            call_num = add_instruction_redirect(
                function_ordinal,
                function_address,
                False,
                replace_instructions,
                process_handle,
                call_num,
            )
             
def find_moved_instruction(address):
    results = []
    for org_addr, (new_start, new_end) in moved_instructions.items():
        if new_start <= address < new_end:
            results.append((org_addr, new_start, new_end))
    return results
    

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
    
    
def get_targetaddr(reg, reg2, reg2_mult, indirect, offset, context, process):
    """use info to get CALL target given thread context."""
    target_addr = offset
    if reg is not None:
        reg = reg.capitalize()
        if reg in context:
            target_addr += context[reg]
        else:
            raise ValueError("Unkownn registry:", reg)
    if reg2 is not None:
        reg2 = reg2.capitalize()
        if reg2 in context:
            target_addr += context[reg2]*reg2_mult
        else:
            raise ValueError("Unkownn registry:", reg2)
    if indirect:
        target_addr = read_ptr(process, target_addr)
    return target_addr
    
def get_target_asm_resolver(reg, reg2, reg2_mult, indirect, offset, where):
    """use info to get CALL target with asm."""
    if reg is not None:
        reg = reg.lower()
    where = where.lower()
    asmcode = ""

    if indirect:
        if reg is None:
            return f"movabs {where}, {offset}\nmov {where}, [{where}]"
        else:
            if reg == where:
                raise ValueError("adding offset to own registry, not implemented")
            else:
                if reg2 is not None:
                    if reg2 == where:
                        raise ValueError("adding offset to own registry2, not implemented")
                    if offset > 2147483647:
                        raise ValueError("offset bigger than 2Gb, not implemented when using reg2")
                    return f"lea  {where}, [{reg} + {reg2}*{reg2_mult} + {offset}]\nmov {where}, [{where}]"
                else:
                    return f"lea  {where}, [{reg} + {offset}]\nmov {where}, [{where}]"
                    #return f"movabs {where}, {offset}\nlea {where}, [{where} + {reg}]\nmov {where}, [{where}]" #Fails when reg is 32 bit and where is 64
    else:
        if reg is None:
            return f"movabs     {where}, {offset}"
        else:
            if offset == 0:
                return f"mov {where}, {reg}"
            else:
                if reg == where:
                    raise ValueError("adding offset to own registry, not implemented")
                else:
                    return f"lea {where}, [{reg} + {offset}]"
                    #return f"movabs {where}, {offset}\nlea {where}, [{where} + {reg}]"#Fails when reg is 32 bit and where is 64#Fails when reg is 32 bit and where is 64
       
    
    return f"mov {where}, 0"
    
    if indirect:
        asmcode += "[ "
    target_addr = offset
    if reg is not None:
        asmcode += reg.lower()
        if offset != 0:
            if offset > 0:
                asmcode += " + " +str(abs(offset))
            else:
                asmcode += " - " +str(abs(offset))
    else:
        asmcode += str(offset)
        
    if indirect:
        asmcode += " ]"
    return asmcode

def is_reg(arg):
    try:
        offset = int(arg, 0)
        return False
    except Exception as e:
        return True

def asm2regaddr(code: Tuple[int, int, str, str]):
    """parse info needed to get CALL target address from a instruction, given thread context."""
    reg = None
    reg2 = None
    reg2_mult = None
    offset = 0
    indirect = False
    asm_text = code[2]
    if "[" in asm_text:  # indirect call like call [rax+8] or RIP-relative
        indirect = True
        mem_expr = asm_text.split("[", 1)[1].split("]", 1)[0].strip()
        mem_parts = mem_expr.split(" ")
        #print(mem_parts)
        if len(mem_parts) == 3:
            reg, op, second = mem_parts[0], mem_parts[1], mem_parts[2]
            if is_reg(second):
                reg2 = second
            else:
                offset = int(second, 0)
        elif len(mem_parts) == 5:
            reg, _, reg2, op, disp_str = mem_parts[0], mem_parts[1], mem_parts[2], mem_parts[3], mem_parts[4]
            offset = int(disp_str, 0)
        elif len(mem_parts) == 1:
            reg, op, disp_str = mem_parts[0], "+", "0"
            offset = int(disp_str, 0)
        else:
            raise ValueError("could not parse call asm: "+ asm_text)
        if reg is not None:
            reg = reg.capitalize()
            
        if reg2 is not None:
            reg_parts = reg2.split("*")
            if len(reg_parts) == 2:
                reg2 = reg_parts[0]
                reg2_mult = int(reg_parts[1])
            else:
                reg2_mult = 1
            reg2 = reg2.capitalize()
        if op == "-":
            offset = -offset
        

        # Since RIP counts per instruction, account for CALL length we haven't executed yet
        if reg == "Rip":
            base_val = code[0] + code[1]
            offset = base_val + offset
            reg = None
        if reg2 == "Rip":
            mult = 1
            if reg2_mult is not None:
                mult = reg2_mult
            base_val = code[0] + code[1]
            offset = (base_val*mult) + offset
            reg2 = None
            reg2_mult = None

    else:
        label = asm_text.split(" ")[1]

        if label.startswith("0x"):
            offset = int(label, 16)
        else:
            reg = label.capitalize()

    return reg, reg2, reg2_mult, indirect, offset


        

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
    
def generate_clean_asm_func_call(code, in_two_parts = False, debug = False, save_full=True):
    global register_save_address, thread_storage_list_address
    
    if save_full:
        raise Exception("save_full not supported any longer")
    
    
    if not save_full:
        assembly1 = "\nlea rsp, [rsp-128]\ncall " + str(save_state_address) + "\n\n" + code.replace(";", "\n") +"\n"
    if debug:
        assembly1 = "\nlea rsp, [rsp-128]\ncall " + str(debug_func_address) + "\n\n" + code.replace(";", "\n") +"\n"
    
    if not save_full:
        assembly2 = "call " + str(restore_state_address) + "\n"
    if in_two_parts:
        return assembly1, assembly2
    return assembly1 + assembly2

# -----------------------------
# DLL injection helpers
# -----------------------------

def run_loadlibrary_in_process(h_process: int, dll_path: str) -> None:
    """Write dll_path to target and call LoadLibraryA via injected assembly."""
    global load_dll_tid
    dll_path = os.path.abspath(dll_path)
    print("trying to inject dll")
    thread = hook_lib.load_library_in_remote(h_process, dll_path)
    
    

def on_calltrace_dll_ready(handle):
    global call_trace_dll_ready
    if call_trace_dll_ready:
        return
    call_trace_dll_ready = True
    
    dll_name = "calltracer.dll"
    pe = pefile.PE(dll_name)
    basename = os.path.basename(dll_name)
    mods = hook_lib.enumerate_modules(handle, base_name = True)
    if basename in mods:
        base_addr = mods[basename]["base"]
    else:
        print("calltracer dll not loaded when thread exited")
        return

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                name = exp.name.decode()
                rva = exp.address
                virtual_address = base_addr + rva
                call_tracer_dll_func[name] = virtual_address
            else:
                print("No export table found.")
        
    else:
        raise Exception("dll has no exports")
    setup_after_dll_loaded(handle)
    
    

def loaded_dll(dll_name: str, callback, event: Any) -> None:
    thread = event.get_thread()
    context = thread.get_context()
    base_addr = context["Rax"]
    if base_addr != 0:
        print("Loaded injected dll:", dll_name)
        basename = os.path.basename(dll_name)
        basic_name, ext = os.path.splitext(basename)
        loaded_modules[basic_name] = base_addr

        callback(event)
        #This code has ben moved to hte load dll event keeping it here for reference here for now 
        #if basic_name == "calltracer" and len(call_tracer_dll_func) == 0:
        #    
    else:
        print("failed to load injected dll:", dll_name)
        sys.exit()


def get_pdata(file_name: str, base_addr: int, exe_basic_name: str) -> None:
    """Parse .pdata from file on disk and populate function ranges & IDs."""
    global pdata, pdata_functions, exe_entry_address, pdata_function_ids, area_for_function_table

    
    functions: List[Tuple[int, int, int, int]] = []
    
    pe_info = pefile.PE(name=file_name, fast_load=True)#cant load from memmory as the important headers are not loaded into memmory
    exe_entry_address = pe_info.OPTIONAL_HEADER.AddressOfEntryPoint + base_addr
    
    pe_info.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'], pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']])
    
    i = 0
    for rf in pe_info.DIRECTORY_ENTRY_EXCEPTION:
        #print(rf.struct.BeginAddress, rf.struct.EndAddress, rf.unwindinfo.Flags, rf.unwindinfo.SizeOfProlog, dir(rf.unwindinfo))
        start_addr = rf.struct.BeginAddress + base_addr
        end_addr = rf.struct.EndAddress + base_addr
        functions.append((start_addr, end_addr, int(rf.unwindinfo.Flags), i))
        pdata_function_ids[start_addr] = exe_basic_name + "_" + str(i)
        i += 1
    
    if area_for_function_table is None:
        nr_of_functions = len(functions)
        area_for_function_table = (nr_of_functions+1)*8#(we add  one just in case i dont remember if ordinal was zero or one indexed)
    pdata_functions = functions


# -----------------------------
# Entrypoint
# -----------------------------
if __name__ == "__main__":
    # If a process is already running we attach; otherwise we create it.
    start_or_attach(sys.argv[1:])
