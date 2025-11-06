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
    pip install pefile
    pip install keystone-engine
    pip install capstone==6.0.0a4
    pip install pdbparse

Note: Run on Windows.


"""
# function_tracer.py notepad++.exe | "C:\Program Files\Git\usr\bin\tee.exe" test.txt

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
import hook_lib
import locale
import bisect
import hashlib
import argparse
import re
_strip_semicolon_comments = re.compile(r'[ \t]*;[^\r\n]*')


import cProfile, pstats, io

pr = cProfile.Profile()
pr.enable()

# -----------------------------
# Globals / State
# -----------------------------

# External breakpoints mapped by address to callback
external_breakpoints: Dict[int, Callable[[Any], None]] = {}

# Loaded module base addresses by basename (e.g., "kernel32")
loaded_modules: Dict[str, int] = {}

# Exported functions from calltracer.dll resolved to absolute addresses
call_tracer_dll_func: Dict[str, int] = {}
call_tracer_thunk_func = {}
call_tracer_thunk_func_ptr = {}

# Per-thread replacement return addresses for MinHook trampolines
# Structure: ret_replacements[tid][jump_table_addr] = [return_addr_stack]
ret_replacements: Dict[int, Dict[int, List[int]]] = {}

# Queue of (assembly_str, callback) to inject and execute
asm_code_to_run: List[Tuple[str, Optional[Callable[[Any], None]]]] = []

# Control flags / addresses
in_loading_phase: bool = True
is_in_injected_code: bool = False
code_injection_address: Optional[int] = None
register_save_address: Optional[int] = None
shell_code_address: Optional[int] = None
shell_code_address_offset: int = 20  # Start at 20 arbitrarily to keep some space free.

# PE / function metadata (.pdata)
pdata: Optional[bytes] = None
pdata_functions: List[Tuple[int, int, int, int]] = []
pdata_index = None
pdata_function_ids: Dict[int, str] = {}
exe_entry_address: int = 0
disassembled_functions = {}
asembly_cache = {}
function_data = {}

# Simple call stack for pretty printing
call_stack: List[str] = []

# Functions (addresses) we plan to hook via MinHook (in calltracer.dll)
# Each entry: (target_fn_addr, enter_callback, exit_callback)
functions_to_hook: List[Tuple[int, Callable[[Any], None], Callable[[Any], None]]] = []

moved_instructions = {}
ref_instructions = {}
suspended = False

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
calls = {}
jumps_index = []
calls_index = []
classfied_extra_functions = []
max_thread_ids = 30000

os.makedirs('output', exist_ok=True)
os.makedirs('cache', exist_ok=True) 
out_file = None

call_map = []
functions_end = {}

exe_basic_name = None
exe_name = None

forbid_break_point_jumps = True # if set to try break point jumps are not used (meaning some functions that need them wont be traced)
use_calls_for_patching = False #Replaces jumps with calls. Slower than jumps as the return address needs to be captured, saved then restored. Using a jump techic uses 2 instructions using calls uses about 150 instructions and multiple memmory writes and reads 
redirect_return = True
respect_prolog_size = False #If we wont replace any instructions after the said prolog size
forbid_entry_tracing = False #does not add any tracing code just injects. For use in testing when program craches
trace_calls = True
only_trace_unknown_calls = False
only_replace_single_instruction_init = False # Only replace the first instruciton in the function init
only_allow_single_instruction_replacements = False # When tracing calls only allow one instruction replacement, leads to many uses of break point jumps whereever a 5 byte jump wont fit (breakpoint jumps are SLOW) ONLY applies to call replacements not INIT replacements.
exclude_call_tracing_in_force_truncated_functions = True # if a function has been truncated (cause it contains data) dont trace calls
force_all_detours = False #if you want to force detorring when if there was no need (for debuging)

if forbid_entry_tracing and redirect_return:
    raise ValueError("cant forbid forbid_entry_tracing when also redirecting return")

call_exclusions = [
    #(2666, 0),
]

enter_exclusions = [
]


rsp_ofset = 128


function_exclusions = []


# -----------------------------
# Helpers
# -----------------------------
def start_or_attach(argv: List[str]) -> None:
    """Start or attach to the given executable.

    """
    global spawned, exe_basic_name, out_file, exe_name, asembly_cache, suspended
    pid = None
    p = argparse.ArgumentParser(description="Run a for-loop over each line of a file.")
    p.add_argument("executable", help="pid or executable")
    p.add_argument("--pause_on_load", action="store_true", help="Wait for the proces to start and load kernel32.dll then pauses it")
    p.add_argument("--find_upacking_region", action="store_true", help="Use together with --pause_on_load to find what regions are unpacked")
    p.add_argument("--wait_for_unpack", help="Wait until executable is unpacked using data from find_upacking_region, format intaddress:hexbyte use together with --pause_on_load")
    p.add_argument("--only_analyse", action="store_true", help="Only does executable analysis")
    p.add_argument("--exclude_functions", default="utf-8", help="json file with function ordinals to exclude")
    p.add_argument("--memory_scan", type=int, default=None, nargs="?", const=-1, help="scans the executable periodicly for changes in executable code. Changes like hooks and unpacking.")
    args = p.parse_args()
    
    arg1 = args.executable
    
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
            
        if args.pause_on_load:
            print("searching for launch of:", exe)
            while True:
                pids = hook_lib.get_pids_by_name(exe)
                if len(pids) >= 1:
                    pid = pids[0]
                    break
        else:
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
    has_loaded_dll = False
    
    print("waiting for kernel32")
    mods = wait_for_kernel32(handle)
    
    
    # if we just spawned the process we suspend it now that kernel32 is loaded to try to catch as much of the activity as posible
    # some activity might still get lost as the way we probe for kernel32 is async but doing it syncronysly would be much more complicated

    if spawned or args.pause_on_load:
        print("suspending process as it has just loaded")
        suspended = True
        res = hook_lib.NtSuspendProcess(handle)
        

    exe_basic_name = get_base_name(executable_path)
    exe_name = executable_path.split("\\")[-1].lower()
    out_file = os.path.abspath('output'+os.sep+exe_basic_name+'.trace')
    if os.path.exists(out_file):
        os.remove(out_file)
    
    base_addr = mods[exe_name]['base']
    
    
    

    assembled_cache_file = "cache\\" + exe_basic_name + "_asembly_cache.json"
    
    if os.path.exists(assembled_cache_file) and time.time() - os.path.getmtime(assembled_cache_file) < 12 * 3600:
        with open(assembled_cache_file, "r") as f:
            asembly_cache = json.load(f)
            for key in asembly_cache:
                asembly_cache[key] = bytes.fromhex(asembly_cache[key])
    print("get pdata")
    get_pdata(executable_path, base_addr, exe_basic_name)
    
    start_addr = 9999999999999999999
    end_addr = 0
    for function_start_addr, function_end_addr, flags, pdata_ordinal, prolog_size in pdata_functions:
        start_addr = min(function_start_addr, start_addr)
        end_addr = max(function_end_addr, end_addr)
        func_len = function_end_addr - function_start_addr
    data_len = end_addr - start_addr
    
    lookup_calltrace_exports()
    
    if args.wait_for_unpack:
        num_str, byte_str = args.wait_for_unpack.split(":")
        
        
        address_of_byte = start_addr + int(num_str)
        packed_byte = bytes([int(byte_str, 16)])
        
        
        mem_dat = hook_lib.read(handle, address_of_byte, 1)
        if packed_byte != mem_dat:
            raise Exception("TO slow")
        
        if suspended:
            print("resuming process while it unpacks")
            hook_lib.NtResumeProcess(handle)
            suspended = False
        
        

        
        while True:
            mem_dat = hook_lib.read(handle, address_of_byte, 1)
            if packed_byte != mem_dat:
                hook_lib.NtSuspendProcess(handle)
                print("suspended process as it has now unpacked")
                suspended = True
                break
        
        #the executable should be suspended and unpacked now
        
    
    if args.find_upacking_region:
        
        #read packed data
        
        
        packed_data = hook_lib.read(handle, start_addr, data_len)
        
        if suspended:
            print("resuming process")
            hook_lib.NtResumeProcess(handle)
            suspended = False
         
        #save packed data to cache for later consumtion
        #packed_data_file = "cache\\" + exe_basic_name + "_packed_data.bin"
        #with open(packed_data_file, "wb") as f:
        #    f.write(packed_data)
        
        input("press enter when executable has unpacked and loaded completly") 
        
        unpacked_data = hook_lib.read(handle, start_addr, data_len)
        
        #save packed data to cache for later consumtion
        #unpacked_data_file = "cache\\" + exe_basic_name + "_unpacked_data.bin"
        #with open(unpacked_data_file, "wb") as f:
        #    f.write(unpacked_data)
        
        last_non_matching_byte = None
        for i in range(data_len-1, -1, -1):
            if packed_data[i] != unpacked_data[i]:
                last_non_matching_byte = i
                break
        if last_non_matching_byte is not None:
            org_dat = bytes([packed_data[last_non_matching_byte]]).hex()
            desc = str(last_non_matching_byte)+":"+org_dat
            print("last_non_matching_byte:", desc)
        else:
            print("no differance after unpack")
        
        exit()
        
    if args.exclude_functions:
        if os.path.exists(args.exclude_functions):
            with open(args.exclude_functions, "r") as f:
                loaded_json = json.load(f)
                for index in loaded_json:
                    func_ordinal = int(index)
                    function_exclusions.append(func_ordinal)
                    #func = get_function_containing(func_addr)
                    #if func is None:
                    #    print("no function at address:", func_addr)
                    #else:
                    #    function_exclusions.append(func[3])
    
    
    
    if args.memory_scan is not None:
        map_file = "output\\"+exe_basic_name+'_map.json'
        
        
        if not os.path.exists(map_file):
            raise Exception("no function map found, run with --only_analyse first (wait for unpacking first if executable does unpacking)")
        with open(map_file, "r") as f:
            call_map = json.load(f)
        
        function_data_cache_file = "cache\\" + exe_basic_name + "_function_data_cache.json"
        if not os.path.exists(function_data_cache_file):
            raise Exception("no original function data found, run with --only_analyse first (wait for unpacking first if executable does unpacking)")
        with open(function_data_cache_file, "r") as f:
            loaded_json = json.load(f)
            for index in loaded_json:
                function_data[int(index)] = bytes.fromhex(loaded_json[index])
        
        if suspended:
            print("resuming process")
            hook_lib.NtResumeProcess(handle)
            suspended = False
        
        last_func_data = []
        for function in call_map:
            if function['unlisted']:
                continue
            last_func_data.append(function_data[function['function_start_addr']])
        
        
        chnages_file = "output\\"+exe_basic_name+'_changed_functions.json'
        changes = {}
        
        if os.path.exists(chnages_file):
            with open(chnages_file, "r") as f:
                loaded_json = json.load(f)
                for index in loaded_json:
                    changes[int(index)] = loaded_json[index]
        
        process_is_still_running = True
        nr_of_checks = 0
        while process_is_still_running:
            #hook_lib.NtSuspendProcess(handle)
            
            i = 0
            for function in call_map:
                if function['unlisted']:
                    continue
                #print(function)
                func_len = function['function_end_addr'] - function['function_start_addr']
                data = hook_lib.read(handle, function['function_start_addr'], func_len)
                if (args.memory_scan == -1 and data != last_func_data[i]) or (args.memory_scan != -1 and data[args.memory_scan] != last_func_data[i][args.memory_scan]):
                    if function['ordinal'] not in changes:
                        changes[function['ordinal']] = 0
                        
                    
                    changes[function['ordinal']] += 1
                    print("function: " + function['function_id'] + " has changed:", changes[function['ordinal']])
                    last_func_data[i] = data
                
                i += 1
            
            #hook_lib.NtResumeProcess(handle)
            print("all functions checked", nr_of_checks)
            nr_of_checks += 1
            
            with open(chnages_file, "w") as f:
                json.dump(changes, f, indent=2)
            
            time.sleep(30.0)
    else:
        print("analyse_executable_code")
        analyse_executable_code(handle)
    
    if not args.only_analyse and not args.memory_scan is not None:
        allocate_mem(handle, exe_entry_address)
        
            
        
        
        inject_trace_injection_functions(handle)
        
        ##if we are using breakpoint jumps we need to inject the dll earlier ro make sure that the vectorised exception handler is registerd
        if not forbid_break_point_jumps:
            print("inject dll")
            inject_dll(handle)
        
        print("hooking executable")
        hook_calls(handle)
        
        #the last thing we do is inject the calltrace dll as the process needs to be resumed for that to work
        #code that needs the calltrace dll will spin untill the dll is ready
    
        
        if forbid_break_point_jumps:
            print("inject dll")
            inject_dll(handle)
    
    if suspended:
        print("resuming process")
        hook_lib.NtResumeProcess(handle)
        suspended = False
    
    if not args.only_analyse and not args.memory_scan is not None:
        with open(assembled_cache_file, "w") as f:
            for key in asembly_cache:
                asembly_cache[key] = asembly_cache[key].hex()
            json.dump(asembly_cache, f, indent=2)
    
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
    ps.print_stats(30)
    print(s.getvalue())
    
def memory_scan(handle):
    pass

def wait_for_kernel32(handle):
    mods = None
    while True:
        try:
            mods = hook_lib.enumerate_modules(handle, do_until_sucess = True, base_name = True)
            if "kernel32.dll" in mods:
                return mods
        except OSError as e:
            pass #print("enumerate_modules faield trying again")

def get_base_name(filename: str) -> str:
    """Return lowercase filename without extension from a Windows path."""
    dname = filename.split("\\")[-1]
    basic_name = dname.split(".")[0].lower()
    return basic_name



def make_asm_key(code: str, address: int) -> str:
    """asembling is slow so we cache the results"""
    h = hashlib.blake2b(digest_size=8)
    h.update(code.encode('utf-8'))
    h.update(address.to_bytes(8, 'little'))
    return str(h.hexdigest())

def asm(CODE: str, address: int = 0) -> bytes:
    """Assemble x64 code at the given address using Keystone."""
    
    ##due to the fact that we alocate allot of code dynamicly allot of asm gets lots of cache miseses
    asm_hash = make_asm_key(CODE, address)
    if asm_hash in asembly_cache:
        return asembly_cache[asm_hash]
        
    try:
        encoding, count = ks.asm(CODE, address)
    except KsError as e:
        # e.errno is a keystone error enum, e.count is # of statements assembled
        print(CODE, address)
        print(f"Keystone error: {e} (errno={getattr(e, 'errno', None)}, " f"count={getattr(e, 'count', None)})")
        traceback.print_stack()
        exit()
    byts = bytes(encoding)
    asembly_cache[asm_hash] = byts
    return byts


def read_ptr(handle, address: int) -> int:
    """Read an 8-byte pointer from the target process memory at address."""
    data = hook_lib.read(handle, address, 8)
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

def allocate_mem(process_handle, address_close_to_code: int) -> None:
    """Allocate remote memory regions."""
    global register_save_address, code_injection_address, shell_code_address, thread_storage_list_address, alocated_thread_storages
    
    print("allocating memmory")
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
    print("remote_memory:", remote_memory)
    
    #we cant to keep the size as small as posible as relative addressing can only handle ofsets of +-2147483647
    size = len(pdata_function_ids)*300 + 100000 #we do 300 bytes per function and 100000 bytes for other stuff
    shell_code_address = 0
    atempt = 1
    while shell_code_address == 0:
        # Allocate large RX region for shellcode near code
        
        preferred_address = (address_close_to_code - size* atempt)
        shell_code_address = ctypes.windll.kernel32.VirtualAllocEx(
            process_handle, ctypes.c_void_p(preferred_address), size, 0x3000, 0x40
        )
        if shell_code_address == 0:
            print("Could not allocate jump table; this can be somewhat random. Trying again.")
            #if atempt > 3:
            #    size //=4
            #    size *= 3
            atempt += 1
    print("shell_code_address:", shell_code_address)
    last_seize = size
    # Allocate register-save area (writable)
    register_save_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, 4096, 0x3000, 0x04)
    if register_save_address == 0:
        print(f"Failed to allocate register_save_address in target process: {ctypes.WinError()}")
        sys.exit(0)
    print("register_save_address:", register_save_address)


    thread_storage_list_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, 8*max_thread_ids, 0x3000, 0x04)
    if thread_storage_list_address == 0:
        raise Exception(f"Failed to allocate memory in target process: {ctypes.WinError()}")
    print("thread_storage_list_address:", thread_storage_list_address)
    
    alocated_thread_storages = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, nr_of_prepared_alocations*8, 0x3000, 0x04)
    if alocated_thread_storages == 0:
        raise Exception(f"Failed to allocate memory in target process: {ctypes.WinError()}")
    print("alocated_thread_storages:", alocated_thread_storages)
    
    print("setting up thread storage")
    #here we prealoacte memory for threads
    for stor_id in range(nr_of_prepared_alocations):
        thread_storage_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, area_for_xsave64 + area_for_function_table + area_for_return_addr_linked_list + area_for_tracing_results, 0x3000, 0x04)
        if thread_storage_address == 0:
            raise Exception(f"Failed to allocate memory in target process: {ctypes.WinError()}")
        hook_lib.write(process_handle, alocated_thread_storages + stor_id*8, struct.pack("<Q", thread_storage_address))
        
        #OLD code to do allocations using dll: hook_lib.inject_asm(process_handle, "sub rsp, 40\nmov     rcx, "+str(alocated_thread_storages + stor_id*8)+"\nmovabs rax, "+str(call_tracer_dll_func['alloc_thread_storage'])+"\n\ncall rax\nadd rsp, 40\nret")

def inject_dll(process_handle):
    # Inject helper DLL with MinHook-based hooks
    run_loadlibrary_in_process(process_handle, "calltracer.dll") #FIXMEEE process
    fixup_calltrace_exports(process_handle)
    
    setup_dll_values(process_handle)
    
    fixup_calltrace_exports_thunks(process_handle)
    
    
    
def inject_trace_injection_functions(process_handle):
    global call_tracer_thunk_ready_addr, register_save_address, code_injection_address, shell_code_address, thread_storage_list_address, restore_state_address, save_state_address, alocated_thread_storages, debug_func_address, add_entry_trace_address, add_called_trace_address, add_call_trace_address, add_exit_trace_address, push_value_from_linkedlist_address, pop_value_from_linkedlist_address, pop_value_with_sameRSP_from_linkedlist_address
    
    call_tracer_thunk_ready_addr = shell_code_address
    shell_code_address += 1
    
    #Setup thunk functions for dll
    for name in call_tracer_dll_func:
        
        
        #this will be zero untill we fill it in
        call_tracer_thunk_func_ptr[name] = shell_code_address
        shell_code_address += 8
        thunk_address = shell_code_address
        
        call_tracer_thunk_func[name] = thunk_address
        
        #This code spins untill the calltracer dll has been loaded
        thunk_func_code = asm(strip_semicolon_comments(f"""
        .check_if_call_trace_ready:
        cmp     byte ptr [{call_tracer_thunk_ready_addr}], 0
        je .check_if_call_trace_ready
        jmp [{call_tracer_thunk_func_ptr[name]}]
        """), call_tracer_thunk_func[name])
        shell_code_address += len(thunk_func_code)
        hook_lib.write(process_handle, call_tracer_thunk_func[name], thunk_func_code, do_checks = False)
    
    
    #save state requires you to push 128 bytes to rsp before calling lea   rsp, [rsp-128]
    #Setup save sate and restore state functions
    
    VirtualAlloc_addr = hook_lib.get_remote_function(process_handle, "kernel32", "VirtualAlloc")
    
    #save state function
    save_state_asm = strip_semicolon_comments(f"""
; ===== prologue: preserve flags & callee-saved registers =====
pushfq

sub   rsp, 8
; save callee-saved GPRs that we will use or clobber
push r15
mov r15, rsp
add r15, {rsp_ofset+24+8}; save original return_address stack location in r15 fix ofset 24 caused by earlier pushes and 128 from before call and 8 from the call

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
        jmp .not_found

    .found:
        mov [r12], rax ; save new vale
        mov     r11, 1 ;set R11 so we store the extended registers we only do it if we need to as it is slow
        ;RDI is already set so alloc_thread_storage(uint64_t out_address) will be called further down



.thread_memmory_is_alocated:
mov r12, [r12]



mov r10, r12
add r10, """+str(area_for_xsave64 + area_for_function_table + area_for_return_addr_linked_list)+"""; get memory area for tracing


mov r8, [r10]   ;Retrive end on list that is saved in the first 64 bits

test r8, r8
jnz  .skip_mem_setup

mov r9, r12
add r9, """+str(area_for_xsave64 + area_for_function_table)+"""
mov [r9], r9 ;setup linked list mem 

mov r8, r10
add r8, 8
mov [r10], r8 ;setup trace mem 

.skip_mem_setup:

;Check if trace memmory starts be become to big
xor r9, r9
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
    
    mov r13, rdi ;save the reg used for storage
    
    ;sub  rsp, 40
    ; call VirtualAlloc
    xor     rcx, rcx           ; lpAddress = NULL
    movabs     rdx, """+str(area_for_xsave64 + area_for_function_table + area_for_return_addr_linked_list + area_for_tracing_results)+"""           ; dwSize = thread_storage_size 
    mov     r8, 0x3000        ; MEM_COMMIT | MEM_RESERVE
    mov     r9, 0x04          ; PAGE_READWRITE
    
    movabs rax, """+str(VirtualAlloc_addr)+"""
    call rax
    ;add  rsp, 40
    
    .allocation_error:
    test rax, rax
    jz .allocation_error
    
    ;Save the return adress
    mov [r13], rax
    
    


    ;Restore r15
    mov r15, [rsp+48]
    jmp .skip_dump_trace
.skip_alloc_thread_storage:


;DUMP thread can run at the same time as alloc_thread_storage as registers will be cloberd but it never will so it does not matter
test    R9, R9
jz .skip_dump_trace

    ;dump saved traces

    mov rcx, r9 ;set first arg
    movabs rax, """+str(call_tracer_thunk_func['dump_trace'])+f"""
    call rax

    ;Restore r15
    mov r15, [rsp+48]

.skip_dump_trace:

jmp [r15 - {rsp_ofset+8}] ;Jump back to return address of save call
    """)
    
    save_state_address = shell_code_address
    save_state_code = asm(save_state_asm, save_state_address)
    shell_code_address += len(save_state_code)
    hook_lib.write(process_handle, save_state_address, save_state_code, do_checks = False)
    
    
    
    
    
    debug_save_state_asm = strip_semicolon_comments(f"""

    """)
    
    debug_func_address = shell_code_address
    debug_save_state_code = asm(debug_save_state_asm, debug_func_address)
    shell_code_address += len(debug_save_state_code)
    hook_lib.write(process_handle, debug_func_address, debug_save_state_code, do_checks = False)
    
    
    #restore state function
    restore_state_asm = strip_semicolon_comments(f"""
    
; ===== after call: pop shadow and undo alignment correction =====

add  rsp, 40 ; Add 32 plus 8 cause we just did this call

pop r12
pop r11
pop r15

;Save the return address for this restore call
mov r10, [rsp-64]
mov [r15-{rsp_ofset+8}], r10

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

lea   rsp, [rsp+{rsp_ofset+8}] ;restore rsp 128 cause we added that before call + 8 cause of this call
jmp [rsp - {rsp_ofset+8}] ;jump to restore return address
""")
    
    restore_state_address = shell_code_address
    restore_state_code = asm(restore_state_asm, restore_state_address)
    shell_code_address += len(restore_state_code)
    hook_lib.write(process_handle, restore_state_address, restore_state_code, do_checks = False)

    
    add_entry_trace_address = shell_code_address
    add_entry_trace_code = asm(strip_semicolon_comments("""
add r12, """+str(area_for_xsave64)+"""
;Save tracing
mov r10, r12
add r10, """+str(area_for_function_table + area_for_return_addr_linked_list)+""" ; get memory area for tracing

mov r8, [r10]   ;Retrive end on list that is saved in the first 64 bits

mov     byte ptr [r8], 1 ;type 1 is function entry (1 byte)
mov     eax, dword ptr gs:[0x48]
mov     dword ptr [r8 + 1], eax ;save thread id (4 bytes)
mov     dword ptr [r8 + 5],  edx;Save function ordinal(4 bytes) edx is a function argument
rdtsc                 ; EDX:EAX = TSC
shl     rdx, 32       ; move high half up
or      rax, rdx      ; RAX = (EDX<<32) | EAX
mov     qword ptr [r8 + 9], rax ;save timestamp (8 bytes)

mov     qword ptr [r8 + 17], r15 ;save return address pointer/function entry rsp(8 bytes)
mov     rcx, [r15]              ;
mov     qword ptr [r8 + 25], rcx ;save return address (8 bytes) 
lea     r8, [r8+33]
mov [r10], r8
ret"""), add_entry_trace_address)
    shell_code_address += len(add_entry_trace_code)
    hook_lib.write(process_handle, add_entry_trace_address, add_entry_trace_code, do_checks = False)
    
    

    add_exit_trace_address = shell_code_address
    add_exit_trace_code = asm(strip_semicolon_comments("""add r12, """+str(area_for_xsave64)+"""

;Save tracing
mov r10, r12
add r10, """+str(area_for_function_table + area_for_return_addr_linked_list)+""" ; get memory area for tracing

mov r8, [r10]   ;Retrive end on list that is saved in the first 64 bits

mov     byte ptr [r8], 2 ;type 2 is function exit (1 byte)
mov     eax, dword ptr gs:[0x48]
mov     dword ptr [r8 + 1], eax ;save thread id (4 bytes)
mov     dword ptr [r8 + 5],  edx;Save function ordinal(4 bytes) edx is a function argument
rdtsc                 ; EDX:EAX = TSC
shl     rdx, 32       ; move high half up
or      rax, rdx      ; RAX = (EDX<<32) | EAX
mov     qword ptr [r8 + 9], rax ;save timestamp (8 bytes)
mov     qword ptr [r8 + 17], r15 ;save return address pointer(8 bytes)

lea     r8, [r8+25]
mov [r10], r8
ret"""), add_exit_trace_address)
    shell_code_address += len(add_exit_trace_code)
    hook_lib.write(process_handle, add_exit_trace_address, add_exit_trace_code, do_checks = False)
    
    
    add_call_trace_address = shell_code_address
    add_call_trace_code = asm(strip_semicolon_comments("""add r12, """+str(area_for_xsave64)+"""

;Save tracing
mov r10, r12
add r10, """+str(area_for_function_table + area_for_return_addr_linked_list)+""" ; get memory area for tracing

mov r8, [r10]   ;Retrive end on list that is saved in the first 64 bits

mov     byte ptr [r8], 3 ;type 3 is function call (1 byte)
mov     eax, dword ptr gs:[0x48]
mov     dword ptr [r8 + 1], eax ;save thread id (4 bytes)
mov     dword ptr [r8 + 5],  edx;Save function ordinal(4 bytes) edx is a function argument
rdtsc                 ; EDX:EAX = TSC
shl     rdx, 32       ; move high half up
or      rax, rdx      ; RAX = (EDX<<32) | EAX
mov     qword ptr [r8 + 9], rax ;save timestamp (8 bytes)

mov     dword ptr [r8 + 17], edi ;save call num (4 bytes) edi is a function argument
mov     rax, [r15-8] ;  arg target address # original rsp in rax, saved in r15 by save_target_asm
mov     qword ptr [r8 + 21], rax ;save raget_address (8 bytes)
lea     r8, [r8+29]
mov [r10], r8
ret"""), add_call_trace_address)
    shell_code_address += len(add_call_trace_code)
    hook_lib.write(process_handle, add_call_trace_address, add_call_trace_code, do_checks = False)
    
    add_called_trace_address = shell_code_address
    add_called_trace_code = asm(strip_semicolon_comments("""

add r12, """+str(area_for_xsave64)+"""

;Save tracing
mov r10, r12
add r10, """+str(area_for_function_table + area_for_return_addr_linked_list)+""" ; get memory area for tracing
;int1 ;DEBUGBS 
mov r8, [r10]   ;Retrive end on list that is saved in the first 64 bits

mov     byte ptr [r8], 4 ;type 4 is function called (1 byte)
mov     eax, dword ptr gs:[0x48]
mov     dword ptr [r8 + 1], eax ;save thread id (4 bytes)
mov     dword ptr [r8 + 5],  edx;Save function ordinal(4 bytes) edx is a function argument
rdtsc                 ; EDX:EAX = TSC
shl     rdx, 32       ; move high half up
or      rax, rdx      ; RAX = (EDX<<32) | EAX
mov     qword ptr [r8 + 9], rax ;save timestamp (8 bytes)

mov     dword ptr [r8 + 17], edi ;save call num (4 bytes) edi is a function argument
lea     r8, [r8+21]
mov [r10], r8

ret"""), add_called_trace_address)
    shell_code_address += len(add_called_trace_code)
    hook_lib.write(process_handle, add_called_trace_address, add_called_trace_code, do_checks = False)
    
    
    push_value_from_linkedlist_address = shell_code_address
    push_value_from_linkedlist_code = asm(strip_semicolon_comments(
f"""

mov rcx, r12
add rcx, {area_for_function_table} ; load address pointing to the top alocation in area_for_function_table

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


ret"""), push_value_from_linkedlist_address)
    shell_code_address += len(push_value_from_linkedlist_code)
    hook_lib.write(process_handle, push_value_from_linkedlist_address, push_value_from_linkedlist_code, do_checks = False)
    
    pop_value_with_sameRSP_from_linkedlist_address = shell_code_address
    pop_value_with_sameRSP_from_linkedlist_code = asm(strip_semicolon_comments("""

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
    jmp .pop_empty

.pop_done:


mov     [r15-100], rax
ret"""), pop_value_with_sameRSP_from_linkedlist_address)
    shell_code_address += len(pop_value_with_sameRSP_from_linkedlist_code)
    hook_lib.write(process_handle, pop_value_with_sameRSP_from_linkedlist_address, pop_value_with_sameRSP_from_linkedlist_code, do_checks = False)
    
    pop_value_from_linkedlist_address = shell_code_address
    pop_value_from_linkedlist_code = asm(strip_semicolon_comments("""

mov     r11, qword ptr [r12]       ; r11 = current top node

    test    r11, r11
    jz      .pop_empty                  ; empty -> return 0


    mov     rax, qword ptr [r11 + 8]    ; rax = node->value
    mov     r11, qword ptr [r11 + 0]    ; r11 = node->prev
    mov     qword ptr [r12], r11        ; update top
    jmp     .pop_done

.pop_empty:
    xor     rax, rax                    ; rax = 0
    int3 ; indication that something has gone teribly wrong
    jmp .pop_empty

.pop_done:


mov     [r15-100], rax
ret"""), pop_value_from_linkedlist_address)
    shell_code_address += len(pop_value_from_linkedlist_code)
    hook_lib.write(process_handle, pop_value_from_linkedlist_address, pop_value_from_linkedlist_code, do_checks = False)
    
    
    
    

def setup_dll_values(process_handle):
    global suspended, out_file, nr_of_prepared_alocations, alocated_thread_storages, area_for_function_table, thread_storage_list_address
    #Here we hope to good we are fast enogh so that no hookin libs are executed while we resume and resuspend after doing our calls # FIXMEE move these to a later part of the code
    if suspended:
        hook_lib.NtResumeProcess(process_handle)
    
    print("set_area_for_function_table")
    mem_size = str(area_for_function_table)
    asf = "sub rsp, 40\nmov     rcx, "+mem_size+"\nmovabs rax, "+str(call_tracer_dll_func['set_area_for_function_table'])+"\n\ncall rax\nadd rsp, 40\nret"
    injection_info = hook_lib.inject_asm(process_handle, asf)
    
    print("set_thread_list_table_addres")
    asf = "sub rsp, 40\nmovabs     rcx, "+str(thread_storage_list_address)+"\nmovabs rax, "+str(call_tracer_dll_func['set_thread_list_table_addres'])+"\n\ncall rax\nadd rsp, 40\nret"
    injection_info = hook_lib.inject_asm(process_handle, asf)
    
    
    print("set out file:", out_file, "using dll function:", call_tracer_dll_func['set_output_file'])
    str_addr, alloc_size = hook_lib.alloc_and_write_remote(process_handle, out_file.encode(locale.getpreferredencoding()) + b'\x00', False)
    set_output_file_asm = "sub rsp, 40\nmovabs     rcx, "+str(str_addr)+"\nmovabs rax, "+str(call_tracer_dll_func['set_output_file'])+"\n\ncall rax\nadd rsp, 40\nret"
    hook_lib.inject_asm(process_handle, set_output_file_asm)
    
    
    if suspended:
        hook_lib.NtSuspendProcess(process_handle)

class PDataIndex:
    def __init__(self, pdata_functions):
        # sort once by start address
        self.pdata = sorted(pdata_functions, key=lambda e: e[0])
        self.starts = [e[0] for e in self.pdata]   # start addresses

    def get_function_containing(self, address):
        # find rightmost start <= address
        i = bisect.bisect_right(self.starts, address) - 1
        if i >= 0:
            start, end, uinfo, pord, pextra = self.pdata[i]
            if address < end:                      # inside [start, end)
                return (start, end, uinfo, pord, pextra)
        return None
        
    def find_first_func(self, address):
        i = bisect.bisect_left(self.starts, address)
        if i == len(self.starts):
            return None
        return self.starts[i]

def get_function_containing(address):
    """
    Return the (function_start_addr, function_end_addr, unwind_info_addr, pdata_ordinal)
    tuple that contains the given address, or None if not found.
    """
    return pdata_index.get_function_containing(address)

def get_cache_data(address, length):
    """
    address: target memory address
    length: number of bytes wanted
    """

    # find correct function blob via your fast function
    func_start, func_end, flags, pdata_ordinal, prolog_size = get_function_containing(address)

    # get raw bytes blob stored for that function
    blob = function_data.get(func_start)
    if blob is None:
        raise KeyError(f"No cache entry for function start {hex(func_start)}")

    # compute offset in that blob
    offset = address - func_start
    end = offset + length

    # bounds check
    if offset < 0 or end > len(blob):
        raise ValueError(
            f"Requested range {hex(address)}..{hex(address+length)} outside blob "
            f"for func {hex(func_start)} (size {len(blob)})"
        )

    # slice and return bytes
    return blob[offset:end]

    
def analyse_executable_code(process_handle):
    global disassembled_functions, function_map, functions_end, loaded_modules, calls_index, jumps_index, function_data
    disassembled_cache_file = "cache\\" + exe_basic_name + "_instructions_cache.json"
    function_data_cache_file = "cache\\" + exe_basic_name + "_function_data_cache.json"
    save_cache = False
    save_function_data_cache = False
    
    if os.path.exists(disassembled_cache_file) and time.time() - os.path.getmtime(disassembled_cache_file) < 12 * 3600:
        with open(disassembled_cache_file, "r") as f:
            loaded_json = json.load(f)
            for index in loaded_json:
                disassembled_functions[int(index)] = loaded_json[index]
    
    if os.path.exists(function_data_cache_file) and time.time() - os.path.getmtime(function_data_cache_file) < 12 * 3600:
        with open(function_data_cache_file, "r") as f:
            loaded_json = json.load(f)
            for index in loaded_json:
                function_data[int(index)] = bytes.fromhex(loaded_json[index])
    
    print("disassemble and analyse instructions", len(pdata_functions))
    
    for function_start_addr, function_end_addr, flags, pdata_ordinal, prolog_size in pdata_functions:
        function_id = get_function_id(function_start_addr)
        func_len = function_end_addr - function_start_addr
        print("disassemble:", function_id, "len:", func_len)
        
        if function_start_addr not in function_data:
            function_data[function_start_addr] = hook_lib.read(process_handle, function_start_addr, func_len)
            save_function_data_cache = True
        
        # Disassemble and patch CALL instructions in the function body
        if function_start_addr in disassembled_functions:
            instructions = disassembled_functions[function_start_addr]
        else:
            instructions = hook_lib.disasm(function_start_addr, function_data[function_start_addr])
            disassembled_functions[function_start_addr] = instructions
            save_cache = True
        prolog = []
        prolog_end = function_start_addr + prolog_size
        
        function_calls = []
        function_jumps = []
        #try to find jumps so we know what jumps backward and to some extent where
        for instruction_num, instruction in enumerate(instructions):
            instruction_asm = instruction[2]
            instruction_name = instruction_asm.split(" ")[0]
            is_jump = instruction_name.startswith("j") or instruction_name.startswith("loop")
            
            instruction_end = instruction[0] + instruction[1]
            if instruction_end <= prolog_end:
                prolog.append(instruction)
                
            is_db_inst = instruction_name == "db"
            
            is_call_inst = instruction_name == "call"
                
            indirect_memory = instruction_name != "lea" and "[" in instruction_asm
            
            found_forced_end = False
            
            if indirect_memory:
                reg, reg2, reg2_mult, indirect, offset = asm2regaddr(instruction)
                if reg is None and reg2 is None:
                    read_from = get_function_containing(offset)
                    if read_from is not None:
                        print("func:", function_id, " asm:", instruction_asm, "uses memory on code in func:", read_from, "memmory address resolves to:", offset)
                        found_forced_end = True
            
            if is_db_inst:
                print("func:", function_id, "contains data")
                found_forced_end = True
                    
            
            if found_forced_end:
                if function_start_addr not in functions_end:
                    functions_end[function_start_addr] = instruction[0]
                    break
            
            if is_jump or is_call_inst:
                
                
                reg, reg2, reg2_mult, indirect, offset = asm2regaddr(instruction)
                
                
                info = {
                    "address": instruction[0],
                    "return_address": instruction[0] + instruction[1],
                    "asm": instruction_asm,
                    "indirect": indirect,
                }
                if (reg is None or (reg is not None and reg.lower() == "rip")) and offset is not None:
                    if not indirect:
                        rip_to = offset
                        info['target'] = rip_to
                    else:
                        info['target_pointer'] = offset
                        try:
                            trg = read_ptr(process_handle, offset)
                        except:
                            trg = None
                        info['target'] = trg
                
                to_addr = None
                if reg is None and reg2 is None:
                    to_addr = offset
                    if indirect:
                        try:
                            to_addr = read_ptr(process_handle, offset)
                        except:
                            print("could not read from indirect address:", offset, "asm:", instruction_asm)
                            to_addr = None
                    
                    if to_addr is not None:
                        if is_jump:
                            if to_addr not in jumps:
                                jumps[to_addr] = []
                            jumps[to_addr].append(instruction)
                        
                        elif is_call_inst:
                            if to_addr not in calls:
                                calls[to_addr] = []
                            calls[to_addr].append(instruction)
                elif is_jump:
                    print("WARNING dynamic jump:", instruction)
                
                if is_call_inst:
                    info['call_num'] = len(function_calls)
                    function_calls.append(info)
                if is_jump:
                    info['jump_num'] = len(function_jumps)
                    function_jumps.append(info)
        
        end_addr = None
        if function_start_addr in functions_end:
            end_addr = functions_end[function_start_addr]
        
        function_map = {
            "ordinal": pdata_ordinal,
            "function_id":function_id,
            "function_start_addr": function_start_addr,
            "function_end_addr": function_end_addr,
            "function_force_end_truncate": end_addr,
            "unlisted": False,
            "flags": flags,
            "calls": function_calls
        }
        call_map.append(function_map)
    
    if save_cache:
        with open(disassembled_cache_file, "w") as f:
            json.dump(disassembled_functions, f, indent=2)
    
    if save_function_data_cache:
        with open(function_data_cache_file, "w") as f:
            func_save = {}
            for index in function_data:
                func_save[index] = function_data[index].hex()
            json.dump(func_save, f, indent=2)
    
    
    #find non listed_functions
    resolved_calls = []
    for address in calls:
        if address not in pdata_function_ids:
            resolved_calls.append(address)
    
    #reload modules incase any more has been loaded
    loaded_modules = hook_lib.enumerate_modules(process_handle, base_name = True)
    
    calls_index = list(calls.keys())
    jumps_index = list(jumps.keys())
    
    for func_addr in resolved_calls:
        classfied = None
        trunc_end = None
        mod_name, mod = get_module_from_address(func_addr)
        if mod is not None:
            
            if mod_name == exe_name:
                max_end = find_first_func(func_addr+1)
                max_mod_end = mod['base'] + mod['size']
                #exit()
                if max_end is None:
                    max_end = max_mod_end
                
                max_end = min(max_end, max_mod_end)
                size = max_end - func_addr
                #print("posible size:", size)
                if func_addr in disassembled_functions:
                    instructions = disassembled_functions[func_addr]
                else:
                    instcode = hook_lib.read(process_handle, func_addr, min(size, 512))
                    instructions = hook_lib.disasm(func_addr, instcode)
                    
                    disassembled_functions[func_addr] = instructions
                    save_cache = True
                
                print("non listed func:", func_addr, "len:", size)
                if len(instructions) > 0 and False:
                    first_instruciton = instructions[0]
                    instruction_asm = first_instruciton[2]
                    inst_name = instruction_asm.split(" ")[0]
                    if inst_name == "ret" or inst_name == "jmp":
                        classfied = "thunk"
                        max_end = first_instruciton[0] + first_instruciton[1]
                        ##this is probably a "thunk" function
                
                
                
                is_linear = True
                if classfied is None:
                    repeat_int3 = 0
                    for inst in instructions:
                        instruction_asm = inst[2]
                        inst_name = instruction_asm.split(" ")[0]
                        
                        thunk_jump = False
                        if inst_name == 'int3':
                            classfied = "probable_func_int3_terminated"
                            max_end = inst[0]
                            repeat_int3 += 1
                        else:
                            if repeat_int3 > 1:
                                break
                            repeat_int3 = 0
                        
                        #print(instruction_asm)
                        is_unconditional_jump = inst_name == 'jmp'
                        if is_linear and is_unconditional_jump:
                            classfied = "thunk"
                            max_end = inst[0] + inst[1]
                            break
                        is_jump = inst_name.startswith("j") or inst_name.startswith("loop")
                        if is_jump:
                            is_linear = False
                        
                            
                        if (is_linear and (inst_name == 'ret' or inst_name == 'int3')):
                            classfied = "mini_func"
                            max_end = inst[0] + inst[1]
                            break
                        
                        if inst_name == 'db':
                            classfied = "probable_func_db_terminated"
                            max_end = inst[0]
                            trunc_end = max_end
                            break
                
                #the disasembler stoped, this is only valid if we read the full posible size
                #if classfied is None:
                #    max_end = instructions[-1][0] + instructions[-1][0]
                
                if classfied is not None:
                    
                    thunk_jmps = []
                    #We check the sure classifications for jumps
                    if classfied == "thunk" or classfied == "mini_func":
                        for inst in instructions:
                            
                            if max_end == inst[0]:
                                break
                            
                            is_jump = inst[2].startswith("j")
                            if is_jump:
                                reg, reg2, reg2_mult, indirect, offset = asm2regaddr(inst)
                                to_addr = None
                                if reg is None and reg2 is None:
                                    to_addr = offset
                                    if indirect:
                                        try:
                                            to_addr = read_ptr(process_handle, offset)
                                        except:
                                            print("could not read from indirect address:", offset, "asm:", inst[2])
                                            to_addr = None
                                    
                                    if to_addr is not None:
                                        thunk_jmps.append(to_addr)
                                        
                                        if to_addr not in jumps:
                                            jumps[to_addr] = []
                                        jumps[to_addr].append(instruction)
                    
                    size = max_end - func_addr
                    classfied_extra_functions.append({
                        "ordinal": None,
                        "function_id": get_base_name(mod_name)+"_"+classfied,
                        "function_start_addr": func_addr,
                        "function_end_addr": max_end,
                        "function_force_end_truncate": trunc_end,
                        "unlisted": True,
                        "thunk_jumps": thunk_jmps,
                        "flags": 0,
                        "calls": []
                    })
                    print("classfied:", classfied, "size:", size)
                #print("\n")
        else:
            print("no module at addr:", func_addr)
    
    for func_desc in classfied_extra_functions:
        func_desc['ordinal'] = len(call_map)
        func_desc['function_id'] += "_unlisted_" + str(func_desc['ordinal'])
        call_map.append(func_desc)
    
    loaded_modules = hook_lib.enumerate_modules(process_handle, base_name = True)
    module_file = "output\\"+exe_basic_name+'_modules.json'
    with open(module_file, "w") as f:
        json.dump(loaded_modules, f, indent=2)
    
    map_file = "output\\"+exe_basic_name+'_map.json'
    with open(map_file, "w") as f:
        json.dump(call_map, f, indent=2)
    
    #find_first_func
    #print(prolog)#might use prolog to find end of function at some point
    
    
    

def hook_calls(process_handle) -> None:
    """Disassemble functions and patch CALLs to insert call-site tracing breakpoints."""
    global disassembled_functions, function_map, functions_end, loaded_modules, suspended
    # Cache to avoid repeated disassembly of large binaries
    
    
    
    print("instrument functions:", len(pdata_functions))
    do_init_at = 100
    #process.suspend() #FIXME we should suspend but process.suspend has a tendency to crash wen handling threads that just closed
    for function_start_addr, function_end_addr, flags, pdata_ordinal, prolog_size in pdata_functions:
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
        
        end_addr = None
        if function_start_addr in functions_end:
            end_addr = functions_end[function_start_addr]
        
        ##test dont track anythingthat contains try except as that has stack unwinding and that fails for some reason when we rewrite the code
        #if flags == 4 or flags == 1 or flags == 2 or flags == 3 or flags != 0:
        #    function_exclusions.append(pdata_ordinal)
        
        
        
        if pdata_ordinal not in function_exclusions:
            instructions = truncate_instructions(disassembled_functions[function_start_addr], end_addr)
            
            print("fixing_func:", pdata_ordinal)
            doing_calls = trace_calls
            if end_addr is not None:
                if exclude_call_tracing_in_force_truncated_functions:
                    doing_calls = False
            
            insert_break_at_calls(process_handle, instructions, function_id, function_start_addr, pdata_ordinal, doing_init, doing_calls, prolog_size)
            
            print("\n\n\n\n")
        
    
    
        
    #process.resume()
    print("inserted tracers nr of calls:", len(call_map))
    
    #save modules file again incase new modules have been loaded since last time
    loaded_modules = hook_lib.enumerate_modules(process_handle, base_name = True)
    module_file = "output\\"+exe_basic_name+'_modules.json'
    with open(module_file, "w") as f:
        json.dump(loaded_modules, f, indent=2)
    
    #Setup memmory and other stuff and hope no other hooking happens while we do that!!!!
    
    
    if not suspended: #if it was spawned it is already suspended
        hook_lib.NtSuspendProcess(process_handle)
        suspended = True
    
    print("write hooks")
    for insert_location, jmp_to_shellcode in jump_writes:
        insert_len = len(jmp_to_shellcode)
        expected_bytes = get_cache_data(insert_location, insert_len)
        actual_bytes = hook_lib.read(process_handle, insert_location, insert_len)
        if actual_bytes == expected_bytes:
            hook_lib.write(process_handle, insert_location, jmp_to_shellcode)
        else:
            print("skiping injection at addr: ", insert_location, " as the bytes have been changed meaning there is selfmodifying code doing stuff.")
    
    
    
    if suspended:
        hook_lib.NtResumeProcess(process_handle)
    print("inserted calltracing")
    

def truncate_instructions(instructions, end_addr = None):
    if end_addr is None:
        return instructions
    trunc_instructions = []
    for inst in instructions:
        if inst[0] == end_addr:
            break
        trunc_instructions.append(inst)
    return trunc_instructions

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
    belived_call_num,
    doing_calls,
    ends_with_jump = False
) -> Tuple[Optional[int], int]:
    """Patch a single instruction (typically CALL) to redirect into shellcode that wraps it with int3 breakpoints.

    Returns (jump_to_address, break_point_entry). jump_to_address is None/False on failure.
    """
    global shell_code_address_offset, shell_code_address, use_calls_for_patching, call_map

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
    rsp_return = False
    save_call_jump_ret = ""
    restore_call_jump_ret = ""
    if jump_type == "normal":
        to_address = jump_to_address
        if closer_alocation:
            to_address = closer_alocation
        asmm = f"jmp {to_address}" + (";nop" * extra_bytes)
        if use_calls_for_patching and not ends_with_jump: ##if we are moving a jump we cant use call patching as the linked_list poper wont execute
            asmm = f"call {to_address}" + (";nop" * extra_bytes)
            
            
            save_call_jump_ret = "lea rsp, [rsp-8]\n" + generate_clean_asm_func_call(strip_semicolon_comments(f"""
            add r12, {area_for_xsave64}
            mov r10, r12
add r10, {function_ordinal*8} ; This fucntion top
mov  rdx, [r15] ; New Value (the return address saved in r15 by generate_clean_asm_func_call)
call {push_value_from_linkedlist_address}
            """))+"\nlea rsp, [rsp+8]\n"
            
            restore_call_jump_ret = generate_clean_asm_func_call(strip_semicolon_comments(f"""
            add r12, {area_for_xsave64}

add r12, {function_ordinal*8}
call {pop_value_from_linkedlist_address} ;places poped value at address r15-100 which is the same as rsp-100 outside of generate_clean_asm_func_call
            """))+"\njmp [rsp-100]\n"
            
            save_ret = "lea rsp, [rsp+8]\n"
            code_a = asm(save_ret, new_instruction_address)
            code.append(code_a)
            new_instruction_address += len(code_a)
            
        jmp_to_shellcode = asm(asmm, insert_location)
    elif jump_type == "2byte":
        jmp_to_shellcode = b"\xCC" + (b"\x90" * extra_bytes)
        jump_breakpoint = insert_location
    elif jump_type == "1byte":
        jmp_to_shellcode = b"\xCC"
        jump_breakpoint = insert_location
    
    has_added_tracing = False
    do_use_trace = True
    if forbid_break_point_jumps:
        if jump_type == "2byte" or jump_type == "1byte":
            print("trace of function "+str(function_ordinal)+"  call ("+str(belived_call_num)+")/ call ignored due to needing breakpoint")
            do_use_trace = False
    
    if jump_breakpoint is not None and do_use_trace:
        jump_breakpoints.append((jump_breakpoint, jump_to_address))
        hook_lib.inject_asm(process_handle, "sub rsp, 40\nmovabs     rcx, "+str(jump_breakpoint)+"\nmovabs     rdx, "+str(jump_to_address)+"\nmovabs rax, "+str(call_tracer_thunk_func['add_jump_breakpoint'])+"\n\ncall rax\nadd rsp, 40\nret")

    
    print(jump_type,'org:', instructions_asm, "(", instructions_len, ") write:", asmm, "bytes:", len(jmp_to_shellcode), "at:", insert_location, "jump_to_address:", jump_to_address, "diff:", jump_distance)

    if is_init:
        print("we are inserting a call init capturer")
        # Tracking assembly: adds a breakpoint before and after the real function.
        # Saves the return address, modifies it to point to the post-call int3, then jumps.

        
        
        
        
        
        jump_table_address = new_instruction_address
        
        enter_asm1 = strip_semicolon_comments(f"""

mov rdx, {function_ordinal}
call {add_entry_trace_address}


"""+(f"""

;Save return addres to linked list for later retrival on function exit
; This linked list can run out of memmory then it will crash TODO think about adding a check for this
mov r10, r12
add r10, {function_ordinal*8} ; This fucntion top
mov  rdx, [r15] ; New Value (the return address saved in r15 by generate_clean_asm_func_call)
call {push_value_from_linkedlist_address}

""" if redirect_return else ""))
    
        #lol = asm(enter_asm1, jump_table_address)
    
        enter_asm = enter_asm1

        if forbid_entry_tracing:
            if save_call_jump_ret != "":
                enter_func_call_code = asm(save_call_jump_ret, jump_table_address)
            else:
                enter_func_call_code = b""
        else:
            enter_func_call_code = asm(generate_clean_asm_func_call(enter_asm)+"\n"+save_call_jump_ret, jump_table_address)
            has_added_tracing = True
        
        jump_write_address = jump_table_address + len(enter_func_call_code)
        
        
        #We redirect the return address to capture return, this is not invisible to the code so it may fail, if that is the case disable it
        #But that also means you wont be able to capture the return. You may be able to put breakpoints on all ret instructions but this will not catch tail calls.
        

        function_caller_asm = [
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
            exit_asm1 = strip_semicolon_comments(f"""
            
mov rdx, {function_ordinal}
call {add_exit_trace_address}


;Load return address from linked list
add r12, {function_ordinal*8}
call {pop_value_with_sameRSP_from_linkedlist_address} #places poped value at address r15-100

""")
        
            exit_asm = exit_asm1
            
            exit_func_call_code = asm("lea rsp, [rsp-8];"+generate_clean_asm_func_call(exit_asm), new_function_return_address)#We have just returned from a call so t onot clober the old return address that was just popped we decrement rsp by 8 before 
            final_jump_code = asm("lea rsp, [rsp+8];jmp [rsp-108]", new_function_return_address + len(exit_func_call_code))#Then we incremet by 8 after
            
            #exit_func_call_code = asm("lea rsp, [rsp-140];"+generate_clean_asm_func_call(exit_asm, extra_push=132), jump_table_address)#
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
    else:
        #for call capturing
        if save_call_jump_ret != "":
            save_retaddres_code = asm(save_call_jump_ret, new_instruction_address)
            code.append(save_retaddres_code)
            new_instruction_address += len(save_retaddres_code)

    func_desc = call_map[function_ordinal]
    
    for instruciton_dat in instructions:
        instruction_address = instruciton_dat[0]
        instruction_len = instruciton_dat[1]
        instruction_asm = capstone_2_keystone(instruciton_dat[2])
        instruction_parts = instruction_asm.split(" ")
        
        call_num = -1
        static_call = False
        
        rip_to = None
        contains_rip = False
        if "rip" in instruction_asm:
            contains_rip = True
        
        trace_this_call = True
        if not doing_calls:
            trace_this_call = False
        
        if instruction_parts[0] == "call":
            reg, reg2, reg2_mult, indirect, offset = asm2regaddr(instruciton_dat)
            
            call_has_known_target = True
            for call in func_desc['calls']:
                if call['address'] == instruction_address:
                    call_num = call['call_num']
                    if 'target' not in call:
                        call_has_known_target = False
                    break;
       
            if only_trace_unknown_calls:
                
                if call_has_known_target:
                    trace_this_call = False
        
            if call_num in excluded_calls:
                trace_this_call = False
        
        if instruction_parts[0] == "call" and trace_this_call:
            
            
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
            print("\ncall info:", function_ordinal, "nr:", call_num, "asm:", instruction_asm, "resolver:", target_resolver, "reg dat:", reg, reg2, reg2_mult, indirect, offset, reg_to_use, "new_addr:", new_instruction_address, "old_addr:", instruction_address)
            
            
            
            save_target_asm = (
                f"mov [rsp-{rsp_ofset}], {reg_to_use} \n" #Save r9
                f"{target_resolver}\n" #fill r9 with target address # {target_resolver}
                f"mov [rsp-8], {reg_to_use}\n" #save r9 in the space where the return address will be filled in
                f"mov {reg_to_use}, [rsp-{rsp_ofset}]\n" #restore r9
            )
            
            
            
            call_asm = strip_semicolon_comments(f"""
mov rdx, {function_ordinal}
mov rdi, {call_num}
call {add_call_trace_address}

            """)
            
            
            
            
            call_func_call_code = asm(save_target_asm + generate_clean_asm_func_call(call_asm), new_instruction_address)
            
            has_added_tracing = True
            code.append(call_func_call_code)
            new_instruction_address += len(call_func_call_code)
            
        
            if reg is None and offset is not None:
                static_call = offset
                # RIP-relative handling
                
            
            
        
        else: #Not a call
            pass
        
        # RIP-relative handling 
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
                do_use_trace = False
                raise Exception("altering: "+instruction_asm + "new offset "+str(instruct_off)+" to large")
            
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


        if instruction_parts[0] == "call" and trace_this_call:
            #We prevoisly filled rsp-8 with the target address
            
            jump_diretly_back = False ##only works if the call is the last moved instruction
            if jump_diretly_back:
                call_asm = (
                    f"mov [rsp-{rsp_ofset}], rax\n" #save rax
                    "mov rax, [rsp-8]\n" #fill rax with target address 
                    f"mov [rsp-{rsp_ofset+8}], rax\n" #save target address in memmory
                    f"movabs rax, {jump_back_address}\n" # fill rax with return address
                    "mov [rsp-8], rax\n" #fill return addres
                    f"mov rax, [rsp-{rsp_ofset}]\n" #restore rax
                    "lea rsp, [rsp-8]\n" # add to rsp to emulate push
                    f"jmp [rsp-{rsp_ofset}]\n" # jump to target address now at a difrent relative ofset as we modifed rsp
                    
                )
                new_code = asm(call_asm, new_instruction_address)#Luckily this reads the target adress from [rsp-8] before it writes the return address to it
            else:
                new_code = asm("call [rsp-8]", new_instruction_address)# this reads the target adress from [rsp-8] (where the call tracer placed it) before it writes the return address to it
                
            code.append(new_code)
            new_instruction_address += len(new_code)
            
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
            if trace_this_call:
                
                call_asm = strip_semicolon_comments(f"""
                
mov rdx, {function_ordinal}
mov rdi, {call_num}
call {add_called_trace_address}

                """)
                
                call_func_called_code = asm(generate_clean_asm_func_call(call_asm), new_instruction_address)
                #call_func_called_code = b""
                
                code.append(call_func_called_code)
                new_instruction_address += len(call_func_called_code)
                
            
            
        
        moved_instructions[instruction_address] = (new_start_address, new_instruction_address)
        
    last_jump_asm = f"jmp [RIP]"
    
    if restore_call_jump_ret != "":
        last_jump_asm =  restore_call_jump_ret#jump to return address
    
    new_code = asm(last_jump_asm, new_instruction_address)
    if restore_call_jump_ret == "":
        new_code += struct.pack("<Q", jump_back_address)
    
    code.append(new_code)
    new_instruction_address += len(new_code)

    shellcode = b"".join(code)
    shell_len = len(shellcode)

    if do_use_trace and (has_added_tracing or force_all_detours):
        ass = ""
        for inst in instructions:
            ass += str(inst[2]) + ";"
        print("REPLACING:", len(instructions), ass)
        shell_code_address_offset += shell_len + 20
        hook_lib.write(process_handle, jump_to_address, shellcode, do_checks = False)
        jump_writes.append((insert_location, jmp_to_shellcode))
    



def find_jumps_to_address(address):
    """
    Return a list of all (offset, instruction) tuples where offset == address.
    """
    ret = []
    if address in jumps:
        ret += jumps[address]
        
    if address in calls:
        ret += calls[address]
        
    return ret

def find_first_func(address):
    """
    Find the next address >= 'address' that is the start of a known function.
    Checks:
      - pdata_functions (function_start_addr)
      - call targets
      - jump targets
    Returns the smallest such address, or None if none exist above the given address.
    """
    candidates = []
    
    first_func = pdata_index.find_first_func(address)
    if first_func is not None:
        candidates.append(first_func)

    i = bisect.bisect_left(jumps_index, address)
    if i != len(jumps_index):
        candidates.append(jumps_index[i])

    i = bisect.bisect_left(calls_index, address)
    if i != len(calls_index):
        candidates.append(calls_index[i])
    
    if len(candidates) == 0:
        return None
    return min(candidates)


def insert_break_at_calls(process_handle, instructions: List[Tuple[int, int, str, str]], function_id: str, function_address: int, function_ordinal: int, do_init: bool, doing_calls: bool, prolog_size: int) -> None:
    """Insert breakpoints at every CALL within a function's instruction list."""
    global shell_code_address_offset
    
    func_id = get_function_id(function_address)
    
    #if function_address in (140697845009392,140697847417424 ):
    #    print("skip instrumenting function:", function_address, func_id)
    #    return
    print("instrumenting:", function_address, func_id)
    belived_call_num = None
    init_free_space = 0
    doing_init = do_init
    
    
    
    init_instructions = []
    call_replace_instructions = []
    num_instructions = len(instructions)
    for instruction_num, instruction in enumerate(instructions):
        instruction_name = instruction[2].split(" ")[0]
        instruction_address = instruction[0]
        instruction_len = instruction[1]
        
        is_jump = instruction_name.startswith("j") or instruction_name.startswith("loop") or instruction_name == "ret"
        
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
            
            #loop and jrcxz instructions are short max 127 bytes so cant be moved
            if instruction_name.startswith("loop") or instruction_name == "jrcxz" or instruction_name == "jecxz" or instruction_name == "jcxz":
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
                    
            if respect_prolog_size:
                if prolog_size < init_free_space + instruction_len:
                    
                    if len(init_instructions) > 0:#If we dont have any prolog bytes we replace THE FIRST instruction anyway
                        use_instruction = False
                    do_relocation = True
            
            if use_instruction:
                init_free_space += instruction_len
                init_instructions.append(instruction)
            
            if num_instructions-1 == instruction_num:#we are at the final instruction, it is now or never
                do_relocation = True
            
            #do_relocation = True #If something jumps in to one of the first few instructions uncomment this
            
            if is_jump: #jumps cant be relocated unless they are the final instruction
                do_relocation = True
            #    doing_init = False # Test without jumps
            
            #if "rip" in instruction[2]:
            #    doing_init = False # Test without things that contain RIP
            
            if only_replace_single_instruction_init:
                if init_free_space > 0:#Issue here if the next instrcution is a call we could pick it up and stuff would be alot easier
                    do_relocation = True
            
            
            #if instruction_name == "cmp":
            #    doing_init = False # Test without things that are calls
            
            if init_free_space >= 5:#Issue here if the next instrcution is a call we could pick it up and stuff would be alot easier
                do_relocation = True
            
            if do_relocation and doing_init:
                
                doing_init = False
                print("relocating_init: ", init_instructions, "cur instruciton:", instruction[2])
                add_instruction_redirect(
                    function_ordinal,
                    function_address,
                    True,
                    init_instructions,
                    process_handle,
                    belived_call_num,
                    doing_calls,
                    ends_with_jump = is_jump
                )
        else:
            call_replace_instructions.append(instruction)
            if instruction_name == "call" and doing_calls:
                
                func_desc = call_map[function_ordinal]
                call_has_known_target = True
                for call in func_desc['calls']:
                    if call['address'] == instruction_address:
                        belived_call_num = call['call_num']
                        if 'target' not in call:
                            call_has_known_target = False
                        break;
                
                trace_this_call = True
                if only_trace_unknown_calls:
                    if call_has_known_target:
                        trace_this_call = False
                search_call = True
                
                if not trace_this_call:
                    search_call = False
                    call_replace_instructions = []
        
        if search_call and doing_calls:
            
            replace_instructions = []
            free_space = 0
            for inst in reversed(call_replace_instructions):
                inst_name = inst[2].split(" ")[0]
                
                if inst_name == 'db' or inst_name.startswith("loop") or instruction_name == "jrcxz" or instruction_name == "jecxz" or instruction_name == "jcxz":#we cant move db stuff we have no idea what they are and we cant move loops or the other jmp instructions as they can only jmp 127 bytes(i guesss we could implment them as "dec rcx jnz .loop")
                    break
                if len(replace_instructions) == 1:#If the instruction preceding a call is a jump or ret the call will never get traced something if of
                    if inst_name == 'ret' or inst_name == "jmp":
                        break
                free_space += inst[1]
                replace_instructions.append(inst)
                
                jump_instructions = find_jumps_to_address(inst[0])
                if len(jump_instructions) != 0:# we cant move instructions that are jumped to unless it is the first moved instruciton
                    break
                if only_allow_single_instruction_replacements:
                    break
                if free_space >= 5:
                    break
            call_replace_instructions = []
            replace_instructions = list(reversed(replace_instructions))
            
            
            add_instruction_redirect(
                function_ordinal,
                function_address,
                False,
                replace_instructions,
                process_handle,
                belived_call_num,
                doing_calls
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

    mod_name, module = get_module_from_address(function_addr)
    module_offset = function_addr - module['base']
    func_id = str(mod_name) + "+" + str(module_offset)
    return func_id


def get_module_from_address(address: int) -> Optional[str]:
    """Return module basename containing the given address by highest base <= address."""


    for mod in loaded_modules:
        module = loaded_modules[mod]
        if module['base'] <= address <= module['base'] + module['size']:
            return mod, module
    
    return None, None
    
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
    # preserves newlines, removes ';' comments + space before them
    return _strip_semicolon_comments.sub('', asm)
    
def generate_clean_asm_func_call(code, in_two_parts = False, debug = False):
    global register_save_address, thread_storage_list_address
    
    
    
    
    assembly1 = f"\nlea rsp, [rsp-{rsp_ofset}]\ncall " + str(save_state_address) + "\n\n" + code.replace(";", "\n") +"\n"
    if debug:
        assembly1 = f"\nlea rsp, [rsp-{rsp_ofset}]\ncall " + str(debug_func_address) + "\n\n" + code.replace(";", "\n") +"\n"
        raise Exception("debug not implemented")
    
    
    assembly2 = "call " + str(restore_state_address) + "\n"
    if in_two_parts:
        return assembly1, assembly2
    return assembly1 + assembly2

# -----------------------------
# DLL injection helpers
# -----------------------------

def run_loadlibrary_in_process(h_process: int, dll_path: str) -> None:
    """Write dll_path to target and call LoadLibraryA via injected assembly."""
    global load_dll_tid, suspended
    dll_path = os.path.abspath(dll_path)
    print("trying to inject dll")
    
    basename = os.path.basename(dll_path)
    
    #We need to unsuspend the proccess since there is some type of lock stoping the loading when not in suspended mode We just have to hope that other hooks dont have time to run
    if suspended:
        hook_lib.NtResumeProcess(h_process)
    print("unsuspend to inject")

    thread = hook_lib.load_library_in_remote(h_process, dll_path)
    
    # wait untill dll is properly loaded
    while True:
        try:
            mods = hook_lib.enumerate_modules(h_process, base_name = True)
            if basename in mods:
                break
        except:
            raise Exception("enumerate_modules failed when wating for dll to load")
    
    print("suspend again")
    if suspended:
        hook_lib.NtSuspendProcess(h_process)
    
def fixup_calltrace_exports(handle):
    global call_tracer_dll_func
    dll_name = "calltracer.dll"
    basename = os.path.basename(dll_name)
    mods = hook_lib.enumerate_modules(handle, base_name = True)
    if basename in mods:
        base_addr = mods[basename]["base"]
        for name in call_tracer_dll_func:
            call_tracer_dll_func[name] += base_addr
    else:
        raise Exception("calltracer dll not loaded")
def fixup_calltrace_exports_thunks(handle):
    global call_tracer_dll_func, call_tracer_thunk_ready_addr
    
    
    for name in call_tracer_dll_func:
        jumpaddr_bytes = struct.pack("<Q", call_tracer_dll_func[name])
        #Fill in thunk addrs jump address
        hook_lib.write(handle, call_tracer_thunk_func_ptr[name], jumpaddr_bytes, do_checks = False)
        
    hook_lib.write(handle, call_tracer_thunk_ready_addr, bytes([1]), do_checks = False)

def lookup_calltrace_exports():
    global call_tracer_dll_func
    dll_name = "calltracer.dll"
    pe = pefile.PE(dll_name)
    

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                name = exp.name.decode()
                rva = exp.address
                call_tracer_dll_func[name] = rva
            else:
                print("No export table found.")
        
    else:
        raise Exception("dll has no exports")
    
    
    
def get_pdata(file_name: str, base_addr: int, exe_basic_name: str) -> None:
    """Parse .pdata from file on disk and populate function ranges & IDs."""
    global pdata, pdata_functions, exe_entry_address, pdata_function_ids, area_for_function_table, pdata_index

    
    functions: List[Tuple[int, int, int, int]] = []
    
    pe_info = pefile.PE(name=file_name, fast_load=True)#cant load from memmory as the important headers are not loaded into memmory
    exe_entry_address = pe_info.OPTIONAL_HEADER.AddressOfEntryPoint + base_addr
    
    pe_info.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'], pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']])
    
    i = 0
    for rf in pe_info.DIRECTORY_ENTRY_EXCEPTION:
        #print(rf.struct.BeginAddress, rf.struct.EndAddress, rf.unwindinfo.Flags, rf.unwindinfo.SizeOfProlog, dir(rf.unwindinfo))
        start_addr = rf.struct.BeginAddress + base_addr
        end_addr = rf.struct.EndAddress + base_addr
        functions.append((start_addr, end_addr, int(rf.unwindinfo.Flags), i, int(rf.unwindinfo.SizeOfProlog)))
        pdata_function_ids[start_addr] = exe_basic_name + "_" + str(i)
        i += 1
    
    if area_for_function_table is None:
        nr_of_functions = len(functions)
        area_for_function_table = (nr_of_functions+1)*8#(we add  one just in case i dont remember if ordinal was zero or one indexed)
    pdata_functions = functions
    pdata_index = PDataIndex(pdata_functions)



# -----------------------------
# Entrypoint
# -----------------------------
if __name__ == "__main__":
    # If a process is already running we attach; otherwise we create it.
    start_or_attach(sys.argv[1:])
