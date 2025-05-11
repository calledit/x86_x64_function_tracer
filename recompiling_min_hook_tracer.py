#!/bin/env python

from winappdbg import Debug, HexDump, win32, System
from functools import partial
import binascii
from winappdbg import CrashDump
import pdb
import os
import struct
from pdbparse.symlookup import Lookup
from pdbparse.undecorate import undecorate
from pdbparse.undname import undname
import pefile
import json
import time
from dataclasses import dataclass
from keystone import Ks, KS_ARCH_X86, KS_MODE_64


import ctypes
import ctypes.wintypes as wintypes


# Initialize Keystone for x64.
ks = Ks(KS_ARCH_X86, KS_MODE_64)

# Load the dbghelp.dll
dbghelp = ctypes.WinDLL("Dbghelp.dll")


# Define the function prototype for UnDecorateSymbolName
UnDecorateSymbolName = dbghelp.UnDecorateSymbolName
UnDecorateSymbolName.argtypes = [
    ctypes.c_char_p,  # Pointer to the decorated symbol (input)
    ctypes.c_char_p,  # Pointer to the buffer for the undecorated name (output)
    ctypes.c_uint,    # Size of the output buffer
    ctypes.c_uint     # Flags controlling the undecoration (0 for default behavior)
]
UnDecorateSymbolName.restype = ctypes.c_uint

def undecorate_symbol(mangled_name, flags=0):
    # Create a buffer for the undecorated name (adjust size if necessary)
    buffer = ctypes.create_string_buffer(2024)
    # Call the function
    result = UnDecorateSymbolName(mangled_name.encode('utf-8'), buffer, ctypes.sizeof(buffer), flags)
    if result:
        return buffer.value.decode('utf-8')
    else:
        return None


threds = {}

jumps = [
    "call",
    "ret",
    "jmp",
]



executable_memmory = {}
executable_memmory_ids = {}

COde_started = False;

pdbs = {}
pdb_names = {}
desc_cahce = {}
breaks = {}
modules = {}

def get_base_name(filename):
    dname = filename.split('\\')[-1]
    basic_name = dname.split('.')[0].lower()
    return basic_name

def get_module_from_address(address):
    found_module = None
    found_base = -1

    # Find the module with the highest base that is less than or equal to the address.
    for module, base in modules.items():
        if base <= address and base > found_base:
            found_module = module
            found_base = base

    return found_module

def get_executable_region_from_address(address):
    for start, length in executable_memmory.items():
        if start <= address < start + length:
            return (start, length)

    return None, None

def find_pdata_function(address):
    """
    Given an address and a list of function info tuples,
    each tuple being (start_addr, end_addr, unwind_info_addr),
    returns the tuple for the function that contains the address.

    If the address does not fall within any function range, returns None.
    """
    for func in pdata_functions:
        start_addr, end_addr, unwind_info_addr = func
        if start_addr <= address < end_addr:
            return func[0]
    return None

def f_id(str):
    data = str.encode('utf-8')
    crc_value = binascii.crc32(data) & 0xffffffff
    return ("{:08X}".format(crc_value))

def on_shell_enter(event):

    thread = event.get_thread()
    context = thread.get_context()

    print("enterd shell code")
    pdb.set_trace()
    exit(0)

def asm(CODE, address = 0):
    encoding, count = ks.asm(CODE, address)
    return bytes(encoding)

def run_func_hook_in_process(h_process, process, func_addr, pTarget, pDetour):
    """
    Calls func_hook(pTarget, pDetour, &original) in the remote process at `func_addr`,
    and returns the value written into `original`.

    - h_process: HANDLE to the target process
    - process:  object with .read(addr, size) and .write(addr, bytes) methods
    - func_addr: absolute address of your func_hook in the remote process
    - pTarget, pDetour: LPVOIDs in the remote process
    """
    ptr_size = ctypes.sizeof(ctypes.c_void_p)

    # 1) Build the x64 stub (must be executable)
    #    stub(rcx)-> rax=rcx; rcx=[rax]; rdx=[rax+8]; r8=[rax+16]; mov rax,func; call rax; ret
    stub = bytearray()
    stub += b'\x48\x89\xc8'                         # mov rax, rcx
    stub += b'\x48\x8b\x08'                         # mov rcx, [rax]
    stub += b'\x48\x8b\x50\x08'                     # mov rdx, [rax+8]
    stub += b'\x4d\x8b\x40\x10'                     # mov r8,  [rax+16]
    stub += b'\x48\xb8' + ctypes.c_uint64(func_addr).value.to_bytes(8, 'little')
    stub += b'\xff\xd0'                             # call rax
    stub += b'\xc3'                                 # ret
    stub_size = len(stub)

    # 2) Compute total size: stub + 4 pointers (pTarget, pDetour, ppOriginal_ptr, original_storage)
    data_size = ptr_size * 4
    total_size = stub_size + data_size

    # 3) Allocate one block for both code+data
    ctypes.windll.kernel32.VirtualAllocEx.restype = wintypes.LPVOID
    remote_block = ctypes.windll.kernel32.VirtualAllocEx(
        h_process, None, total_size,
        0x3000,
        0x40
    )
    if not remote_block:
        raise ctypes.WinError()

    # 4) Write stub at start of block
    process.write(remote_block, bytes(stub))

    # 5) Prepare the data area:
    #    offset = remote_block + stub_size
    data_base = remote_block + stub_size
    #    slot0 = pTarget
    #    slot1 = pDetour
    #    slot2 = pointer to slot3  (i.e. data_base + 3*ptr_size)
    #    slot3 = 0 (where hook will write original)
    slot3_addr = data_base + 3 * ptr_size
    buf = (
        ctypes.c_uint64(pTarget).value.to_bytes(ptr_size, 'little') +
        ctypes.c_uint64(pDetour).value.to_bytes(ptr_size, 'little') +
        ctypes.c_uint64(slot3_addr).value.to_bytes(ptr_size, 'little') +
        (0).to_bytes(ptr_size, 'little')
    )
    process.write(data_base, buf)

    # 6) Launch the stub—passing `data_base` as the single LPVOID
    thread_id = ctypes.c_ulong(0)
    h_thread = ctypes.windll.kernel32.CreateRemoteThread(
        h_process, None, 0,
        ctypes.c_void_p(remote_block),      # stub entrypoint
        ctypes.c_void_p(data_base),         # rcx for stub
        0,
        ctypes.byref(thread_id)
    )
    if not h_thread:
        raise ctypes.WinError()

    # 7) Wait for it to finish ####XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX will fail as the process i paused due to the debugger
    ctypes.windll.kernel32.WaitForSingleObject(h_thread, 0xFFFFFFFF)
    ctypes.windll.kernel32.CloseHandle(h_thread)

    # 8) Read back the original-pointer value from slot3
    data = process.read(slot3_addr, ptr_size)
    original = int.from_bytes(data, 'little')
    return original

def loaded_dll(dll_name, event):
    print("Loaded dll")

    thread = event.get_thread()
    context = thread.get_context()
    base_addr = context['Rax']
    if base_addr != 0:
        basename = os.path.basename(dll_name)
        basic_name, ext = os.path.splitext(basename)
        modules[basic_name] = base_addr

        if basic_name == "calltracer" and len(dll_func) == 0:
            pe = pefile.PE(dll_name)

            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        name = exp.name.decode()
                        rva = exp.address
                        virtual_address = base_addr + rva
                        #print(f"{name} virtual_address: 0x{virtual_address:X}")
                        dll_func[name] = virtual_address
                        #if name == "print_text":
                        #    asemb = f"movabs rax, 0x{virtual_address:016X};call rax"
                        #    code_to_run.append((asemb, test_called_function))
                        #    process_handle = process.get_handle()
                        #    run_func_hook_in_process(process_handle, process, virtual_address, base_addr, base_addr+50)
                        #    process.close_handle()
                    else:
                        print("No export table found.")
                hook_functions()
    else:
        print("failed to load dll:", dll_name)
        exit()

ret_replacements = {}
def min_hooked_entry_hook(ujump_table_address, callback, event):
    if ujump_table_address not in ret_replacements:
        ret_replacements[ujump_table_address] = []

    thread = event.get_thread()
    process = event.get_process()
    context = thread.get_context()
    stack_pointer = context['Rsp']
    return_address = read_ptr(process, stack_pointer)

    ret_replacements[ujump_table_address].append(return_address)
    print("min_hooked_entry_hook", ujump_table_address, "table:", ret_replacements[ujump_table_address])
    callback(event)

def min_hooked_exit_hook(ujump_table_address, callback, event):
    original_return_address = ret_replacements[ujump_table_address].pop()
    print("min_hooked_exit_hook", original_return_address)
    event.get_thread().set_pc(original_return_address)
    callback(event)

def min_hooked_function(jump_table_address, enter_callback, exit_callback, event):
    global remote_memory

    thread = event.get_thread()
    context = thread.get_context()
    result = context['Rax']

    if result != 0:
        print("failed to hook function:", jump_table_address)
        exit()


    process = event.get_process()
    address_to_trampoline = process.read(remote_memory, 8)
    address_to_trampoline = struct.unpack("<Q", address_to_trampoline)[0]
    print("min_hooked_function:", result, "addr:", address_to_trampoline)

    second_interupt = jump_table_address + (24 - 2)
    #This is the tracking asembly, it adds a braek point before and after jumping to the function.
    #It achives this by saving the return addres, then modifiying it, then when the funtion is done jumping to
    #the saved return address.
    asmm = f"int 3;push rax;mov rax, [RIP + 22];mov [RSP+0x8], rax;pop rax;jmp [RIP + 0x2];int 3"
    jump_code = asm(asmm, jump_table_address) + struct.pack("<Q", address_to_trampoline) + struct.pack("<Q", second_interupt)

    external_breakpoints[jump_table_address+2] = part = partial(min_hooked_entry_hook, jump_table_address, enter_callback)

    external_breakpoints[second_interupt+2] = partial(min_hooked_exit_hook, jump_table_address, exit_callback)
    process.write(jump_table_address, jump_code)

def min_hook_enabled(event):
    thread = event.get_thread()
    context = thread.get_context()
    result = context['Rax']

    print("min_hook_enabled:", result)

def hook_functions():
    global remote_memory, shell_code_address, shell_code_address_ofset

    hook_function = dll_func['hook_function']
    enable_function = dll_func['enable_hooks']
    for target_fn_addr, enter_callback, exit_callback in functions_to_hook:
        print("hook", target_fn_addr, "using:", dll_func['hook_function'])

        jump_table_address = shell_code_address + shell_code_address_ofset

        shell_code_address_ofset += 50 # 100 bytes might be enogh

        code_to_run.append((f"mov rcx, 0x{target_fn_addr:016X};mov rdx, 0x{jump_table_address:016X};mov r8, 0x{remote_memory:016X};mov rax, 0x{hook_function:016X};call rax", partial(min_hooked_function, jump_
table_address, enter_callback, exit_callback)))

    #Enable hooks
    code_to_run.append((f"sub rsp, 0x28;mov rax, 0x{enable_function:016X};call rax;add rsp, 0x28;", min_hook_enabled))

def run_loadlibrary_in_process(h_process, process, dll_path):
    global remote_memory, shell_code_address, shell_code_address_ofset
    # Open the target process with required access rights
    #h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    #if not h_process:
    #    raise Exception("Failed to open target process: {}".format(ctypes.WinError()))

    # Prepare the DLL path as a null-terminated byte string
    dll_path_bytes = dll_path.encode('ascii') + b'\x00'

    # Allocate memory in the target process for the DLL path
    ctypes.windll.kernel32.VirtualAllocEx.restype = ctypes.c_ulonglong
    remote_memory = ctypes.windll.kernel32.VirtualAllocEx(h_process, None, 1000, 0x3000, 0x04)
    if not remote_memory:
        raise Exception("Failed to allocate memory in target process: {}".format(ctypes.WinError()))

    # Write the DLL path into the allocated memory in the target process
    process.write(remote_memory, dll_path_bytes)

    kernel32 = process.get_module_by_name('kernel32.dll')

    load_library_addr = kernel32.resolve('LoadLibraryA')

    print("load_library_addr:", load_library_addr)

    code_to_run.append((f"sub rsp, 0x20;mov rcx, 0x{remote_memory:016X};mov rax, 0x{load_library_addr:016X};call rax;add rsp, 0x20", partial(loaded_dll, dll_path)))


    # Create a remote thread in the target process that calls LoadLibraryA with our DLL path
    #thread_id = ctypes.c_ulong(0)
    #h_thread = ctypes.windll.kernel32.CreateRemoteThread(h_process, None, 0, load_library_addr, remote_memory, 0, ctypes.byref(thread_id))
    #if not h_thread:
    #    raise Exception("Failed to create remote thread: {}".format(ctypes.WinError()))

    # Optionally, wait for the remote thread to finish
    #ctypes.windll.kernel32.WaitForSingleObject(h_thread, 0xFFFFFFFF)

    # Clean up handles
    #ctypes.windll.kernel32.CloseHandle(h_thread)
    #kernel32.CloseHandle(h_process)

    return True


def go_jump_breakpoint(jump_to_adddress, callback, event):
    event.get_thread().set_pc(jump_to_adddress)
    #print("special jump:", jump_to_adddress)
    callback(event)


shell_code_address_ofset = 20 #We start at 20 for no particular reason, might be good to have free space...
def add_jump_table_entry(instruction_address_not_used, instructions, process, callback):
    global shell_code_address, shell_code_address_ofset

    asmembly = []
    code = []
    jump_to_address = shell_code_address + shell_code_address_ofset
    jump_back_address = None
    new_instruction_address = jump_to_address

    break_point_entry = -1


    for instruction in instructions:
        instruction_address = instruction[0]
        instruction_len = instruction[1]
        jump_back_address = instruction_address + instruction_len


        instruction_asm = instruction[2]
        instruction_parts = instruction_asm.split(' ')
        instruction_raw_bytes = bytes.fromhex(instruction[3])


        insert_len = 0
        jump_type = 'none'
        if instruction_len >= 5:
            insert_len = 5
            jump_type = 'normal'

            #Add break point for tracking
            new_code = b'\xCC'
            code.append(new_code)
            new_instruction_address += len(new_code)
            break_point_entry = new_instruction_address

        elif instruction_len >= 2 and instruction_parts[0] in ("call"):
            insert_len = 1
            jump_type = 'call'
        else:
            insert_len = 1
            jump_type = '1byte'

        extra_bytes = max(instruction_len - insert_len, 0)
        jmp_to_shellcode = None
        asmm = False
        if jump_type == 'normal':
            asmm = f"jmp 0x{jump_to_address:x}"+(";nop"*extra_bytes)
        elif jump_type == 'call':
            jmp_to_shellcode = b'\xCC'+(b'\x90'*extra_bytes)
            break_point_entry = instruction_address + 1
        elif jump_type == '1byte':
            jmp_to_shellcode = b'\xCC'
            break_point_entry = instruction_address + 1



        is_jump = instruction_asm.startswith('j')

        call_relocate = False

        if "rip +" in instruction_asm or "rip -" in instruction_asm:
            print("Acounting for alterd rip", instruction_asm)
            diff = new_instruction_address - instruction[0]
            rip_address = f"rip - 0x{(diff & 0xffffffff):x}"
            instruction_asm = instruction_asm.replace("rip", rip_address)
        elif "rip" in instruction_asm:
            print("If something saves or does something with rip directly we cant move the instruction")
            return False, break_point_entry


        if instruction_parts[0] in ("call", "jmp"):

            #Recomplie jmps and calls
            if len(instruction_parts) == 2 and instruction_parts[1].startswith('0x'):
                #since the asembly uses absolute addresses we dont need to change anything
                print ("static call/jmp")
                if instruction_parts[0] == 'call':
                    call_relocate = True

                #original_jump = int(instruction_parts[1], 16)
                #print("before:", instruction_asm)
                #instruction_asm = instruction_parts[0]+" "+f"0x{(original_jump):x}"
            else:
                print ("dynamic call/jmp")
                if instruction_parts[0] == 'call':
                    call_relocate = True
                #print("call may be relative and it may not, it depends on the type", instruction_asm)
                #return False, break_point_entry
        elif is_jump:
            print("strange jumping will fail", instruction_asm)
            return False, break_point_entry
        elif instruction_parts[0] in ("cmp"):
            print("non movable instruction", instruction_asm)
            return False, break_point_entry

        if asmm or jmp_to_shellcode:
            if jmp_to_shellcode is None:
                jmp_to_shellcode = asm(asmm, instruction_address)
            print("write:", asmm, "len:", len(jmp_to_shellcode), "at:", instruction_address)
            process.write(instruction_address, jmp_to_shellcode)
            #We add a callback to the breakpoint. That was coded in to the jump table.
            if jump_type == 'normal':
                external_breakpoints[break_point_entry] = callback
            else:
                external_breakpoints[break_point_entry] = partial(go_jump_breakpoint, jump_to_address, callback)
        else:
            return False, break_point_entry


        new_code = asm(instruction_asm, new_instruction_address)
        code.append(new_code)
        new_instruction_address += len(new_code)

        if call_relocate:
            call_relocations[jump_back_address] = new_instruction_address

        break #only check first instruciton


    #displacement = jump_back_address - new_instruction_address
    instruction_asm = f"jmp 0x{jump_back_address:x}"
    print("last_jump asm:", instruction_asm)
    new_code = asm(instruction_asm, new_instruction_address)
    code.append(new_code)
    new_instruction_address += len(new_code)

    code = b''.join(code)

    shellcode = code

    #print("shellcode:", shellcode)

    shell_len = len(shellcode)


    shell_code_address_ofset += shell_len + 20
    process.write(jump_to_address, shellcode)







    return jump_to_address, break_point_entry

def deal_with_injection_callaback(callback, save_place, event):
    global is_in_injecetd_code
    del external_breakpoints[save_place]
    callback(event)
    is_in_injecetd_code = False

is_in_injecetd_code = False
code_injection_address = None
register_save_address = None
def inject_asembly(process,  code, return_address, code_done_callback = None):
    save_place = code_injection_address
    asmembly1 = f"""
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
    {code}"""

    if code_done_callback is not None:
        asmembly1 += ';int 3;'
    else:
        exit("Not implemented, you need to speficy a callback so we can know when we are out of the injecetd code and set is_in_injecetd_code = False")
        #To fix we need to use multiple save addresses and code injection addresses

    print(asmembly1)
    shellcode1 = asm(asmembly1, save_place)

    save_place += len(shellcode1)
    if code_done_callback is not None:
        external_breakpoints[save_place] = partial(deal_with_injection_callaback, code_done_callback, save_place)

    asmembly2 = f"""
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
    print(asmembly2)
    shellcode2 = asm(asmembly2, save_place) + struct.pack("<Q", return_address)

    shellcode = shellcode1 + shellcode2

    process.write(code_injection_address, shellcode)
    return code_injection_address

def test_called_function(event):
    print("executed injected code")
    #exit(0)


dll_func = {}
hProcess = None
external_breakpoints = {}
code_to_run = []
functions_to_hook = []
call_relocations = {}
call_stack = {}
last_function = {}
pdata_function_ids = {}
shell_code_address = None
process_handle = None
Initiating = True
add_dll = True
exe_basic_name = None
def my_event_handler( event ):
    global add_dll, COde_started, hProcess, shell_code_address, exe_basic_name, process_handle, register_save_address, code_injection_address, is_in_injecetd_code, Initiating

    # Get the process ID where the event occured.
    pid = event.get_pid()

    # Get the thread ID where the event occured.
    tid = event.get_tid()

    process = event.get_process()

    # Find out if it's a 32 or 64 bit process.
    bits = process.get_bits()

    # Get the value of EIP at the thread.
    address = event.get_thread().get_pc()

    #print(address, entry_address)

    # Get the event name.
    name = event.get_event_name()

    # Get the event code.
    code = event.get_event_code()

    filename = ""



    # If the event is an exception...
    if code == win32.EXCEPTION_DEBUG_EVENT:

        # Get the exception user-friendly description.
        name = event.get_exception_description()

        # Get the exception code.
        code = event.get_exception_code()


        if name == "Breakpoint":

            inject_ok = False
            if address in external_breakpoints or (Initiating and address == entry_address):
                inject_ok = True
                #if Initiating:
                #    event.debug.stalk_at(pid, entry_address)

            #print("Info:", Initiating, inject_ok, is_in_injecetd_code, address)
            if len(code_to_run) != 0 and not is_in_injecetd_code and inject_ok:
                #if Initiating:
                #    event.debug.dont_stalk_at(pid, entry_address)
                asmd, code_done_callback = code_to_run.pop(0)
                break_point_location = address # minus one if own breakpoint just address if winappdbgs breakpoint
                if address != entry_address:
                    break_point_location -= 1
                code_address = inject_asembly(process, asmd, break_point_location, code_done_callback)
                print("injected assembly:", asmd, "jump back to addres:", break_point_location)
                is_in_injecetd_code = True
                event.debug.dont_break_at(pid, entry_address) #disable breakpoint so it is not copied
                event.get_thread().set_pc(code_address)
                #if Initiating:
                #    event.debug.stalk_at(pid, entry_address)
                return

            if Initiating and is_in_injecetd_code:
                event.debug.break_at(pid, entry_address)#enable breakpoint after removing it to mitigate copying of it

            if len(code_to_run) == 0 and Initiating and not is_in_injecetd_code and inject_ok:
                print("disable entry break point")
                event.debug.dont_break_at(pid, entry_address)
                Initiating = False

            if address in external_breakpoints:
                callb = external_breakpoints[address]
                callb(event)
                return
            else:
                print("unknown break_point called", tid, address)


        print("error:", name, code, address)
        return

        # Get the address where the exception occurred.
        try:
            address = event.get_fault_address()
        except NotImplementedError:
            address = event.get_exception_address()

    # If the event is a process creation or destruction,
    # or a DLL being loaded or unloaded...
    elif code in ( win32.CREATE_PROCESS_DEBUG_EVENT,
                   win32.EXIT_PROCESS_DEBUG_EVENT,
                   win32.LOAD_DLL_DEBUG_EVENT,
                   win32.UNLOAD_DLL_DEBUG_EVENT ):

        # Get the filename.
        filename = event.get_filename()


    if code in (win32.LOAD_DLL_DEBUG_EVENT, win32.CREATE_PROCESS_DEBUG_EVENT):
        filename = event.get_filename()
        basic_name = get_base_name(filename)
        pdb_name = 'pdbs\\'+basic_name+".pdb"

        #print(basic_name)
        update_executable_memmory(process)


        base_addr = event.get_module_base()
        #print(base_addr, "\n")

        modules[basic_name] = base_addr

        if os.path.exists(pdb_name):
            print(basic_name, pdb_name, base_addr)
            pdb_names[basic_name] = base_addr
            if basic_name not in pdbs:
                try:
                    pdbs[basic_name] = Lookup([(pdb_name, 0)])
                except Exception as e:
                    print("failed to load pdb", pdb_name, e)


        #if basic_name == "breakpoint_dll":
            #update_executable_memmory(process)
            #base_injection_addr = None
            #for addr in executable_memmory_ids:
            #    modu = get_module_from_address(addr)
            #    if modu == basic_name:
            #        base_injection_addr = addr




        if basic_name == "kernel32" and shell_code_address is None:



            process_handle = process.get_handle()

            # We inject a dll that has fast code for tracing as well as access to MinHook
            if add_dll:
                run_loadlibrary_in_process(process_handle, process, "calltracer.dll")
                add_dll = False

            base_addr = modules[exe_basic_name]
            ctypes.windll.kernel32.VirtualAllocEx.argtypes = [
                wintypes.HANDLE,     # hProcess
                ctypes.c_void_p,     # lpAddress
                ctypes.c_size_t,     # dwSize
                wintypes.DWORD,      # flAllocationType
                wintypes.DWORD       # flProtect
            ]

            size = 0x100000
            #For some reason we cant ask for the acutal base address
            base_ask_addr = base_addr - size
            preferred_address = base_ask_addr #(base_ask_addr + 0x10000 - 1) & ~(0x10000 - 1)
            ctypes.windll.kernel32.VirtualAllocEx.restype = ctypes.c_ulonglong
            base_injection_addr = ctypes.windll.kernel32.VirtualAllocEx(process_handle, ctypes.c_void_p(preferred_address), size, 0x3000, 0x40)
            if base_injection_addr == 0:
                print("could not alocate jump to table, please try again this seams sort of random")
                exit(0)


            register_save_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, 4096, 0x3000, 0x04)
            if not register_save_address:
                print("Failed to allocate register_save_address memory in target process: {}".format(ctypes.WinError()))
                exit(0)

            base_ask_addr = base_addr - size*2
            preferred_address = base_ask_addr

            code_injection_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, ctypes.c_void_p(preferred_address), 0x100000, 0x3000, 0x40)
            if not code_injection_address:
                print("Failed to allocate code_injection_address memory in target process: {}".format(ctypes.WinError()))
                exit(0)

            process.close_handle()

            print("alocated", hex(base_addr), hex(base_injection_addr), abs(base_addr-base_injection_addr))

            print("base injection addr:", base_injection_addr)

            #exit(0)
            shell_code_address = base_injection_addr

            #shellcode = asm("mov rax, 0x1; ret")

            #process.write(shell_code_address, shellcode)

            #mode = process.get_module_at_address(shell_code_address)#FIXME in breakpoint.py if module is None: return

            print("wrote shellcode to:", hex(shell_code_address))


            #event.debug.break_at(pid, shell_code_address, on_shell_enter)

            #Now we have loaded memmory space to add our jumptables

            print('loaded_modules:', len(modules), "own_module_name: ", exe_basic_name)
            print("executable_memmory:", len(executable_memmory))
            print("nr functions:", len(pdata_functions))
            pdata_ordinal = 0
            disasembled_functions = []
            disasembled_cache_file = exe_basic_name+"_instructions_cache.json"
            if os.path.exists(disasembled_cache_file) and time.time() - os.path.getmtime(disasembled_cache_file) < 24*3600:
                with open(disasembled_cache_file, 'r') as f:
                    disasembled_functions = json.load(f)
            save_cache = False
            for function_pdata_entry in pdata_functions:

                if pdata_ordinal % 1000 == 0:
                    print("processed (", pdata_ordinal, ") functions...")

                #All modules might not have loaded yeat if we are attaching to a pid but the main one has so things should work
                start_address, end_address, unwind_address = function_pdata_entry
                function_length = end_address - start_address

                #We save a ordinal name for the fuction
                pdata_function_ids[start_address] = exe_basic_name + "_" + str(pdata_ordinal)

                function_id = get_function_id(start_address)


                if len(disasembled_functions) > pdata_ordinal:
                    instructions = disasembled_functions[pdata_ordinal]
                else:
                    instcode = process.read(start_address, function_length)
                    instructions = process.disassemble_string(start_address, instcode)
                    disasembled_functions.append(instructions)
                    save_cache = True

                insert_break_at_call(event, pid, instructions, function_id, function_goto_break_point, function_ret_break_point, function_enter_break_point, function_exited_break_point)

                pdata_ordinal += 1

            if save_cache:
                with open(disasembled_cache_file, 'w') as f:
                    json.dump(disasembled_functions, f)

            #Now that we have all the instructions we add a break point on the entrypoint
            event.debug.break_at(pid, entry_address, exe_entry)


    if name == "Process creation event":
        exe_basic_name = get_base_name(filename)

        base_addr = event.get_module_base()

        #load the .pdata with function debug entrys... FIXME: we can load this from memmory it is loaded in to memmory at base_address
        get_pdata(process.get_filename(), base_addr)
        print("Process started", "pc:", address, "base_addr:", base_addr, "entry:", entry_address)

    if name == "Thread creation event":
        try:
            process.scan_modules()
        except Exception as e:
            w=0

    # Show a descriptive message to the user.
    #print("------------------")
    format_string = "%s, %s, (0x%s) at address 0x%s, process %d, thread %d"
    message = format_string % ( name,
                                filename,
                                HexDump.integer(code, bits),
                                HexDump.address(address, bits),
                                pid,
                                tid )
    #print (message)

def exe_entry(event):
    print("first instruction enterd")
    my_event_handler(event)

#check if a sequence of instructions contains a call
def check_if_contians_call(instructions):
    for instruction in instructions:
        if 'call' == instruction[2].split(" ")[0]:
            return True
    return False

def callback_joiner(callbacks, event):
    for callback in callbacks:
        callback(event)


def min_hook_function():
    asemb = f"movabs rax, 0x{virtual_address:016X};call rax"
    code_to_run.append((asemb, test_called_function))
    print("")


calls = []
known_return_addresses = []

thread_in_known_function = {}
first_func = None
#inserts a ret at all ret instructions in the list
def insert_break_at_call(event, pid, instructions, function_id, call_callback, ret_callback, enter_callback, exited_callback):
    global first_func
    add_next_inscruction_as_return = False
    rets = 0
    call_num = 0

    process = event.get_process()

    for instruction_num, instruction in enumerate(instructions):
        instruction_name = instruction[2].split(" ")[0]
        callback_to_add = []
        instruction_address = instruction[0]
        instruction_len = instruction[1]
        is_known_jump_to_adress = False

        if instruction_num == 0:
        #    callback_to_add.append(partial(enter_callback, function_id, instruction_address))
            functions_to_hook.append((instruction_address, partial(enter_callback, function_id, instruction_address), partial(ret_callback, function_id, instruction_address)))
            is_known_jump_to_adress = True
            print("type: enter_callback")

        if add_next_inscruction_as_return:
            print("type: exit_callback")
            known_return_addresses.append(instruction_address)
            callback_to_add.append(partial(exited_callback, function_id, instruction_address, call_num))
            add_next_inscruction_as_return = False

        if 'call' == instruction_name:
            print("type: callback")
            add_next_inscruction_as_return = True
            calls.append(instruction_address)
            call_num = len(calls)-1
            callback_to_add.append(partial(call_callback, function_id, instruction_address, instruction, call_num))
        elif 'ret' == instruction_name:
            print("type: return")
        #    callback_to_add.append(partial(ret_callback, function_id, instruction_address))
            rets += 1

        #if we want callbacks from this instruction address
        if len(callback_to_add) != 0:
            if len(callback_to_add) > 1:
                callback = partial(callback_joiner, callback_to_add)
            else:
                callback = callback_to_add[0]


            if first_func is None:
                first_func = instruction_address


            #print("original instruction", "len:", instruction_len, "asm:", instruction[2])

            replace_instructions = [instruction]

            #FIXME: TEST if displacement is to large and warn
            #print(displacement, shell_code_address, instruction_address)
            extra_bytes = instruction_len - 5 #the jump is 5 bytes long
            asmm = None
            break_point_entry = None

            jump_to_address, break_point_entry = add_jump_table_entry(instruction_address, replace_instructions, process = process, callback = callback)
            if not jump_to_address:
                print("could not create jump_table_entry")
                event.debug.break_at(pid, instruction_address, callback)

            #if asmm is not None:
            #    pass
            #    jmp_to_shellcode = asm(asmm, instruction_address)
            #    print("write:", asmm, "len:", len(jmp_to_shellcode), "at:", instruction_address)

            #    process.write(instruction_address, jmp_to_shellcode)

                #We add a callback to the breakpoint. That was coded in to the jump table.
            #    external_breakpoints[break_point_entry] = callback
            #else: #No tactic was found to make this breakpoint in to shellcode using a slow breakpoint

            #break


    #event.debug.enable_all_breakpoints()
    if rets == 0:
        print("function:", function_id, "has no returns")



last_called_function = {}

@dataclass
class CallInfo:
    id: str
    function_addres: int
    expected_stack_pointer_at_function_init: int = None
    return_address: int = None
    is_external_API: bool = False
    call_num: int = None
    has_jumped_to_id: str = None

call_stack_enter_exit = {}
def function_exited_break_point(inside_function_id, instruction_address, call_num, event):
    thread = event.get_thread()
    pc     = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()


    if tid not in call_stack:
        call_stack[tid] = [CallInfo(inside_function_id, instruction_address)]
        call_stack_enter_exit[tid] = [[False, False, call_num]]
        print("thread:", tid, "", "Inital function:", inside_function_id)


    #We clear any surpurflus entries in call_stack_enter_exit that can arrise when functions dont have ret's
    count_to_pop = 0
    for i, item in enumerate(reversed(call_stack_enter_exit[tid])):
        if item[2] == call_num:
            count_to_pop = i+1
            break


    #incase we missed rets we reset the stack to what it should be
    stack_to_pop = 0
    for i, item in enumerate(reversed(call_stack[tid])):
        if item.call_num == call_num:
            stack_to_pop = i+1
            break


    #if count_to_pop != 0:
    #    print("pop:", count_to_pop)

    #FIXME something is vrong here call_stack_enter_exit is the wrong length due to jumps ee need to account for the jumps
    #If we are expecing a exit breakpoint we pop of the stack oterwize we asume this breakpoint is a result of unrealated jumping to to return address
    if len(call_stack_enter_exit[tid]) >= 2 and call_stack_enter_exit[tid][(-count_to_pop)-1][1]:
        print("thread:", tid, " "*(2*len(call_stack[tid])), "return to function:", inside_function_id, "from call_num:", call_num)
        if len(call_stack[tid]) > 0:
            for i in range(stack_to_pop):
                call_stack[tid].pop()
        else:
            print("depth empty")

        for i in range(count_to_pop):
            call_stack_enter_exit[tid].pop()

        call_stack_enter_exit[tid][-1][1] = False #No longer expecting function Exit


    else:#we are not expecing a return so this must be a internal jump that heppedn to jump to the return address
        print("thread:", tid, " "*(2*len(call_stack[tid])), "Jump to return address belonging to:", call_num, " in function:", inside_function_id)
        #print(call_stack_enter_exit[tid])
        w=0



def function_enter_break_point(inside_function_id, instruction_address, event):
    thread = event.get_thread()
    pc     = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()

    init_callstack = False

    if tid not in call_stack:
        call_stack[tid] = [CallInfo(inside_function_id, instruction_address)]
        call_stack_enter_exit[tid] = [[False, False, None]]
        init_callstack = True
        print("thread:", tid, "", "Inital function:", inside_function_id)


    #Are we expecting a enter?
    if len(call_stack_enter_exit[tid]) >= 1 and call_stack_enter_exit[tid][-1][0]:
        #print("we entred a function:", inside_function_id)
        call_stack_enter_exit[tid][-1][0] = False

        #Add extra enter exit state Which gets removed on ret
        call_stack_enter_exit[tid].append([False, False, None])#Not expecting Extry and not Exit in new fucntion
    #el
    elif not init_callstack:

        curent_known_func_id = call_stack[tid][-1].id
        if call_stack[tid][-1].has_jumped_to_id is not None:
            curent_known_func_id = call_stack[tid][-1].has_jumped_to_id

        if curent_known_func_id != inside_function_id:
            print("thread:", tid, " "*(2*len(call_stack[tid])), "Jump to function:", inside_function_id)
            call_stack[tid][-1].has_jumped_to_id = inside_function_id
        else:
            #Not expecting a enter this is probably just a internal jump
            #print("Not expecting a enter this is probably just a internal jump.", inside_function_id, call_stack)
            w=0
        return
    else:
        return #Not expecting a enter this is probably just the

    context = thread.get_context()
    stack_pointer = context['Rsp']

    stack_value_at_expected_stack_pointer = None
    last_call_info = call_stack[tid][-1]

    # An entry should not be able to happen when the stack was not filled by a call breakpoint
    # We must be in a second callback where the last did not clear the stack due to not having a ret instruction
    if last_call_info.call_num is None:
        print("thread:", tid, " "*(2*len(call_stack[tid])), "Assumed ret from:", last_call_info.id, "based on Entry in to new fuction.")
        call_stack[tid].pop()
        last_call_info = call_stack[tid][-1]
    last_called_f, expected_stack_pointer_after_call, expected_stack_value_after_call = last_call_info.function_addres, last_call_info.expected_stack_pointer_at_function_init, last_call_info.return_address

    if expected_stack_value_after_call in call_relocations:
        expected_stack_value_after_call = call_relocations[expected_stack_value_after_call]

    if expected_stack_pointer_after_call != None:
        stack_value_at_expected_stack_pointer = read_ptr(process, expected_stack_pointer_after_call)

    #print("e:", last_called_f, expected_stack_pointer_after_call, expected_stack_value_after_call)
    #print("a:", pc, stack_pointer, stack_value_at_expected_stack_pointer)

    #this is not the function we called last; meaning it is either a external API callback or a jump to the begining of the function
    if instruction_address != last_called_f or expected_stack_pointer_after_call != stack_pointer or stack_value_at_expected_stack_pointer != expected_stack_value_after_call:

        # One might assume that the stack pointer should be lower inscase we are inside a callback from the last API call but since the API call might
        # have used a diffrent stack. That is not a guarante. The only way to know if we are trully in the API call is to break at the return of the API call.


        if stack_pointer != expected_stack_pointer_after_call:
            if stack_value_at_expected_stack_pointer == expected_stack_value_after_call:

                # THINK OF:
                #
                # If the call stack was just initalized this comparision dont make sence since the CallInfo data is all zero
                if not init_callstack:
                    activation_type = None
                    if not call_stack[tid][-1].is_external_API:#if this is comming from a function we have decomplied ww would know about the call so this must be a jump
                        activation_type = 'Jump'#probably but not necicarily a tail call optimization

                    add_to_callstack = False
                    if activation_type is None:
                        activation_type = 'Jump or Call'

                        #We techically dont know if this was a call or a jump but we will treat it as a call anyways and add to the callstack
                        add_to_callstack = True



                    print("thread:", tid, " "*(2*len(call_stack[tid])), str(activation_type)+" to function:", inside_function_id)

                    if add_to_callstack:
                        if_call_return_address = read_ptr(process, stack_pointer)
                        call_stack[tid].append(CallInfo(inside_function_id, instruction_address, None, if_call_return_address, is_external_API = False, call_num = None))
                # We cant know if this was a call or a jump, we can use certain heristics. But we cant know for sure, right now. If we later get
                # a ret then we know it was a call.
                # the heristics we can use is. Look at the stack and assume it is a return address. If the instruction before was not a call this
                # is a jump, if it was a call this may be a call.

            else:
                w=0
                print("Something is wrong, the return address is gone from the stack")
                print(call_stack[tid])
        else:
            print("wierd jumping behaviors", "stack pointer:",  stack_pointer, "==", expected_stack_pointer_after_call, " execution addres(instruction_address):" ,instruction_address, "!=", last_called_f, "st
ack value:", stack_value_at_expected_stack_pointer, "!=", expected_stack_value_after_call)
            if stack_value_at_expected_stack_pointer == expected_stack_value_after_call:
                print("this might happen if we call one function but that function simply jumps to this function(", inside_function_id, ")")
            else:
                print("this should basicly never happen, it is if we call one function but that function does something to the stack then jumps to this function")


depth = []
def function_goto_break_point(inside_function_id, instruction_address, code, call_num,  event):
    #this gets called on breakpoints
    thread = event.get_thread()
    pc     = thread.get_pc()
    tid = event.get_tid()

    if tid not in call_stack:
        call_stack[tid] = [CallInfo(inside_function_id, instruction_address)]
        call_stack_enter_exit[tid] = [[False, False, call_num]]
        thread_in_known_function[tid] = False
        print("thread:", tid, "", "Inital function:", inside_function_id)

    #if thread_in_known_function[tid]:
    #    last_known_function = call_stack[tid][-1]
    #
    #    if last_known_function != inside_function_id:
    #        print("thread:", tid, " "*(2*(len(call_stack[tid])-1)), "switched function, from:", last_known_function, "to:", inside_function_id)
    #        call_stack[tid][-1] = inside_function_id

    process = event.get_process()
    context = thread.get_context()
    #print(context['Rsp'])
    target_addr = call_asm2addr(code, context, process)


    expected_stack_pointer_after_call = context['Rsp']-8#We expect the call to subtract 8 bytes (the length of a pointer) to Rsp
    return_address = instruction_address + code[1] #We expect the call to store the next instruction as a return address

    #last_called_function[tid] = target_addr, expected_stack_pointer_after_call, expected_stack_value_after_call

    #print("c:", target_addr, expected_stack_pointer_after_call, expected_stack_value_after_call)

    if find_pdata_function(target_addr) is not None:
        to_fuction_id = get_function_id(target_addr)
        print("thread:", tid, " "*(2*len(call_stack[tid])), "Call to function:", to_fuction_id, "call_num:", call_num, "in function:", inside_function_id)
        is_external_API = False
    else:
        try:
            API_func_desc = get_function_desc(target_addr)
        except Exception as e:
            import traceback
            print(target_addr, code, context, instruction_address)
            traceback.print_exc()
            print("filed to get API_func_desc", e)
            exit(0)
        print("thread:", tid, " "*(2*len(call_stack[tid])), "Call to: ", API_func_desc, " API in function:", inside_function_id, "call_num:", call_num)
        to_fuction_id = API_func_desc
        is_external_API = True

    call_stack_enter_exit[tid][-1][1] = True #Expecting Exited event in this fuction


    call_stack[tid].append(CallInfo(to_fuction_id, target_addr, expected_stack_pointer_after_call, return_address, is_external_API, call_num))
    call_stack_enter_exit[tid].append([True, False, call_num])#expecting Extry and not Exit in new fucntion



    #Print the call stack
    #print("thread: ", tid, nice_callstack(call_stack[tid]))

    return

def function_ret_break_point(inside_function_id, instruction_address, event):
    #this gets called on breakpoints
    thread = event.get_thread()
    pc     = thread.get_pc()
    tid = event.get_tid()

    context = thread.get_context()

    process = event.get_process()

    stack_empty = False
    if tid not in call_stack:
        call_stack[tid] = []
        call_stack_enter_exit[tid] = []
        thread_in_known_function[tid] = False
        stack_empty = True

    return_address = read_ptr(process, context['Rsp'])

    # Here we let get_function_desc find the function name despite uss not having the exact right fuction start address


    if return_address not in known_return_addresses:
        return_func_desc = get_function_desc(return_address)
        print("thread:", tid, " "*(2*len(call_stack[tid])), "Exit from callback function:", inside_function_id, "return to:", return_func_desc)

        #If we actually did a callback we can verify here
        if len(call_stack[tid]) > 0:
            if call_stack[tid][-1].id == inside_function_id and call_stack[tid][-1].call_num is None: #We only exit a call if we registerd that we enterd it and we dont register all callback entries
                call_stack[tid].pop()
        else:
            print("depth empty")

    else:
        return_function = find_pdata_function(return_address)
        return_func_desc = get_function_desc(return_function)
        print("thread:", tid, " "*(2*len(call_stack[tid])), "Exit from function:", inside_function_id, "returning to:", return_func_desc)

        if len(call_stack[tid]) > 0:
            u=1 #call_stack[tid].pop()
        else:
            print("depth empty")

        if stack_empty:
            call_stack[tid] = [CallInfo(return_func_desc, return_function)]
            print("thread:", tid, "", "Inital function:", return_func_desc)


    #print("remove the extra enter exit state that was added on entry:", inside_function_id)
    if len(call_stack_enter_exit[tid]) > 1:
        call_stack_enter_exit[tid].pop()
    #We now expect entry agin if there was a second callback
    call_stack_enter_exit[tid][-1][0] = True

    return

def nice_callstack(call_stack):
    return "->".join(call_stack)

pdata = None
pdata_functions = []
entry_address = 0
def get_pdata(filen, base_addr):
    global pdata, pdata_functions, entry_address

    pe = pefile.PE(filen)
    entry_address = pe.OPTIONAL_HEADER.AddressOfEntryPoint + base_addr
    functions = []
    for section in pe.sections:
        if b'.pdata' in section.Name:
            pdata_data = section.get_data()
            pdata = pdata_data
            #print(f"Found .pdata section, length: {len(pdata_data)} bytes")

            # Each RUNTIME_FUNCTION entry in x64 is typically 12 bytes long.
            entry_size = 12
            num_entries = len(pdata_data) // entry_size
            #print(f"Number of entries (max): {num_entries}")

            for i in range(num_entries):
                entry = pdata_data[i * entry_size:(i + 1) * entry_size]
                # Unpack according to <III format: start address, end address, unwind info address
                start_addr, end_addr, unwind_info_addr = struct.unpack('<III', entry)
                if start_addr == 0 and end_addr == 0:
                    break
                functions.append((start_addr+base_addr, end_addr+base_addr, unwind_info_addr))
                #print(f"Entry {i}: Start: {hex(start_addr)}, End: {hex(end_addr)}, Unwind Info: {hex(unwind_info_addr)}")
            break

    pdata_functions = functions

free_memory = {}
def update_executable_memmory(process):
    global executable_memmory, executable_memmory_ids, free_memory
    #try:
    #   process.scan_modules()
    #except Exception as e:
    #   print("module_scan failed")

    memoryMap = process.get_memory_map()
    executable_memmory, free_memory = mem_p(memoryMap)
    for start, length in executable_memmory.items():
        #Generate a id for each executable region
        modu = get_module_from_address(start)
        if modu is None:
            modu = "none"
        id = modu +"_"+ f_id(str(length)+"_"+str(read_ptr(process, start)))
        executable_memmory_ids[start] = id

def get_function_id(function_addr):

    #If this is a known function it gets that id
    if function_addr in pdata_function_ids:
        return pdata_function_ids[function_addr]

    #if it not we generate a id for the function
    region_start, region_len = get_executable_region_from_address(function_addr)
    mod = get_module_from_address(function_addr)
    region_id = executable_memmory_ids[region_start]
    func_region_ofset = function_addr - region_start
    func_id = str(region_id)+"+"+str(func_region_ofset)
    return func_id

def undecorate_nice(decorated, remove_arguments = True):
    undeced = undecorate_symbol(decorated)
    #if present Remove "public: virtual long __cdecl "
    pts = undeced.split(" __cdecl ")
    ret = pts[-1]
    if remove_arguments:
        ret = ret.split("(")[0].split("_<")[0]
    return ret

def get_function_desc(function_address, remove_arguments = True, undecodrated = False):
    global desc_cahce

    mod = get_module_from_address(function_address)
    if mod not in pdb_names:
        return get_function_id(function_address)

    if function_address in desc_cahce:
        return desc_cahce[function_address]

    pdb_base = pdb_names[mod]
    ofest = function_address - pdb_base
    full_name = pdbs[mod].lookup(ofest)
    func_name = full_name.split("!", 1)
    func_name_preample = func_name.pop(0)
    func_name = func_name.pop(0)
    #Sometimes there is a + with some extra garbage at the end that need to be removed
    func_name = func_name.split('+').pop(0)
    undeced = undecorate_nice(func_name, remove_arguments)

    ret = func_name_preample + "!" + undeced
    if undecodrated:
        return ret + " " +full_name
    desc_cahce[function_address] = ret
    return ret

def mem_p(memoryMap):

    execs = {}
    free_memory = {}
    bits = 64
    for mbi in memoryMap:
        is_exec = False
        # Address and size of memory block.
        BaseAddress = mbi.BaseAddress #HexDump.address(mbi.BaseAddress, bits)
        RegionSize  = mbi.RegionSize #HexDump.address(mbi.RegionSize,  bits)

        # State (free or allocated).
        if   mbi.State == win32.MEM_RESERVE:
            State   = "Reserved  "
        elif mbi.State == win32.MEM_COMMIT:
            State   = "Commited  "
        elif mbi.State == win32.MEM_FREE:
            State   = "Free      "
            free_memory[BaseAddress] = RegionSize
        else:
            State   = "Unknown   "

        # Page protection bits (R/W/X/G).
        if mbi.State != win32.MEM_COMMIT:
            Protect = "          "
        else:
    ##            Protect = "0x%.08x" % mbi.Protect
            if   mbi.Protect & win32.PAGE_NOACCESS:
                Protect = "--- "
            elif mbi.Protect & win32.PAGE_READONLY:
                Protect = "R-- "
            elif mbi.Protect & win32.PAGE_READWRITE:
                Protect = "RW- "
            elif mbi.Protect & win32.PAGE_WRITECOPY:
                Protect = "RC- "
            elif mbi.Protect & win32.PAGE_EXECUTE:
                is_exec = True
                Protect = "--X "
            elif mbi.Protect & win32.PAGE_EXECUTE_READ:
                is_exec = True
                Protect = "R-X "
            elif mbi.Protect & win32.PAGE_EXECUTE_READWRITE:
                is_exec = True
                Protect = "RWX "
            elif mbi.Protect & win32.PAGE_EXECUTE_WRITECOPY:
                is_exec = True
                Protect = "RCX "
            else:
                Protect = "??? "
            if   mbi.Protect & win32.PAGE_GUARD:
                Protect += "G"
            else:
                Protect += "-"
            if   mbi.Protect & win32.PAGE_NOCACHE:
                Protect += "N"
            else:
                Protect += "-"
            if   mbi.Protect & win32.PAGE_WRITECOMBINE:
                Protect += "W"
            else:
                Protect += "-"
            Protect += "   "

        if is_exec:
            execs[BaseAddress] = RegionSize
        # Type (file mapping, executable image, or private memory).
        if   mbi.Type == win32.MEM_IMAGE:
            Type    = "Image     "
        elif mbi.Type == win32.MEM_MAPPED:
            Type    = "Mapped    "
        elif mbi.Type == win32.MEM_PRIVATE:
            Type    = "Private   "
        elif mbi.Type == 0:
            Type    = "Free      "
        else:
            Type    = "Unknown   "

        #if RegionSize == 0x400:
        #    print(BaseAddress, RegionSize, Type, State, Protect, HexDump.address(BaseAddress))

    return execs, free_memory




def call_asm2addr(code, context, process):

    asm = code[2]
    if '[' in asm:#if this is a unstatic call
        mem_expr = asm.split('[', 1)[1].split(']', 1)[0].strip()
        mem_parts = mem_expr.split(' ')
        if len(mem_parts) != 1:
            reg, op, disp_str = mem_parts[0], mem_parts[1], mem_parts[2]
        else:
            reg, op, disp_str = mem_parts[0], '+', '0'
        reg = reg.capitalize()
        displacement = 0
        if op and disp_str:
            displacement = int(disp_str, 0)
            if op == '-':
                displacement = -displacement

        base_val = context[reg]

        org_location = code[0]
        org_ret_location = org_location + code[1]

        #Since Rip counts on each instruction we need to account for the length of the call instruction that we have not enterd yeat
        if reg == 'Rip':
            base_val = code[0] #We may have move the instruction so RIP will be incorrect for the original asembly code
            base_val += code[1] #Add the length of the call instruciton

        effective_addr = base_val + displacement
        #print(effective_addr, code)
        target_addr = read_ptr(process, effective_addr)

    else:

        label = code[2].split(" ")[1]

        if label.startswith("0x"):
            target_addr = int(label, 16)
            return target_addr

        reg = label.capitalize()

        #If this is a direct call like "call rax"
        if reg in context:
            target_addr = context[reg]
        else:
            raise ValueError("resolve_label error",e, code[2], label)

    return target_addr

def read_ptr(process, address):
    """
    Reads a pointer (4 bytes on 32-bit or 8 bytes on 64-bit) from process memory at the given address.
    """
    # Read the pointer-sized data from the process memory.
    data = process.read(address, 8)

    # Unpack the data into an integer.
    return struct.unpack("<Q", data)[0]


# if process is already started we attch to it otherwise to start it up
def simple_debugger( argv ):

    # Instance a Debug object, passing it the event handler callback.
    debug = Debug( my_event_handler, bKillOnExit = True )
    try:
        aSystem = System()
        aSystem.request_debug_privileges()
        aSystem.scan_processes()
        pid = None
        if len(argv) == 1:
            executable = argv[0]
            for ( process, name ) in debug.system.find_processes_by_filename(executable):
                #pid = process.get_pid()
                print("found pid:", pid, name)

        if pid is None:
            # Start a new process for debugging.
            debug.execv(argv)
        else:
            debug.attach( pid )

        # Wait for the debugee to finish.
        debug.loop()

    # Stop the debugger.
    finally:
        debug.stop()

# When invoked from the command line,
# the first argument is an executable file,
# and the remaining arguments are passed to the newly created process.
if __name__ == "__main__":
    import sys
    simple_debugger( sys.argv[1:] )
