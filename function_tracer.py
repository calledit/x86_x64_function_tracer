#!/bin/env python

#from winappdbg import Debug, HexDump, win32, System
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


# pip install git+https://github.com/MarioVilas/winappdbg.git
# pip install pefile
# pip install keystone-engine
# pip install capstone==6.0.0a4

external_breakpoints = {}
loaded_modules = {}
call_tracer_dll_func = {}
ret_replacements = {}
asm_code_to_run = []

allocate_and_inject_dll = True
in_loading_phase = True
is_in_injecetd_code = False
code_injection_address = None
register_save_address = None
shell_code_address = None
shell_code_address_ofset = 20 #We start at 20 for no particular reason, might be good to have free space...

pdata = None
pdata_functions = []
pdata_function_ids = {}
exe_entry_address = 0

call_stack = []

functions_to_hook = []

# Initialize Keystone for x64.
ks = Ks(KS_ARCH_X86, KS_MODE_64)

# if process is already started we attch to it otherwise to start it up
def start_or_attach_debuger( argv ):

    # Instance a Debug object, passing it the event handler callback.
    debug_obj = Debug(on_debug_event, bKillOnExit = True )
    try:
        aSystem = System()
        aSystem.request_debug_privileges()
        aSystem.scan_processes()
        pid = None
        
        #Find any running executable
        if len(argv) == 1:
            executable = argv[0]
            for ( process, name ) in debug_obj.system.find_processes_by_filename(executable):
                pid = process.get_pid()
        
        #If there was no running instance of the executable start it
        if pid is None:
            # Start a new process for debugging.
            print("start:", argv)
            debug_obj.execv(argv)
        else:
            debug_obj.attach(pid)

        # Wait for the debugee to finish.
        debug_obj.loop()

    # Stop the debugger.
    finally:
        debug_obj.stop()

def get_base_name(filename):
    dname = filename.split('\\')[-1]
    basic_name = dname.split('.')[0].lower()
    return basic_name
    
def asm(CODE, address = 0):
    encoding, count = ks.asm(CODE, address)
    return bytes(encoding)
    
def read_ptr(process, address):
    """
    Reads a pointer (4 bytes on 32-bit or 8 bytes on 64-bit) from process memory at the given address.
    """
    # Read the pointer-sized data from the process memory.
    data = process.read(address, 8)

    # Unpack the data into an integer.
    return struct.unpack("<Q", data)[0]
    
def allocate_mem_and_inject_dll(event, process, pid, address_close_to_code):
    global remote_memory, register_save_address, code_injection_address, shell_code_address
    #Alocate memmory for jump stuff
    ctypes.windll.kernel32.VirtualAllocEx.argtypes = [
        wintypes.HANDLE,     # hProcess
        ctypes.c_void_p,     # lpAddress
        ctypes.c_size_t,     # dwSize
        wintypes.DWORD,      # flAllocationType
        wintypes.DWORD       # flProtect
    ]
    
    process_handle = process.get_handle()
    
    # Allocate memory in the target process for varoius small stuff
    ctypes.windll.kernel32.VirtualAllocEx.restype = ctypes.c_ulonglong
    remote_memory = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, 1000, 0x3000, 0x04)
    if not remote_memory:
        raise Exception("Failed to allocate memory in target process: {}".format(ctypes.WinError()))

    size = 0x100000
    #For some reason we cant ask for the acutal base address
    base_ask_addr = address_close_to_code - size*5
    preferred_address = base_ask_addr #(base_ask_addr + 0x10000 - 1) & ~(0x10000 - 1)
    
    base_injection_addr = ctypes.windll.kernel32.VirtualAllocEx(process_handle, ctypes.c_void_p(preferred_address), size, 0x3000, 0x40)
    if base_injection_addr == 0:
        print("could not alocate jump to table, please try again this seams sort of random")
        exit(0)
    
    shell_code_address = base_injection_addr
    
    #print("distance from prefered:", shell_code_address-preferred_address)
    #exit()


    register_save_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, None, 4096, 0x3000, 0x04)
    if not register_save_address:
        print("Failed to allocate register_save_address memory in target process: {}".format(ctypes.WinError()))
        exit(0)

    base_ask_addr = address_close_to_code - size*10
    preferred_address = base_ask_addr

    code_injection_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, ctypes.c_void_p(preferred_address), 0x100000, 0x3000, 0x40)
    if not code_injection_address:
        print("Failed to allocate code_injection_address memory in target process: {}".format(ctypes.WinError()))
        exit(0)

    # We inject a dll that has fast code for tracing as well as access to MinHook calltracer.dll

    run_loadlibrary_in_process(process_handle, process, "calltracer.dll")
    

    #Now that we have all the instructions we add a break point on the entrypoint
    event.debug.break_at(pid, exe_entry_address, exe_entry)

    process.close_handle()

def min_hooked_entry_hook(ujump_table_address, callback, event):
    thread = event.get_thread()
    tid = thread.get_tid()
    
    if tid not in ret_replacements:
        ret_replacements[tid] = {}
        ret_replacements[tid][ujump_table_address] = []
    if ujump_table_address not in ret_replacements[tid]:
        ret_replacements[tid][ujump_table_address] = []
    
    process = event.get_process()
    context = thread.get_context()
    stack_pointer = context['Rsp']
    return_address = read_ptr(process, stack_pointer)

    ret_replacements[tid][ujump_table_address].append(return_address)
    #print("min_hooked_entry_hook", ujump_table_address, "table:", ret_replacements[ujump_table_address])
    callback(event)

def min_hooked_exit_hook(ujump_table_address, callback, event):
    tid = event.get_tid()
    original_return_address = ret_replacements[tid][ujump_table_address].pop()
    #print("min_hooked_exit_hook", original_return_address)
    event.get_thread().set_pc(original_return_address)
    callback(event)

def min_hooked_function(jump_table_address, enter_callback, exit_callback, event):
    """Gets executed after minhook has hooked a function"""
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
    #This is the tracking asembly, it adds a break point before and after jumping to the function.
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

    hook_function = call_tracer_dll_func['hook_function']
    enable_function = call_tracer_dll_func['enable_hooks']
    for target_fn_addr, enter_callback, exit_callback in functions_to_hook:
        print("hook", target_fn_addr, "using:", call_tracer_dll_func['hook_function'])

        jump_table_address = shell_code_address + shell_code_address_ofset

        shell_code_address_ofset += 50 # 50 bytes might be enogh

        asm_code_to_run.append((f"mov rcx, 0x{target_fn_addr:016X};mov rdx, 0x{jump_table_address:016X};mov r8, 0x{remote_memory:016X};mov rax, 0x{hook_function:016X};call rax", partial(min_hooked_function, jump_table_address, enter_callback, exit_callback)))

    #Enable hooks
    if len(functions_to_hook) != 0:
        print("enable func_location:", enable_function)
        asmm = (
            "mov r11, rsp;"
            ##FIX stack needs to be aligned to some thing chat GPT said this outcomented code shold align but it did not work
            #"sub rsp, 0x30;"
            #"and rsp, -16;"
            #"add rsp, 8;"
            f"mov rax, 0x{enable_function:016X};"
            "call rax;"
            "mov rsp, r11;"
        )
        asm_code_to_run.append((asmm, min_hook_enabled))


def deal_with_breakpoint(event, process, pid, tid, address):
    global in_loading_phase, is_in_injecetd_code
    #ASM injection here
    inject_ok = False
    if address in external_breakpoints or (in_loading_phase and address == exe_entry_address):
        inject_ok = True

    if len(asm_code_to_run) != 0 and not is_in_injecetd_code and inject_ok:
        asmd, code_done_callback = asm_code_to_run.pop(0)
        break_point_location = address
        
        # when this is a winappdbgs breakpoint (ie made with event.debug.break_at) the address points to the CC instruction otherwize it points to the following address acount for this here
        if address != exe_entry_address:
            break_point_location -= 1
        
        code_address = inject_asembly(process, asmd, break_point_location, code_done_callback)
        #print("injected assembly:", asmd, "jump back to addres:", break_point_location)
        is_in_injecetd_code = True
        
        #disable breakpoint so it is not copied when we run MinHook
        event.debug.dont_break_at(pid, exe_entry_address)
        event.get_thread().set_pc(code_address)
        return True

    if in_loading_phase and is_in_injecetd_code:
        #enable breakpoint after removing so that it trigers the next time
        event.debug.break_at(pid, exe_entry_address)

    if len(asm_code_to_run) == 0 and in_loading_phase and not is_in_injecetd_code and inject_ok:
        print("Loading phase done disabling entry break point")
        event.debug.dont_break_at(pid, exe_entry_address)
        in_loading_phase = False
    
    if address in external_breakpoints:
        callb = external_breakpoints[address]
        callb(event)
        return True
    else:
        print("unknown break_point called", tid, address)
    
    return False
    
def hook_calls(process, event, pid):
    
    #Disasembeling large executable takes allot of time to we cache the results
    disasembled_functions = []
    disasembled_cache_file = exe_basic_name+"_instructions_cache.json"
    if os.path.exists(disasembled_cache_file) and time.time() - os.path.getmtime(disasembled_cache_file) < 12*3600:
        with open(disasembled_cache_file, 'r') as f:
            disasembled_functions = json.load(f)
    save_cache = False
    
    #patch executable
    for funcion_start_addr, funcion_end_addr, unwind_info_addr, pdata_ordinal in pdata_functions:
        function_id = get_function_id(funcion_start_addr)
        
        #Set up minhooking for tracking function entry and exit 
        functions_to_hook.append((funcion_start_addr, partial(function_enter_break_point, function_id, funcion_start_addr), partial(function_exit_break_point, function_id, funcion_start_addr)))
        
        #For calls made in fucntions we disasemble and replace any call instructions
        if len(disasembled_functions) > pdata_ordinal:
            instructions = disasembled_functions[pdata_ordinal]
        else:
            instcode = process.read(funcion_start_addr, funcion_end_addr-funcion_start_addr)
            instructions = process.disassemble_string(funcion_start_addr, instcode)
            disasembled_functions.append(instructions)
            save_cache = True
        
        insert_break_at_calls(event, pid, instructions, function_id)
    
    if save_cache:
        with open(disasembled_cache_file, 'w') as f:
            json.dump(disasembled_functions, f)

def add_instruction_redirect(instruction_address_not_used, instructions, process, enter_callback, exit_callback):
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
                print("write:", asmm, "at:", instruction_address, 'jump_to_address:', jump_to_address, 'diff:',jump_to_address-instruction_address)
                jmp_to_shellcode = asm(asmm, instruction_address)
            print("write:", asmm, "len:", len(jmp_to_shellcode), "at:", instruction_address)
            process.write(instruction_address, jmp_to_shellcode)
            #We add a callback to the breakpoint. That was coded in to the jump table.
            if jump_type == 'normal':
                external_breakpoints[break_point_entry] = enter_callback
            else:
                external_breakpoints[break_point_entry] = partial(go_jump_breakpoint, jump_to_address, enter_callback)
        else:
            return False, break_point_entry


        new_code = asm(instruction_asm, new_instruction_address)
        code.append(new_code)
        new_instruction_address += len(new_code)

        #if call_relocate:
        #    call_relocations[jump_back_address] = new_instruction_address

        break #only check first instruciton

    code.append(b'\xCC')
    new_instruction_address += 1
    break_point_exit = new_instruction_address
    external_breakpoints[break_point_exit] = exit_callback

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

def go_jump_breakpoint(jump_to_adddress, callback, event):
    event.get_thread().set_pc(jump_to_adddress)
    #print("special jump:", jump_to_adddress)
    callback(event)

def insert_break_at_calls(event, pid, instructions, function_id):
    add_next_inscruction_as_return = False
    rets = 0
    call_num = 0

    process = event.get_process()

    for instruction_num, instruction in enumerate(instructions):
        instruction_name = instruction[2].split(" ")[0]
        instruction_address = instruction[0]
        instruction_len = instruction[1]

        if 'call' == instruction_name:
            print("type: callback")
            call_num += 1
            
            #callback_to_add.append(partial(call_callback, function_id, instruction_address, instruction, call_num))
            #(inside_function_id, instruction_address, call_num, event)
            replace_instructions = [instruction]
            #print(instruction)
            
            jump_to_address, break_point_entry = add_instruction_redirect(instruction_address, replace_instructions, process, partial(function_call_break_point, function_id, instruction_address, call_num, instruction), partial(function_called_break_point, function_id, instruction_address, call_num))
            if not jump_to_address:
                print("could not create jump_table_entry")
                exit()
                


def on_debug_event(event, reduse_address = False):
    global external_breakpoints, exe_basic_name, loaded_modules, exe_entry_address, allocate_and_inject_dll
    #global add_dll, COde_started, hProcess, shell_code_address, exe_basic_name, process_handle, register_save_address, code_injection_address, is_in_injecetd_code, Initiating

    # Get the process ID where the event occured.
    pid = event.get_pid()

    # Get the thread ID where the event occured.
    tid = event.get_tid()

    process = event.get_process()

    # Find out if it's a 32 or 64 bit process.
    bits = process.get_bits()

    # Get the value of EIP at the thread.
    address = event.get_thread().get_pc()

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
        exception_code = event.get_exception_code()

        if name == "Breakpoint":
            
            breakpoint_dealth_with = deal_with_breakpoint(event, process, pid, tid, address)
            return

        print("non breakpoint EXCEPTION_DEBUG_EVENT:", name, exception_code, address)
        return


    if code in (win32.LOAD_DLL_DEBUG_EVENT, win32.CREATE_PROCESS_DEBUG_EVENT):
        filename = event.get_filename()
        basic_name = get_base_name(filename)
        pdb_name = 'pdbs\\'+basic_name+".pdb"


        base_addr = event.get_module_base()

        loaded_modules[basic_name] = base_addr
        
        #Load pdb's here



        if basic_name == "kernel32":
            
            if allocate_and_inject_dll:
                allocate_mem_and_inject_dll(event, process, pid, exe_entry_address)
                allocate_and_inject_dll = False
                
                #Hook all functions and calls
                hook_calls(process, event, pid)
            


    if name == "Process creation event":
        #Save global .exe name
        filename = event.get_filename()
        exe_basic_name = get_base_name(filename)

        base_addr = event.get_module_base()

        #load the .pdata with function debug entrys... FIXME: we can load this from memmory it is loaded in to memmory at base_address
        get_pdata(filename, base_addr, exe_basic_name)
        print("Process started", "exe_basic_name:", exe_basic_name, "pc:", address, "base_addr:", base_addr, "entry:", exe_entry_address)

    if name == "Thread creation event":
        try:
            process.scan_modules()
        except Exception as e:
            pass

def function_enter_break_point(function_id, instruction_address, event):
    thread = event.get_thread()
    pc     = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()
    print ("  "*len(call_stack) + 'enter: '+ function_id)
    
def function_exit_break_point(function_id, instruction_address, event):
    thread = event.get_thread()
    pc     = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()
    print ("  "*(len(call_stack)+1) + 'exit: '+ function_id)
    
def function_call_break_point(parent_function_id, instruction_address, call_num, instruction, event):
    thread = event.get_thread()
    pc     = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()
    
    context = thread.get_context()
    #print(context['Rsp'])
    target_addr = call_asm2addr(instruction, context, process)
    
    target_function_id = get_function_id(target_addr)
    
    call_stack.append('call '+target_function_id)
    
    print ("  "*len(call_stack) + 'call: nr_'+str(call_num)+' '+target_function_id+' from '+ parent_function_id)
    
def function_called_break_point(parent_function_id, instruction_address, call_num, event):
    thread = event.get_thread()
    pc     = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()
    
    called_function_id = call_stack.pop()
    
    print ("  "*(len(call_stack)+1) + 'called: nr_'+str(call_num)+'  from '+ parent_function_id)
    

def get_function_id(function_addr):

    #If this is a known function it gets that id
    if function_addr in pdata_function_ids:
        return pdata_function_ids[function_addr]

    #if it not we generate a id for the function
    #region_start, region_len = get_executable_region_from_address(function_addr)
    mod = get_module_from_address(function_addr)
    module_ofset = function_addr - loaded_modules[mod]
    func_id = str(mod)+"+"+str(module_ofset)
    #region_id = executable_memmory_ids[region_start]
    #func_region_ofset = function_addr - region_start
    #func_id = str(region_id)+"+"+str(func_region_ofset)
    return func_id

def get_module_from_address(address):
    found_module = None
    found_base = -1

    # Find the module with the highest base that is less than or equal to the address.
    for module, base in loaded_modules.items():
        if base <= address and base > found_base:
            found_module = module
            found_base = base

    return found_module

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

def deal_with_injection_callaback(callback, save_place, event):
    global is_in_injecetd_code
    del external_breakpoints[save_place]
    callback(event)
    is_in_injecetd_code = False


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

    #print(asmembly1)
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
    #print(asmembly2)
    shellcode2 = asm(asmembly2, save_place) + struct.pack("<Q", return_address)

    shellcode = shellcode1 + shellcode2

    process.write(code_injection_address, shellcode)
    return code_injection_address



def run_loadlibrary_in_process(h_process, process, dll_path):
    
    # Prepare the DLL path as a null-terminated byte string
    dll_path_bytes = dll_path.encode('ascii') + b'\x00'

    # Allocate memory in the target process for the DLL path
    ctypes.windll.kernel32.VirtualAllocEx.restype = ctypes.c_ulonglong
    name_remote_memory = ctypes.windll.kernel32.VirtualAllocEx(h_process, None, 1000, 0x3000, 0x04)
    if not name_remote_memory:
        raise Exception("Failed to allocate memory in target process: {}".format(ctypes.WinError()))

    # Write the DLL path into the allocated memory in the target process
    process.write(name_remote_memory, dll_path_bytes)

    kernel32 = process.get_module_by_name('kernel32.dll')

    load_library_addr = kernel32.resolve('LoadLibraryA')

    asm_code_to_run.append((f"sub rsp, 0x20;mov rcx, 0x{name_remote_memory:016X};mov rax, 0x{load_library_addr:016X};call rax;add rsp, 0x20", partial(loaded_dll, dll_path)))

def loaded_dll(dll_name, event):

    thread = event.get_thread()
    context = thread.get_context()
    base_addr = context['Rax']
    if base_addr != 0:
        print("Loaded injected dll:", dll_name)
        basename = os.path.basename(dll_name)
        basic_name, ext = os.path.splitext(basename)
        loaded_modules[basic_name] = base_addr

        if basic_name == "calltracer" and len(call_tracer_dll_func) == 0:
            pe = pefile.PE(dll_name)

            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        name = exp.name.decode()
                        rva = exp.address
                        virtual_address = base_addr + rva
                        call_tracer_dll_func[name] = virtual_address
                    else:
                        print("No export table found.")
                hook_functions() #here we just to hook all functions listed in the .pdata
    else:
        print("failed to load injected dll:", dll_name)
        exit()


def exe_entry(event):
    print("first instruction enterd")
    on_debug_event(event, reduse_address = True)


def get_pdata(filen, base_addr, exe_basic_name):
    global pdata, pdata_functions, exe_entry_address, pdata_function_ids

    pe = pefile.PE(filen)
    exe_entry_address = pe.OPTIONAL_HEADER.AddressOfEntryPoint + base_addr
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
                functions.append((start_addr+base_addr, end_addr+base_addr, unwind_info_addr, i))
                pdata_function_ids[start_addr+base_addr] = exe_basic_name + "_" + str(i)
                #print(f"Entry {i}: Start: {hex(start_addr)}, End: {hex(end_addr)}, Unwind Info: {hex(unwind_info_addr)}")
            break

    pdata_functions = functions

# When invoked from the command line,
# the first argument is an executable file,
# and the remaining arguments are passed to the newly created process if there is no running instance of it.
if __name__ == "__main__":
    start_or_attach_debuger( sys.argv[1:] )
