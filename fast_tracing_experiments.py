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

def asm(CODE):
    encoding, count = ks.asm(CODE)
    return bytes(encoding)


def run_loadlibrary_in_process(h_process, process, dll_path):
    # Open the target process with required access rights
    #h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    #if not h_process:
    #    raise Exception("Failed to open target process: {}".format(ctypes.WinError()))

    # Prepare the DLL path as a null-terminated byte string
    dll_path_bytes = dll_path.encode('utf-8')
    dll_path_size = len(dll_path_bytes) + 1

    # Allocate memory in the target process for the DLL path
    ctypes.windll.kernel32.VirtualAllocEx.restype = ctypes.c_ulonglong
    remote_memory = ctypes.windll.kernel32.VirtualAllocEx(h_process, None, dll_path_size, 0x3000, 0x04)
    if not remote_memory:
        raise Exception("Failed to allocate memory in target process: {}".format(ctypes.WinError()))

    # Write the DLL path into the allocated memory in the target process
    process.write(remote_memory, dll_path_bytes)

    kernel32 = process.get_module_by_name('kernel32.dll')

    load_library_addr = kernel32.resolve('LoadLibraryA')

    ctypes.windll.kernel32.CreateRemoteThread.argtypes = [
        wintypes.HANDLE,       # hProcess
        wintypes.LPVOID,       # lpThreadAttributes
        ctypes.c_size_t,       # dwStackSize
        wintypes.LPVOID,       # lpStartAddress (LPTHREAD_START_ROUTINE)
        wintypes.LPVOID,       # lpParameter
        wintypes.DWORD,        # dwCreationFlags
        ctypes.POINTER(wintypes.DWORD)  # lpThreadId
    ]
    # Create a remote thread in the target process that calls LoadLibraryA with our DLL path
    thread_id = ctypes.c_ulong(0)
    h_thread = ctypes.windll.kernel32.CreateRemoteThread(h_process, None, 0, load_library_addr, remote_memory, 0, ctypes.byref(thread_id))
    if not h_thread:
        raise Exception("Failed to create remote thread: {}".format(ctypes.WinError()))

    # Optionally, wait for the remote thread to finish
    #ctypes.windll.kernel32.WaitForSingleObject(h_thread, 0xFFFFFFFF)

    # Clean up handles
    ctypes.windll.kernel32.CloseHandle(h_thread)
    #kernel32.CloseHandle(h_process)

    return True


hProcess = None
call_stack = {}
last_function = {}
pdata_function_ids = {}
target_address = None
process_handle = None
exe_basic_name = None
def my_event_handler( event ):
    global COde_started, hProcess, target_address, exe_basic_name, process_handle

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
        code = event.get_exception_code()


        if name == "Breakpoint":
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


        update_executable_memmory(process)

        base_addr = event.get_module_base()

        modules[basic_name] = base_addr

        if os.path.exists(pdb_name):
            print(basic_name, pdb_name, base_addr)
            pdb_names[basic_name] = base_addr
            if basic_name not in pdbs:
                pdbs[basic_name] = Lookup([(pdb_name, 0)])


        #if basic_name == "breakpoint_dll":
            #update_executable_memmory(process)
            #base_injection_addr = None
            #for addr in executable_memmory_ids:
            #    modu = get_module_from_address(addr)
            #    if modu == basic_name:
            #        base_injection_addr = addr




        if basic_name == "kernel32" and target_address is None:


            update_executable_memmory(process)



            process_handle = process.get_handle()

            # We need to load the extra memmory as a dll so it get placed in close proximity to the original
            # code so it can be jumped to breakpoint_dll does nothing expect fill out space
            #run_loadlibrary_in_process(process_handle, process, "breakpoint_dll.dll")

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
            preferred_address = (base_ask_addr + 0x10000 - 1) & ~(0x10000 - 1)
            ctypes.windll.kernel32.VirtualAllocEx.restype = ctypes.c_ulonglong
            base_injection_addr = ctypes.windll.kernel32.VirtualAllocEx(process_handle, ctypes.c_void_p(preferred_address), size, 0x3000, 0x40)

            process.close_handle()

            print("alocated", hex(base_addr), hex(base_injection_addr), abs(base_addr-base_injection_addr))

            print("base injection addr:", base_injection_addr)

            #exit(0)
            target_address = base_injection_addr

            shellcode = asm("mov rax, 0x1; ret")

            process.write(target_address, shellcode)

            #mode = process.get_module_at_address(target_address)#FIXME in breakpoint.py if module is None: return

            print("wrote shellcode to:", hex(target_address))


            event.debug.break_at(pid, target_address, on_shell_enter)

            #Now we have loaded memmory space to add our jumptables

            print('loaded_modules:', len(modules), "own_module_name: ", exe_basic_name)
            print("executable_memmory:", len(executable_memmory))
            print("nr functions:", len(pdata_functions))
            pdata_ordinal = 0
            disasembled_functions = []
            disasembled_cache_file = exe_basic_name+"_instructions_cache.json"
            if os.path.exists(disasembled_cache_file):
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
                    instructions = event.get_thread().disassemble(start_address, function_length)
                    disasembled_functions.append(instructions)
                    save_cache = True

                insert_break_at_call(event, pid, instructions, function_id, function_goto_break_point, function_ret_break_point, function_enter_break_point, function_exited_break_point)

                pdata_ordinal += 1

            if save_cache:
                with open(disasembled_cache_file, 'w') as f:
                    json.dump(disasembled_functions, f)




    if name == "Process creation event":
        exe_basic_name = get_base_name(filename)

        base_addr = event.get_module_base()

        #load the .pdata with function debug entrys... FIXME: we can load this from memmory it is loaded in to memmory at base_address
        get_pdata(process.get_filename(), base_addr)
        print("Process started")

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


#check if a sequence of instructions contains a call
def check_if_contians_call(instructions):
    for instruction in instructions:
        if 'call' == instruction[2].split(" ")[0]:
            return True
    return False

def callback_joiner(callbacks, event):
    for callback in callbacks:
        callback(event)





calls = []
known_return_addresses = []

thread_in_known_function = {}
first_func = None
#inserts a ret at all ret instructions in the list
def insert_break_at_call(event, pid, instructions, function_id, call_callback, ret_callback, enter_callback, exited_callback):
    global first_func
    add_next_inscruction_as_return = False
    rets = 0
    r_callback = partial(ret_callback, function_id)
    e_callback = partial(enter_callback, function_id)
    call_num = 0

    process = event.get_process()

    for instruction_num, instruction in enumerate(instructions):
        instruction_name = instruction[2].split(" ")[0]
        callback_to_add = []

        if instruction_num == 0:
            callback_to_add.append(e_callback)

        if add_next_inscruction_as_return:
            known_return_addresses.append(instruction[0])
            callback_to_add.append(partial(exited_callback, function_id, call_num))
            add_next_inscruction_as_return = False
            #print("return address", function_id, call_num, hex(instruction[0]))

        if 'call' == instruction_name:
            add_next_inscruction_as_return = True
            calls.append(instruction[0])
            call_num = len(calls)-1
            callback_to_add.append(partial(call_callback, function_id, instruction, call_num))
            #print("call", function_id, call_num, hex(instruction[0]))
        elif 'ret' == instruction_name:
            callback_to_add.append(r_callback)
            rets += 1


        if len(callback_to_add) != 0:
            if len(callback_to_add) > 1:
                callback = partial(callback_joiner, callback_to_add)
            else:
                callback = callback_to_add[0]

            address_of_jump_instruction = instruction[0]
            if first_func is None:
                first_func = address_of_jump_instruction
            #arget_address = first_func
            displacement = target_address - (address_of_jump_instruction)
            #FIXME: TEST if displacement is to large and warn
            #print(displacement, target_address, address_of_jump_instruction)
            asmm = f"jmp 0x{(displacement & 0xffffffff):x};nop"
            jmp_to_shellcode = asm(asmm)
            print("input", asmm, jmp_to_shellcode)
            #print("jmp_shell_lne", len(jmp_to_shellcode))
            process.write(address_of_jump_instruction, jmp_to_shellcode)

            writen_instruction = event.get_thread().disassemble(address_of_jump_instruction, len(jmp_to_shellcode))
            print(writen_instruction)

            #event.debug.break_at(pid, instruction[0], callback)
            break

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
def function_exited_break_point(inside_function_id, call_num, event):
    thread = event.get_thread()
    pc     = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()


    if tid not in call_stack:
        call_stack[tid] = [CallInfo(inside_function_id, pc)]
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



def function_enter_break_point(inside_function_id, event):
    thread = event.get_thread()
    pc     = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()

    init_callstack = False

    if tid not in call_stack:
        call_stack[tid] = [CallInfo(inside_function_id, pc)]
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
    if expected_stack_pointer_after_call != None:
        stack_value_at_expected_stack_pointer = read_ptr(process, expected_stack_pointer_after_call)"based on Entry in to new fuction.")
        call_stack[tid].pop()
    #print("e:", last_called_f, expected_stack_pointer_after_call, expected_stack_value_after_call)
    #print("a:", pc, stack_pointer, stack_value_at_expected_stack_pointer)_after_call = last_call_info.function_addres, last_call_info.expected_stack_pointer_at_function_init, last_call_info.return_address

    #this is not the function we called last; meaning it is either a external API callback or a jump to the begining of the function
    if pc != last_called_f or expected_stack_pointer_after_call != stack_pointer or stack_value_at_expected_stack_pointer != expected_stack_value_after_call:

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
                        call_stack[tid].append(CallInfo(inside_function_id, pc, None, if_call_return_address, is_external_API = False, call_num = None))
                # We cant know if this was a call or a jump, we can use certain heristics. But we cant know for sure, right now. If we later get
                # a ret then we know it was a call.
                # the heristics we can use is. Look at the stack and assume it is a return address. If the instruction before was not a call this
                # is a jump, if it was a call this may be a call.

            else:
                w=0
                print("Something is wrong, the return address is gone from the stack")
                print(call_stack[tid])
        else:
            print("wierd jumping behaviors")
            if stack_value_at_expected_stack_pointer == expected_stack_value_after_call:
                print("this should basicly never happen, it is if we call one function but that function simply jumps to this function")
            else:
                print("this should basicly never happen, it is if we call one function but that function does something to the stack then jumps to this function")


depth = []
def function_goto_break_point(inside_function_id, code, call_num,  event):
    #this gets called on breakpoints
    thread = event.get_thread()
    pc     = thread.get_pc()
    tid = event.get_tid()

    if tid not in call_stack:
        call_stack[tid] = [CallInfo(inside_function_id, pc)]
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
    target_addr = call_asm2addr(code, context, process)


    expected_stack_pointer_after_call = context['Rsp']-8#We expect the call to subtract 8 bytes (the length of a pointer) to Rsp
    return_address = pc + code[1] #We expect the call to store the next instruction as a return address

    #last_called_function[tid] = target_addr, expected_stack_pointer_after_call, expected_stack_value_after_call

    #print("c:", target_addr, expected_stack_pointer_after_call, expected_stack_value_after_call)

    if find_pdata_function(target_addr) is not None:
        to_fuction_id = get_function_id(target_addr)
        print("thread:", tid, " "*(2*len(call_stack[tid])), "Call to function:", to_fuction_id, "call_num:", call_num, "in function:", inside_function_id)
        is_external_API = False
    else:
        API_func_desc = get_function_desc(target_addr)
        print("thread:", tid, " "*(2*len(call_stack[tid])), "Call to: ", API_func_desc, " API in function:", inside_function_id, "call_num:", call_num)
        to_fuction_id = API_func_desc
        is_external_API = True

    call_stack_enter_exit[tid][-1][1] = True #Expecting Exited event in this fuction


    call_stack[tid].append(CallInfo(to_fuction_id, target_addr, expected_stack_pointer_after_call, return_address, is_external_API, call_num))
    call_stack_enter_exit[tid].append([True, False, call_num])#expecting Extry and not Exit in new fucntion



    #Print the call stack
    #print("thread: ", tid, nice_callstack(call_stack[tid]))

    return

def function_ret_break_point(inside_function_id, event):
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
def get_pdata(filen, base_addr):
    global pdata, pdata_functions

    pe = pefile.PE(filen)
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

def get_funcion_desc(function_address, remove_arguments = True, undecodrated = False):
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

        #Since Rip counts on each instruction we need to account for the length of the call instruction that we have not enterd yeat
        if reg == 'Rip':
            base_val += code[1] #Add the length of the call instruciton

        effective_addr = base_val + displacement
        target_addr = read_ptr(process, effective_addr)

    else:
        label = code[2].split(" ")[1]

        reg = label.capitalize()

        #If this is a direct call like "call rax"
        if reg in context:
            target_addr = context[reg]
        else:
            try:
                target_addr = process.resolve_label(label)
            except Exception as e:
                print("resolve_label error",e, code[2], label)

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
