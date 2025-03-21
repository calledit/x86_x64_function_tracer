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

import ctypes

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


hProcess = None
call_stack = {}
last_function = {}
pdata_function_ids = {}
def my_event_handler( event ):
    global COde_started, hProcess

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


    if name == "Process creation event":


        filename = event.get_filename()
        exe_basic_name = get_base_name(filename)
        update_executable_memmory(process)

        base_addr = event.get_module_base()

        #load the .pdata with function debug entrys
        get_pdata(process.get_filename(), base_addr)

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

            insert_break_at_call(event, pid, instructions, function_id, function_goto_break_point, function_ret_break_point, funct
ion_enter_break_point, function_exited_break_point)

            pdata_ordinal += 1

        if save_cache:
            with open(disasembled_cache_file, 'w') as f:
                json.dump(disasembled_functions, f)


    if name == "Thread creation event":
        process.scan_modules()

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
#inserts a ret at all ret instructions in the list
def insert_break_at_call(event, pid, instructions, function_id, call_callback, ret_callback, enter_callback, exited_callback):
    add_next_inscruction_as_return = False
    rets = 0
    r_callback = partial(ret_callback, function_id)
    e_callback = partial(enter_callback, function_id)
    re_callback = partial(exited_callback, function_id)
    for instruction_num, instruction in enumerate(instructions):
        instruction_name = instruction[2].split(" ")[0]
        callback_to_add = []

        if instruction_num == 0:
            callback_to_add.append(e_callback)

        if add_next_inscruction_as_return:
            known_return_addresses.append(instruction[0])
            callback_to_add.append(re_callback)
            add_next_inscruction_as_return = False

        if 'call' == instruction_name:
            add_next_inscruction_as_return = True
            calls.append(instruction[0])
            call_num = len(calls)-1
            callback_to_add.append(partial(call_callback, function_id, instruction, call_num))
        elif 'ret' == instruction_name:
            callback_to_add.append(r_callback)
            rets += 1


        if len(callback_to_add) != 0:
            if len(callback_to_add) > 1:
                callback = partial(callback_joiner, callback_to_add)
            else:
                callback = callback_to_add[0]
            event.debug.break_at(pid, instruction[0], callback)

    if rets == 0:
        print("function:", function_id, "has no returns")



last_called_function = {}

call_stack_enter_exit = {}
def function_exited_break_point(inside_function_id, event):
    thread = event.get_thread()
    pc     = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()


    if tid not in call_stack:
        call_stack[tid] = [inside_function_id]
        call_stack_enter_exit[tid] = [[False, False]]
        print("thread:", tid, "", "Inital function:", inside_function_id)

    #If we are expecing a exit we pop of the stack
    # The issue we are having is that A return inside a call back is beeing registerd as the return for the API Call
    if len(call_stack_enter_exit[tid]) >= 2 and call_stack_enter_exit[tid][-2][1]:
        print("thread:", tid, " "*(2*len(call_stack[tid])), "return to function:", inside_function_id)
        if len(call_stack[tid]) > 0:
            call_stack[tid].pop()
        else:
            print("depth empty")
        call_stack_enter_exit[tid].pop()
        call_stack_enter_exit[tid][-1][1] = False #No longer expecting function Exit


    else:#we are not expecing a return so this must be a internal jump that heppedn to jump to the return address
        print("thread:", tid, " "*(2*len(call_stack[tid])), "Jump to return address in function:", inside_function_id)
        w=0



def function_enter_break_point(inside_function_id, event):
    thread = event.get_thread()
    pc     = thread.get_pc()
    tid = event.get_tid()
    process = event.get_process()



    if tid not in call_stack:
        call_stack[tid] = [inside_function_id]
        call_stack_enter_exit[tid] = [[False, False]]
        print("thread:", tid, "", "Inital function:", inside_function_id)

    if len(call_stack_enter_exit[tid]) >= 1 and call_stack_enter_exit[tid][-1][0]:
        #print("we entred a function:", inside_function_id)
        call_stack_enter_exit[tid][-1][0] = False

        #Add extra enter exit state Which gets removed on ret
        call_stack_enter_exit[tid].append([False, False])#Not expecting Extry and not Exit in new fucntion

    context = thread.get_context()
    stack_pointer = context['Rsp']

    stack_value_at_expected_stack_pointer = 0
    last_called_f, expected_stack_pointer_after_call, expected_stack_value_after_call = 0, 0, 0
    if tid in last_called_function:
        last_called_f, expected_stack_pointer_after_call, expected_stack_value_after_call = last_called_function[tid]
        stack_value_at_expected_stack_pointer = read_ptr(process, expected_stack_pointer_after_call)

    #print("e:", last_called_f, expected_stack_pointer_after_call, expected_stack_value_after_call)
    #print("a:", pc, stack_pointer, stack_value_at_expected_stack_pointer)

    #this is not the function we called last meaning it is either a external API callback or a jump to the begining of the functio
n
    if pc != last_called_f or expected_stack_pointer_after_call != stack_pointer or stack_value_at_expected_stack_pointer != expec
ted_stack_value_after_call:
        #print("Jump or Call to function:", inside_function_id)

        # One might assume that the stack pointer should be lower inscase we are inside a callback from the last API call but sinc
e the API call might
        # have used a diffrent stack. That is not a guarante. The only way to know if we are trully in the API call is to break at
 the return of the API call.


        if stack_pointer != expected_stack_pointer_after_call:
            if stack_value_at_expected_stack_pointer == expected_stack_value_after_call:

                # FIXME: only the first time the breakpoint is trigerd can it be a call back if it happens agian it is a jump from
 inside the function and honestly
                # it is not even sure it is call to begin with. As The API call might jump to this address instead of calling.
                # If we hit a ret latter We can verify if  if was a API call
                #print("This might be inside the API call")
                print("thread:", tid, " "*(2*len(call_stack[tid])), "Call(or jump) to function:", inside_function_id,"FIXme last_c
alled_function need to be the parent not jsut the last call")
                #call_stack[tid].append(inside_function_id)

            else:
                w=0
                print("this is NOT inside the API call FIXME:This check does not account for the fact that callbacks make is so th
at last_called_function is not the parent")
                #print("the API call has returned since our return address is gone from the stack. We might now in a call back tha
t comes from a unknown source, the stack_value may be a return address to the API calle now if this was a call or this may be jump
 outside of the API call")
        else:
            print("wierd jumping behaviors")
            if stack_value_at_expected_stack_pointer == expected_stack_value_after_call:
                print("this should basicly never happen, it is if we call one function but that function simply jumps to this func
tion")
            else:
                print("this should basicly never happen, it is if we call one function but that function does something to the sta
ck then jumps to this function")


depth = []
def function_goto_break_point(inside_function_id, code, call_num,  event):
    #this gets called on breakpoints
    thread = event.get_thread()
    pc     = thread.get_pc()
    tid = event.get_tid()

    if tid not in call_stack:
        call_stack[tid] = [inside_function_id]
        call_stack_enter_exit[tid] = [[False, False]]
        thread_in_known_function[tid] = False
        print("thread:", tid, "", "Inital function:", inside_function_id)

    #if thread_in_known_function[tid]:
    #    last_known_function = call_stack[tid][-1]
    #
    #    if last_known_function != inside_function_id:
    #        print("thread:", tid, " "*(2*(len(call_stack[tid])-1)), "switched function, from:", last_known_function, "to:", insid
e_function_id)
    #        call_stack[tid][-1] = inside_function_id

    process = event.get_process()
    target_addr = call_asm2addr(code, thread, process)


    context = thread.get_context()
    expected_stack_pointer_after_call = context['Rsp']-8#We expect the call to subtract 8 bytes (the length of a pointer) to Rsp
    expected_stack_value_after_call = pc + code[1] #We expect the call to store the next instruction as a return address

    last_called_function[tid] = target_addr, expected_stack_pointer_after_call, expected_stack_value_after_call

    #print("c:", target_addr, expected_stack_pointer_after_call, expected_stack_value_after_call)

    if find_pdata_function(target_addr) is not None:
        to_fuction_id = get_function_id(target_addr)
        print("thread:", tid, " "*(2*len(call_stack[tid])), "Call to function:", to_fuction_id, "call_num:", call_num)

    else:
        API_func_desc = get_function_desc(target_addr)
        print("thread:", tid, " "*(2*len(call_stack[tid])), "Call to: ", API_func_desc, " API in function:", inside_function_id, "
call_num:", call_num)
        to_fuction_id = API_func_desc

    call_stack_enter_exit[tid][-1][1] = True #Expecting Exited event in this fuction
    call_stack[tid].append(to_fuction_id)
    call_stack_enter_exit[tid].append([True, False])#expecting Extry and not Exit in new fucntion



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
        print("thread:", tid, " "*(2*len(call_stack[tid])), "Exit from callback function:", inside_function_id, "return to:", retu
rn_func_desc)

        #If we actually did a callback we can verify here
        if len(call_stack[tid]) > 0:
            if call_stack[tid][-1] == inside_function_id: #We only exit a call if we registerd that we enterd it and we dont regis
ter all callback entries
                u=1 #call_stack[tid].pop()
        else:
            print("depth empty")

    else:
        return_function = find_pdata_function(return_address)
        return_func_desc = get_function_desc(return_function)
        print("thread:", tid, " "*(2*len(call_stack[tid])), "Exit from function:", inside_function_id, "returning to:", return_fun
c_desc)

        if len(call_stack[tid]) > 0:
            u=1 #call_stack[tid].pop()
        else:
            print("depth empty")

        if stack_empty:
            call_stack[tid] = [return_func_desc]
            print("thread:", tid, "", "Inital function:", return_func_desc)


    #print("remove the extra enter exit state that was added on entry:", inside_function_id)
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


def update_executable_memmory(process):
    global executable_memmory, executable_memmory_ids
    #try:
    #   process.scan_modules()
    #except Exception as e:
    #   print("module_scan failed")

    memoryMap = process.get_memory_map()
    executable_memmory = mem_p(memoryMap)
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

    return execs




def call_asm2addr(code, thread, process):

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

        context = thread.get_context()
        #
        base_val = context[reg]

        #Since Rip counts on each instruction we need to account for the length of the call instruction that we have not enterd ye
at
        if reg == 'Rip':
            base_val += code[1] #Add the length of the call instruciton

        effective_addr = base_val + displacement
        target_addr = read_ptr(process, effective_addr)

    else:
        label = code[2].split(" ")[1]
        try:
            target_addr = process.resolve_label(label)
        except Exception as e:
                print(e, code[2], label)

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
                pid = process.get_pid()
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
