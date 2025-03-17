#!/bin/env python

from winappdbg import Debug, HexDump, win32, System
from functools import partial
from winappdbg import CrashDump
import pdb
import os
import struct
from pdbparse.symlookup import Lookup
from pdbparse.undecorate import undecorate
from pdbparse.undname import undname

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

COde_started = False;

pdbs = {}
pdb_names = {}
desc_cahce = {}
breaks = {}
modules = {}

calls_to_hook = [
    '??$TID3D11DeviceContext_Map_@$00@CContext@@SAJPEAUID3D11DeviceContext5@@PEAUID3D11Resource@@IW4D3D11_MAP@@IPEAUD3D11_MAPPED_SUBRESOURCE@@@Z',
    #we can only do one at the time as each time we add ret break points the next function cant find any ret breakpoints
    #'??$TID3D11DeviceContext_Unmap_@$00@CContext@@SAXPEAUID3D11DeviceContext5@@PEAUID3D11Resource@@I@Z',
    #'??$TID3D11DeviceContext_RSSetViewports_@$00@CContext@@SAXPEAUID3D11DeviceContext5@@IPEBUD3D11_VIEWPORT@@@Z',
    #'??$TID3D11DeviceContext_DrawIndexed_@$00@CContext@@SAXPEAUID3D11DeviceContext5@@IIH@Z'
]

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

def call_tofunc(code, event):
    thread = event.get_thread()
    #context = thread.get_context()
    process = event.get_process()

    str_desc, addr = call_asm2addr(code, thread, process)
    print("function entry: ", str_desc)

    #pdb.set_trace()

def api_callback(function_name, event):
    print("got api callback to:", function_name)
    thread = event.get_thread()
    context = thread.get_context()

    process = event.get_process()
    return_address = read_ptr(process, context['Rsp'])
    #pdb.set_trace()
    add_ret_breakpoints_to_memmory_region(event, return_address, function_name)

def my_event_handler( event ):
    global COde_started

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


            if basic_name == 'd3d11':
                print("loading directx11")

                for func_name in calls_to_hook:
                    found_key = None
                    found_index = None
                    found_addr = None
                    for (base, limit), items in pdbs[basic_name].names.items():
                        if func_name in items:
                            found_key = (base, limit)
                            found_index = items.index(func_name)
                            found_addr = pdbs[basic_name].locs[base, limit][found_index] + base_addr
                            break

                    nice_func_name = undecorate_nice(func_name)

                    print("function ", nice_func_name," found at:", found_addr)
                    callback = partial(api_callback, nice_func_name)
                    add_breakpoint(event, pid, found_addr, callback)

                #print(pdbs[basic_name].names)
                #exit(1)

            if basic_name == 'd3d9':
                print("loading directx9")
                #print(pdbs[basic_name].names)
                #exit(1)

            #exit(0)
            #pdb.set_trace()

    if name == "Single step event":
        print("dead code")
        capture_call_to(event)
        return

        if not COde_started:
            memoryMap = process.get_memory_map()
            print(CrashDump.dump_memory_map( memoryMap ))
            COde_started = True
        step2(event)
        return

    if name == "Process creation event":

        filename = event.get_filename()
        exe_basic_name = get_base_name(filename)
        call_stack[tid] = []
        update_executable_memmory(process)
        if False:

            print('loaded_modules:', modules, "own_module_name: ", exe_basic_name)
            print("executable_memmory:", executable_memmory)
            disasembled_regions = 0
            for star_adrs in executable_memmory:
                #All modules might not have loaded yeat if we are attaching to a pid but the main one has so things should work
                module_name = get_module_from_address(star_adrs)
                # Only disasemble the code of the acctual executable
                #print(module_name, star_adrs)
                if exe_basic_name == module_name:
                    # only disasemble the first executable region
                    # The second part of the memorymap generally seas to be some type of standard library
                    if disasembled_regions == 0:
                        adrs_len = executable_memmory[star_adrs]
                        print("disasembeling: ", module_name, star_adrs, adrs_len)
                        add_breakpoints_to_memmory_region(event, star_adrs, adrs_len)
                    disasembled_regions += 1


    if name == "Thread creation event":
        call_stack[tid] = []
        process.scan_modules()

    # Show a descriptive message to the user.
    print("------------------")
    format_string = "%s, %s, (0x%s) at address 0x%s, process %d, thread %d"
    message = format_string % ( name,
                                filename,
                                HexDump.integer(code, bits),
                                HexDump.address(address, bits),
                                pid,
                                tid )
    print (message)

def update_executable_memmory(process):
        global executable_memmory
        #try:
        #       process.scan_modules()
        #except Exception as e:
        #       print("module_scan failed")

        memoryMap = process.get_memory_map()
        executable_memmory = mem_p(memoryMap)


def add_breakpoint(event, pid, address, func):
    if address not in breaks:
        event.debug.break_at(pid, address, break_point)
        breaks[address] = []
    breaks[address].append(func)

def ret_break_callback(inner_func_name, event):
    print("got ret callback from inner_func_name:", inner_func_name)
    print("We now need to clear all the other ret breakpoints that we added")
    event.debug.erase_all_breakpoints()
    thread = event.get_thread()
    context = thread.get_context()

    process = event.get_process()
    return_address = read_ptr(process, context['Rsp'])

    print("return_address from function that contains a api call:", return_address)

    last_instlen = None
    last_instruct = None
    #all lengths a call can be with most common first
    for last_instruciton_length in [5, 4, 3, 2, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]:
        last_instruction_start = return_address - last_instruciton_length
        try:
            instructions = event.get_thread().disassemble(last_instruction_start, last_instruciton_length)
            if len(instructions) != 1:
                continue
            last_instruct = instructions[0]
            disasm = last_instruct[2]
            str_inst = disasm.split(" ")[0]
            if str_inst == "call":
                print("found last call:", disasm)
                last_instlen = last_instruciton_length
                break
        except Exception as e:
                e=0

    if last_instlen is None:
        raise ValueError("last instruction could not have been a call something is wrong")

    last_instruction_start = return_address - last_instlen
    pid = event.get_pid()
    #here we can either get the function if it is static or add a breakpoint and wait untill that hits
    calbak = partial(call_tofunc, last_instruct)
    add_breakpoint(event, pid, last_instruction_start, calbak)

    memoryMap = process.get_memory_map()
    executable_memmory = mem_p(memoryMap)


def add_breakpoint(event, pid, address, func):
    if address not in breaks:
        event.debug.break_at(pid, address, break_point)
        breaks[address] = []
    breaks[address].append(func)

#def ret_break_callback(inner_func_name, event):
#    print("got ret callback from inner_func_name:", inner_func_name)
#    print("We now need to clear all the other ret breakpoints that we added")
#    thread = event.get_thread()
#    context = thread.get_context()
#
#    process = event.get_process()
#    return_address = read_ptr(process, context['Rsp'])
#
#    #bytes_representing_the_call =
#
#    pdb.set_trace()




# I picked the search length arbirarrliy probably way to long
def add_ret_breakpoints_to_memmory_region(event, star_adrs, func_name, adrs_len = 1000000):

    region_start, region_len = get_executable_region_from_address(star_adrs)
    if region_start is None and region_len is None:
        raise ValueError("The return address is not to executable memmory somthing is very wrong")
    region_end = region_start + region_len
    search_end = star_adrs + adrs_len
    search_end_pos = min(region_end, search_end)

    search_len = search_end_pos - star_adrs

    print(executable_memmory)
    print("disasemble code", star_adrs, search_len, get_module_from_address(star_adrs))

    #exit(1)

    pid = event.get_pid()
    instructions   = event.get_thread().disassemble( star_adrs, search_end_pos - star_adrs)
    print("adding ret breakpoints, nr of instructions to check", len(instructions))
    rets = []
    for inst in instructions:
        disasm = inst[2]
        str_inst = disasm.split(" ")[0]
        if str_inst == "ret":
            ret_id = len(rets)
            rets.append(inst)
            ret_pos = inst[0]
            ret_backback = partial(ret_break_callback, func_name)

            add_breakpoint(event, pid, ret_pos, ret_backback)

    nr_rets = len(rets)
    #Rets may be zero as they get replaced with breakpoints
    #if nr_rets == 0:
    #    raise ValueError("nr rets should never be zero a function should return at atleast one place")
    #print("nr of rets", nr_rets)



def add_breakpoints_to_memmory_region(event, star_adrs, adrs_len):
    print("disasemble code", star_adrs, adrs_len)

    pid = event.get_pid()
    instructions   = event.get_thread().disassemble( star_adrs, adrs_len)
    print("adding breakpoints, nr of instructions to check", len(instructions))
    calls = []
    for inst in instructions:
        disasm = inst[2]
        str_inst = disasm.split(" ")[0]
        if str_inst == "call":
            call_id = len(calls)
            calls.append(inst)
            call_pos = inst[0]
            next_inst_pos = call_pos + inst[1]
            call_backbakc = partial(call_break, call_id)
            ret_backback = partial(ret_break, call_id)


            add_breakpoint(event, pid, call_pos, call_backbakc)

            add_breakpoint(event, pid, next_inst_pos, ret_backback)

    print("nr of calls", len(calls))


def undecorate_nice(decorated):
    undeced = undecorate_symbol(decorated)
    #if present Remove "public: virtual long __cdecl "
    pts = undeced.split(" __cdecl ")
    return pts[-1]

def get_function_desc(function_address, label, undecodrated = False):
    global desc_cahce

    mod = label.split('!')[0]
    if mod not in pdb_names:
        return ""

    if function_address in desc_cahce:
        return desc_cahce[function_address]

    pdb_base = pdb_names[mod]
    ofest = function_address - pdb_base
    full_name = pdbs[mod].lookup(ofest)
    func_name = full_name.split("!", 1)
    func_name_preample = func_name.pop(0)
    func_name = func_name.pop(0)
    undeced = undecorate_nice(func_name)

    ret = func_name_preample + "!" + undeced
    if undecodrated:
        return ret + " " +full_name
    desc_cahce[function_address] = ret
    return ret

def break_point(event):
    #this gets called on breakpoints
    thread = event.get_thread()
    pc     = thread.get_pc()

    for callbac in breaks[pc]:
        callbac(event)

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

    return execs

call_stack = {}

def read_ptr(process, address):
    """
    Reads a pointer (4 bytes on 32-bit or 8 bytes on 64-bit) from process memory at the given address.
    """
    # Read the pointer-sized data from the process memory.
    data = process.read(address, 8)

    # Unpack the data into an integer.
    return struct.unpack("<Q", data)[0]

def call_asm2addr(code, thread, process):
    #print(asm)
    #pdb.set_trace()
    asm = code[2]
    output = "call "
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

        #Since Rip counts on each instruction we need to account for the length of the call instruction that we have not enterd yeat
        if reg == 'Rip':
            base_val += code[1] #Add the length of the call instruciton

        effective_addr = base_val + displacement
        target_addr = read_ptr(process, effective_addr)

        label = process.get_label_at_address( target_addr )
        asm += ' => '+str(label)
        asm += ' => '+str(target_addr)
        name_l = get_function_desc(target_addr, label)
        asm += ' ' + name_l

    else:
        label = code[2].split(" ")[1]
        target_addr = process.resolve_label(label)
        asm += ' => '+str(target_addr)

        name_l = get_function_desc(target_addr, label)
        asm += ' ' + name_l

    if name_l != "":
        output += name_l
    else:
        output += label

    return output, target_addr



def call_break(call_id, event):
    tid = event.get_tid()

    call_stack[tid].append(call_id)
    call_depth = len(call_stack[tid])
    thread = event.get_thread()


    process = event.get_process()
    pc     = thread.get_pc()
    code   = thread.disassemble( pc, 0x10 ) [0]

    output, address = call_asm2addr(code, thread, process)

    print('    '*call_depth, call_id, output)


def ret_break(call_id, event):

    tid = event.get_tid()

    if len(call_stack[tid]) == 0 or call_id != call_stack[tid][-1]:
        #Sometimes there are jumps to the instruction after a call, We ignore subseqvent breaks here
        #this could be solved by placing breakpoints at the ret instructions.

        #print("quiting non entred function call_id:", call_id, call_stack[-1], call_stack)
        return



    thread = event.get_thread()
    pc     = thread.get_pc()
    call_depth = len(call_stack[tid])

    print('    '*(call_depth+1), call_id, "ret")

    call_stack[tid].pop()





def step2( event ):
    thread = event.get_thread()
    thread_id = event.get_tid()

    pc     = thread.get_pc()

    #print("step2 pc:", pc, "tid:", thread_id)

    check_if_call(event)
    return
    is_jumper, next_jump = find_next_jumper(thread, pc)
    next_jump_address = next_jump[0]

    if next_jump_address == pc:
        print("this is a jump address")
        return
    #else:
    #    #event.debug.stop_tracing(thread_id)

    #Continue searching for jump if first serach failed
    while not is_jumper:
        is_jumper, next_jump = find_next_jumper(thread, next_jump_address)
        next_jump_address = next_jump[0]
    print(next_jump, "next_jump_address:", next_jump_address, "pc:", pc)

    pid = event.get_pid()
    print("set_break: ", next_jump_address, "tid", thread_id)
    event.debug.stalk_at(pid, next_jump_address, threds[thread_id])
    #restart_tracing(event)

def find_next_jumper(thread, pc):
    nr_of_instructions_to_check = 0x100
    instructions   = thread.disassemble( pc, nr_of_instructions_to_check)
    last_inst = None
    i=0
    for inst in instructions:
        disasm = inst[2]
        #print(inst)
        #if i == 1:
        #    return True, inst
        #
        str_inst = disasm.split(" ")[0]
        if str_inst in jumps:
            return True, inst
        last_inst = inst
        i+=1
        #print(str_inst)
        #raise Exception("no jumping instruciton in serach space, increse searchspace")
    return False, last_inst

def check_if_call(event):
    thread = event.get_thread()
    pc     = thread.get_pc()
    code   = thread.disassemble( pc, 0x10 ) [0]
    if 'call' == code[2].split(" ")[0]:
        tid = event.get_tid()

        print("tid:", tid, "is call:", code)
        return True
    return False


def restart_tracing(thread_id, event):
    #print("restart_tracing")
    thread = event.get_thread()
    pc     = thread.get_pc()
    print("restart_tracing pc:", pc, "tid:", thread_id)
    if event.get_tid() != thread_id:
        print("starting tracing on wrong thread", thread_id, event)
        exit()
    check_if_call(event)
    event.debug.start_tracing( event.get_tid() )
    #event.debug.start_tracing_all()

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
