import argparse
import struct
from dataclasses import dataclass
from typing import Optional
from pdbparse.symlookup import Lookup


import download_pdb
import json
import os


def get_mod_containing(address):
    """
    Return the (function_start_addr, function_end_addr, unwind_info_addr, pdata_ordinal)
    tuple that contains the given address, or None if not found.
    """
    if modules is not None:
        for mid in modules:
            mod = modules[mid]
            if mod['base'] <= address < mod['base']+mod['size']:
                return mid
    return None

def get_function_containing(address):
    """
    Return the (function_start_addr, function_end_addr, unwind_info_addr, pdata_ordinal)
    tuple that contains the given address, or None if not found.
    """
    for entry in func_map:
        function_start_addr, function_end_addr = entry['function_start_addr'], entry['function_end_addr']
        if function_start_addr <= address < function_end_addr:
            return entry
    return None

def get_name_of_function(address):
    if address in functions:
        func = functions[address]
        if func['unlisted'] and len(func['thunk_jumps']) == 1:
            thunk_jump = func['thunk_jumps'][0]
            return func['function_id'] + f" continues to ({thunk_jump}) " + get_name_of_function(thunk_jump)
        return func['function_id']
    in_func = get_function_containing(address)
    if in_func is not None:
        return "call to inside of: " + in_func['function_id']
    
    mod_name = get_mod_containing(address)
    if mod_name is None:
        return "unknown module"
    if mod_name in module_lookup:
        if isinstance(module_lookup[mod_name], tuple):
            
            #load pdb and download it if we dont have it 
            mod = modules[mod_name]
            pdb_file = module_lookup[mod_name][0]
            if ":\\windows\\" in mod['path'].lower():
                download_pdb.get_pdb_from_microsoft(mod['path'])
            if os.path.exists(pdb_file) and os.path.getsize(pdb_file) != 0:
                addrs_names = Lookup([module_lookup[mod_name]])
                module_lookup[mod_name] = dict(next(iter(addrs_names.addrs.values()))['addrs'])
        
        if not isinstance(module_lookup[mod_name], tuple):
            mod_lookup = module_lookup[mod_name]
            if address in mod_lookup:
                return mod_name + "!" + undecorate_nice(mod_lookup[address])
    return "unknown function in: " + mod_name

import ctypes

# Load the dbghelp.dll
dbghelp = ctypes.WinDLL("Dbghelp.dll")


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

def undecorate_nice(decorated, remove_arguments = True):
    
    func_name = decorated #decorated.split("!", 1)
    #func_name_preample = func_name.pop(0)
    #func_name = func_name.pop(0)
    #Sometimes there is a + with some extra garbage at the end that need to be removed
    func_name = func_name.split('+').pop(0)
    undeced = undecorate_symbol(func_name)
    #if present Remove "public: virtual long __cdecl "
    pts = undeced.split(" __cdecl ")
    ret = pts[-1]
    if remove_arguments:
        ret = ret.split("(")[0].split("_<")[0]
    return ret

@dataclass
class TracePoint:
    i: int
    trace_type: int
    thread_id: int
    function_ordinal: int
    timestamp: int
    return_address_pointer: Optional[int] = None
    return_address: Optional[int] = None
    call_num: Optional[int] = None
    target_address: Optional[int] = None
    enter_type: Optional[str] = None
    type_str: Optional[str] = None
    matching_enter: Optional[int] = None

def print_traces(traces, stack_offset, contains_exits):
    stack_height = stack_offset
    for trace in traces:
        
        if trace.type_str == 'exit' or trace.type_str == 'called':
            stack_height -= 1
        
        typ = trace.type_str
        if contains_exits:
            if trace.type_str == "enter" and trace.enter_type is None:
               typ = 'jump'
            if trace.type_str == "exit" and trace.matching_enter == None:
               typ = 'un_matched_exit'
        
        
        print(f"{trace.i:03d}", "  "*stack_height, typ, "func:", trace.function_ordinal, "tid:", trace.thread_id, 'ptr:', trace.return_address_pointer, 'callnum:', trace.call_num, trace.enter_type, trace.matching_enter, trace.return_address, trace.target_address)
        
        
        
        if trace.enter_type == "enter" or trace.type_str == 'call':
            stack_height += 1

modules = None
module_lookup = {}
func_map = []
functions = {}
ordinal2addr = {}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='shows binary call trace files')
    parser.add_argument('--file', type=str, required=True, help='Binary trace file')
    parser.add_argument('--modules', type=str, required=False, help='File with modules')
    parser.add_argument('--map', type=str, required=False, help='File with modules')
    args = parser.parse_args()
    
    
    if args.modules is not None:
        with open(args.modules, "r") as f:
            modules = json.load(f)
            for mid in modules:
                mod = modules[mid]
                pdb_file = "pdbs\\" + download_pdb.get_pdb_name(mod['path'])
                module_lookup[mid] = (pdb_file, mod['base'])
    
    if args.map is not None:
        with open(args.map, "r") as f:
            func_map = json.load(f)
            for func in func_map:
                functions[func['function_start_addr']] = func
                ordinal2addr[func['ordinal']] = func['function_start_addr']
    
    
    #print(get_mod_containing(140695557676265))
    #exit()
    i=0
    contains_exits = False
    call_stacks = {}
    return_stack = []
    un_matched_exits = []
    traces = []
    with open(args.file, "rb") as f:
        while dat_type := f.read(17):
            trace_type, thread_id, function_ordinal, timestamp = struct.unpack("<BIIQ", dat_type)
            
            trace = TracePoint(i, trace_type, thread_id, function_ordinal, timestamp)
            
            if thread_id not in call_stacks:
                call_stacks[thread_id] = []
            
            extra = ""
            func_addr = None
            
            lift_stack = False
            prt_str = ""
            if trace.trace_type == 1:# type 1 is function enter
                trace.return_address_pointer, trace.return_address = struct.unpack("<QQ", f.read(16))
                
                trace.type_str = "enter"
                if function_ordinal in ordinal2addr:
                    func_addr = ordinal2addr[function_ordinal]
                

            if trace.trace_type == 2:# type 2 is function exit
                trace.type_str = "exit"
                contains_exits = True
                trace.return_address_pointer, = struct.unpack("<Q", f.read(8))
                trace.enter_type == "exit"
                found_matching_enter = False
                for trc in reversed(traces):
                    if  trc.thread_id == trace.thread_id and trc.function_ordinal == trace.function_ordinal:
                        if trc.trace_type == 1 and trc.return_address_pointer == trace.return_address_pointer and trc.enter_type is None:
                            trc.enter_type = 'enter'
                            trace.matching_enter = trc.i
                            found_matching_enter = True
                            break
                
                if not found_matching_enter:
                    un_matched_exits.append(trace.i)# This may happen if the program craches inside some function before it returns (i think)
                
            if trace.trace_type == 3:# type 3 is function call
                trace.type_str = "call"
                lift_stack = True
                trace.call_num, trace.target_address = struct.unpack("<IQ", f.read(12))
                func_addr = trace.target_address

            if trace.trace_type == 4:# type 4 is function called
                call_stacks[thread_id].pop()
                trace.type_str = "called"
                trace.call_num, = struct.unpack("<I", f.read(4))
                        
            traces.append(trace)
            
            stack_height = len(call_stacks[thread_id])
            
            name = None
            
            if module_lookup is not None and func_addr is not None:
                name = get_name_of_function(func_addr)
            
            print(f"{trace.i:03d}", "  "*stack_height, trace.type_str, "func:", trace.function_ordinal, "tid:", trace.thread_id, 'time:', trace.timestamp, 'callnum:', trace.call_num, trace.enter_type, trace.matching_enter, trace.return_address, trace.target_address, name)
            

            if lift_stack:
                call_stacks[thread_id].append(function_ordinal)
            i+=1
            #if i == 200:
            #    break
        #exit()
        print("\n")
        if contains_exits:
            print("printing in hindsight allows you to acount for enter and exits effect on the call stack")
            print_traces(traces, len(un_matched_exits), contains_exits)
        
