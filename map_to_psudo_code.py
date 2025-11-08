import argparse
import struct
from dataclasses import dataclass
from typing import Optional
from pdbparse.symlookup import Lookup
import bisect

import download_pdb
import json
import os


_func_map = []
_func_starts = []


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
    Binary search for the function that contains `address`.
    Assumes `build_func_index()` was called once after func_map is loaded.
    """
    i = bisect.bisect_right(_func_starts, address) - 1
    if i >= 0:
        entry = _func_map[i]
        if address < entry['function_end_addr']:
            return entry
    return None
    
def build_func_index(func_map):
    global _func_map, _func_starts
    _func_map = sorted(func_map, key=lambda e: e['function_start_addr'])
    _func_starts = [e['function_start_addr'] for e in _func_map]

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
                try:
                    addrs_names = Lookup([module_lookup[mod_name]])
                    module_lookup[mod_name] = dict(next(iter(addrs_names.addrs.values()))['addrs'])
                except:
                    print("could not parse pdb for: ", mod_name)
                    module_lookup[mod_name] = {}
        
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
        
        func_addr = None
        
        if trace.type_str == "enter":
            if trace.function_ordinal in ordinal2addr:
                func_addr = ordinal2addr[trace.function_ordinal]
        elif trace.type_str == "call":
            func_addr = trace.target_address
            
        if trace.type_str == 'exit' or trace.type_str == 'called':
            stack_height -= 1
        
        typ = trace.type_str
        if contains_exits:
            if trace.type_str == "enter" and trace.enter_type is None:
               typ = 'jump'
            if trace.type_str == "exit" and trace.matching_enter == None:
               typ = 'un_matched_exit'
        
        name = None
            
        if module_lookup is not None and func_addr is not None:
            name = get_name_of_function(func_addr)
        
        print(f"{trace.i:03d}", "  "*stack_height, typ, "func:", trace.function_ordinal, "tid:", trace.thread_id, 'ptr:', trace.return_address_pointer, 'callnum:', trace.call_num, trace.enter_type, trace.matching_enter, trace.return_address, trace.target_address, name)
        
        
        
        if trace.enter_type == "enter" or trace.type_str == 'call':
            stack_height += 1

modules = None
module_lookup = {}
func_map = []
functions = {}
name_to_index = {}

def show_top_counts(counts):
    top_30 = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:30]

    for key, val in top_30:
        print(key, val)

def add_names_to_calls():
    global functions
    changed = False
    for func in func_map:
        for call in func['calls']:
            if 'target_name' not in call and 'target' in call:
                call['target_name'] = get_name_of_function(call['target'])
                changed = True
    return changed
    
def get_clean_func_name(txt):
    if 'continues to' in txt:
        parts = txt.split(" ")
        if parts[-1] == "":
            return txt
        return parts[-1]
    return txt
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='shows binary call trace files')
    parser.add_argument('--map', type=str, required=True, help='File with function map')
    parser.add_argument("--print_unresolved", action="store_true", help="prints the asm of unresolved targets")
    args = parser.parse_args()
    
    

    with open(args.map, "r") as f:
        func_map = json.load(f)
        for i, func in enumerate(func_map):
            name_to_index[func['function_id']] = i
        
        for i, func in enumerate(func_map):
            print("def "+func['function_id']+"():")
            printed = False
            for call in func['calls']:
                if 'target_name' in call:
                    print("\t"+get_clean_func_name(call['target_name'])+"()")
                    printed = True
                elif args.print_unresolved:
                    print("\tasm(\""+call['asm']+"\")")
                    printed = True
            if 'continues_in_to_next' in func and func['continues_in_to_next']:
                print("\t"+func['continues_in_to_next']+"()")
                printed = True
            
            if not printed:
                print("\tpass")
            print("\n")
        
