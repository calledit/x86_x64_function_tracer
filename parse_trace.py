import argparse
import struct
from dataclasses import dataclass
from typing import Optional


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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='shows binary call trace files')
    parser.add_argument('--file', type=str, required=True, help='Binary trace file')
    args = parser.parse_args()
    
    i=0
    contains_exits = False
    stack_height = 0
    call_stack = []
    return_stack = []
    un_matched_exits = []
    traces = []
    with open(args.file, "rb") as f:
        while dat_type := f.read(17):
            trace_type, thread_id, function_ordinal, timestamp = struct.unpack("<BIIQ", dat_type)
            
            trace = TracePoint(i, trace_type, thread_id, function_ordinal, timestamp)
            
            extra = ""
            
            lift_stack = False
            prt_str = ""
            if trace.trace_type == 1:# type 1 is function enter
                trace.return_address_pointer, trace.return_address = struct.unpack("<QQ", f.read(16))
                
                trace.type_str = "enter"
                

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

            if trace.trace_type == 4:# type 4 is function called
                stack_height -= 1
                call_stack.pop()
                trace.type_str = "called"
                trace.call_num, = struct.unpack("<I", f.read(4))
                        
            traces.append(trace)
            
            print(f"{trace.i:03d}", "  "*stack_height, trace.type_str, "func:", trace.function_ordinal, "tid:", trace.thread_id, 'ptr:', trace.return_address_pointer, 'callnum:', trace.call_num, trace.enter_type, trace.matching_enter, trace.return_address, trace.target_address)
            

            if lift_stack:
                call_stack.append(function_ordinal)
                stack_height += 1
            i+=1
            #if i == 200:
            #    break
        #exit()
        print("\n")
        if contains_exits:
            print("printing in hindsight allows you to acount for enter and exits effect on the call stack")
            print_traces(traces, len(un_matched_exits), contains_exits)
        
