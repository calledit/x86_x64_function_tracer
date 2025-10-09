import argparse
import struct

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='shows binary call trace files')
    parser.add_argument('--file', type=str, required=True, help='Binary trace file')
    args = parser.parse_args()
    
    i=0
    with open(args.file, "rb") as f:
        while dat_type := f.read(17):
            trace_type, thread_id, function_ordinal, timestamp = struct.unpack("<BIIQ", dat_type)
            
            
            extra = ""
            prt_str = ""
            if trace_type == 1:# type 1 is function enter
                return_address_pointer, return_address = struct.unpack("<QQ", f.read(16))
                prt_str = "enter:"
                extra = "return_address_pointer: "+str(return_address_pointer)+" return_address: "+str(return_address)
                
            if trace_type == 2:# type 2 is function exit
                prt_str = "exit:"
            if trace_type == 3:# type 3 is function call
                prt_str = "call:"
                call_num, target_address = struct.unpack("<IQ", f.read(12))
                extra = "call_num: "+str(call_num)+" target_address: "+str(target_address)
                
            if trace_type == 4:# type 4 is function called
                prt_str = "called:"
                call_num, = struct.unpack("<I", f.read(4))
                extra = "call_num: "+str(call_num)
            
            print(trace_type, prt_str, "tid:", thread_id, "function_ordinal:", function_ordinal, "time:", timestamp, extra)
            i+=1
            #if i == 3:
            #    exit()