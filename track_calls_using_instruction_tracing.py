from winappdbg import Debug, HexDump, win32
from functools import partial

threds = {}

jumps = [
    "jmp",               # Unconditional jump

    # Conditional jumps
    "je", "jz",          # Jump if Equal / Zero
    "jne", "jnz",        # Jump if Not Equal / Not Zero
    "jg", "jnle",        # Jump if Greater / Not Less or Equal
    "jge", "jnl",        # Jump if Greater or Equal / Not Less
    "jl", "jnge",        # Jump if Less / Not Greater or Equal
    "jle", "jng",        # Jump if Less or Equal / Not Greater
    "ja", "jnbe",        # Jump if Above / Not Below or Equal
    "jae", "jnb",        # Jump if Above or Equal / Not Below
    "jb", "jnae",        # Jump if Below / Not Above or Equal
    "jbe", "jna",        # Jump if Below or Equal / Not Above
    "jo",                # Jump if Overflow
    "jno",               # Jump if Not Overflow
    "js",                # Jump if Sign (Negative)
    "jns",               # Jump if Not Sign (Non-Negative)
    "jp", "jpe",         # Jump if Parity (Even)
    "jnp", "jpo",        # Jump if Not Parity (Odd)
    "jc",                # Jump if Carry
    "jnc",               # Jump if Not Carry

    # Loop control jumps
    "loop",              # Loop with rcx counter
    "loope", "loopz",    # Loop while Zero Flag (ZF) is set
    "loopne", "loopnz",  # Loop while Zero Flag (ZF) is not set

    # Procedure control
    "call",              # Call procedure
    "ret",               # Return from procedure
]

jumps = [
    "call",
]

def my_event_handler( event ):

    # Get the process ID where the event occured.
    pid = event.get_pid()

    # Get the thread ID where the event occured.
    tid = event.get_tid()

    # Find out if it's a 32 or 64 bit process.
    bits = event.get_process().get_bits()

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


    if name == "Single step event":
        step2(event)
        return

    if name == "Thread creation event" or name == "Process creation event":
        threds[tid] = partial(restart_tracing, tid)
        event.debug.start_tracing( tid)

    # Show a descriptive message to the user.
    print ("------------------")
    format_string = "%s, %s, (0x%s) at address 0x%s, process %d, thread %d"
    message = format_string % ( name,
                                filename,
                                HexDump.integer(code, bits),
                                HexDump.address(address, bits),
                                pid,
                                tid )
    print (message)


def step2( event ):
    thread = event.get_thread()
    thread_id = event.get_tid()

    pc     = thread.get_pc()

    print("step2 pc:", pc, "tid:", thread_id)

    is_jumper, next_jump = find_next_jumper(thread, pc)
    next_jump_address = next_jump[0]

    if next_jump_address == pc:
        print("this is a jump address")
        return
    else:
        event.debug.stop_tracing(thread_id)

    #Continue searching for jump if first serach failed
    while not is_jumper:
        is_jumper, next_jump = find_next_jumper(thread, next_jump_address)
        next_jump_address = next_jump[0]
    print(next_jump, "next_calle_address:", next_jump_address, "pc:", pc)

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

def simple_debugger( argv ):

    # Instance a Debug object, passing it the event handler callback.
    debug = Debug( my_event_handler, bKillOnExit = True )
    try:

        # Start a new process for debugging.
        debug.execv( argv )

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
