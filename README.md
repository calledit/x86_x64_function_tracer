# game render loop vr injector
Library that finds the render function in a x64 executable.

The Library is built on the call trace project.
A project or tool or whatever that traces function calls in an executable by using breakpoints.

## The call trace project

For reverse engineering it would be useful to get the exact call trace of a binary
Exactly what jumps where what sections of code calls what addresses and so on.

This information would allow one to find where functions are located in the code. Even if you did not have debug symbols.
Compilation optimisations might make this impossible in some cases. But in some cases it should work.

There are various tools that promise this ability. None of them work except for simple binaries.

### Dynamic instrumentation tools
Due to the emense classic nr of instructions that need to be tracked implementing such feature with a classic debugger is to slow.
The solution to this is a Dynamic instrumentation tool. These exist but are complex beasts.
On linux you have callgrind a part of the valgrind project. Which should work in wine but does not for some reason. On windows you have DynamoRIO.

There is also a tool called frida that allows you to inject javascript in to any x86 binary. But it is slow and crashy.

I have been unable to get callgrind to work partly due to how modern games tend to use launchers that verify the executable. I have not been able to use DynamoRIO mostly cause i strugle to understand where to begin.

I would like to be able to attach after the process has spawned either by repplacing a dll or simply by attachin a debugger to the process id.


## Work so far

### Brach tracing

Initially i tried implementing this as a full fledged dynamic instrumentation tool on top of a debugger. This code is located in [track_calls_using_instruction_tracing.py] Instead of stepping each instruction in the debugger, decompiles blocks of the executable and adds breakpoints att all branches. Then when it gets to those branches it adds new breakpoints. This continues forever.
This proved to be to slow, especially considering the use of python(which is very slow) as the debugger scripting engine.

### Call tracing
Th file [track_calls_using_debug_events.py] also traces using breakpoints but it decompiles the entire executable module by module on startup then adds breakpoints on the main executable calls and returns. This has proved to be an effective learning platform. However it will not work if the executable is using self-modifying code.

Both of these implementations have issues with multithreaded code as the debugger will catch any thread and the code has not been written to take that in to account.


### next step
I have been thinking of new solution that does not capture the call trace as it happens.
It works in reverse based on the assumption that the code you are interested in will run in a loop.

Basically you start by selecting a API call to a dll (direct X) for example.
1. You add a breakpoint in that API call.
2. You look at the return adress then decompile from that adress forward until you hit a ret instruction.
3. You add a breakpoint at that ret instruction
4. When that breakpoint hits, you obtain the return address from the stack which is from where the current function was called.
5. Then you step one instruction back from that return address and add a breakpoint.
6. Now we hope that the function is run in a loop and that the breakpoint is called again.
7. When these breakpoints hit this is when we now where the calling function starts.
8. Rinse and repeat until you are at the top level.

You may want to capture multiple of each break point as each function may be called from multiple locations.


## Current work

- [x] The symbol loader from winappdbg is extremely slow and very very bad it almost never finds the true function. Implemented a new symbol loader which loads .pdb files.
- [x] Initially we looked at directX 9 due to its simplicity, we need to start looking at the reversing of dx11. Maybe we should build a text dx11 project.
- [ ] We will want to be able to decode the arguments of the API functions we add breakpoints to so that we can differentiate different rendering passes for example. Need to figure out how to do that.
- [ ] Implement the loop based debugger
