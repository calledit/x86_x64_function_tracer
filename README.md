# X64 call tracer
X64 call tracer is a project that has the goal to trace all function calls in a executable.

## Reason behind project
For reverse engineering it would be useful to get the exact call trace of a binary
Exactly what jumps where what sections of code calls what addresses and so on.

This information would allow one to find where functions are located in the code. Even if you did not have debug symbols.
Compilation optimisations might make this impossible in some cases. But in some cases it should work.

There are various tools that promise this ability. None of them work except for simple binaries.

## Dynamic instrumentation tools
Due to the emense classic nr of instructions that need to be tracked implementing such feature with a classic debugger and breakpoints is to slow.
The solution to this is a Dynamic instrumentation tool. These exist but are complex beasts.
On linux you have callgrind a part of the valgrind project. Which should work in wine but does not for some reason. On windows you have DynamoRIO.

There is also a tool called frida that allows you to inject javascript in to any x86 binary. But it is slow based on breakpoints and crashy.

I have been unable to get callgrind to work in complex senarios partly due to how modern games tend to use launchers that verify the executable. You also have DynamoRIO a moster of a project just like callgrind. When you have intelPIN. 

I would like to be able to attach after the process has spawned either by replacing a dll or simply by attaching a debugger to the process id. My hope is that only focusing on tracing function calls will make the project smaller.


## Current function
[function_tracer.py](function_tracer.py)

1. Either spaws a new process or atatches with debuger.
2. it injects a dll ( calltrace.dll ) that can be used for injecitng varoius new tasks in to specific functions.
3. It looks at the .exe .pdata information to find all functions.
4. It decompiles all functions injects a trace point at the begining of each fucntion and replaces all calls with jumps to trampolines that registers the call and then executes it, then registers that the call was finished.
	it is posible to turn on a flag to enable a specially crafted trampoline that modifies the return address so the tools also captures when the function returns. This feature is not completly transparent so may cause some functions to not behave properly so is disabled by default.

## Usage
```bash
# Capture trace
python function_tracer.py {name of exeutable to attach to or spawn}

# View trace
python parse_trace.py --file output\{executable}.trace
```
Injecting traces is never completly transparent so the exectuable may crach when entering certain functions funcions. For example functions that are selfmodifying or does other unusual behavior. To help with this senario there is the function_exclusions list witch allows you to specify functions that sould not be traced. To figure out what functions are problematic simply run the tool over and over adding the functions which crash to the list as you go.

Tracing does add a speed penalty which can be problematic for functions that are called over and over in loops. By running the tool multiple times you can find these functions and exclude them to.

## Next steps
- Add feature to create a map of all calls.
- Build tool that analyses a captured trace and builds a call graph.
- Build tool that uses the call graph to supplement the call map with info about dynamic calls.
- Remove debugger

## Current issues
Modern games have anti debug features that kill the game as soon as you attach a debugger.
calltrace was originally built on features made avalible throgh a debugger so it still attaches with a debugger.
The debuggger only does a few small things that should be fairly easy to reimplement without a debugger.
Main things are that the debugger keeps track of breakpoints used for jumps and signalling to python code. It lists loaded modules and it sets up thread local storage for tracing in asm.
All those things can be replaced with other methods that does not relly on debugging.