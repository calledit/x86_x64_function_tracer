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
2. it injects a dll ( calltrace.dll ) that has fast tracing funcitons implemented.
3. It looks at the .exe .pdata information to find all functions.
4. It decompiles all functions and replaces all calls with jumps to trampolines that registers the call and then executes it, then registers that the call was finished.
5. It uses Minhook to instrument all functions. This means we also capture any time a function is enterd. Which is necesicary to capture callbacks from external librarys.
6. Using a specially crafted trampoline that modifies the return address we also capture when the function returns.

## Current isues
1. Currently all tracing is still done using brakpoints this is to slow (so slow that some functions crach as they have race conditions with other threads).
	The solution to this is to move the actuall tracing in to calltrace.dll removing the need for tracing using breakpoints.
2. MinHook can not instrument functions that are very short, for example a function that only consists of a single ret instruction.
	The solution to this is to either get rid of MinHook. Or to implement a work around for such functions.
3. Some calls like "call rax" is to short (only 2 bytes long) to be replaced by a long jump you could replace it with a short jump (but it can only jump 127 bytes forward or back).
	The current solution to this is to replace such instructions with a 0xCC breakpoint and then implement the jump in the debuger. This works but is slow.
4. When the work around for nr 3 is used MinHook will sometimes relocate the 0xCC breakpoint when this happens we lose track of the brak point and can no longer do the jump properly.
	The solution to this is either to get rid of MinHook or to run MinHook first then instrument the MinHook trampoline or to somehow track where MinHook moved the breakpoint.
	Given the issues with MinHook the best solution tís probaly to reimplement the MinHook injection code in python.
 




# Old README (will be removed as new one is filled in) 
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

I have been unable to get callgrind to work partly due to how modern games tend to use launchers that verify the executable. I have not been able to use DynamoRIO mostly cause i struggle to understand where to begin.

I would like to be able to attach after the process has spawned either by replacing a dll or simply by attaching a debugger to the process id.

## recompling_tracer.py
Does what trace.py but tries to be faster by not using breakpoints. Currelty work in progress.
Using recopilation it can:
Capture most calls, as most calls are 5 bytes or longer (BUT NOT ALL), and if you can capture the call you can capture the exit breakpoint ie. type 1 & 2. Type 3 can be captured sometimes. and type 4 cant be captured using recompilation. As the ret instruction is only 1 byte long....

I am thinking of using something like MinHook to capture type 3 & 4 as it is more stable than anything i will be able to build in a short while, but i am not sure about what implications using MinHook might have to the rest of the code yeat.
If you only use minhook you run in to issues with librarys calling themselfs. Which we are not intressted in; but that should be able to be filterd out.
You would first set break points on all calls. Then as the call is trigered you would register to where it was going then hook that function. After the function was hooked you would remove the breakpoint. As long as each call always calls the same function this would work great. My guess is that each call calls the same function 99.999999999% of the time, BUT SOMETIMES IT WONT. We could just set breakpoints on the ones that potentially could have this issue.
I belive it will have issues with tail call optimiations.
I found the solution to tracking tail call optimatations. You simply wrap each call in a second call.
```

MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal);
pTarget is the address of the function we want to track.
pDetour is the address to the place where the jump table function is.
ppOriginal is a address to a function setup by MinHook, a function that "goes to" the original function.

pDetour would look somehting like:

int 3 # to track function enter, By checking the stack pointer and stack pointer value we might even be able to figure out if this is a tail call optimized call.
call ppOriginal
int 3 # to track function return
ret

This allows one to track the entry and return of each call. But it does make tail call optimizations less effective. So some programs that use recursion ALLOT might break.
```
They way this would be used would be:
1. Find all function in the .ptable
2. Find all calls in each function. Replace them with jumps if longer than 5 bytes. Otherwise replace with int 3 otherwise.
3. Setup code that moves the instruction pointer to the jump table as the int 3 is reached. That is the int 3 will work like a (very slow) jump.
4. Hook all the functions.

The slow jump sucks but it will work. It will need to occur as the instruction call rax or call [rax+8] is 2 and 3 bytes long. In many cases you can probably find places around the call that can be replaced.
If the int 3 is moved by MinHook that strategy will fail.


## trace.py
trace.py traces all calls and rets in a function. Earlier versions tried to use shortcuts but they all had various issues. The point of trace.py is to as good as you are going to get a call tracer when it comes to accuracy. Speed is important but it suposed to be refernce for accuracy.

The main call tracing in trace.py is built on four types of breakpoints.
1. Making a call. Each call instruction gets a breakpoint.
2. Returning from a call. All instructions directly following a call gets a breakpoint.
3. Entering a function. The entrypoint of each function gets a breakpoint.
4. Exiting a function. Each ret instruction gets a breakpoint.

Breakpoint type 1 & 2 are the most important ones. You can trace an executable without type 3 & 4 but the trace will be less accurate. If you miss type 3 and not type 4 you may miss certain callbacks from external libraries (callbacks to certain functions that dont have their own ret instruction) and you will not be able to capture arguments to callbacks and the order of callbacks will be imposible to recover in certain cases. If you miss type 3 & 4 you may again miss certain callbacks and again no arguments. If you miss type 4 but not type 3 you will miss certain callbacks to that are executed more than once.

Breakpoint type 3 is only made posible when you have a function map a map that declares where each function starts. On linux a function map can be generated by scaning the executable for entry instructions (that inserts framepointers) on windows (which trace.py is primarly made for) this map is found in the .pdata section of the executable/module. You can also dynamicly generate a partial function map by running the executable with breakpoint type 1 & 2 and recording all call targets which may be usefull if you dont have entry instrucitons or the .pdata table has been striped.

#### Non obvoius issues
Are entires in the .pdata section trully functions? Ie does the stack pointer always point to the return address on execution entry in to a .pdata section.
I know they are not allwys called direcly but sometimes they are jumped to.

Certain functions dont use their own ret instruction but jump to a external library and let that library return. This means that a entry breakpoint may not allways be paired with a exit breakpoint. Since a function can contain a jump to its own entry we only count the first time a entry breakpoint is made and this count is reset when exiting the function. This means that functions that dont have their own ret and are used as callbacks more than once in a row is imposible to track. This could be solved by putting a hardware breakpoint on the memmory address of the return address. But then we need to know the true return address.

But this goes back to hte first point we cant know if a entry in to a function that is not directly preceded by a traced call is actually a call and if the stack pointer is thus pointing to a return address. It may be a jump that preceded the entry. If it is there is no return address then the stack pointer will be pointing to some random address that is not the function return address at all.



##### Some improvments
- One thing that can be done that works 100% of the time is to single step the execution, but that is simply to slow. So is not an improvment.
- Adding a memmory access hardwarebreakpoint on access to the stack. This might be a good idea, but threding might be problematic.
- If you are exiting from an external callback and the stackpointer is larger than it was on you last breakpoint then you know the callback was made from somewhere inside that last call. Mabye it is true that the call back was made from inside the last API i call regadless of the stackpointer. But mabye interupts could be a counter example but i dont know how they work on x64. This cant be done as there are many calls that use alternative stacks for callbacks.

## Making it fast
Instead of breakpoints we need to alter the opcodes and wrap functions and add jump to tables and stuff like that.

For breakpoint type 1 and 2 this revolves around replacing call instructions with instructions that allow us to wrap the call instruction.
calls that are 5 bytes or longer are easy to replace you simply switch them out for a jump to a place where you can do whatever you want then jump back.

For calls that are 2 and 3 bytes long it gets tricker. The only jump you can fit in that is a short jump (which is 2 bytes long), a short jump only allows jumping forward or backwards 127 bytes.
And 127 bytes is not enogh to jump to a place where there is free memmory.

I see two posible solutions to this; both of them have issues.

1. Use the area of the instructions just ahead of the call.
   For example the instructions:
   ```
   48 8b 01        MOV        RAX,qword ptr [param_1->unused]
   0e ff 10        CALL       qword ptr [RAX]
   ```
Gives you 6 usable bytes those instructions can be moved a new area and a jump can be inserted to that area.
This requires that the instructions are not doing relative jumps or have recerences to RIP (lets call these replacable instructions).
It also requires that no other code jumps direcly to the call. Cause after replacement that jump will end up in the midle of an instruction.

2. The other way to solve this is to ove the call instruction to a new memory region where it can be wraped. Then to search the surunding area of the call for replacable instructions. Then we move those instructions to a new memmory region and insert jump to the new memmory region and second jump to where wraped call is the area of the replaced instrucitons. Finnaly we replace the orginal call and place a shortjump to the long call of the wraped call instruction. This has the same issue as the first one, that jumps to thes instructions will fail result in segfaults.

The first one will proably work for most places.
And using a breakpoint for the new places where we cant find a solution can work as a fallback.

Tracing breakpoint type 3 will be similar to how the short version of call was done you will take a number of instrucitons move them and pray that ther are no jumps in to the instuctions. If you cant move the instructions you will have to rely on breakpoints.


Tracing breakpoint type 4 can only be effeictly solved by wraping the entire call in a new call instruction. The issue with this is jumps IE .pdata fucnctions that are not functions. Not sure if this is a thing. Anyway tracing breakpoint type 4 is the least important type to trace. We might not even need to do it.

If you have access to Intel Processor Trace(hardware based instruction logging) Finding where a ret came from or if fucntion was called or jumped to should be easy.

Next up is recreating the tracer in C and importing those C functions as A DLL.

We will need 4 exported C functions:
* function_enter_break_point(inside_function_id)
* function_exited_break_point(inside_function_id, call_num)
* function_ret_break_point(inside_function_id)
* function_goto_break_point(inside_function_id, code, call_num)
  
We can probably decompose code in function_goto_break_point before we get to c. Mabye decompose in to something like (bool)is_pointer (int)offset (int)registervalue. Or do the full decomposition in asembly and have a (int)target_function argumnet.

We will also need to export something like
* export_stack_trace()
* reset_stack_trace()

## Work so far

### Branch tracing

Initially i tried implementing this as a full fledged dynamic instrumentation tool on top of a debugger. This code is located in [track_calls_using_instruction_tracing.py](track_calls_using_instruction_tracing.py) Instead of stepping each instruction in the debugger, decompiles blocks of the executable and adds breakpoints att all branches. Then when it gets to those branches it adds new breakpoints. This continues forever.
This proved to be to slow, especially considering the use of python(which is very slow) as the debugger scripting engine.

### Call tracing
Th file [track_calls_using_debug_events.py](track_calls_using_debug_events.py) also traces using breakpoints but it decompiles the entire executable module by module on startup then adds breakpoints on the main executable calls and returns. This has proved to be an effective learning platform. However it will not work if the executable is using self-modifying code.

Both of these implementations have issues with multithreaded code as the debugger will catch any thread and the code has not been written to take that in to account.


We also have [trace_basic.py](trace_basic.py) trace_basic.py uses the Pdata to find and add breakpoints at the start och each function and then it disasembles each function and ads breakpoints at all ret(return) instrucitons.

### next step
I have been thinking of new solution that does not capture the call trace as it happens.
It works in reverse based on the assumption that the code you are interested in will run in a loop.

Basically you start by selecting a API call to a dll (direct X) for example.
1. You add a breakpoint in that API call.
2. You look at the return adress then decompile from that adress forward until you hit a ret instruction. (techinically this might fail as the code may jump away so technically you need to trace every jump after this. But assuming a normal boring compiler just decompiling from that point untill there is ret should work)
3. You add a breakpoint at that ret instruction
4. When that breakpoint hits, you obtain the return address from the stack which is from where the current function was called.
5. Then you step one instruction back from that return address and add a breakpoint.
6. Now we hope that the function is run in a loop and that the breakpoint is called again.
7. When these breakpoints hit this is when we now where the calling function starts.
8. Rinse and repeat until you are at the top level.

You may want to capture multiple of each break point as each function may be called from multiple locations.

### Update
Built the loop based tracer see [track_calls_backwards_from_dll.py](track_calls_backwards_from_dll.py)
It works as good as it will work. The issue that makes it not work quite right is that the return address is not allways corect.
Pressumably there are places where there are jumps to the begining of a function this makes it so that the top of the stack is not always a return address when the begining of a function hits. Or some function is purposly manipulating the stack.

To solve this you would need to trace at the location of call rather than in the function beeing called.

PS. None of these methods will capture call backs in a good way.

If we are tracing at the call we could probably speed things upp by not using breakpoins but instead allter the call so that it goes to a location in the empty space infront of the function. That way we can track the function with a native funcion that is being called or jumped to from that place. DynamoRIO is starting to look quite nice at this point.



## Current work

- [x] The symbol loader from winappdbg is extremely slow and very very bad it almost never finds the true function. Implemented a new symbol loader which loads .pdb files.
- [x] Initially we looked at directX 9 due to its simplicity, we need to start looking at the reversing of dx11. Maybe we should build a text dx11 project.
- [ ] We will want to be able to decode the arguments of the API functions we add breakpoints to so that we can differentiate different rendering passes for example. Need to figure out how to do that.
- [X] Implement the loop based debugger


# Stereo injection
Many stereo injection plugins for games does alternative frame rendering; that is they don't alter the games render code. The mods simply move the camera every other frame and sends every other frame to each eye.
This causes almost instant nausea and is a horrible experience. It is better to simply not have stereoHead tracking at all. Head tracking is 80% of the experience so if you can manage that it is often enough.

The beter way is to actually render the game twice. This can be done in two ways.
* Traditional Rendering:
In a basic setup, you’d indeed update the view/projection matrices for each eye and issue separate draw calls. This means the scene is rendered twice—once for each eye.
* Single-Pass Stereo (Multi-View Rendering):
With advanced techniques, you can leverage multiple viewports along with instancing. In single-pass stereo, you submit your geometry once and use the GPU to transform it twice (or more) for each eye, each using a different viewport and camera matrix. This reduces CPU overhead by avoiding multiple draw calls even though conceptually, two different views are being produced.

Both generate the same image but **Single-Pass Stereo** is more efficient so will in theory allow for higher FPS. But it can also be allot harder to patch in since you need to modify shader code as well as the normal game code. **Traditional Rendering** may be easy to pull off depending argumentson how the games rendering works.
If you are lucky like in the example dx11 file in [example_simple_dx11_render.cpp](example_simple_dx11_render.cpp) you have a clean render function all you need to do is find it, change the camera matrix and run the function an extra time on each loop.
If you are not able to do that you need to capture all DX11 calls.
Then either save their buffers and argumensts then run them again or copy all the arguments and buffers and simultaneously run them in a different dx11 instance.

