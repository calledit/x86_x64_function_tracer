# X64 call tracer
**X64 Call Tracer** is a tool for tracing function calls in x64 Windows executables.  
Its goal is simple: capture *what* calls *what* (and optionally when functions return), even when debug symbols are missing — useful for reverse engineering, analyzing game engines, or understanding large unfamiliar binaries.


# Motivation

Knowing the exact call trace of a binary (which code paths call which addresses / functions) makes it far easier to locate functions and understand program structure without symbols.

Compiler optimizations, aggressive inlining, self-modifying code, and dynamic code generation can break complete tracing — this is a practical tool, not a magic bullet.

Existing tools (Callgrind/Valgrind, DynamoRIO, Intel PIN, Frida) can provide similar functionality, but are often heavyweight, fragile with protected launchers, or slow for complex binaries.  
**X64 Call Tracer** focuses narrowly on *function-call tracing* to stay smaller and easier to attach to running processes.


## Features (current)

- **`function_tracer.py`** (main):
  1. Spawns a new process **or** attaches to a running one (by PID or name).
  2. Injects a helper DLL (`calltrace.dll`) into the target.  
     The DLL handles trace buffering, memory allocation, and saving traces to disk.
  3. Parses the executable’s `.pdata` section to discover functions.
  4. Instruments functions:
     - Injects a trace point at the beginning of each function.
     - Replaces direct `call` sites with jumps to trampolines that record the call, invoke the original target, and record completion.
     - Optional: a “return-address modification” mode that captures when functions return.  
       ⚠️ This is **experimental** and may break some functions, so it’s **disabled by default**.
  5. Once injection is complete, the Python process exits; the target process continues and writes traces to disk during execution.

- **`parse_trace.py`**:
  - Converts raw `.trace` files into a human-readable or analyzable format.

## Usage
```bash
# Capture trace
python function_tracer.py {name of exeutable to attach to or spawn, or pid}

# View trace
python parse_trace.py --file output\{executable}.trace --modules "output\{executable}_modules.json" --map "output\{executable}_map.json
```

## Requirements
```bash
pip install pefile keystone-engine capstone>=6.0.0a4 pdbparse
```

## Limitations & Caveats

- **Not fully transparent** — instrumentation tries to be as transparent as posible but  
  self-modifying code, JITs, or anti-tamper checks may detect or break under it.
- **Performance penalty** — tracing every call is expensive.  
  Use exclusions to remove hot functions or utility calls.
- **Incomplete coverage** — inlining, tail calls, or dynamic code can escape detection.
- **Launchers / anti-cheat** — some executables verify integrity and may reject injection.
- **Platform** — designed for **x64 Windows**
- **Data in code section** - some libraries put data in the .code section, this may lead to data beeing interpreted as code.


## Reliability Tips

1. Start with a simple short trace to verify setup.
2. Run, reproduce behavior, inspect the generated trace.
3. If the target crashes after instrumentation:
   - Look at c:\dbg\debug_output.txt and other output files for exception info to find the issue.
   - Add crashing functions to `function_exclusions`.
   - Re-run and iterate.
4. Exclude hot-loop functions to reduce slowdown.
5. Keep return-address mode disabled unless you need exact returns.

## Configuration

- **`function_exclusions`** — a list of functions (addresses/names) that should *not* be traced.  
  Useful for avoiding crashes or excessive slowdown.

- **Trace output** — binary `.trace` files written to `output/`.  
  Parse them using `parse_trace.py` for inspection or graph generation.


## Next steps
- Add feature to create a map of all calls.
- Build tool that analyses a captured trace and builds a call graph.
- Build tool that uses the call graph to supplement the call map with info about dynamic calls.

## Acknowledgements

Inspired by dynamic instrumentation frameworks such as:
- **Valgrind / Callgrind**
- **DynamoRIO**
- **Intel PIN**
- **Frida**

Each has its strengths and trade-offs.  
**X64 Call Tracer** narrows the problem space to stay lightweight and more flexible for attaching to arbitrary processes.
