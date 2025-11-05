# dump_exec_regions_for_ptxed.py
# Usage: python dump_exec_regions_for_ptxed.py <pid> <out_dir>
# Example: python dump_exec_regions_for_ptxed.py 1234 C:\tmp\pt_raw
#
# Produces files like: C:\tmp\pt_raw\exec_0x7ffd0dbb0000_0x10000.bin
# Prints/execs a ptxed line with --raw entries for every executable region.
#
# NOTE: requires hook_lib.py from:
# https://raw.githubusercontent.com/calledit/x86_x64_function_tracer/refs/heads/main/hook_lib.py

import os
import sys
import ctypes
import subprocess
import traceback
import re
import zlib

# import the helper library (must be in same folder or on PYTHONPATH)
import hook_lib as hl

CHUNK = 0x10000  # read 64KiB at a time

# --- Win32 constants ---
PAGE_EXECUTE             = 0x10
PAGE_EXECUTE_READ        = 0x20
PAGE_EXECUTE_READWRITE   = 0x40
PAGE_EXECUTE_WRITECOPY   = 0x80
PAGE_NOACCESS            = 0x01
PAGE_GUARD               = 0x100

MEM_COMMIT               = 0x1000

# --- ctypes setup ---
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", ctypes.c_uint16),
        ("wReserved", ctypes.c_uint16),
        ("dwPageSize", ctypes.c_uint32),
        ("lpMinimumApplicationAddress", ctypes.c_void_p),
        ("lpMaximumApplicationAddress", ctypes.c_void_p),
        ("dwActiveProcessorMask", ctypes.c_void_p),  # ULONG_PTR
        ("dwNumberOfProcessors", ctypes.c_uint32),
        ("dwProcessorType", ctypes.c_uint32),
        ("dwAllocationGranularity", ctypes.c_uint32),
        ("wProcessorLevel", ctypes.c_uint16),
        ("wProcessorRevision", ctypes.c_uint16),
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]

kernel32.GetSystemInfo.argtypes = [ctypes.POINTER(SYSTEM_INFO)]
kernel32.GetSystemInfo.restype  = None

kernel32.VirtualQueryEx.argtypes = [
    ctypes.c_void_p,  # HANDLE
    ctypes.c_void_p,  # LPCVOID (address)
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

def get_max_address():
    si = SYSTEM_INFO()
    kernel32.GetSystemInfo(ctypes.byref(si))
    return ctypes.cast(si.lpMaximumApplicationAddress, ctypes.c_void_p).value or (1 << (8 * ctypes.sizeof(ctypes.c_void_p))) - 1

def protect_is_executable(protect: int) -> bool:
    if protect == 0:
        return False
    # Keep guarded pages if they are executable – CFG thunks live there.
    exec_mask = (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                 PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
    return bool(protect & exec_mask)


def enumerate_needed_regions(hProc, addresses, pad_before=0, pad_after=0, require_committed=True):
    """
    Given a process handle and a set/iterable of addresses (ints),
    return merged memory regions that cover them:
        [(base, size, protect, state), ...]
    pad_before/after are extra bytes to include around each region (page-aligned).
    """
    PAGE = 0x1000

    def align_down(x): return x & ~(PAGE - 1)
    def align_up(x):   return (x + PAGE - 1) & ~(PAGE - 1)

    def vqe(addr):
        mbi = MEMORY_BASIC_INFORMATION()
        if kernel32.VirtualQueryEx(hProc, ctypes.c_void_p(addr),
                                   ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            return None
        base = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0
        size = int(mbi.RegionSize)
        prot = int(mbi.Protect)
        state = int(mbi.State)
        return base, size, prot, state

    # 1) Collect raw regions (optionally padded)
    raw = []
    meta = {}  # (base,size) -> (protect,state)
    for a in set(addresses):
        info = vqe(a)
        if not info:
            continue
        base, size, prot, state = info
        if require_committed and state != 0x1000:  # MEM_COMMIT
            continue
        if pad_before or pad_after:
            nb = align_down(base - pad_before if base >= pad_before else 0)
            ne = align_up(base + size + pad_after)
            base, size = nb, ne - nb
        raw.append((base, size))
        meta[(base, size)] = (prot, state)

    if not raw:
        return []

    # 2) Merge overlapping/adjacent regions
    segs = [(b, b + s) for (b, s) in raw]
    segs.sort()
    merged = []
    cs, ce = segs[0]
    for s, e in segs[1:]:
        if s <= ce:  # overlap or touch
            if e > ce:
                ce = e
        else:
            merged.append((cs, ce))
            cs, ce = s, e
    merged.append((cs, ce))

    # 3) Build result with best-available (protect,state) (optional: 0 if mixed)
    out = []
    for s, e in merged:
        size = e - s
        # Try to reuse a meta entry; otherwise query once for the merged base
        ps = meta.get((s, size))
        if ps is None:
            info = vqe(s)
            if info:
                _, _, prot, state = info
            else:
                prot = state = 0
        else:
            prot, state = ps
        out.append((s, size, prot, state))

    return out

def enumerate_executable_regions(hProc):
    """Yield (base, size, protect) for each committed, executable region."""
    max_addr = get_max_address()
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    granularity = 0x1000  # fallback advance if VQE fails

    while addr < max_addr:
        res = kernel32.VirtualQueryEx(hProc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if res == 0:
            # If VQE fails, advance by one page to avoid infinite loop
            addr += granularity
            continue

        base   = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0
        size   = int(mbi.RegionSize)
        state  = int(mbi.State)
        prot   = int(mbi.Protect)

        if state == MEM_COMMIT and size > 0 and protect_is_executable(prot):
            yield (base, size, prot)

        # advance
        if size <= 0:
            addr += granularity
        else:
            addr = base + size

def dump_region(hProc, base, size, out_dir, fname = None):
    if fname is None:
        fname = f"exec_0x{base:016x}_0x{size:x}.bin"
    out_path = os.path.join(out_dir, fname)
    try:
        #return out_path
        with open(out_path, "wb") as f:
            remaining = size
            offset = 0
            while remaining > 0:
                toread = CHUNK if remaining >= CHUNK else remaining
                buf = ctypes.create_string_buffer(toread)
                read = ctypes.c_size_t(0)
                ok = hl.ReadProcessMemory(
                    hProc,
                    ctypes.c_void_p(base + offset),
                    buf,
                    ctypes.c_size_t(toread),
                    ctypes.byref(read)
                )
                if not ok or read.value == 0:
                    # zero-fill on failure to keep contiguous file layout
                    f.write(b"\x00" * toread)
                else:
                    f.write(buf.raw[:read.value])
                    if read.value < toread:
                        f.write(b"\x00" * (toread - read.value))
                remaining -= toread
                offset += toread
        return out_path
    except Exception as e:
        print(f"Failed to dump region base=0x{base:016x} size=0x{size:x} -> {e}")
        traceback.print_exc()
        return None


def extract_ptxed_ips_from_string(output_text: str):
    """
    Parses ptxed output text (as a single string) and returns two sets:
        (decoded_ips, missing_ips)

    decoded_ips  -> all instruction addresses that ptxed reported (from lines like [tsc, ip])
    missing_ips  -> addresses that caused 'no memory mapped at this address' errors
    """
    decoded_ips = set()
    missing_ips = set()

    # Matches lines like: [3cfd7a8, 7ff742b35db7: ...]
    re_ip_line = re.compile(r"\[([0-9a-fA-F]+),\s*([0-9a-fA-F]+)\]")
    # Catch any hex address on a line that mentions 'no memory mapped'
    re_hex = re.compile(r"0x[0-9a-fA-F]+|[0-9a-fA-F]+")

    for line in output_text.splitlines():
        # Extract IPs from decoded lines
        m = re_ip_line.search(line)
        if m:
            try:
                ip = int(m.group(2), 16)
                decoded_ips.add(ip)
            except ValueError:
                pass

        # Extract addresses from missing-memory lines
        if "no memory mapped" in line.lower():
            for addr_str in re_hex.findall(line):
                try:
                    addr = int(addr_str, 16)
                    missing_ips.add(addr)
                except ValueError:
                    pass

    return decoded_ips, missing_ips


def main():
    """
    script to parse intel PT traces usefull for finding why something crached
    """
    if len(sys.argv) < 3:
        print("Usage: python dump_exec_regions_for_ptxed.py <pid> <out_dir>")
        return 1

    pid = int(sys.argv[1])
    out_dir = sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    
    print("FIND ADDRESES that ptxed wants")
    ptxed_path = r"C:\Users\calle\projects\libipt\bin\Release\ptxed.exe"
    
    # to find entry in to VectoredExceptionHandlerAddress use then stop parsing at that point
    # C:\Users\calle\projects\libipt\bin\Release\ptdump.exe --no-pad --lastip C:\dbg\intel_pt_trace.tpp|findstr {hex(VectoredExceptionHandlerAddress)}
    trace_path = r"C:\dbg\intel_pt_trace.tpp" # :0-0x000000000067b77c
    
    

    args = [ptxed_path, "--offset", "--event:ip", "--pt", trace_path]
    


    # open process
    try:
        hProc = hl.get_handle(pid)
    except Exception as e:
        print("Failed to open process:", e)
        return 1

    print(f"Enumerating executable regions for PID {pid} ...")

    count = 0
    total_bytes = 0
    has_errors = True
    dumped_regions = []
    while has_errors:
        print("---- round ----")
        input_args = list(args)
        input_args.append("--quiet")
        input_args.extend(dumped_regions)
        
        print(input_args)
        result = subprocess.run(
            input_args,
            capture_output=True,     # ← Captures stdout and stderr
            text=True,               # ← Decode bytes to str automatically
        )
        decoded_ips, missing_ips = extract_ptxed_ips_from_string(result.stdout + result.stderr)
        
        if len(missing_ips) == 0:
            has_errors = False
            break
        
        regions = enumerate_needed_regions(hProc, missing_ips)
        new_regions = False
        for base, size, prot, _ in regions:
            if base in []:
                continue
            print(f"Adding exec region base=0x{base:016x} size=0x{size:x} protect=0x{prot:x}")
            new_regions = True
            out_path = dump_region(hProc, base, size, out_dir, str(len(dumped_regions)))
            if out_path:
                count += 1
                total_bytes += size
                if len(dumped_regions) > 150:
                    has_errors = False #We still have errors but windows wont let us send any more arguments
                    break
                dumped_regions.extend(["--raw", f"{out_path}:0-0x{size:x}:0x{base:x}"])#:0x{base:x}
        if not new_regions:
            break
    
    try:
        hl.CloseHandle(hProc)
    except Exception:
        pass

    print(f"Dumped {count} executable regions (~0x{total_bytes:x} bytes).")
    
    input_args = args
    input_args.extend(dumped_regions)
    subprocess.run(input_args)  # no shell=True!
    
    

if __name__ == "__main__":
    sys.exit(main())
