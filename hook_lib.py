import ctypes
from ctypes import wintypes
import subprocess
import sys
import os
import time
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KsError
import struct, traceback
import capstone

# ---- Win32 libs ----------------------------------------------------------
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

# ---- Constants -----------------------------------------------------------
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03
MAX_PATH = 260
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

# ---- Helper: Process enumeration (Toolhelp) ------------------------------
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
CreateToolhelp32Snapshot.restype = wintypes.HANDLE

Process32FirstW = kernel32.Process32FirstW
Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
Process32FirstW.restype = wintypes.BOOL

Process32NextW = kernel32.Process32NextW
Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
Process32NextW.restype = wintypes.BOOL


CloseHandle = kernel32.CloseHandle


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       wintypes.LPVOID),
        ("AllocationBase",    wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
    ]

OpenProcess = kernel32.OpenProcess
VirtualAllocEx = kernel32.VirtualAllocEx
WriteProcessMemory = kernel32.WriteProcessMemory
ReadProcessMemory = kernel32.ReadProcessMemory
CreateRemoteThread = kernel32.CreateRemoteThread
WaitForSingleObject = kernel32.WaitForSingleObject
GetExitCodeThread = kernel32.GetExitCodeThread
VirtualProtectEx = kernel32.VirtualProtectEx
CloseHandle = kernel32.CloseHandle
FlushInstructionCache = kernel32.FlushInstructionCache
VirtualQueryEx = kernel32.VirtualQueryEx
VirtualProtectEx = kernel32.VirtualProtectEx


#Fix issues
VirtualAllocEx.restype = ctypes.c_ulonglong
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
kernel32.GetProcAddress.restype = ctypes.c_void_p
CreateRemoteThread.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
CreateRemoteThread.restype = wintypes.HANDLE
VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
VirtualProtectEx.restype = wintypes.BOOL
WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
WaitForSingleObject.restype = wintypes.DWORD
GetExitCodeThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
GetExitCodeThread.restype = wintypes.BOOL
kernel32.FlushInstructionCache.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t]
kernel32.FlushInstructionCache.restype = wintypes.BOOL
ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL
VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
VirtualQueryEx.restype  = ctypes.c_size_t
VirtualProtectEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
VirtualProtectEx.restype  = wintypes.BOOL

ntdll = ctypes.WinDLL("ntdll")
NtSuspendProcess = ntdll.NtSuspendProcess
NtResumeProcess  = ntdll.NtResumeProcess


MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE    = 0x40
PAGE_WRITECOPY            = 0x08
PAGE_GUARD                 = 0x100
PAGE_NOACCESS              = 0x01
PAGE_READONLY              = 0x02
PAGE_EXECUTE_WRITECOPY     = 0x80
INFINITE = 0xFFFFFFFF
PROCESS_ALL = 0x1F0FFF

MEM_FREE                  = 0x10000

MEM_IMAGE                 = 0x1000000
MEM_MAPPED                = 0x40000
MEM_PRIVATE               = 0x20000
WAIT_OBJECT_0 = 0x00000000




# Initialize Keystone for x64.
ks = Ks(KS_ARCH_X86, KS_MODE_64)


def asm(CODE: str, address: int = 0) -> bytes:
    """Assemble x64 code at the given address using Keystone."""
    try:
        encoding, count = ks.asm(CODE, address)
    except KsError as e:
        # e.errno is a keystone error enum, e.count is # of statements assembled
        print(CODE, address)
        print(f"Keystone error: {e} (errno={getattr(e, 'errno', None)}, " f"count={getattr(e, 'count', None)})")
        traceback.print_stack()
        exit()
    return bytes(encoding)

def get_pids_by_name(exe_name):
    """Return list of PIDs whose exe name matches exe_name (case-insensitively).
       exe_name can be 'notepad.exe' or a full path; matching is done on basename."""
    target = os.path.basename(exe_name).lower()
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == wintypes.HANDLE(-1).value:
        raise OSError("CreateToolhelp32Snapshot(Process) failed: %d" % ctypes.get_last_error())
    pids = []
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            name = pe.szExeFile.lower()
            if name == target:
                pids.append(int(pe.th32ProcessID))
            ok = Process32NextW(snap, ctypes.byref(pe))
    finally:
        CloseHandle(snap)
    return pids

# ---- Module enumeration (PSAPI + Toolhelp fallback) ----------------------
# PSAPI-based functions (preferred)
def list_modules_psapi(hProc, base_name = False):

    try:
        # allocate large array of HMODULE pointers
        arr_size = 4096
        HMODULE_ARR = (ctypes.c_void_p * arr_size)
        arr = HMODULE_ARR()
        cb_needed = wintypes.DWORD()

        EnumProcessModulesEx = psapi.EnumProcessModulesEx
        EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
        EnumProcessModulesEx.restype = wintypes.BOOL

        if not EnumProcessModulesEx(hProc, ctypes.cast(arr, ctypes.POINTER(ctypes.c_void_p)), ctypes.sizeof(arr), ctypes.byref(cb_needed), LIST_MODULES_ALL):
            raise OSError("EnumProcessModulesEx failed: %d" % ctypes.get_last_error())

        count = int(cb_needed.value // ctypes.sizeof(ctypes.c_void_p))
        if count == 0:
            return {}

        if count > arr_size:
            HMODULE_ARR2 = (ctypes.c_void_p * count)
            arr2 = HMODULE_ARR2()
            if not EnumProcessModulesEx(hProc, ctypes.cast(arr2, ctypes.POINTER(ctypes.c_void_p)), ctypes.sizeof(arr2), ctypes.byref(cb_needed), LIST_MODULES_ALL):
                raise OSError("EnumProcessModulesEx(2) failed: %d" % ctypes.get_last_error())
            arr = arr2

        # GetModuleFileNameExW
        GetModuleFileNameExW = psapi.GetModuleFileNameExW
        GetModuleFileNameExW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
        GetModuleFileNameExW.restype = wintypes.DWORD

        # GetModuleInformation
        class MODULEINFO(ctypes.Structure):
            _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                        ("SizeOfImage", wintypes.DWORD),
                        ("EntryPoint", ctypes.c_void_p)]
        GetModuleInformation = psapi.GetModuleInformation
        GetModuleInformation.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MODULEINFO), wintypes.DWORD]
        GetModuleInformation.restype = wintypes.BOOL

        out = {}
        buf = ctypes.create_unicode_buffer(MAX_PATH)
        for i in range(count):
            hmod = arr[i]
            path_len = GetModuleFileNameExW(hProc, hmod, buf, MAX_PATH)
            path = buf.value if path_len else "<unknown>"
            base = None
            size = None
            try:
                mi = MODULEINFO()
                if GetModuleInformation(hProc, hmod, ctypes.byref(mi), ctypes.sizeof(mi)):
                    base = int(mi.lpBaseOfDll) if mi.lpBaseOfDll else None
                    size = int(mi.SizeOfImage)
            except Exception:
                pass
            key = path
            if base_name:
                key = os.path.basename(key).lower()
            out[key] = {"path": path, "base": base, "size": size}
        return out
    finally:
        pass

# Toolhelp-based module listing
class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * MAX_PATH)
    ]

Module32FirstW = kernel32.Module32FirstW
Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
Module32FirstW.restype = wintypes.BOOL
Module32NextW = kernel32.Module32NextW
Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
Module32NextW.restype = wintypes.BOOL


def enumerate_modules(hProc, do_until_sucess = False, base_name = False):
    """Try PSAPI first; fallback to Toolhelp."""
    mods = False
    while not mods:
        mods = list_modules_psapi(hProc, base_name)
        if mods or not do_until_sucess:
            break
        time.sleep(0.01)
    
    return mods


# ---- Start process helper ------------------------------------------------
def try_start_executable(exe_path):
    """
    Try to start exe_path using subprocess.Popen.
    Returns PID if started and appears in process list within timeout, else None.
    """
    exe_folder = os.path.dirname(exe_path)
    # If exe_path is just a name, rely on PATH / cwd
    try:
        proc = subprocess.Popen([exe_path], cwd=exe_folder, shell=False)
    except FileNotFoundError as e:
        # not found on PATH / as-is
        return None, f"Could not start '{exe_path}': {e}"
    except Exception as e:
        return None, f"Failed to start '{exe_path}': {e}"

    return proc.pid

# ---- CLI -----------------------------------------------------------------
def print_modules(mods):

    if not mods:
        print(f"No modules.")
        return
    print(f"--- modules ---")
    for k in mods:
        m = mods[k]
        base = ("0x%016X" % m["base"]) if m.get("base") else "N/A"
        size = str(m.get("size")) if m.get("size") else "N/A"
        print(f"{base:>18}  {size:>8}  {m['path']}")
    print("")
    
    
def get_remote_function(hProc, module_name, func_name):
    # Determine remote address of LoadLibraryA via RVA method:
    # local kernel32 base and local LoadLibraryA address
    local_k32 = ctypes.WinDLL(module_name, use_last_error=True)
    local_k32_handle = local_k32._handle
    local_loadlib = kernel32.GetProcAddress(local_k32_handle, func_name.encode('utf-8'))
    if not local_loadlib:
        raise OSError("GetProcAddress("+func_name+") failed locally")

    local_rva = int(local_loadlib) - int(local_k32_handle)

    # find remote kernel32 base via enumerate_modules
    remote_k32_base = None
    mods = enumerate_modules(hProc, base_name = True)
    if "kernel32.dll" in mods:
        remote_k32_base = mods[module_name+".dll"]["base"]

    if not remote_k32_base:
        raise OSError("Failed to locate kernel32/kernelbase base in target process")

    remote_loadlib = int(remote_k32_base) + int(local_rva)
    return remote_loadlib

def load_library_in_remote(hProc, dll_path: str, wait: bool = True):
    """
    Load dll_path into the remote process pid.
    Returns a dict with information about the loaded module:
      {"path": str, "base": int, "size": int}
    If the DLL is already loaded, returns the existing module info.
    Raises OSError on failure.
    """


    try:
        # write the dll path into remote process
        dll_bytes = dll_path.encode('ascii') + b'\x00'
        remote_str = VirtualAllocEx(hProc, None, len(dll_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote_str:
            raise OSError(f"VirtualAllocEx(dllpath) failed: {ctypes.get_last_error()}")
        
        written = ctypes.c_size_t()
        ok = WriteProcessMemory(hProc, remote_str, dll_bytes, len(dll_bytes), ctypes.byref(written))
        if not ok or written.value != len(dll_bytes):
            raise OSError(f"WriteProcessMemory(dllpath) failed: {ctypes.get_last_error()} wrote={getattr(written,'value',None)}")
        
        remote_loadlib = get_remote_function(hProc, "kernel32", "LoadLibraryA")
        # create thread to call LoadLibraryA(remote_str)
        hThread = CreateRemoteThread(hProc, 0, 0, remote_loadlib, remote_str, 0, None)
        if not hThread:
            raise OSError(f"CreateRemoteThread(LoadLibraryA) failed: {ctypes.get_last_error()}")

        if wait:
            WaitForSingleObject(hThread, INFINITE)
            # optionally can read exit code but it's 32-bit only
            #exit_code = wintypes.DWORD()
            #GetExitCodeThread(hThread, ctypes.byref(exit_code))
            
        return

    finally:
        pass

def get_handle(pid):
    # open process
    hProc = OpenProcess(PROCESS_ALL, False, int(pid))
    if not hProc:
        raise OSError(f"OpenProcess({pid}) failed: {ctypes.get_last_error()}")
    return hProc
    
def _query_mbi(hProcess, addr):
    mbi = MEMORY_BASIC_INFORMATION()
    res = VirtualQueryEx(hProcess, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if res == 0:
        print("adress: ", addr)
        raise ctypes.WinError(ctypes.get_last_error())
    return mbi

def write(hProcess, lpBaseAddress: int, lpBuffer: bytes, do_checks = True) -> int:
    """
    Writes to the memory of the process `hProcess` starting at `lpBaseAddress`.
    Temporarily adjusts page protections if needed.

    :param hProcess: HANDLE to the process (open with PROCESS_VM_WRITE | PROCESS_VM_OPERATION).
    :param lpBaseAddress: integer base address to start writing to.
    :param lpBuffer: bytes to write.
    :return: number of bytes actually written (may be less than len(lpBuffer)).
    :raises: ctypes.WinError on fatal failures (e.g. VirtualQueryEx).
    """
    if not lpBuffer:
        return 0
    
    bytes_total = len(lpBuffer)
    bytes_written_total = 0
    org_lpBaseAddress = lpBaseAddress
    
    if do_checks:
        # Query memory info for the target address
        mbi = _query_mbi(hProcess, lpBaseAddress)

        # Check that this region has content (committed)
        if not (mbi.State & MEM_COMMIT):
            # mirror original behavior: consider invalid address
            raise ctypes.WinError(ERROR_INVALID_ADDRESS)

        # Decide whether we need to change protection to allow writing
        need_protect = False
        new_prot = None

        # If image or mapped, use WRITE_COPY semantics
        if mbi.Type == MEM_IMAGE or mbi.Type == MEM_MAPPED:
            new_prot = PAGE_WRITECOPY
            need_protect = True
        else:
            # if existing protection is writable, we don't need to change
            prot = mbi.Protect
            # prot flags that indicate writable include PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_WRITECOPY
            writable_flags = (PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_WRITECOPY)
            if prot in writable_flags:
                need_protect = False
                new_prot = None
            else:
                # if executable but not writable, escalate to RXW
                # this mirrors the original: for executable pages, use PAGE_EXECUTE_READWRITE
                exec_flags = (PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE)
                if prot in exec_flags:
                    new_prot = PAGE_EXECUTE_READWRITE
                else:
                    # default fallback: PAGE_READWRITE
                    new_prot = PAGE_READWRITE
                need_protect = True


        old_prot_value = wintypes.DWORD(0)
        protected = False

        # Try to change protection if needed (best-effort)
        if need_protect and new_prot is not None:
            ok = VirtualProtectEx(hProcess, ctypes.c_void_p(org_lpBaseAddress), ctypes.c_size_t(bytes_total), new_prot, ctypes.byref(old_prot_value))
            if not ok:
                # best effort: if we fail, we proceed but warn via exception or just continue like original did
                # We'll raise a warning-like exception? To keep parity with original, just proceed without protection change.
                protected = False
            else:
                protected = True
    else:
        protected = False
    try:
        # Write in a loop until complete or until WriteProcessMemory writes zero/fails
        mv = memoryview(lpBuffer)
        remaining = bytes_total
        offset = 0

        while remaining > 0:
            chunk = mv[offset: offset + remaining]  # memoryview slice
            # Create a contiguous buffer for this chunk
            buf = (ctypes.c_ubyte * len(chunk)).from_buffer_copy(chunk.tobytes())
            written = ctypes.c_size_t(0)
            ok = WriteProcessMemory(hProcess,
                                    ctypes.c_void_p(lpBaseAddress + offset),
                                    ctypes.byref(buf),
                                    ctypes.c_size_t(len(chunk)),
                                    ctypes.byref(written))
            if not ok:
                # WriteProcessMemory failed — break and return what we have
                break
            if written.value == 0:
                # Nothing written (shouldn't usually happen) — break
                break
            offset += written.value
            remaining -= written.value
            bytes_written_total += written.value

    finally:
        # Restore original protection if we changed it
        if protected:
            tmp = wintypes.DWORD(0)
            VirtualProtectEx(hProcess, ctypes.c_void_p(org_lpBaseAddress), ctypes.c_size_t(bytes_total), mbi.Protect, ctypes.byref(tmp))

    return bytes_written_total

def alloc_and_write_remote(hProc, data: bytes, make_executable: bool = True, try_r_x_first: bool = True):
    size = len(data)
    remote = VirtualAllocEx(hProc, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not remote:
        raise OSError(f"VirtualAllocEx failed: {ctypes.get_last_error()}")
    return write_remote(hProc, remote, data, make_executable, try_r_x_first)

def hexadecimal(data, separator=""):
        """
        Convert binary data to a string of hexadecimal numbers.

        :param data: Binary data.
        :type  data: str

        :param separator: Separator between the hexadecimal
            representation of each character.
        :type  separator: str

        :return: Hexadecimal representation.
        :rtype:  str
        """
        return separator.join(["%.2x" % c for c in data])


def _is_protection_readable(prot: int) -> bool:
    """Return True if protection flags include readable permissions and are not guard/noaccess."""
    if prot & PAGE_GUARD:
        return False
    if prot == PAGE_NOACCESS:
        return False
    readable = (PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
                PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)
    return any(prot & flag == flag for flag in readable)


def read(hProcess, lpBaseAddress: int, nSize: int) -> bytes:
    """
    Read nSize bytes from process hProcess starting at lpBaseAddress.
    Validates the memory regions are committed and readable.
    Raises ctypes.WinError on error or if address is invalid.
    Returns the bytes read (length == nSize) or raises.
    """
    if nSize <= 0:
        return b""

    addr = int(lpBaseAddress)
    end_addr = addr + int(nSize)
    out_chunks = []

    # Walk through memory regions covering [addr, end_addr)
    cur = addr
    while cur < end_addr:
        mbi = MEMORY_BASIC_INFORMATION()
        res = VirtualQueryEx(hProcess, cur, ctypes.byref(mbi), ctypes.sizeof(mbi))
        if res == 0:
            # Could not query — treat as invalid address
            raise ctypes.WinError(ERROR_INVALID_ADDRESS)
        region_base = int(ctypes.addressof(mbi.BaseAddress.contents)) if isinstance(mbi.BaseAddress, ctypes.c_void_p) else int(ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0)
        # Compatibility: better to use value conversion:
        region_base = int(ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value)
        region_size = int(mbi.RegionSize)
        region_end = region_base + region_size

        # Ensure the region is committed
        if not (mbi.State & MEM_COMMIT):
            raise ctypes.WinError(ERROR_INVALID_ADDRESS)

        # Ensure readable protections
        if not _is_protection_readable(mbi.Protect):
            raise ctypes.WinError(ERROR_INVALID_ADDRESS)

        # How many bytes we can read from this region
        offset_into_region = cur - region_base
        to_read = min(end_addr, region_end) - cur
        if to_read <= 0:
            # shouldn't happen, but prevent infinite loops
            raise ctypes.WinError(ERROR_INVALID_ADDRESS)

        # Allocate buffer and read
        buf = (ctypes.c_ubyte * to_read)()
        read_here = ctypes.c_size_t(0)
        ok = ReadProcessMemory(hProcess,
                               cur,
                               ctypes.byref(buf),
                               ctypes.c_size_t(to_read),
                               ctypes.byref(read_here))
        if not ok:
            # API failed
            raise ctypes.WinError(ctypes.get_last_error())

        if read_here.value != to_read:
            # partial read — treat as error to match original behavior
            raise ctypes.WinError(ctypes.get_last_error())

        # convert to bytes and append
        out_chunks.append(ctypes.string_at(ctypes.addressof(buf), to_read))

        # advance
        cur += to_read

    # join chunks and return
    result = b"".join(out_chunks)
    if len(result) != nSize:
        raise ctypes.WinError()  # defensive
    return result

def disasm(address, code):
    # Get the constants for the requested architecture.
    arch, mode = (capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    # Get the decoder function outside the loop.
    md = capstone.Cs(arch, mode)
    decoder = md.disasm_lite
    
    

    # Create the variables for the instruction length, mnemonic and
    # operands. That way they won't be created within the loop,
    # minimizing the chances data might be overwritten.
    # This only makes sense for the buggy vesion of the bindings, normally
    # memory accesses are safe).
    length = mnemonic = op_str = None

    # For each instruction...
    result = []
    offset = 0
    while offset < len(code):
        # Disassemble a single instruction, because disassembling multiple
        # instructions may cause excessive memory usage (Capstone allocates
        # approximately 1K of metadata per each decoded instruction).
        instr = None
        try:
            instr = list(decoder(code[offset : offset + 64], address + offset, 1))[
                0
            ]
        except IndexError:
            pass  # No instructions decoded.
        except capstone.CsError:
            pass  # Any other error.

        # On success add the decoded instruction.
        if instr is not None:
            # Get the instruction length, mnemonic and operands.
            # Copy the values quickly before someone overwrites them,
            # if using the buggy version of the bindings (otherwise it's
            # irrelevant in which order we access the properties).
            length = instr[1]
            mnemonic = instr[2]
            op_str = instr[3]

            # Concatenate the mnemonic and the operands.
            if op_str:
                disasm = "%s %s" % (mnemonic, op_str)
            else:
                disasm = mnemonic


        # On error add a "define constant" instruction.
        # The exact instruction depends on the architecture.
        else:
            # The number of bytes to skip depends on the architecture.
            # On Intel processors we'll skip one byte, since we can't
            # really know the instruction length. On the rest of the
            length = 1

            skipped = code[offset : offset + length]

            # Build the "define constant" instruction.
            # On Intel processors it's "db".
            # On ARM processors it's "dcb".
            mnemonic = "db "
            b = []
            for item in skipped:
                if chr(item).isalpha():
                    b.append("'%s'" % chr(item))
                else:
                    b.append("0x%x" % item)
            op_str = ", ".join(b)
            if mnemonic:
                disasm = mnemonic + op_str
            else:
                disasm = op_str

        # Add the decoded instruction to the list.
        result.append(
            (
                address + offset,
                length,
                disasm,
            )
        )

        # Update the offset.
        offset += length

    # Return the list of decoded instructions.
    return result

def write_remote(hProc, remote, data: bytes, make_executable: bool = True, try_r_x_first: bool = True):
    """
    Allocate remote RW memory, write `data` and (optionally) change protection to RX.
    Returns (remote_addr, size). Raises OSError on failure.
    """
    if not data:
        raise ValueError("Empty data")

    size = len(data)

    

    try:
        # 2) WriteProcessMemory (loop until complete)
        buf = (ctypes.c_ubyte * size).from_buffer_copy(data)
        written_total = 0
        while written_total < size:
            written = ctypes.c_size_t(0)
            addr = ctypes.c_void_p(int(remote) + written_total)
            # chunk_ptr with offset
            chunk_ptr = ctypes.byref(buf, written_total)
            ok = WriteProcessMemory(hProc, addr, chunk_ptr, size - written_total, ctypes.byref(written))
            if not ok:
                raise OSError(f"WriteProcessMemory failed at offset {written_total}: {ctypes.get_last_error()}")
            if written.value == 0:
                break
            written_total += written.value

        if written_total != size:
            raise OSError(f"WriteProcessMemory incomplete: wrote {written_total}/{size}")

        # 3) Try to make executable (best-effort)
        if make_executable:
            oldprot = wintypes.DWORD(0)
            if try_r_x_first:
                ok = VirtualProtectEx(hProc, ctypes.c_void_p(remote), ctypes.c_size_t(size), PAGE_EXECUTE_READ, ctypes.byref(oldprot))
                if not ok:
                    # fallback to RXW
                    VirtualProtectEx(hProc, ctypes.c_void_p(remote), ctypes.c_size_t(size), PAGE_EXECUTE_READWRITE, ctypes.byref(oldprot))
            else:
                VirtualProtectEx(hProc, ctypes.c_void_p(remote), ctypes.c_size_t(size), PAGE_EXECUTE_READWRITE, ctypes.byref(oldprot))

        # 4) Flush I-cache
        FlushInstructionCache(hProc, ctypes.c_void_p(remote), ctypes.c_size_t(size))

        return int(remote), size

    except Exception:
        # cleanup on failure
        try:
            VirtualFreeEx(hProc, ctypes.c_void_p(remote), 0, MEM_RELEASE)
        except Exception:
            pass
        raise


def inject_asm(hProc, asm_code: str, wait: bool = True):
    """
    Assemble `asm_code` (with asm()) and run it in process `hProc`.
    This call optionally waits for the remote thread to finish.

    Returns a dict similar to your original function.
    """
    # assemble to get rough size
    shell = asm(asm_code, 0)
    code_size = len(shell)*2
    if code_size == 0:
        raise ValueError("Empty assembly")

    remote_code = None
    hThread = None

    try:
        # 1) Allocate RW memory in remote process
        remote_code = VirtualAllocEx(hProc, None, code_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote_code:
            raise OSError(f"VirtualAllocEx failed: {ctypes.get_last_error()}")
        
        # assemble to get exact code to inject with the correct ofsets
        shell = asm(asm_code, remote_code)
        
        # Allocate & write remote, make executable
        remote_code, code_size = write_remote(hProc, remote_code, shell, make_executable=True)
        
        
        # create remote thread and wait or not
        hThread = CreateRemoteThread(hProc, None, 0, ctypes.c_void_p(remote_code), None, 0, None)
        if not hThread:
            raise OSError(f"CreateRemoteThread failed: {ctypes.get_last_error()}")

        exit_code = 0
        if wait:
            w = WaitForSingleObject(hThread, INFINITE)
            if w != WAIT_OBJECT_0:
                raise OSError(f"WaitForSingleObject returned {w}: {ctypes.get_last_error()}")

            ec = wintypes.DWORD()
            if not GetExitCodeThread(hThread, ctypes.byref(ec)):
                raise OSError(f"GetExitCodeThread failed: {ctypes.get_last_error()}")
            exit_code = int(ec.value)

    finally:
        # close thread handle (only if we waited or thread handle exists)
        try:
            if hThread and wait:
                CloseHandle(hThread)
        except Exception:
            pass

    return {
        "remote_code": int(remote_code) if remote_code else None,
        "code_size": len(shell),
        "thread_handle": int(hThread) if hThread else None,
        "exit_code": exit_code
    }


def get_process_image_path(hProc) -> str:
    """
    Return full executable path for the process referenced by handle hProc.
    Raises OSError on failure.
    NOTE: this function does NOT close hProc.
    """
    if not hProc:
        raise ValueError("hProc must be a valid process handle")

    # Prefer QueryFullProcessImageNameW
    qfp = getattr(kernel32, "QueryFullProcessImageNameW", None)
    
    qfp.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    qfp.restype = wintypes.BOOL

    buf_len = wintypes.DWORD(260)
    while True:
        buf = ctypes.create_unicode_buffer(buf_len.value)
        success = qfp(hProc, 0, buf, ctypes.byref(buf_len))
        if success:
            return buf.value
        err = ctypes.get_last_error()
        # ERROR_INSUFFICIENT_BUFFER == 122
        if err == 122:
            # enlarge and retry
            buf_len = wintypes.DWORD(max(buf_len.value * 2, 1024))
            continue
        raise OSError(f"QueryFullProcessImageNameW failed: err={err}")






# helper: read remote memory and return bytes
def read_remote(hProc, addr: int, size: int) -> bytes:
    """
    Read `size` bytes from process hProc at address `addr`. Raises OSError on failure.
    """

    buf = (ctypes.c_ubyte * size)()
    read = ctypes.c_size_t(0)
    ok = ReadProcessMemory(hProc, ctypes.c_void_p(addr), ctypes.byref(buf), ctypes.c_size_t(size), ctypes.byref(read))
    if not ok:
        raise OSError(f"ReadProcessMemory failed at 0x{addr:X}: err={ctypes.get_last_error()}")
    if read.value != size:
        # Sometimes ReadProcessMemory reads less than requested; return what we got.
        return bytes(buf)[: read.value]
    return bytes(buf)