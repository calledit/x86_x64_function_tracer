import ctypes
from ctypes import wintypes
import subprocess
import sys
import os
import time
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KsError
import struct, traceback

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


MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
INFINITE = 0xFFFFFFFF
PROCESS_ALL = 0x1F0FFF


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
def list_modules_psapi(hProc):

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
            return []

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

        out = []
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
            out.append({"path": path, "base": base, "size": size})
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

def list_modules_toolhelp(pid):
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == wintypes.HANDLE(-1).value:
        raise OSError("CreateToolhelp32Snapshot(Module) failed: %d" % ctypes.get_last_error())
    try:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(MODULEENTRY32W)
        ok = Module32FirstW(snap, ctypes.byref(me))
        if not ok:
            raise OSError("Module32FirstW failed: %d" % ctypes.get_last_error())
        out = []
        while ok:
            path = me.szExePath
            base = int(me.modBaseAddr) if me.modBaseAddr else None
            size = int(me.modBaseSize)
            out.append({"path": path, "base": base, "size": size})
            ok = Module32NextW(snap, ctypes.byref(me))
        return out
    finally:
        CloseHandle(snap)

def enumerate_modules(hProc, pid = None):
    """Try PSAPI first; fallback to Toolhelp."""
    try:
        mods = list_modules_psapi(hProc)
        if mods:
            return mods
    except Exception as e:
        # PSAPI might fail due to rights/cross-bitness; fallback
        print(f"PSAPI failed for handle {hProc}: {e}", file=sys.stderr)
    
    if pid is None:
        raise Exception("no PID given")
    return list_modules_toolhelp(pid)

# ---- Start process helper ------------------------------------------------
def try_start_executable(exe_path):
    """
    Try to start exe_path using subprocess.Popen.
    Returns PID if started and appears in process list within timeout, else None.
    """
    # If exe_path is just a name, rely on PATH / cwd
    try:
        proc = subprocess.Popen([exe_path], shell=False)
    except FileNotFoundError as e:
        # not found on PATH / as-is
        return None, f"Could not start '{exe_path}': {e}"
    except Exception as e:
        return None, f"Failed to start '{exe_path}': {e}"

    return proc.pid

# ---- CLI -----------------------------------------------------------------
def print_modules_for_pid(mods):

    if not mods:
        print(f"No modules.")
        return
    print(f"--- modules ---")
    for m in mods:
        base = ("0x%016X" % m["base"]) if m.get("base") else "N/A"
        size = str(m.get("size")) if m.get("size") else "N/A"
        print(f"{base:>18}  {size:>8}  {m['path']}")
    print("")

def load_library_in_remote(hProc, dll_path: str, wait: bool = True):
    """
    Load dll_path into the remote process pid.
    Returns a dict with information about the loaded module:
      {"path": str, "base": int, "size": int}
    If the DLL is already loaded, returns the existing module info.
    Raises OSError on failure.
    """

    # If already loaded, return that module info
    mods = enumerate_modules(hProc)
    target_name = os.path.basename(dll_path).lower()
    for m in mods:
        if os.path.basename(m["path"]).lower() == target_name:
            return m  # already loaded

    try:
        # write the dll path into remote process
        dll_bytes = dll_path.encode('ascii') + b'\x00'
        remote_str = VirtualAllocEx(hProc, None, len(dll_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote_str:
            raise OSError(f"VirtualAllocEx(dllpath) failed: {ctypes.get_last_error()}")
        print(remote_str)
        written = ctypes.c_size_t()
        ok = WriteProcessMemory(hProc, remote_str, dll_bytes, len(dll_bytes), ctypes.byref(written))
        if not ok or written.value != len(dll_bytes):
            raise OSError(f"WriteProcessMemory(dllpath) failed: {ctypes.get_last_error()} wrote={getattr(written,'value',None)}")

        # Determine remote address of LoadLibraryA via RVA method:
        # local kernel32 base and local LoadLibraryA address
        local_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        local_k32_handle = local_k32._handle
        local_loadlib = kernel32.GetProcAddress(local_k32_handle, b"LoadLibraryA")
        if not local_loadlib:
            raise OSError("GetProcAddress(LoadLibraryA) failed locally")

        local_rva = int(local_loadlib) - int(local_k32_handle)

        # find remote kernel32 base via enumerate_modules
        remote_k32_base = None
        mods = enumerate_modules(pid)
        for m in mods:
            if os.path.basename(m["path"]).lower() == "kernel32.dll":
                remote_k32_base = m["base"]
                break
            # sometimes kernelbase.dll implements LoadLibrary; also check kernelbase.dll
            if os.path.basename(m["path"]).lower() == "kernelbase.dll" and remote_k32_base is None:
                # keep as fallback if not found kernel32
                remote_k32_base = m["base"]

        if not remote_k32_base:
            raise OSError("Failed to locate kernel32/kernelbase base in target process")

        remote_loadlib = int(remote_k32_base) + int(local_rva)

        # create thread to call LoadLibraryA(remote_str)
        hThread = CreateRemoteThread(hProc, None, 0, remote_loadlib, remote_str, 0, None)
        if not hThread:
            raise OSError(f"CreateRemoteThread(LoadLibraryA) failed: {ctypes.get_last_error()}")

        if wait:
            WaitForSingleObject(hThread, INFINITE)
            # optionally can read exit code but it's 32-bit only
            exit_code = wintypes.DWORD()
            GetExitCodeThread(hThread, ctypes.byref(exit_code))

        # enumerate modules again and find our DLL
        time.sleep(0.05)  # small delay to allow loader to finish mapping
        mods2 = enumerate_modules(pid)
        for m in mods2:
            if os.path.basename(m["path"]).lower() == target_name:
                return m

        # If we reach here, the module didn't appear (maybe loader failed)
        raise OSError("DLL injection appeared to complete but module not found in remote module list")

    finally:
        try:
            CloseHandle(hProc)
        except Exception:
            pass

def get_handle(pid):
    # open process
    hProc = OpenProcess(PROCESS_ALL, False, int(pid))
    if not hProc:
        raise OSError(f"OpenProcess({pid}) failed: {ctypes.get_last_error()}")
    return hProc

def alloc_and_write_remote(hProc, data: bytes, make_executable: bool = True, try_r_x_first: bool = True):
    """
    Allocate remote RW memory, write `data` and (optionally) change protection to RX.
    Returns (remote_addr, size). Raises OSError on failure.
    """
    if not data:
        raise ValueError("Empty data")

    size = len(data)

    # 1) Allocate RW memory in remote process
    remote = VirtualAllocEx(hProc, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not remote:
        raise OSError(f"VirtualAllocEx failed: {ctypes.get_last_error()}")

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


def inject_asm(hProc, asm_code: str, wait: bool = False):
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
        # Allocate & write remote, make executable
        remote_code, code_size = alloc_and_write_remote(hProc, shell, make_executable=True)
        
        # assemble to get exact code to inject with the correct ofsets
        shell = asm(asm_code, remote_code)
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