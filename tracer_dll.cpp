// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include "MinHook.h"
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>

extern "C" {
    __declspec(dllexport) void print_to_file(const char* str);
    __declspec(dllexport) MH_STATUS hook_function(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal);
    __declspec(dllexport) void enable_hooks();
    __declspec(dllexport) void print_text();
    __declspec(dllexport) uint64_t function_enter_trace_point(uint64_t function_address, uint64_t return_address_pointer, uint64_t return_address);
    __declspec(dllexport) uint64_t function_exit_trace_point(uint64_t function_address);
    __declspec(dllexport) uint64_t function_call_trace_point(uint64_t function_address, uint64_t call_address, uint64_t return_address, uint64_t target_address);
    __declspec(dllexport) uint64_t function_called_trace_point(uint64_t function_address, uint64_t call_address, uint64_t return_address);
}
void init();

std::string output_buffer_str = "";
HANDLE current_process;

void bufer_2_file() {

    print_to_file(output_buffer_str.c_str());
    output_buffer_str = "";
}

void print(std::string str) {
    output_buffer_str += str + "\n";

    if (output_buffer_str.length() > 2000) {
        bufer_2_file();
    }
}



// global (process-wide)
static DWORD g_flsIndex = FLS_OUT_OF_INDEXES;

// Call once during DLL_PROCESS_ATTACH (not in DllMain, or do the minimal call only)
bool InitTraceGuards() {
    if (g_flsIndex == FLS_OUT_OF_INDEXES) {
        g_flsIndex = FlsAlloc([](void* p) noexcept {
            // Called on thread exit and when the FLS slot is freed.
            // Mark the thread as "dead"/tearing down.
            // Can't call into the C++ runtime safely here; keep it trivial.
            // We can't write to C++ TLS here; that's the point of using FLS.
            });
    }
    return g_flsIndex != FLS_OUT_OF_INDEXES;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        init();
        break;
    case DLL_THREAD_ATTACH:
        InitTraceGuards();
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
        bufer_2_file();
        break;
    }
    return TRUE;
}

// Call this at the beginning of any hook/tracer entry
inline bool TraceTLSIsUsable() noexcept {
    // If FLS isn't set up yet, be conservative: refuse to touch C++ TLS.
    if (g_flsIndex == FLS_OUT_OF_INDEXES) return false;

    // We store a small alive flag in FLS. If absent, create one (first use on this thread).
    void* v = FlsGetValue(g_flsIndex);
    if (!v) {
        // Allocate a tiny per-thread flag that has no destructor (intentionally leaked on thread end).
        // This avoids depending on C++ TLS lifetime.
        static constexpr uintptr_t kAlive = 1;
        FlsSetValue(g_flsIndex, reinterpret_cast<void*>(kAlive));
        return true;
    }

    // If the FLS callback ran at thread-exit, you can flip it to a special value there
    // (e.g., set to nullptr again or to 2). For simplicity, treat non-null as "alive".
    return true;
}


static inline bool is_readable_page(DWORD prot) {
    // treat these as readable; include execute+read variants
    const DWORD READ_MASK =
        PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (prot & PAGE_GUARD)     return false;   // touching it raises an exception
    if (prot & PAGE_NOACCESS)  return false;
    return (prot & READ_MASK) != 0;
}

// Safe peek: returns true only if the full 8 bytes were read; never crashes.
extern "C" __declspec(noinline)
bool safe_read_u64ll(uint64_t* out, const void* addr) noexcept {
    if (!out || !addr) return false;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(addr, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT)                return false;

    // Ensure the entire 8-byte read lies inside this region
    auto base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    auto limit = base + mbi.RegionSize;
    auto p = reinterpret_cast<uintptr_t>(addr);
    if (p < base || (p + sizeof(uint64_t)) > limit) return false;

    if (!is_readable_page(mbi.Protect)) return false;


    print(std::string(" addr ") + std::to_string((uintptr_t)addr));
    bufer_2_file();
    SIZE_T n = 0;
    if (!ReadProcessMemory(current_process, addr,
        out, sizeof(*out), &n))
        return false;

    return n == sizeof(*out);
}


static inline bool safe_read_u64(uint64_t* out, const void* p) noexcept {
    if (!out || !p) return false;
    __try{
        SIZE_T n = 0;
        if (ReadProcessMemory(current_process, p, out, sizeof(*out), &n) && n == sizeof(*out)) {
            return true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *out = 0;
    }
    return false;
}


// -------------------------------
// Per-thread return-address stacks
// -------------------------------
// For each thread we keep a map: function_address -> vector<saved_return_address>
// This mirrors the Python approach ret_replacements[tid][jump_table_address] = stack

static thread_local std::unordered_map<uint64_t, std::vector<uint64_t>>* tls_ret_stacks_ptr = nullptr;

inline std::unordered_map<uint64_t, std::vector<uint64_t>>& GetTLSMap() {
    if (!tls_ret_stacks_ptr) {
        tls_ret_stacks_ptr = new std::unordered_map<uint64_t, std::vector<uint64_t>>();
    }
    return *tls_ret_stacks_ptr;
}

uint64_t function_enter_trace_point(uint64_t function_address, uint64_t return_address_pointer, uint64_t return_address) {
    // Safety: check pointer before dereferencing

    auto& tls_ret_stacks = GetTLSMap();
    tls_ret_stacks[function_address].push_back(return_address);

    // Logging (unchanged format aside from content)
    uint32_t thread_id = static_cast<uint32_t>(__readgsdword(0x48));
    std::string thread_id_str = std::to_string(thread_id);
    std::string function_address_str = std::to_string((uintptr_t)function_address);
    std::string return_address_pointer_str = std::to_string((uintptr_t)return_address_pointer);
    std::string return_address_str = std::to_string((uintptr_t)return_address);

    std::string desc = std::string("enter: ") + thread_id_str + " " + function_address_str + " " + return_address_pointer_str + " " + return_address_str;
    print(desc);

    // Return 0 for now. If you want this function to return something useful to the caller,
    // e.g., an index or the saved address, we can change this.
    return 0;
}

uint64_t function_exit_trace_point(uint64_t function_address) {
    uint64_t original_return = 0;
    auto& tls_ret_stacks = GetTLSMap();

    auto it = tls_ret_stacks.find(function_address);
    if (it != tls_ret_stacks.end()) {
        auto& vec = it->second;
        if (!vec.empty()) {
            original_return = vec.back();
            vec.pop_back();
            if (vec.empty()) {
                // remove empty vector to avoid unbounded growth of the map
                tls_ret_stacks.erase(it);
            }
        }
    }

    uint32_t thread_id = static_cast<uint32_t>(__readgsdword(0x48));
    std::string thread_id_str = std::to_string(thread_id);
    std::string function_address_str = std::to_string((uintptr_t)function_address);
    std::string return_address_str = std::to_string((uintptr_t)original_return);

    std::string desc = std::string("exit: ") + thread_id_str + " " + function_address_str + " " + return_address_str;
    print(desc);

    // Return the original return address so the caller can jump/restore to it.
    return original_return;
}

uint64_t function_call_trace_point(uint64_t function_address, uint64_t call_address, uint64_t return_address, uint64_t target_address) {
    uint32_t thread_id = static_cast<uint32_t>(__readgsdword(0x48));
    std::string thread_id_str = std::to_string(thread_id);
    std::string function_address_str = std::to_string((uintptr_t)function_address);
    std::string call_address_str = std::to_string((uintptr_t)call_address);
    std::string return_address_str = std::to_string((uintptr_t)return_address);
    std::string target_address_str = std::to_string((uintptr_t)target_address);


    std::string desc = std::string("call: ") + thread_id_str + " " + function_address_str + " " + call_address_str + " " + return_address_str + " " + target_address_str;
    print(desc);
    return 0;
}

uint64_t function_called_trace_point(uint64_t function_address, uint64_t call_address, uint64_t return_address) {
    uint32_t thread_id = static_cast<uint32_t>(__readgsdword(0x48));
    std::string thread_id_str = std::to_string(thread_id);
    std::string function_address_str = std::to_string((uintptr_t)function_address);
    std::string call_address_str = std::to_string((uintptr_t)call_address);
    std::string return_address_str = std::to_string((uintptr_t)return_address);


    std::string desc = std::string("called: ") + thread_id_str + " " + function_address_str + " " + call_address_str + " " + return_address_str;
    print(desc);
    return 0;
}


int export_stack_trace() {

}

int reset_stack_trace() {

}


MH_STATUS hook_function(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal) {
    return MH_CreateHook(pTarget, pDetour, ppOriginal);
}

void enable_hooks() {
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        print("Failed to enable hooks");
    }
}

void init() {
	FILE* fp;
	
    current_process = GetCurrentProcess();

	fopen_s(&fp, "C:\\dbg\\debug_output.txt", "w");
    if (fp) {
        fputs("", fp);
        fclose(fp);
    }
	
    if (MH_Initialize() != MH_OK) {
        print("ERROR: Failed to initialize MinHook");
    }else{
		print("calltrace_loaded:");
	}
    bufer_2_file();
}


void print_text() {

    print("Printing text");
}





void print_to_file(const char* str) {
    FILE* fp;

    fopen_s(&fp, "C:\\dbg\\debug_output.txt", "a");
    if (fp) {
        fputs(str, fp);
        fclose(fp);
    }
}