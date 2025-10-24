// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <shared_mutex>

extern "C" {
    __declspec(dllexport) void print_to_file(const char* str);
    __declspec(dllexport) void print_text();
    __declspec(dllexport) uint64_t alloc_thread_storage(uint64_t out_address);
    __declspec(dllexport) uint64_t set_area_for_function_table(uint64_t size);
    __declspec(dllexport) uint64_t dump_trace(uint64_t thread_storage_address);
    __declspec(dllexport) uint64_t dump_all_traces();
    __declspec(dllexport) uint64_t set_output_file(char* file_path);
    __declspec(dllexport) uint64_t add_jump_breakpoint(uint64_t addr, uint64_t target);
}

uint64_t area_for_xsave64 = 12228;
uint64_t area_for_function_table = 0;
uint64_t area_for_return_addr_linked_list = 3 * 8 * 100000;
uint64_t area_for_tracing_results = 8 * 10000000;

constexpr uint32_t kMaxAllocations = 65536;     // tune as you like

// Contiguous array of all allocations done by alloc_thread_storage()
alignas(64) static uint64_t g_allocations[kMaxAllocations] = { 0 };
// Number of valid entries in g_allocations
static std::atomic<uint32_t> g_alloc_count{ 0 };

std::string output_buffer_str = "";

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

uint64_t set_area_for_function_table(uint64_t size) {
    area_for_function_table = size;
	print(std::string("set_area_for_function_table: ") + std::to_string(size));
    return 0;
}

std::string output_file = "";

uint64_t set_output_file(char *file_path) {
    output_file = std::string(file_path);
	print(std::string("set_output_file: ") + output_file);
    return 0;
}

void init();


HANDLE current_process;

std::mutex file_mutex;

static std::unordered_map<uint64_t, uint64_t> jump_breakpoints;
static std::shared_mutex jump_rwlock;
static PVOID gVehHandle = nullptr;


uint64_t add_jump_breakpoint(uint64_t addr, uint64_t target)
{

    //std::unique_lock<std::shared_mutex> wlock(jump_rwlock); // exclusive
    jump_breakpoints[(uint64_t)addr] = (uint64_t)target;
    return 0;
}

uint64_t alloc_thread_storage(uint64_t out_address)
{

    uint64_t thread_storage_size = area_for_xsave64 + area_for_function_table + area_for_return_addr_linked_list + area_for_tracing_results;

    void* p = VirtualAlloc(nullptr, static_cast<SIZE_T>(thread_storage_size),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) {
        // Optional: log the failure code
        DWORD err = GetLastError();
        print(std::string("alloc_thread_storage failed ") + " err=" + std::to_string(err));
        bufer_2_file();
        return 0;
    }

	//Write the thread storage address to the out_address
    uint64_t thread_storage_address = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(p));
    uint64_t* out_ptr = reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(out_address));
    *out_ptr = thread_storage_address;


	//Setup the linked list entry pointer
    uint64_t linked_list_entr = thread_storage_address + area_for_xsave64 + area_for_function_table;
    uint64_t* linked_list_entr_ptr = reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(linked_list_entr));
    *linked_list_entr_ptr = linked_list_entr;

	//Setup the begining of trace area pointer
    uint64_t begining_of_trace_area = linked_list_entr + area_for_return_addr_linked_list;
    uint64_t* begining_of_trace_area_ptr = reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(begining_of_trace_area));
    *begining_of_trace_area_ptr = begining_of_trace_area + 8;


    uint32_t idx = g_alloc_count.fetch_add(1, std::memory_order_relaxed);
    if (idx < kMaxAllocations) {
        g_allocations[idx] = thread_storage_address;
    }
    else {
        // Optional:  log if you overflow the buffer
        print("alloc_thread_storage: g_allocations is full");
        bufer_2_file();
        // keep the allocation; just not tracked in the array
    }

    return 1;
}

uint64_t dump_trace(uint64_t thread_storage_address)
{
    if (thread_storage_address == 0)
        return 0;

    // Compute derived addresses (same layout as Python)
    uint64_t begining_of_trace_area =
        thread_storage_address +
        area_for_xsave64 +
        area_for_function_table +
        area_for_return_addr_linked_list;

    // Read end-of-trace pointer (stored at *begining_of_trace_area)
    uint64_t end_of_trace_data = *reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(begining_of_trace_area));

    uint64_t trace_data_addr = begining_of_trace_area + 8;
    int64_t trace_data_len = static_cast<int64_t>(end_of_trace_data - trace_data_addr);

    if (trace_data_len < 0) {
        print(std::string("SHOULD NEVER HAPPEN dump_trace: empty or invalid trace len=") + std::to_string(trace_data_len));
        bufer_2_file();
        // Reset pointer anyway
        *reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(begining_of_trace_area)) = trace_data_addr;
        return 0;
    }

    // Copy the trace bytes into memory buffer
    std::vector<uint8_t> trace_data;
    trace_data.resize(static_cast<size_t>(trace_data_len));
    memcpy(trace_data.data(),
        reinterpret_cast<void*>(static_cast<uintptr_t>(trace_data_addr)),
        static_cast<size_t>(trace_data_len));

    // Append to file
    FILE* fp = nullptr;
	//if you want per-thread files
    //std::string thread_output_file = output_file + std::to_string(thread_storage_address) + ".trace";

	{//scope lock
        std::lock_guard<std::mutex> lock(file_mutex);
        fopen_s(&fp, output_file.c_str(), "ab");
        if (fp) {
            fwrite(trace_data.data(), 1, trace_data.size(), fp);
            fclose(fp);
        }
        else {
            print("dump_trace: failed to open trace file");
            bufer_2_file();
        }
    }
    // Reset trace buffer pointer to trace_data_addr (i.e. empty trace)
    *reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(begining_of_trace_area)) = trace_data_addr;

    //print(std::string("dump_trace ok: len=") + std::to_string(trace_data_len) +
    //    " base=" + std::to_string(thread_storage_address));
    //bufer_2_file();

    return static_cast<uint64_t>(trace_data_len);
}

uint64_t dump_all_traces()
{
    // Load how many allocations we have (snapshot)
    uint32_t count = g_alloc_count.load(std::memory_order_acquire);
    uint64_t total_bytes = 0;
    print("dump_all_traces()");
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t addr = g_allocations[i];
        if (addr == 0) continue;

        // Call the existing dump_trace for this allocation.
        dump_trace(addr);


    }

    return 0;
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


static std::atomic<bool> g_shutdown_requested{ false };
static HANDLE g_shutdown_event = nullptr;
static HANDLE g_worker = nullptr;

DWORD WINAPI WorkerThread(LPVOID) {
    HANDLE ev = g_shutdown_event;
    for (;;) {
        DWORD w = WaitForSingleObject(ev, INFINITE);
        if (w == WAIT_OBJECT_0) break; // shutdown signaled
    }
    // --- Do your real cleanup here (file flush, buffers, etc.) ---
    // Keep in mind: if process is terminating, you may have little time.
    
    return 0;
}

//This does not work it is stupid llm code
bool tracer_init() {
    // Call this from your host right after LoadLibrary (NOT from DllMain)
    g_shutdown_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_shutdown_event) return false;
    g_worker = CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    return g_worker != nullptr;
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
        //tracer_init();
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        dump_all_traces();
        if (gVehHandle) {
            RemoveVectoredExceptionHandler(gVehHandle);
            gVehHandle = nullptr;
		}
        bufer_2_file();
        //Dumb llm code
        //g_shutdown_requested.store(true, std::memory_order_relaxed);
        //if (g_shutdown_event) SetEvent(g_shutdown_event);
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
// For each thread we keep a map: function_num -> vector<saved_return_address>
// This mirrors the Python approach ret_replacements[tid][jump_table_address] = stack

static thread_local std::unordered_map<uint64_t, std::vector<uint64_t>>* tls_ret_stacks_ptr = nullptr;

inline std::unordered_map<uint64_t, std::vector<uint64_t>>& GetTLSMap() {
    if (!tls_ret_stacks_ptr) {
        tls_ret_stacks_ptr = new std::unordered_map<uint64_t, std::vector<uint64_t>>();
    }
    return *tls_ret_stacks_ptr;
}


int export_stack_trace() {

}

int reset_stack_trace() {

}

//this wont work if there is a debugger attached
static LONG CALLBACK BreakpointVeh(EXCEPTION_POINTERS* ep)
{
    auto* rec = ep->ExceptionRecord;
    auto* ctx = ep->ContextRecord;

    if (rec->ExceptionCode == EXCEPTION_BREAKPOINT) {
        // Read the opcode at RIP to know how far to skip.
        // 0xCC       = 1-byte INT3
        // 0xCD 0x03  = 2-byte INT 3

        uint64_t rip = ctx->Rip;

        
        {
            //std::shared_lock<std::shared_mutex> lock(jump_rwlock);
            auto it = jump_breakpoints.find(rip);
            if (it != jump_breakpoints.end()) {
                ctx->Rip = it->second;   // redirect
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

		//this is a normal breakpoint not a jump breakpoint we set
        //return EXCEPTION_CONTINUE_SEARCH;

        print("got unkown breakpoint trying to deal with it: " + std::to_string(rip));
        bufer_2_file();

        BYTE* ip = reinterpret_cast<BYTE*>(ctx->Rip);
        SIZE_T skip = 0;

        if (ip[0] == 0xCC) {
            skip = 1;
        }
        else if (ip[0] == 0xCD && ip[1] == 0x03) {
            skip = 2;
        }
        else {
            // Some other breakpoint-like instruction (e.g., ICEBP 0xF1) also ends up as BREAKPOINT in practice.
            // Conservative default: skip 1 byte to avoid re-faulting forever.
            skip = 1;
        }

        ctx->Rip += skip;

        

        // If this breakpoint replaced a real byte (i.e., you planted it),
        // you probably want to restore the original byte before resuming.

        return EXCEPTION_CONTINUE_EXECUTION; // resume as if nothing happened
    }
    else if (rec->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        print("got single step exception");
        bufer_2_file();
        // Hardware breakpoints / TF traps also come here.
        // Handle if you care; otherwise let others handle it.
        return EXCEPTION_CONTINUE_SEARCH;
    }
    else if (rec->ExceptionCode == 0x40010006) { // STATUS_WAKE_SYSTEM_DEBUGGER
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if (rec->ExceptionCode == 0x4001000A) { // STATUS_WAKE_SYSTEM_DEBUGGER_CONTINUE
        return EXCEPTION_CONTINUE_EXECUTION;
    }
	else if (rec->ExceptionCode == 0x406D1388) { // MS_VC_EXCEPTION - Not really an error; used by Visual Studio for thread naming.
        return EXCEPTION_CONTINUE_SEARCH;
    }
	else if (rec->ExceptionCode == 0xC0000005) { // EXCEPTION_ACCESS_VIOLATION - We are probably going to crash time to save traces
		// Sometimes this exeption hits when we are replacing call instructions with breakpoints when we are not pauseing the threads
        // if that is the case it will be resoleved by the time this exeption exits so we can just ignore it
        print("EXCEPTION_ACCESS_VIOLATION: RIP: " + std::to_string(ctx->Rip) + " RSP: " + std::to_string(ctx->Rsp));
        dump_all_traces();
        bufer_2_file();
		return EXCEPTION_CONTINUE_SEARCH;//mabye the is atry catch that will handle it
    }
    else if (rec->ExceptionCode == 0xC000001D) { // STATUS_ACCESS_VIOLATION - We are probably going to crash time to save traces
        print("STATUS_ILLEGAL_INSTRUCTION: RIP: " + std::to_string(ctx->Rip) + " RSP: " + std::to_string(ctx->Rsp));
        dump_all_traces();
        bufer_2_file();
        return EXCEPTION_CONTINUE_SEARCH;//mabye the is atry catch that will handle it
    }
    
    else {
        print("got other exception:"+ std::to_string(rec->ExceptionCode) + " RIP: " + std::to_string(ctx->Rip));
		dump_all_traces(); // We are probably going to crash, try to save traces
        bufer_2_file();
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


void init() {
	FILE* fp;
	
	//Not used remove later
    current_process = GetCurrentProcess();

	fopen_s(&fp, "C:\\dbg\\debug_output.txt", "w");
    if (fp) {
        fputs("", fp);
        fclose(fp);
    }
	
    

    gVehHandle = AddVectoredExceptionHandler(/*First=*/1, BreakpointVeh);
    if (!gVehHandle) {
        print("AddVectoredExceptionHandler failed");
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