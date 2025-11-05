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
#include <sstream>
#include <iomanip>

extern "C" {
#include "include/libipt.h" // <<-- from WinIPT
}
#include <tlhelp32.h>

struct SuspendedThread {
    HANDLE hThread;
    DWORD  threadId;
    DWORD  prevSuspendCount; // from SuspendThread
};

#pragma comment(lib, "libipt.lib") // link against WinIPT static lib (or add to project settings)

extern "C" {
    __declspec(dllexport) void print_to_file(const char* str);
    __declspec(dllexport) void print_text();
    __declspec(dllexport) uint64_t alloc_thread_storage(uint64_t out_address);
    __declspec(dllexport) uint64_t set_area_for_function_table(uint64_t size);
    __declspec(dllexport) uint64_t set_thread_list_table_addres(uint64_t addr);
    __declspec(dllexport) uint64_t dump_trace(uint64_t thread_storage_address);
    __declspec(dllexport) uint64_t dump_all_traces();
    __declspec(dllexport) uint64_t set_output_file(char* file_path);
    __declspec(dllexport) uint64_t add_jump_breakpoint(uint64_t addr, uint64_t target);
}

uint64_t area_for_xsave64 = 12228;
uint64_t area_for_function_table = 0;
uint64_t thread_list_table_addres = 0;
uint64_t area_for_return_addr_linked_list = 3 * 8 * 100000;
uint64_t area_for_tracing_results = 8 * 10000000;
uint64_t max_thread_ids = 30000;

constexpr uint32_t kMaxAllocations = 65536;     // tune as you like

// Contiguous array of all allocations done by alloc_thread_storage()
alignas(64) static uint64_t g_allocations[kMaxAllocations] = { 0 };
// Number of valid entries in g_allocations
static std::atomic<uint32_t> g_alloc_count{ 0 };

std::string output_buffer_str = "";

HANDLE current_process;



static std::vector<SuspendedThread> g_suspended_threads;

static std::vector<SuspendedThread> suspend_all_other_threads(DWORD selfTid)
{
    std::vector<SuspendedThread> suspended;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return suspended;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    if (Thread32First(hSnap, &te)) {
        DWORD myPid = GetCurrentProcessId();
        do {
            if (te.th32OwnerProcessID != myPid) continue;
            if (te.th32ThreadID == selfTid)     continue;

            HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
            if (!ht) continue;

            DWORD prev = SuspendThread(ht);
            if (prev == (DWORD)-1) {
                CloseHandle(ht);
                continue;
            }

            suspended.push_back({ ht, te.th32ThreadID, prev });
        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);
    return suspended;
}

static void resume_threads(std::vector<SuspendedThread>& threads)
{
    for (auto& t : threads) {
        if (!t.hThread) continue;
        // Resume until the count reaches 0
        for (;;) {
            DWORD prev = ResumeThread(t.hThread);
            if (prev == (DWORD)-1) break;
            if (prev <= 1) break; // now running
        }
        CloseHandle(t.hThread);
        t.hThread = nullptr;
    }
    threads.clear();
}

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

BOOL
EnableIpt(
    VOID
)
{
    SC_HANDLE hScm, hSc;
    BOOL bRes;
    bRes = FALSE;

    //
    // Open a handle to the SCM
    //
    hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hScm != NULL)
    {
        //
        // Open a handle to the IPT Service
        //
        hSc = OpenService(hScm, L"Ipt", SERVICE_START);
        if (hSc != NULL)
        {
            //
            // Start it
            //
            bRes = StartService(hSc, 0, NULL);
            if ((bRes == FALSE) &&
                (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING))
            {
                //
                // If it's already started, that's OK
                //
                bRes = TRUE;
            }
            else if (bRes == FALSE)
            {
                wprintf(L"[-] Unable to start IPT Service (err=%d)\n",
                    GetLastError());
                if (GetLastError() == ERROR_NOT_SUPPORTED)
                {
                    wprintf(L"[-] This is likely due to missing PT support\n");
                }
            }

            //
            // Done with the service
            //
            CloseServiceHandle(hSc);
        }
        else
        {
            wprintf(L"[-] Unable to open IPT Service (err=%d). "
                L"Are you running Windows 10 1809?\n",
                GetLastError());
        }

        //
        // Done with the SCM
        //
        CloseServiceHandle(hScm);
    }
    else
    {
        wprintf(L"[-] Unable to open a handle to the SCM (err=%d)\n",
            GetLastError());
    }

    //
    // Return the result
    //
    return bRes;
}

BOOL
EnableAndValidateIptServices(
    VOID
)
{
    WORD wTraceVersion;
    DWORD dwBufferVersion;
    BOOL bRes;

    //
    // First enable IPT
    //
    bRes = EnableIpt();
    if (bRes == FALSE)
    {
        wprintf(L"[-] Intel PT Service could not be started!\n");
        goto Cleanup;
    }

    //
    // Next, check if the driver uses a dialect we understand
    //
    bRes = GetIptBufferVersion(&dwBufferVersion);
    if (bRes == FALSE)
    {
        wprintf(L"[-] Failed to communicate with IPT Service: (err=%d)\n",
            GetLastError());
        goto Cleanup;
    }
    if (dwBufferVersion != IPT_BUFFER_MAJOR_VERSION_CURRENT)
    {
        wprintf(L"[-] IPT Service buffer version is not supported: %d\n",
            dwBufferVersion);
        goto Cleanup;
    }

    //
    // Then, check if the driver uses trace versions we speak
    //
    bRes = GetIptTraceVersion(&wTraceVersion);
    if (bRes == FALSE)
    {
        wprintf(L"[-] Failed to get Trace Version from IPT Service (err=%d)\n",
            GetLastError());
        goto Cleanup;
    }
    if (wTraceVersion != IPT_TRACE_VERSION_CURRENT)
    {
        wprintf(L"[-] IPT Service trace version is not supported %d\n",
            wTraceVersion);
        goto Cleanup;
    }

Cleanup:
    //
    // Return result
    //
    return bRes;
}

// WinIPT / libipt integration state
static std::atomic_bool gIptTracingEnabled{ false };

HANDLE gIptProcHandle = NULL;
IPT_OPTIONS opts = {};

static void ipt_start() {
    // Build IPT options

    BOOL ok = StartProcessIptTracing(gIptProcHandle, opts);
    if (ok) {
        gIptTracingEnabled.store(true);
    }
    else {
        DWORD err = GetLastError();
        print(std::string("ipt: StartProcessIptTracing failed err=") + std::to_string(err));
    }
}

// Start process IPT tracing (call at DLL attach)
static void ipt_start_for_process()
{

    if (!EnableAndValidateIptServices()) {
        print("ipt: EnableAndValidateIptServices failed, skipping IPT tracing");
        bufer_2_file();
        return;
	}

    if (!gIptProcHandle) {
        // Match the tool: PROCESS_VM_READ is enough; add QUERY just in case.
        gIptProcHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
        if (!gIptProcHandle) { print("ipt: OpenProcess failed"); bufer_2_file(); return; }
    }

    opts.OptionVersion = IPT_BUFFER_MAJOR_VERSION_V1;
    opts.TimingSettings = IptNoTimingPackets; // (use this once everything works)
    opts.CycThreshold = 0;
    // Topa: choose with power-of-two like the tool; 11 seamed big trying 10.
    opts.TopaPagesPow2 = 10;
    opts.MatchSettings = IptMatchByAnyApp;
    opts.Inherit = 1;
    opts.ModeSettings = IptCtlUserModeOnly;


    ipt_start();

    
    bufer_2_file();
}

uint8_t* last_buffer = nullptr;
DWORD last_buffer_size = 0;

static void ipt_clear(){
    if (!gIptTracingEnabled.load()) {
        return;
    }

    DWORD traceSize = 0, lastErr = 0;
    if (!GetProcessIptTraceSize(current_process, &traceSize)) {
        DWORD e = GetLastError();
        print(std::string("ipt: GetProcessIptTraceSize failed err=") + std::to_string(e));
        return;
	}
    
    if (traceSize > 8000 * 1024 * 1024) {
		//trace size too big saving it
	

        if (last_buffer) {
            HeapFree(GetProcessHeap(), 0, last_buffer);
	    }

        // Allocate buffer for trace
		last_buffer_size = traceSize;
        last_buffer = reinterpret_cast<uint8_t*>(HeapAlloc(GetProcessHeap(), 0, traceSize));
        if (!last_buffer) {
            print("ipt: HeapAlloc failed for trace buffer");
            bufer_2_file();
            return;
        }

        // Get the trace into our buffer
        BOOL rcGet = GetProcessIptTrace(current_process, last_buffer, traceSize);
        if (!rcGet) {
            DWORD e = GetLastError();
            print(std::string("ipt: GetProcessIptTrace failed err=") + std::to_string(e));
            //HeapFree(GetProcessHeap(), 0, current_buffer);
            bufer_2_file();
            return;
        }

        //Restart tracing right to clear the kernel buffer
        StopProcessIptTracing(current_process);
        ipt_start();
    }

	

}

static void ipt_stop()
{
    if (!gIptTracingEnabled.load()) {
        print("ipt: tracing not enabled, skipping ipt_stop_and_dump_to_file");
        bufer_2_file();
        return;
    }

    HANDLE hThread = GetCurrentThread();
    // Pause the crashing thread’s IPT stream.
    BOOLEAN paused = FALSE;
    
    if (!PauseThreadIptTracing(hThread, &paused)) {
        DWORD e = GetLastError();
        print(std::string("ipt: PauseThreadIptTracing failed err=") + std::to_string(e));
    }
    if (last_buffer) {
        FILE* fp = nullptr;
        fopen_s(&fp, "C:\\dbg\\intel_pt_trace_last_trace.tpp", "wb");
        if (fp) { fwrite(last_buffer, 1, last_buffer_size, fp); fclose(fp); print("ipt: wrote thread trace"); }
        else { print(std::string("ipt: fopen failed: ")); }
    }

    // Query the trace size
    DWORD traceSize = 0, lastErr = 0;
    for (int i = 0; i < 50; ++i) {
        if (GetProcessIptTraceSize(current_process, &traceSize) && traceSize) break;
        lastErr = GetLastError();
        Sleep(5);
    }
    if (!traceSize) {
        print(std::string("ipt: GetProcessIptTraceSize failed or zero size, rc=") + std::to_string(traceSize) + " err=" + std::to_string(lastErr));
        bufer_2_file();
        // Attempt to resume tracing if desired
        gIptTracingEnabled.store(false);
        return;
    }

    print(std::string("ipt: trace size bytes=") + std::to_string(traceSize));
    bufer_2_file();

    // Allocate buffer for trace
    uint8_t* buffer = reinterpret_cast<uint8_t*>(HeapAlloc(GetProcessHeap(), 0, traceSize));
    if (!buffer) {
        print("ipt: HeapAlloc failed for trace buffer");
        bufer_2_file();
        gIptTracingEnabled.store(false);
        return;
    }

    // Get the trace into our buffer
    BOOL rcGet = GetProcessIptTrace(current_process, buffer, traceSize);
    if (!rcGet) {
        DWORD e = GetLastError();
        print(std::string("ipt: GetProcessIptTrace failed err=") + std::to_string(e));
        HeapFree(GetProcessHeap(), 0, buffer);
        bufer_2_file();
        gIptTracingEnabled.store(false);
        return;
    }
    {
        FILE* fp = nullptr;
        fopen_s(&fp, "C:\\dbg\\intel_pt_trace.tpp", "wb");
        if (fp) { fwrite(buffer, 1, traceSize, fp); fclose(fp); print("ipt: wrote thread trace"); }
        else { print(std::string("ipt: fopen failed: ")); }
    }
    HeapFree(GetProcessHeap(), 0, buffer);
    std::string command = "C:\\dbg\\dump.bat " + std::to_string(GetCurrentProcessId());
    system(command.c_str());

    
    // Restart tracing right away to continue coverage incase we dont crash
    if (!ResumeThreadIptTracing(hThread, &paused)) {
        print(std::string("ipt: ResumeThreadIptTracing failed err=") + std::to_string(GetLastError()));
    }
    else {
        print("ipt: thread tracing resumed");
    }
    

    bufer_2_file();
}

static void ipt_shutdown()
{
    if (gIptTracingEnabled.load()) {
        StopProcessIptTracing(GetCurrentProcess());
        gIptTracingEnabled.store(false);
    }
}

uint64_t set_area_for_function_table(uint64_t size) {
    area_for_function_table = size;
	print(std::string("set_area_for_function_table: ") + std::to_string(size));
    return 0;
}

uint64_t set_thread_list_table_addres(uint64_t addr) {
    thread_list_table_addres = addr;
    print(std::string("set_thread_list_table_addres: ") + std::to_string(thread_list_table_addres));
    return 0;
}

std::string output_file = "";

uint64_t set_output_file(char *file_path) {
    output_file = std::string(file_path);
	print(std::string("set_output_file: ") + output_file);
    return 0;
}

void init();




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
    /*
	done in asm code now
	//Setup the linked list entry pointer
    uint64_t linked_list_entr = thread_storage_address + area_for_xsave64 + area_for_function_table;
    uint64_t* linked_list_entr_ptr = reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(linked_list_entr));
    *linked_list_entr_ptr = linked_list_entr;

	//Setup the begining of trace area pointer
    uint64_t begining_of_trace_area = linked_list_entr + area_for_return_addr_linked_list;
    uint64_t* begining_of_trace_area_ptr = reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(begining_of_trace_area));
    *begining_of_trace_area_ptr = begining_of_trace_area + 8;
    */

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
    print("dump_all_traces()");
    if (thread_list_table_addres == 0){
        print("dump_all_traces: have not recived thread_list_table_addres from injected code yet");
        bufer_2_file();
        return 0;
	}
    for (uint32_t i = 0; i < max_thread_ids; i+=1) {
        uint64_t addr = thread_list_table_addres + i * 8;

        uint64_t* addr_ptr = reinterpret_cast<uint64_t*>(static_cast<uintptr_t>(addr));
        uint64_t value_at_addr = *addr_ptr;
        if (value_at_addr == 0) continue;

        // Call the existing dump_trace for this allocation.
        dump_trace(value_at_addr);


    }

    return 0;
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
		//ipt_start_for_process(); //Does not work on amd processors
        //tracer_init();
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        dump_all_traces();
        if (gVehHandle) {
            RemoveVectoredExceptionHandler(gVehHandle);
            gVehHandle = nullptr;
		}
        ipt_shutdown();
        bufer_2_file();
        //Dumb llm code
        //g_shutdown_requested.store(true, std::memory_order_relaxed);
        //if (g_shutdown_event) SetEvent(g_shutdown_event);
        break;
    }
    return TRUE;
}

template <typename T>
std::string to_hex_string(T value, bool with_prefix = true, bool uppercase = true)
{
    std::ostringstream oss;
    if (uppercase)
        oss.setf(std::ios::uppercase);

    if (with_prefix)
        oss << "0x";

    oss << std::hex << std::setw(sizeof(T) * 2) << std::setfill('0') << value;

    return oss.str();
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

		//check ipt is to big and if it is clear it
        ipt_clear();

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

    DWORD threadId = GetCurrentThreadId();
    
    if (rec->ExceptionCode == EXCEPTION_SINGLE_STEP) {
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
        DWORD selfTid = GetCurrentThreadId();

        // Freeze everyone else
        g_suspended_threads = suspend_all_other_threads(selfTid);
        ipt_stop();
        print("EXCEPTION_ACCESS_VIOLATION: TID: " + std::to_string(threadId) + " RIP: " + std::to_string(ctx->Rip) + "(" + to_hex_string(ctx->Rip) + ") RSP: " + std::to_string(ctx->Rsp) + " RAX: " + std::to_string(ctx->Rax));
        dump_all_traces();
        bufer_2_file();
        system("pause");
        resume_threads(g_suspended_threads);
        
		return EXCEPTION_CONTINUE_SEARCH;//mabye the is atry catch that will handle it
    }
    else if (rec->ExceptionCode == 0xC000001D) { // STATUS_ILLEGAL_INSTRUCTION - We are probably going to crash time to save traces
        DWORD selfTid = GetCurrentThreadId();

        // Freeze everyone else
        g_suspended_threads = suspend_all_other_threads(selfTid);
        ipt_stop();
        print("STATUS_ILLEGAL_INSTRUCTION: TID: " + std::to_string(threadId) + " RIP: " + std::to_string(ctx->Rip) + "("+ to_hex_string(ctx->Rip) + ") RSP: " + std::to_string(ctx->Rsp) + " RAX: " + std::to_string(ctx->Rax));
        dump_all_traces();
        bufer_2_file();
        system("pause");
        resume_threads(g_suspended_threads);
        
        return EXCEPTION_CONTINUE_SEARCH;//mabye the is atry catch that will handle it
    }
    else if (rec->ExceptionCode == 0xE06D7363) { // MSVC C++ exception
        return EXCEPTION_CONTINUE_SEARCH; // let C++ runtime handle it
    }
    else {

        DWORD selfTid = GetCurrentThreadId();

        // Freeze everyone else
        g_suspended_threads = suspend_all_other_threads(selfTid);
        ipt_stop();
        print("got other exception: "+ std::to_string(rec->ExceptionCode) + " TID: " + std::to_string(threadId) + "(" + to_hex_string(ctx->Rip) + ") RIP: " + std::to_string(ctx->Rip) + " RAX: " + std::to_string(ctx->Rax));
		dump_all_traces(); // We are probably going to crash, try to save traces
        bufer_2_file();
        system("pause");
        resume_threads(g_suspended_threads);
        
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


void init() {

	FILE* fp;
	
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

    uint64_t VEH_addr = reinterpret_cast<uint64_t>(&BreakpointVeh);
    print("VectoredExceptionHandler address: "+ std::to_string(VEH_addr) + "("+ to_hex_string(VEH_addr) +")");

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