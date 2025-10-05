// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include "MinHook.h"
#include <string>
#include <unordered_map>
#include <vector>

extern "C" {
    __declspec(dllexport) void print_to_file(const char* str);
    __declspec(dllexport) MH_STATUS hook_function(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal);
    __declspec(dllexport) void enable_hooks();
    __declspec(dllexport) void print_text();
    __declspec(dllexport) uint64_t function_enter_trace_point(uint64_t function_address, uint64_t return_address_pointer);
    __declspec(dllexport) uint64_t function_exit_trace_point(uint64_t function_address);
    __declspec(dllexport) uint64_t function_call_trace_point(uint64_t function_address, uint64_t call_address, uint64_t return_address, uint64_t target_address);
    __declspec(dllexport) uint64_t function_called_trace_point(uint64_t function_address, uint64_t call_address, uint64_t return_address);
}
void init();

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
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
        bufer_2_file();
        break;
    }
    return TRUE;
}






// -------------------------------
// Per-thread return-address stacks
// -------------------------------
// For each thread we keep a map: function_address -> vector<saved_return_address>
// This mirrors the Python approach ret_replacements[tid][jump_table_address] = stack
static thread_local std::unordered_map<uint64_t, std::vector<uint64_t>> tls_ret_stacks;

uint64_t function_enter_trace_point(uint64_t function_address, uint64_t return_address_pointer) {
    // Safety: check pointer before dereferencing
    uint64_t return_address = 0;
    if (return_address_pointer != 0) {
        // return_address_pointer is expected to point to a uint64_t on the thread stack (the stored return address)
        // Use a volatile read to avoid optimizer reordering (defensive)
        return_address = *reinterpret_cast<uint64_t*>(return_address_pointer);
    }

    // push onto per-thread stack for this function_address
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