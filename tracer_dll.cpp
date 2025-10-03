// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include "MinHook.h"

extern "C" {
    __declspec(dllexport) void print(const char* str);
    __declspec(dllexport) MH_STATUS hook_function(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal);
    __declspec(dllexport) void enable_hooks();
    __declspec(dllexport) void print_text();
}
void init();

BOOL APIENTRY DllMain( HMODULE hModule,
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
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}



int function_enter_break_point(int inside_function_id) {

}
int function_exit_break_point(int inside_function_id, int call_num) {

}
int function_call_break_point(int inside_function_id) {

}
int function_called_break_point(int inside_function_id, int code, int call_num) {

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
    if (MH_Initialize() != MH_OK) {
        print("Failed to initialize MinHook");
        return;
    }
    //print("Initialized MinHook");
}


void print_text() {

    print("Printing text");
}


void print(const char* str) {
    FILE* fp;

    fopen_s(&fp, "C:\\dbg\\debug_output.txt", "a");
    if (fp) {
        fputs(str, fp);
        fputs("\n", fp);
        fclose(fp);
    }
}
