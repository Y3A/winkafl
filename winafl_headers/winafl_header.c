#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>

#include "winafl_header.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAP_SIZE                        65536
#define STATIC_COV_SECTION_NAME         ".cov"
#define STATIC_COV_SECTION_NAME_LEN     4
#define AFL_STATIC_CONFIG_ENV           TEXT("AFL_STATIC_CONFIG")
#define MAX_STRING_SIZE                 64

#pragma pack(push, 1)
    typedef struct
    {
        ULONG_PTR coverage_bitmap;
        ULONG64   padding1;
        ULONG64   prev_loc;
        ULONG64   padding2;
        ULONG64   pid;
    } STATIC_COVERAGE_DATA, *PSTATIC_COVERAGE_DATA;
#pragma pack(pop)

    //
    // The handle to the pipe used to talk with afl-fuzz.exe
    //

    HANDLE g_winafl_pipe = INVALID_HANDLE_VALUE;

    //
    // The no fuzzing mode is enabled when a binary is run without
    // passing the fuzzing configuration in the AFL_STATIC_CONFIG
    // environment variable (running a binary by itself, without
    // being run via afl-fuzz.exe will enable this mode for example).
    // Under this mode, the persistent loop exits after a single
    // iteration.
    //

    BOOL g_nofuzzing_mode = FALSE;

    //
    // The no instrumentation mode means the binary is running
    // without an AFL instrumented module in its address-space.
    // As a result, it means there is no coverage information
    // available (g_static_coverage_data is empty). This happens
    // when the persistent loop is run without instrumenting any
    // modules.
    //

    BOOL g_noinstrumentation = TRUE;

    // For now just support instrumenting one module

    STATIC_COVERAGE_DATA *g_static_coverage_data;

    // Mapped trace_bit buffer from AFL's process into harness process

    ULONG64 *g_area_ptr;

    //
    // The current iterations track the number of iterations the persistent
    // loop has been through.
    //

    SIZE_T g_current_iterations;

    //
    // The n iterations is the total number total iterations that
    // afl-fuzz.exe wants to be run every time the target process is
    // spawned. This is configured via the AFL_STATIC_CONFIG environment
    // variable.
    //

    SIZE_T g_niterations;

    //
    // Some synchronization primitives.
    //

    INIT_ONCE g_init_once = INIT_ONCE_STATIC_INIT, g_init_once_bareminimum = INIT_ONCE_STATIC_INIT;

    //
    // Optional base address to filter out false positive exceptions
    //

    ULONG_PTR g_crashing_module_base;


    LONG __afl_VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)

        /*++

        Routine Description:

            Catch any unhandled exceptions and let afl-fuzz.exe know.

        --*/

    {
        DWORD Dummy = 0;

        //
        // Filter any unwanted exceptions here, perhaps those caught by program
        //

        /*
        if (!g_crashing_module_base)
            g_crashing_module_base = GetModuleHandleW(L"test.dll");

        if ((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress - g_crashing_module_base == 0x1022)
            return EXCEPTION_CONTINUE_SEARCH;
        */

        // 
        // Reaching this point means (you believe) the exception is not handled by the program and should be reported
        // 

        wprintf(TEXT("[*] The program just crashed.\n"));

        if (g_nofuzzing_mode == FALSE) {
            WriteFile(g_winafl_pipe, "C", 1, &Dummy, NULL);
            TerminateProcess(GetCurrentProcess(), 0);
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    VOID __afl_display_banner()

        /*++

        Routine Description:

            Displays the AFL persistent loop banner.

        --*/

    {
        wprintf(TEXT("pwn it all\n"));
        wprintf(TEXT("Based on WinAFL by <ifratric@google.com>\n"));
    }

    BOOL CALLBACK __afl_set_it_up()

        /*++

        Routine Description:

            Sets up the environment: creates the pipe to talk with afl-fuzz.exe,
            maps the coverage byte-map that afl-fuzz.exe will map in and fix-up
            the instrumented module so that its coverage byte-map pointer points
            inside the shared memory section.

        --*/

    {
        BOOL        Status = TRUE;
        HANDLE      MappedFile = NULL;
        DWORD       SizeNeeded;
        HMODULE     Modules[128];
        SIZE_T      i = 0;
        WCHAR       PipeName[MAX_STRING_SIZE], ShmName[MAX_STRING_SIZE],
            FuzzerId[MAX_STRING_SIZE], StaticConfig[MAX_STRING_SIZE],
            InstrumentedModuleName[MAX_STRING_SIZE];

        //
        // Let's first figure out if we are running with any instrumented module,
        // in the address space.
        // If not, we turn on the no instrumentation switch.
        //

        Status = EnumProcessModulesEx(GetCurrentProcess(), Modules, sizeof(Modules), &SizeNeeded, LIST_MODULES_64BIT);

        if (Status == FALSE) {
            wprintf(TEXT("[-] EnumProcessModulesEx failed - too many modules loaded?.\n"));
            TerminateProcess(GetCurrentProcess(), 0);
        }

        for (i = 0; i < SizeNeeded / sizeof(Modules[0]); ++i) {
            PVOID Base = (PVOID)Modules[i];
            PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
            PIMAGE_SECTION_HEADER Sections = (PIMAGE_SECTION_HEADER)(NtHeaders + 1);
            USHORT j = 0;

            DWORD breakout = FALSE;

            for (j = 0; j < NtHeaders->FileHeader.NumberOfSections; ++j) {
                if (memcmp(Sections[j].Name, STATIC_COV_SECTION_NAME, STATIC_COV_SECTION_NAME_LEN) != 0) {
                    continue;
                }

                GetModuleBaseNameW(GetCurrentProcess(), Modules[i], InstrumentedModuleName, MAX_STRING_SIZE);
                g_static_coverage_data = (STATIC_COVERAGE_DATA *)(
                    Sections[j].VirtualAddress + (ULONG64)Base
                    );

                wprintf(
                    TEXT("[+] Found a statically instrumented module: %s\n"),
                    InstrumentedModuleName
                );
                g_noinstrumentation = FALSE;
                breakout = TRUE;
                break;
            }

            if (breakout)
                break;
        }

        if (g_noinstrumentation == TRUE) {
            wprintf(TEXT("[-] No instrumented module found.\n"));
            Status = FALSE;
        }

        //
        // Let's figure out, if afl-fuzz.exe spawned us or not?
        // If not, we can switch on the no fuzzing mode and exit.
        //

        if (GetEnvironmentVariableW(AFL_STATIC_CONFIG_ENV, StaticConfig, MAX_STRING_SIZE) == 0) {
            wprintf(TEXT("[-] Not running under afl-fuzz.exe.\n"));
            g_nofuzzing_mode = TRUE;
            Status = FALSE;
            goto clean;
        }

        //
        // We are running under afl-fuzz.exe; let's open the pipe used for
        // communication, create a named shared memory section to store the coverage
        // data and fix-up the instrumented module so that its instrumentation writes
        // in the shared memory section's content.
        //

        RtlZeroMemory(&PipeName, MAX_STRING_SIZE * sizeof(PipeName[0]));
        RtlZeroMemory(&ShmName, MAX_STRING_SIZE * sizeof(ShmName[0]));

        wprintf(TEXT("[*] Setting up the environment (%s)..\n"), StaticConfig);
        if (swscanf_s(StaticConfig, TEXT("%[a-zA-Z0-9]:%u"), FuzzerId, _countof(FuzzerId), &g_niterations) != 2) {
            wprintf(
                TEXT("[-] The ") AFL_STATIC_CONFIG_ENV TEXT(" environment variable isn't properly formated.\n")
            );
            Status = FALSE;
            goto clean;
        }

        swprintf_s(PipeName, _countof(PipeName), TEXT("\\\\.\\pipe\\afl_pipe_%s"), FuzzerId);
        swprintf_s(ShmName, _countof(ShmName), TEXT("afl_shm_%s"), FuzzerId);

        //
        // Connect to the named pipe.
        //

        g_winafl_pipe = CreateFileW(
            PipeName,                      // pipe name
            GENERIC_READ | GENERIC_WRITE,  // read and write access
            0,                             // no sharing
            NULL,                          // default security attributes
            OPEN_EXISTING,                 // opens existing pipe
            0,                             // default attributes
            NULL                           // no template file
        );

        if (g_winafl_pipe == INVALID_HANDLE_VALUE) {
            wprintf(TEXT("[-] Opening the named pipe failed.\n"));
            Status = FALSE;
            goto clean;
        }

        //
        // Get the named shared memory section mapped.
        //

        MappedFile = OpenFileMappingW(
            FILE_MAP_ALL_ACCESS,
            FALSE,
            ShmName
        );

        if (MappedFile == NULL) {
            wprintf(TEXT("[-] Opening the file mapping failed.\n"));
            Status = FALSE;
            goto clean;
        }

        g_area_ptr = MapViewOfFile(
            MappedFile,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            MAP_SIZE
        );

        if (g_area_ptr == NULL) {
            wprintf(TEXT("[-] Mapping a view of the shared memory section failed.\n"));
            Status = FALSE;
            goto clean;
        }

        // Set area pointer in binary so shellcode starts logging coverage
        g_static_coverage_data->coverage_bitmap = g_area_ptr;

    clean:

        if (g_nofuzzing_mode == FALSE && g_noinstrumentation == TRUE) {

            //
            // It means there is no instrumented module in the address space,
            // and we are being run through AFL..weird. Display a pop-up!
            //

            wprintf(TEXT("[-] You are running without instrumentation under afl-fuzz.exe.\n"));

            MessageBoxW(
                NULL,
                TEXT("You are running without instrumentation under afl-fuzz.exe."),
                NULL,
                MB_OK | MB_ICONERROR
            );
        }

        if (MappedFile != NULL) {
            CloseHandle(MappedFile);
        }

        return Status;
    }

    BOOL CALLBACK __afl_set_up_bareminimum()

        /*++

        Routine Description:

            Installs the unhandled exception handler to ease reproducability.
            The handler gets installed even if running without afl-fuzz.exe, or
            if running a non-instrumented module. This is particularly useful
            for debugging issues found by afl-fuzz.exe on a vanilla target (in
            the case the debugging symbols are a bit funky on an instrumented
            binary for example).

        --*/

    {

        //
        // Set up the exception handler.
        //

        AddVectoredExceptionHandler(0, __afl_VectoredHandler);

        //
        // Display the banner to know the persistent loop is here.
        //

        __afl_display_banner();
        return TRUE;
    }

    BOOL __afl_persistent_loop()

        /*++

        Routine Description:

            Persistent loop implementation.

        --*/

    {
        BOOL        Status;
        CHAR        Command = 0;
        DWORD       Dummy = 0;
        SIZE_T      i = 0;

        if (g_nofuzzing_mode == TRUE) {

            //
            // Force exit at the first iteration when afl-fuzz isn't detected
            // to fake "normal" execution of instrumented binary.
            //

            Status = FALSE;
            goto clean;
        }

        Status = InitOnceExecuteOnce(
            &g_init_once_bareminimum,
            __afl_set_up_bareminimum,
            NULL,
            NULL
        );

        Status = InitOnceExecuteOnce(
            &g_init_once,
            __afl_set_it_up,
            NULL,
            NULL
        );

        if (Status == FALSE) {
            wprintf(TEXT("[+] Enabling the no fuzzing mode.\n"));
            g_nofuzzing_mode = TRUE;
            Status = TRUE;
            goto clean;
        }

        //
        // If this not the first time, it means we have to signal afl-fuzz that
        // the previous test-case ended.
        //

        if (g_current_iterations > 0)
            WriteFile(g_winafl_pipe, "K", 1, &Dummy, NULL);

        if (g_current_iterations == g_niterations) {

            //
            // It is time to stop the machine!
            //

            CloseHandle(g_winafl_pipe);
            g_winafl_pipe = INVALID_HANDLE_VALUE;

            g_static_coverage_data->coverage_bitmap = NULL;

            UnmapViewOfFile(g_area_ptr);

            Status = FALSE;
            goto clean;
        }

        //
        // Tell afl-fuzz that we are ready for the next iteration.
        //

        WriteFile(g_winafl_pipe, "P", 1, &Dummy, NULL);

        //
        // Wait until we have the go from afl-fuzz to go ahead (below call is blocking).
        //

        ReadFile(g_winafl_pipe, &Command, 1, &Dummy, NULL);
        if (Command != 'F') {
            if (Command == 'Q') {
                wprintf(TEXT("[+] Received the quit signal, exiting.\n"));
            }
            else {
                wprintf(TEXT("[-] Received an unknown command from afl-fuzz, exiting (%.2x).\n"), Command);
            }

            CloseHandle(g_winafl_pipe);
            g_winafl_pipe = INVALID_HANDLE_VALUE;

            g_static_coverage_data->coverage_bitmap = NULL;

            UnmapViewOfFile(g_area_ptr);
            Status = FALSE;

            goto clean;
        }

    clean:
        g_current_iterations++;

        if (g_noinstrumentation == FALSE)
            g_static_coverage_data->prev_loc = 0;

        return Status;
    }

#ifdef __cplusplus
}
#endif
