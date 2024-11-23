#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>

#include "winafl_header.h"
#include "HelperPublic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAP_SIZE                        65536
#define STATIC_COV_SECTION_NAME         ".cov"
#define STATIC_COV_SECTION_NAME_LEN     4
#define AFL_STATIC_CONFIG_ENV           TEXT("AFL_STATIC_CONFIG")
#define MAX_STRING_SIZE                 64

#define COVERAGE_SECTION_BASE           0xfffff8035175d000           // Fill this with help of windbg
#define PREV_LOC_OFFSET                 0x10
#define PID_OFFSET                      0x20

    static BOOL write_qword(ULONG_PTR addr, ULONG64 qword);

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

    // Mapped trace_bit buffer from AFL's process into harness process

    ULONG64 *g_area_ptr = NULL;

    // Handle of helper driver

    HANDLE g_helper_driver = NULL;

    // Address of mapped coverage bitmap in kernel

    ULONG_PTR g_kernel_mapped_bitmap = NULL;

    // Address of MDL describing mapped coverage bitmap

    ULONG_PTR g_kernel_mapped_mdl = NULL;

    // Argument buffer to quickly write QWORDs to arbitrary addresses

    HELPER_WRITE_VM_IN *g_write_input_buffer = NULL;

    //
    // The current iterations track the number of iterations the persistent
    // loop has been through.
    //

    SIZE_T g_current_iterations = 0;

    //
    // The n iterations is the total number total iterations that
    // afl-fuzz.exe wants to be run every time the target process is
    // spawned. This is configured via the AFL_STATIC_CONFIG environment
    // variable.
    //

    SIZE_T g_niterations = 0;

    //
    // Some synchronization primitives.
    //

    INIT_ONCE g_init_once = INIT_ONCE_STATIC_INIT, g_init_once_bareminimum = INIT_ONCE_STATIC_INIT;

    VOID __afl_display_banner()

        /*++

        Routine Description:

            Displays the AFL persistent loop banner.

        --*/

    {
        wprintf(TEXT("pwn it all\n"));
        wprintf(TEXT("Based on WinAFL by <ifratric@google.com>\n"));
    }

    static BOOL write_qword(ULONG_PTR addr, ULONG64 qword)
    {
        DWORD              ret = 0;

        if (!g_write_input_buffer) {
            g_write_input_buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HELPER_WRITE_VM_IN) + sizeof(ULONG64));
            if (!g_write_input_buffer) {
                wprintf(TEXT("[-] Allocate for write buffer fail.\n"));
                return FALSE;
            }
        }

        g_write_input_buffer->WritePtr = addr;
        *(ULONG64 *)(&g_write_input_buffer->Buffer) = qword;
        g_write_input_buffer->WriteLength = sizeof(ULONG64);

        if (!DeviceIoControl(
            g_helper_driver,
            IOCTL_HELPER_WRITE_VM,
            g_write_input_buffer,
            sizeof(HELPER_WRITE_VM_IN) + sizeof(ULONG64),
            NULL,
            0,
            &ret,
            NULL
        )
            ) {
            wprintf(TEXT("[-] Write fail.\n"));
            return FALSE;
        }

        return TRUE;
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
        DWORD       SizeNeeded = 0;
        HMODULE     Modules[128];
        SIZE_T      i = 0;
        WCHAR       PipeName[MAX_STRING_SIZE], ShmName[MAX_STRING_SIZE],
            FuzzerId[MAX_STRING_SIZE], StaticConfig[MAX_STRING_SIZE];

        // For kernel we don't check if instrumented target exists or not

        g_noinstrumentation = FALSE;

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

        // Create handle to helper driver

        g_helper_driver = CreateFileW(HELPER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0);
        if (g_helper_driver == INVALID_HANDLE_VALUE) {
            wprintf(TEXT("[-] Opening handle to helper driver failed.\n"));
            Status = FALSE;
            goto clean;
        }

        // Map a copy into kernel space, so driver doesn't fault when accessing it in high IRQL

        HELPER_MAP_VM_IN  map_address_input = { g_area_ptr, MAP_SIZE };
        HELPER_MAP_VM_OUT map_address_output = { 0 };
        DWORD             ret = 0;

        if (!DeviceIoControl(
            g_helper_driver,
            IOCTL_HELPER_MAP_VM,
            &map_address_input,
            sizeof(HELPER_MAP_VM_IN),
            &map_address_output,
            sizeof(HELPER_MAP_VM_OUT),
            &ret,
            NULL
        )
            ) {
            wprintf(TEXT("[-] Mapping coverage bitmap to kernel space failed.\n"));
            Status = FALSE;
            goto clean;
        }

        g_kernel_mapped_bitmap = map_address_output.MappedPtr;
        g_kernel_mapped_mdl = map_address_output.MDLPtr;

        // Register coverage base with driver

        HELPER_REGISTER_BASE_IN register_input = { COVERAGE_SECTION_BASE, g_kernel_mapped_bitmap, GetCurrentProcessId() };

        if (!DeviceIoControl(
            g_helper_driver,
            IOCTL_HELPER_REGISTER_BASE,
            &register_input,
            sizeof(HELPER_REGISTER_BASE_IN),
            NULL,
            0,
            &ret,
            NULL
        )
            ) {
            wprintf(TEXT("[-] Registering coverage base failed.\n"));
            Status = FALSE;
            goto clean;
        }

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

            Display banner.

        --*/

    {

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
        BOOL        Status = FALSE, Quitting = FALSE;
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
            // For kernel it's generally not useful to "restart" the harness
            // So normally we'll crank -fuzz_iterations real high and almost never restart
            //

            CloseHandle(g_winafl_pipe);
            g_winafl_pipe = INVALID_HANDLE_VALUE;

            // Unmap coverage section

            HELPER_UNMAP_VM_IN unmap_args = { g_kernel_mapped_bitmap, g_kernel_mapped_mdl };
            DWORD ret = 0;
            DeviceIoControl(g_helper_driver, IOCTL_HELPER_UNMAP_VM, &unmap_args, sizeof(HELPER_UNMAP_VM_IN), NULL, 0, &ret, NULL);

            CloseHandle(g_helper_driver);

            UnmapViewOfFile(g_area_ptr);

            Status = FALSE;
            Quitting = TRUE;
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

            // Unmap coverage section

            HELPER_UNMAP_VM_IN unmap_args = { g_kernel_mapped_bitmap, g_kernel_mapped_mdl };
            DWORD ret = 0;
            DeviceIoControl(g_helper_driver, IOCTL_HELPER_UNMAP_VM, &unmap_args, sizeof(HELPER_UNMAP_VM_IN), NULL, 0, &ret, NULL);

            CloseHandle(g_helper_driver);

            UnmapViewOfFile(g_area_ptr);

            Status = FALSE;
            Quitting = TRUE;
            goto clean;
        }

    clean:
        g_current_iterations++;

        if (g_noinstrumentation == FALSE && !Quitting) {
            write_qword(COVERAGE_SECTION_BASE + PREV_LOC_OFFSET, 0);
        }

        return Status;
    }

#ifdef __cplusplus
}
#endif