#include <Windows.h>
#include <stdio.h>

#include "winafl_header.h"

#define DRIVER_DEVNAME      L"\\Device\\VulnDriver"
#define DRIVER_NAME         L"\\??\\VulnDriver"
#define DRIVER_IOCTL_BASE   0x8206

#define IOCTL_PARSE_BUFFER \
    CTL_CODE(DRIVER_IOCTL_BASE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_SAMPLE_SIZE 15
#define SHM_SIZE MAX_SAMPLE_SIZE + 4

unsigned char *shm_data;

int setup_shmem(const char *name)
{
    HANDLE map_file;

    map_file = OpenFileMappingA(
        FILE_MAP_ALL_ACCESS,   // read/write access
        FALSE,                 // do not inherit the name
        name);            // name of mapping object

    if (map_file == NULL) {
        puts("Error accessing shared memory");
        return 0;
    }

    shm_data = (unsigned char *)MapViewOfFile(map_file, // handle to map object
        FILE_MAP_ALL_ACCESS,  // read/write permission
        0,
        0,
        SHM_SIZE);

    if (shm_data == NULL) {
        puts("Error accessing shared memory");
        return 0;
    }

    return 1;
}

int main(int argc, char **argv)
{
    setup_shmem(argv[1]);

    HANDLE hDriver = CreateFileW(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD  ret;

    while (__afl_persistent_loop()) {
        DWORD sample_size = *(DWORD *)(shm_data);
        if (sample_size > MAX_SAMPLE_SIZE) sample_size = MAX_SAMPLE_SIZE;
        char *sample_bytes = (char *)malloc(sample_size);
        memcpy(sample_bytes, shm_data + sizeof(DWORD), sample_size);

        DeviceIoControl(hDriver, IOCTL_PARSE_BUFFER, sample_bytes, sample_size, NULL, 0, &ret, NULL);

        if (sample_bytes) free(sample_bytes);
    }

    CloseHandle(hDriver);
    
    return 0;
}