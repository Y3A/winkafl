#pragma once

#define HELPER_NAME         L"\\??\\AFLHelper"
#define HELPER_IOCTL_BASE   0x8206

#define IOCTL_HELPER_READ_VM \
    CTL_CODE(HELPER_IOCTL_BASE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HELPER_WRITE_VM \
    CTL_CODE(HELPER_IOCTL_BASE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HELPER_MAP_VM \
    CTL_CODE(HELPER_IOCTL_BASE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HELPER_UNMAP_VM \
    CTL_CODE(HELPER_IOCTL_BASE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HELPER_REGISTER_BASE \
    CTL_CODE(HELPER_IOCTL_BASE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct
{
    ULONG_PTR CoverageBitmap;
    ULONG64   Padding1;
    ULONG64   PreviousLoc;
    ULONG64   Padding2;
    ULONG64   Pid;
} STATIC_COVERAGE_DATA, *PSTATIC_COVERAGE_DATA;
#pragma pack(pop)

typedef struct
{
    ULONG_PTR       ReadPtr;
} HELPER_READ_VM_IN;

typedef struct
{
    ULONG_PTR       WritePtr;
    ULONG           WriteLength;
    unsigned char   Buffer[ANYSIZE_ARRAY];
} HELPER_WRITE_VM_IN;

typedef struct
{
    ULONG_PTR       MapPtr;
    ULONG           MapLength;
} HELPER_MAP_VM_IN;

typedef struct
{
    ULONG_PTR       MappedPtr;
    ULONG_PTR       MDLPtr;
} HELPER_MAP_VM_OUT;

typedef struct
{
    ULONG_PTR       MappedPtr;
    ULONG_PTR       MDLPtr;
} HELPER_UNMAP_VM_IN;

typedef struct
{
    ULONG_PTR       CoverageBase;
    ULONG_PTR       KBitmapBase;
    ULONG           Pid;
} HELPER_REGISTER_BASE_IN;