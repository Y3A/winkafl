#pragma once

#include "HelperPublic.h"

#define HELPER_TAG      'phfA'
#define HELPER_DEVNAME  L"\\Device\\AFLHelper"
#define DRIVER_PREFIX   "AFLHelper: "

#define err(msg, status) KdPrint((DRIVER_PREFIX "Error %s : (0x%08X)\n", msg, status))
#define log(msg) KdPrint((DRIVER_PREFIX "%s\n", msg))

typedef int BOOL;

typedef struct
{
    LIST_ENTRY        Link;
    ULONG             Pid;
    PVOID             MappedAddress;
    PMDL              Mdl;
} USER_MAPPING_ENTRY, *PUSER_MAPPING_ENTRY;

void HelperUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS HelperCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS HelperCleanUp(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS HelperDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

static NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR info);