#include <ntddk.h>

#include "Helper.h"

static LIST_ENTRY           g_ProcessMappingHead;
static FAST_MUTEX           g_Lock;
static STATIC_COVERAGE_DATA *g_CoverageBase;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS        status = STATUS_SUCCESS;
    PDEVICE_OBJECT  devObj = NULL;
    UNICODE_STRING  devName = RTL_CONSTANT_STRING(HELPER_DEVNAME);
    UNICODE_STRING  symLink = RTL_CONSTANT_STRING(HELPER_NAME);
    BOOL            symLinkCreated = FALSE;

    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);
    if (!NT_SUCCESS(status)) {
        err("IoCreateDevice", status);
        goto out;
    }

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        err("IoCreateSymbolicLink", status);
        goto out;
    }
    symLinkCreated = TRUE;

    DriverObject->DriverUnload = HelperUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = \
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = HelperCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HelperDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = HelperCleanUp;

    InitializeListHead(&g_ProcessMappingHead);
    ExInitializeFastMutex(&g_Lock);

out:
    if (!NT_SUCCESS(status)) {
        if (devObj)
            IoDeleteDevice(devObj);
        if (symLinkCreated)
            IoDeleteSymbolicLink(&symLink);
    }

    return status;
}

void HelperUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING  symLink = RTL_CONSTANT_STRING(HELPER_NAME);

    ExAcquireFastMutex(&g_Lock);

    // stop logging coverage

    if (g_CoverageBase) {
        RtlZeroMemory(g_CoverageBase, sizeof(STATIC_COVERAGE_DATA));
        g_CoverageBase = NULL;
    }

    // cleanup any remaining mappings

    for (LIST_ENTRY *cur = RemoveHeadList(&g_ProcessMappingHead); cur != &g_ProcessMappingHead; cur = RemoveHeadList(&g_ProcessMappingHead)) {
        USER_MAPPING_ENTRY *entry = (USER_MAPPING_ENTRY *)cur;
        MmUnmapLockedPages(entry->MappedAddress, entry->Mdl);
        MmUnlockPages(entry->Mdl);
        IoFreeMdl(entry->Mdl);
        ExFreePoolWithTag(cur, HELPER_TAG);
    }

    ExReleaseFastMutex(&g_Lock);

    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);

    return;
}

NTSTATUS HelperCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    return CompleteRequest(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS HelperCleanUp(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    ULONG callerPid = 0;

    callerPid = HandleToULong(PsGetCurrentProcessId());

    ExAcquireFastMutex(&g_Lock);

    // stop logging coverage

    if (g_CoverageBase) {
        RtlZeroMemory(g_CoverageBase, sizeof(STATIC_COVERAGE_DATA));
        g_CoverageBase = NULL;
    }

    for (LIST_ENTRY *cur = &g_ProcessMappingHead, *next = cur->Flink; next && next != &g_ProcessMappingHead; ) {
        cur = next;
        next = next->Flink;
        USER_MAPPING_ENTRY *entry = (USER_MAPPING_ENTRY *)cur;

        if (entry->Pid == callerPid) {
            MmUnmapLockedPages(entry->MappedAddress, entry->Mdl);
            MmUnlockPages(entry->Mdl);
            IoFreeMdl(entry->Mdl);

            RemoveEntryList(cur);
            ExFreePoolWithTag(cur, HELPER_TAG);
        }
    }

    ExReleaseFastMutex(&g_Lock);

    return CompleteRequest(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS HelperDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS            status = STATUS_SUCCESS;
    PIO_STACK_LOCATION  irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG               inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG               outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG               info = 0;

    if (Irp->AssociatedIrp.SystemBuffer == NULL) {
        status = STATUS_INVALID_BUFFER_SIZE;
        info = 0;
        goto out;
    }

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_HELPER_READ_VM:
    {
        info = outputLen;
        if (info == 0)
            goto out;

        if (inputLen != sizeof(HELPER_READ_VM_IN)) {
            status = STATUS_INVALID_BUFFER_SIZE;
            info = 0;
            goto out;
        }

        HELPER_READ_VM_IN *inputBuffer = NULL;
        unsigned char     *outputBuffer = NULL;
        inputBuffer = Irp->AssociatedIrp.SystemBuffer;
        outputBuffer = Irp->AssociatedIrp.SystemBuffer;

        RtlCopyMemory(outputBuffer, (unsigned char *)inputBuffer->ReadPtr, outputLen);

        break;
    }

    case IOCTL_HELPER_WRITE_VM:
    {
        info = 0;

        if (inputLen < sizeof(HELPER_WRITE_VM_IN)) {
            status = STATUS_INVALID_BUFFER_SIZE;
            info = 0;
            goto out;
        }

        HELPER_WRITE_VM_IN *inputBuffer = NULL;
        inputBuffer = Irp->AssociatedIrp.SystemBuffer;

        RtlCopyMemory((unsigned char *)inputBuffer->WritePtr, (unsigned char *)inputBuffer->Buffer, inputBuffer->WriteLength);

        break;
    }

    case IOCTL_HELPER_MAP_VM:
    {
        info = outputLen;

        if (inputLen != sizeof(HELPER_MAP_VM_IN) || outputLen != sizeof(HELPER_MAP_VM_OUT)) {
            status = STATUS_INVALID_BUFFER_SIZE;
            info = 0;
            goto out;
        }

        HELPER_MAP_VM_IN    *inputBuffer = NULL;
        HELPER_MAP_VM_OUT   *outputBuffer = NULL;
        PMDL                mdl = NULL;
        PVOID               mappedAddress = NULL;
        USER_MAPPING_ENTRY  *entry = NULL;
        ULONG               callerPid = 0;

        inputBuffer = Irp->AssociatedIrp.SystemBuffer;
        outputBuffer = Irp->AssociatedIrp.SystemBuffer;

        mdl = IoAllocateMdl((PVOID)inputBuffer->MapPtr, inputBuffer->MapLength, FALSE, FALSE, NULL);
        if (!mdl) {
            status = STATUS_UNSUCCESSFUL;
            err("IoAllocateMdl", status);
            info = 0;
            goto out;
        }

        MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);

        mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
        if (!mappedAddress) {
            status = STATUS_UNSUCCESSFUL;
            err("MmMapLockedPagesSpecifyCache", status);
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            info = 0;
            goto out;
        }

        outputBuffer->MappedPtr = (ULONG_PTR)mappedAddress;
        outputBuffer->MDLPtr = (ULONG_PTR)mdl;

        entry = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(USER_MAPPING_ENTRY), HELPER_TAG);
        if (entry == NULL) {
            status = STATUS_UNSUCCESSFUL;
            err("ExAlocatePool2", status);
            MmUnmapLockedPages(mappedAddress, mdl);
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            info = 0;
            goto out;
        }

        callerPid = HandleToULong(PsGetCurrentProcessId());
        entry->MappedAddress = mappedAddress;
        entry->Mdl = mdl;
        entry->Pid = callerPid;

        ExAcquireFastMutex(&g_Lock);

        InsertHeadList(&g_ProcessMappingHead, &entry->Link);

        ExReleaseFastMutex(&g_Lock);

        break;
    }

    case IOCTL_HELPER_UNMAP_VM:
    {
        info = 0;

        if (inputLen != sizeof(HELPER_UNMAP_VM_IN)) {
            status = STATUS_INVALID_BUFFER_SIZE;
            info = 0;
            goto out;
        }

        HELPER_UNMAP_VM_IN *inputBuffer = NULL;
        ULONG              callerPid = 0;

        inputBuffer = Irp->AssociatedIrp.SystemBuffer;

        if (!inputBuffer->MappedPtr || !inputBuffer->MDLPtr) {
            status = STATUS_INVALID_ADDRESS;
            info = 0;
            goto out;
        }

        callerPid = HandleToULong(PsGetCurrentProcessId());

        ExAcquireFastMutex(&g_Lock);

        // stop logging coverage

        if (g_CoverageBase) {
            RtlZeroMemory(g_CoverageBase, sizeof(STATIC_COVERAGE_DATA));
            g_CoverageBase = NULL;
        }

        for (LIST_ENTRY *cur = g_ProcessMappingHead.Flink; cur && cur != g_ProcessMappingHead.Flink; cur = cur->Flink) {
            USER_MAPPING_ENTRY *entry = (USER_MAPPING_ENTRY *)cur;

            if (entry->Pid == callerPid && entry->MappedAddress == (PVOID)inputBuffer->MappedPtr && entry->Mdl == (PMDL)inputBuffer->MDLPtr) {
                MmUnmapLockedPages((PVOID)inputBuffer->MappedPtr, (PMDL)inputBuffer->MDLPtr);
                MmUnlockPages((PMDL)inputBuffer->MDLPtr);
                IoFreeMdl((PMDL)inputBuffer->MDLPtr);

                RemoveEntryList(cur);
                ExFreePoolWithTag(cur, HELPER_TAG);
                break;
            }
        }

        ExReleaseFastMutex(&g_Lock);

        break;
    }

    case IOCTL_HELPER_REGISTER_BASE:
    {
        info = 0;

        if (inputLen != sizeof(HELPER_REGISTER_BASE_IN)) {
            status = STATUS_INVALID_BUFFER_SIZE;
            info = 0;
            goto out;
        }

        HELPER_REGISTER_BASE_IN *inputBuffer = NULL;

        inputBuffer = Irp->AssociatedIrp.SystemBuffer;

        if (!inputBuffer->CoverageBase || !inputBuffer->KBitmapBase || !inputBuffer->Pid) {
            status = STATUS_INVALID_ADDRESS;
            info = 0;
            goto out;
        }

        ExAcquireFastMutex(&g_Lock);

        g_CoverageBase = (STATIC_COVERAGE_DATA *)inputBuffer->CoverageBase;
        g_CoverageBase->CoverageBitmap = inputBuffer->KBitmapBase;
        g_CoverageBase->Pid = inputBuffer->Pid;

        ExReleaseFastMutex(&g_Lock);

        break;
    }

    }
out:
    return CompleteRequest(Irp, status, info);
}


static NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR info)
{
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}