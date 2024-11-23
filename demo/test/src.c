#include <ntddk.h>

#define DRIVER_DEVNAME      L"\\Device\\VulnDriver"
#define DRIVER_NAME         L"\\??\\VulnDriver"
#define DRIVER_IOCTL_BASE   0x8206

typedef int BOOL;

#define IOCTL_PARSE_BUFFER \
    CTL_CODE(DRIVER_IOCTL_BASE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

void DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

static NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR info);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS        status = STATUS_SUCCESS;
    PDEVICE_OBJECT  devObj = NULL;
    UNICODE_STRING  devName = RTL_CONSTANT_STRING(DRIVER_DEVNAME);
    UNICODE_STRING  symLink = RTL_CONSTANT_STRING(DRIVER_NAME);
    BOOL            symLinkCreated = FALSE;

    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);
    if (!NT_SUCCESS(status)) {
        goto out;
    }

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        goto out;
    }
    symLinkCreated = TRUE;

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = \
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;

out:
    if (!NT_SUCCESS(status)) {
        if (devObj)
            IoDeleteDevice(devObj);
        if (symLinkCreated)
            IoDeleteSymbolicLink(&symLink);
    }

    return status;
}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING  symLink = RTL_CONSTANT_STRING(DRIVER_NAME);

    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);

    return;
}

NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    return CompleteRequest(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS            status = STATUS_SUCCESS;
    PIO_STACK_LOCATION  irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG               inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG               info = 0;

    if (Irp->AssociatedIrp.SystemBuffer == NULL) {
        status = STATUS_INVALID_BUFFER_SIZE;
        info = 0;
        goto out;
    }

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_PARSE_BUFFER:
    {
        if (inputLen < 10) {
            status = STATUS_INVALID_BUFFER_SIZE;
            info = 0;
            goto out;
        }

        char *inputBuffer = Irp->AssociatedIrp.SystemBuffer;

        if (inputBuffer[0] == 'H')
            if (inputBuffer[1] == 'A')
                if (inputBuffer[2] == 'C')
                    if (inputBuffer[3] == 'K')
                        if (inputBuffer[4] == 'I')
                            if (inputBuffer[5] == 'N')
                                if (inputBuffer[6] == 'G')
                                    if (inputBuffer[7] == '!')
                                        KeBugCheck(0x1337);
        {
            status = STATUS_SUCCESS;
            info = 0;
            goto out;
        }

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