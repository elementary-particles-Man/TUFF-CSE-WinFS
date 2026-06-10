/*
* tuffcsewinfs.c
*
* TUFF-CSE-WinFS v1 Windows Volume Filter Driver (Pass-through Skeleton)
* Phase: P1A (Driver Package Boundary)
*/

#include "tuffcsewinfs.h"

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("TUFF-CSE-WinFS v1: DriverEntry [P1A Skeleton]\n");

    // Initialize all dispatch routines to pass-through
    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = DispatchPassThrough;
    }

    DriverObject->DriverExtension->AddDevice = AddDevice;
    DriverObject->DriverUnload = Unload;

    return STATUS_SUCCESS;
}

NTSTATUS
AddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT PhysicalDeviceObject
)
{
    NTSTATUS status;
    PDEVICE_OBJECT filterDeviceObject;
    PDEVICE_EXTENSION deviceExtension;

    DbgPrint("TUFF-CSE-WinFS v1: AddDevice\n");

    status = IoCreateDevice(
        DriverObject,
        sizeof(DEVICE_EXTENSION),
        NULL,
        FILE_DEVICE_DISK,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &filterDeviceObject
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    deviceExtension = (PDEVICE_EXTENSION)filterDeviceObject->DeviceExtension;
    deviceExtension->PhysicalDeviceObject = PhysicalDeviceObject;
    deviceExtension->TargetDeviceObject = IoAttachDeviceToDeviceStack(filterDeviceObject, PhysicalDeviceObject);

    if (deviceExtension->TargetDeviceObject == NULL) {
        IoDeleteDevice(filterDeviceObject);
        return STATUS_NO_SUCH_DEVICE;
    }

    filterDeviceObject->Flags |= (deviceExtension->TargetDeviceObject->Flags & (DO_DIRECT_IO | DO_BUFFERED_IO | DO_POWER_PAGABLE));
    filterDeviceObject->DeviceType = deviceExtension->TargetDeviceObject->DeviceType;
    filterDeviceObject->Characteristics = deviceExtension->TargetDeviceObject->Characteristics;

    filterDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

NTSTATUS
DispatchPassThrough(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

    // PHASE_P1B/P2: Hook read/write here for CSE processing.
    // For P1A, we just pass through.

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(deviceExtension->TargetDeviceObject, Irp);
}

VOID
Unload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("TUFF-CSE-WinFS v1: Unload\n");
}
