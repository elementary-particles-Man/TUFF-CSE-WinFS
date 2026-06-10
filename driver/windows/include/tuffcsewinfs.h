/*
* tuffcsewinfs.h
*
* TUFF-CSE-WinFS v1 Driver Header
* Phase: P1A (Source Skeleton)
*/

#ifndef _TUFFCSEWINFS_H_
#define _TUFFCSEWINFS_H_

#include <ntddk.h>

#define TUFF_CSE_WINFS_TAG 'fSCT'

typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT TargetDeviceObject;
    PDEVICE_OBJECT PhysicalDeviceObject;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// Prototypes
DRIVER_INITIALIZE DriverEntry;
DRIVER_ADD_DEVICE AddDevice;
DRIVER_UNLOAD Unload;

NTSTATUS
DispatchPassThrough(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

#endif // _TUFFCSEWINFS_H_
