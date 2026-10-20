#pragma once

// USBIPSFilter.h
// Windows File System Minifilter Driver Specification
// Module: Scenario 3 Protected-File Pre-Access Denial

#ifndef _USBIPS_FILTER_H_
#define _USBIPS_FILTER_H_

#define USBIPS_PORT_NAME L"\\USBIPSFilterPort"
#define USBIPS_MAX_PATH_LEN 512
#define USBIPS_MAX_PROTECTED_PATHS 32

// Communication Message Types
typedef enum _USBIPS_MESSAGE_TYPE
{
    USBIPS_MSG_REGISTER_CLIENT = 1,
    USBIPS_MSG_SYNC_POLICIES   = 2,
    USBIPS_MSG_PRE_OPEN        = 3,
    USBIPS_MSG_PRE_READ        = 4,
    USBIPS_MSG_PRE_WRITE       = 5,
    USBIPS_MSG_PRE_DELETE      = 6,
    USBIPS_MSG_PRE_RENAME      = 7
} USBIPS_MESSAGE_TYPE;

// Event Notification payload sent from Minifilter to User-Mode Client
typedef struct _USBIPS_ACCESS_NOTIFICATION
{
    USBIPS_MESSAGE_TYPE MessageType;
    ULONG               ProcessId;
    WCHAR               ProcessName[260];
    WCHAR               FilePath[USBIPS_MAX_PATH_LEN];
    ULONG               DesiredAccess;
    ULONG               ShareAccess;
    BOOLEAN             IsRemovableMedia;
    WCHAR               RemovableVolume[16];
} USBIPS_ACCESS_NOTIFICATION, *PUSBIPS_ACCESS_NOTIFICATION;

// Reply payload sent from User-Mode Client back to Minifilter
typedef struct _USBIPS_ACCESS_REPLY
{
    BOOLEAN BlockOperation;         // If TRUE, minifilter completes IRP with STATUS_ACCESS_DENIED
    BOOLEAN QuarantineDevice;       // If TRUE, device containment triggered
    ULONG   EnforcementStatus;      // NTSTATUS or winerror code
} USBIPS_ACCESS_REPLY, *PUSBIPS_ACCESS_REPLY;

// Policy Synchronization payload sent from User-Mode Client to Minifilter
typedef struct _USBIPS_POLICY_SYNC
{
    ULONG Count;
    WCHAR ProtectedPaths[USBIPS_MAX_PROTECTED_PATHS][USBIPS_MAX_PATH_LEN];
} USBIPS_POLICY_SYNC, *PUSBIPS_POLICY_SYNC;

#endif // _USBIPS_FILTER_H_
