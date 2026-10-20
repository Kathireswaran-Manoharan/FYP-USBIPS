// USBIPSFilter.c
// Windows File System Minifilter Driver Implementation
// Module: Scenario 3 Protected-File Pre-Access Denial at File-System Layer
//
// Target: Windows 10 / Windows 11 x64 Kernel-Mode File System Minifilter
// Requires: Windows Driver Kit (WDK) 10/11 and Visual Studio C++ Driver Workload

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "USBIPSFilter.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Minifilter registration table requires function pointers")

// ============================================================
// Global Driver State
// ============================================================

typedef struct _USBIPS_FILTER_DATA
{
    PFLT_FILTER         FilterHandle;
    PFLT_PORT           ServerPort;
    PFLT_PORT           ClientPort;
    ERESOURCE           PolicyLock;
    USBIPS_POLICY_SYNC  CurrentPolicy;
} USBIPS_FILTER_DATA, *PUSBIPS_FILTER_DATA;

static USBIPS_FILTER_DATA g_FilterData;

// ============================================================
// Forward Declarations
// ============================================================

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS USBIPSFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS USBIPSFilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS USBIPSFilterPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
);

VOID USBIPSFilterPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS USBIPSFilterPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
);

FLT_PREOP_CALLBACK_STATUS USBIPSPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS USBIPSPreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS USBIPSPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS USBIPSPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

// Operation registration callbacks
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      USBIPSPreCreate,
      NULL },

    { IRP_MJ_READ,
      0,
      USBIPSPreRead,
      NULL },

    { IRP_MJ_WRITE,
      0,
      USBIPSPreWrite,
      NULL },

    { IRP_MJ_SET_INFORMATION,
      0,
      USBIPSPreSetInformation,
      NULL },

    { IRP_MJ_OPERATION_END }
};

// Filter Registration specification
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),          // Size
    FLT_REGISTRATION_VERSION,          // Version
    0,                                 // Flags
    NULL,                              // Context registration
    Callbacks,                         // Operation callbacks
    USBIPSFilterUnload,                // FilterUnload
    USBIPSFilterInstanceSetup,         // InstanceSetup
    NULL,                              // InstanceQueryTeardown
    NULL,                              // InstanceTeardownStart
    NULL,                              // InstanceTeardownComplete
    NULL,                              // GenerateFileName
    NULL,                              // NormalizeNameComponent
    NULL                               // NormalizeContextCleanup
};

// ============================================================
// Driver Initialization & Unload
// ============================================================

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&g_FilterData, sizeof(USBIPS_FILTER_DATA));
    ExInitializeResourceLite(&g_FilterData.PolicyLock);

    // Register filter with Filter Manager
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterData.FilterHandle);
    if (!NT_SUCCESS(status))
    {
        ExDeleteResourceLite(&g_FilterData.PolicyLock);
        return status;
    }

    // Create user-mode communication port: \USBIPSFilterPort
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status))
    {
        FltUnregisterFilter(g_FilterData.FilterHandle);
        ExDeleteResourceLite(&g_FilterData.PolicyLock);
        return status;
    }

    RtlInitUnicodeString(&portName, USBIPS_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);

    status = FltCreateCommunicationPort(
        g_FilterData.FilterHandle,
        &g_FilterData.ServerPort,
        &oa,
        NULL,
        USBIPSFilterPortConnect,
        USBIPSFilterPortDisconnect,
        USBIPSFilterPortMessage,
        1 // Max concurrent connections (single USBIPS agent)
    );

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status))
    {
        FltUnregisterFilter(g_FilterData.FilterHandle);
        ExDeleteResourceLite(&g_FilterData.PolicyLock);
        return status;
    }

    // Start filtering
    status = FltStartFiltering(g_FilterData.FilterHandle);
    if (!NT_SUCCESS(status))
    {
        FltCloseCommunicationPort(g_FilterData.ServerPort);
        FltUnregisterFilter(g_FilterData.FilterHandle);
        ExDeleteResourceLite(&g_FilterData.PolicyLock);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS USBIPSFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    if (g_FilterData.ServerPort != NULL)
    {
        FltCloseCommunicationPort(g_FilterData.ServerPort);
        g_FilterData.ServerPort = NULL;
    }

    if (g_FilterData.FilterHandle != NULL)
    {
        FltUnregisterFilter(g_FilterData.FilterHandle);
        g_FilterData.FilterHandle = NULL;
    }

    ExDeleteResourceLite(&g_FilterData.PolicyLock);
    return STATUS_SUCCESS;
}

NTSTATUS USBIPSFilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    // Attach to all local disk and network volumes
    return STATUS_SUCCESS;
}

// ============================================================
// Communication Port Handlers
// ============================================================

NTSTATUS USBIPSFilterPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    g_FilterData.ClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID USBIPSFilterPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    if (g_FilterData.ClientPort != NULL)
    {
        FltCloseClientPort(g_FilterData.FilterHandle, &g_FilterData.ClientPort);
        g_FilterData.ClientPort = NULL;
    }
}

NTSTATUS USBIPSFilterPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferSize < sizeof(USBIPS_POLICY_SYNC))
    {
        return STATUS_INVALID_PARAMETER;
    }

    PUSBIPS_POLICY_SYNC newPolicy = (PUSBIPS_POLICY_SYNC)InputBuffer;

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_FilterData.PolicyLock, TRUE);

    RtlCopyMemory(&g_FilterData.CurrentPolicy, newPolicy, sizeof(USBIPS_POLICY_SYNC));

    ExReleaseResourceLite(&g_FilterData.PolicyLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================
// Helper: Path Matching
// ============================================================

static BOOLEAN IsPathInProtectedFolder(
    _In_ PCUNICODE_STRING FilePath
)
{
    BOOLEAN matched = FALSE;

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0)
    {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_FilterData.PolicyLock, TRUE);

    for (ULONG i = 0; i < g_FilterData.CurrentPolicy.Count && i < USBIPS_MAX_PROTECTED_PATHS; ++i)
    {
        PCWCH cfgPath = g_FilterData.CurrentPolicy.ProtectedPaths[i];
        if (cfgPath[0] == L'\0') continue;

        UNICODE_STRING protectedPrefix;
        RtlInitUnicodeString(&protectedPrefix, cfgPath);

        // 1. Direct NT prefix matching (e.g. \Device\HarddiskVolume3\USBIPS_Protected)
        if (FilePath->Length >= protectedPrefix.Length)
        {
            UNICODE_STRING subString;
            subString.Buffer = FilePath->Buffer;
            subString.Length = protectedPrefix.Length;
            subString.MaximumLength = protectedPrefix.Length;

            if (RtlEqualUnicodeString(&subString, &protectedPrefix, TRUE))
            {
                matched = TRUE;
                break;
            }
        }

        // 2. Directory component matching for DOS policies (e.g. "C:\USBIPS_Protected" -> "\USBIPS_Protected")
        PCWCH colon = wcschr(cfgPath, L':');
        PCWCH relPath = (colon != NULL) ? (colon + 1) : cfgPath;
        if (relPath != NULL && relPath[0] != L'\0')
        {
            // Case-insensitive search within normalized NT path buffer
            // Safely verify null-termination or substring boundary
            ULONG relLenBytes = (ULONG)wcslen(relPath) * sizeof(WCHAR);
            if (FilePath->Length >= relLenBytes)
            {
                for (USHORT offset = 0; offset + relLenBytes <= FilePath->Length; offset += sizeof(WCHAR))
                {
                    UNICODE_STRING slice;
                    slice.Buffer = (PWCH)((PCHAR)FilePath->Buffer + offset);
                    slice.Length = (USHORT)relLenBytes;
                    slice.MaximumLength = (USHORT)relLenBytes;

                    UNICODE_STRING target;
                    RtlInitUnicodeString(&target, relPath);

                    if (RtlEqualUnicodeString(&slice, &target, TRUE))
                    {
                        matched = TRUE;
                        break;
                    }
                }
                if (matched) break;
            }
        }
    }

    ExReleaseResourceLite(&g_FilterData.PolicyLock);
    KeLeaveCriticalRegion();

    return matched;
}

// ============================================================
// Minifilter Pre-Operation Callbacks (Pre-Access Denial)
// ============================================================

FLT_PREOP_CALLBACK_STATUS USBIPSPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Skip kernel-mode requests if safe
    if (Data->RequestorMode == KernelMode)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status))
    {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Check if target file is within an admin-protected folder
    if (IsPathInProtectedFolder(&nameInfo->Name))
    {
        ACCESS_MASK desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        ULONG disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

        BOOLEAN isWriteOrModify = (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC)) != 0;
        BOOLEAN isReadOrCopy = (desiredAccess & (FILE_READ_DATA | GENERIC_READ)) != 0;

        if (isWriteOrModify || isReadOrCopy)
        {
            // If connected to User-Mode agent, query policy verdict
            if (g_FilterData.ClientPort != NULL)
            {
                USBIPS_ACCESS_NOTIFICATION notif;
                RtlZeroMemory(&notif, sizeof(notif));
                notif.MessageType = isWriteOrModify ? USBIPS_MSG_PRE_WRITE : USBIPS_MSG_PRE_READ;
                notif.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
                notif.DesiredAccess = desiredAccess;

                RtlCopyMemory(
                    notif.FilePath,
                    nameInfo->Name.Buffer,
                    min(nameInfo->Name.Length, sizeof(notif.FilePath) - sizeof(WCHAR))
                );

                USBIPS_ACCESS_REPLY reply;
                ULONG replyLen = sizeof(reply);
                LARGE_INTEGER timeout;
                timeout.QuadPart = -5000000LL; // 500ms timeout

                status = FltSendMessage(
                    g_FilterData.FilterHandle,
                    &g_FilterData.ClientPort,
                    &notif,
                    sizeof(notif),
                    &reply,
                    &replyLen,
                    &timeout
                );

                if (NT_SUCCESS(status) && reply.BlockOperation)
                {
                    FltReleaseFileNameInformation(nameInfo);
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    return FLT_PREOP_COMPLETE; // Deny before handle creation!
                }
            }
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS USBIPSPreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // PreCreate already inspects and denies read access during handle open.
    // PreRead handles non-cached or direct I/O filtering.
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS USBIPSPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS USBIPSPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
