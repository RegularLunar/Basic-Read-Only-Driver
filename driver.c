#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#pragma warning(disable: 4201)
#pragma warning(disable: 4214)

/* =================================================================
 * Constants
 * ================================================================= */

#define DRIVER_NAME           L"\\Driver\\DriverWithGlasses"
#define DRIVER_DEVICE_NAME    L"\\Device\\DriverWithGlasses"
#define DRIVER_SYMBOLIC_LINK  L"\\DosDevices\\DriverWithGlasses"

 // All three IOCTLs use METHOD_BUFFERED: input and output share SystemBuffer,
 // sized to max(inLen, outLen). Keep this in mind in the dispatch handler.
#define IOCTL_READ_MEMORY     CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULE_BASE CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PING            CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// PING_MAGIC lets usermode verify it's talking to this driver and not some
// other device that happened to accept the open.
#define PING_MAGIC            0xDEADBEEFCAFEBABEULL

// 64 KB cap. Large enough for most game struct reads; small enough to keep
// the kernel stack allocation in the buffered I/O path reasonable.
#define MAX_READ_SIZE         0x10000

// x64 usermode address space limits.
// UM_LOW excludes the null page + 64 KB guard region; UM_HIGH is the
// canonical user-space ceiling on x64 Windows.
#define UM_LOW   0x10000ULL
#define UM_HIGH  0x7FFFFFFFFFFFULL

/* =================================================================
 * Structures
 * ================================================================= */

 // Packed so the layout matches what usermode sends verbatim.
 // Without pack(1), the compiler may insert padding before source_address.
#pragma pack(push, 1)
typedef struct _READ_MEMORY_REQUEST {
    ULONG   target_pid;
    ULONG64 source_address;
    ULONG   read_size;
    ULONG   padding;
} READ_MEMORY_REQUEST, * PREAD_MEMORY_REQUEST;
#pragma pack(pop)

// In/out struct: usermode fills target_pid + module_name, driver fills
// base_address + module_size on success.
typedef struct _MODULE_BASE_REQUEST {
    ULONG   target_pid;
    WCHAR   module_name[256];
    ULONG64 base_address;
    ULONG   module_size;
    ULONG   padding;
} MODULE_BASE_REQUEST, * PMODULE_BASE_REQUEST;

typedef struct _PING_RESPONSE {
    ULONG64 magic;
} PING_RESPONSE, * PPING_RESPONSE;

/* =================================================================
 * Undocumented exports
 * ================================================================= */

 // Not in any public DDK header; manually declared from reverse-engineered
 // prototypes. Stable across Win10/11 x64 in practice.

 // PreviousMode=KernelMode suppresses the internal user-address range probe
 // inside MmCopyVirtualMemory. We do our own validation beforehand, so this
 // is intentional - passing UserMode would raise exceptions instead of
 // returning an error status.
NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(
    IN PEPROCESS SourceProcess, IN PVOID SourceAddress,
    IN PEPROCESS TargetProcess, OUT PVOID TargetAddress,
    IN SIZE_T BufferSize, IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T ReturnSize);

NTSYSAPI PVOID NTAPI PsGetProcessPeb(IN PEPROCESS Process);

// Allocates a real DRIVER_OBJECT and calls the provided init function with it.
// Used because kdmapper doesn't provide a valid DriverObject to DriverEntry.
NTSYSAPI NTSTATUS NTAPI IoCreateDriver(
    IN PUNICODE_STRING DriverName,
    IN PDRIVER_INITIALIZE InitializationFunction);

/* =================================================================
 * PEB structures
 * ================================================================= */

 // Partial reimplementations covering only the fields we access.
 // The SDK-provided definitions either conflict with ntifs.h includes or
 // aren't exposed at all in the DDK headers. Offsets verified on x64.

typedef struct _PEB_LDR_DATA2 {
    ULONG Length; UCHAR Initialized; PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA2, * PPEB_LDR_DATA2;

typedef struct _LDR_DATA_TABLE_ENTRY2 {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase; PVOID EntryPoint; ULONG SizeOfImage;
    UNICODE_STRING FullDllName; UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY2, * PLDR_DATA_TABLE_ENTRY2;

typedef struct _PEB2 {
    UCHAR Reserved1[2]; UCHAR BeingDebugged; UCHAR Reserved2[1];
    PVOID Reserved3[2]; PPEB_LDR_DATA2 Ldr;
} PEB2, * PPEB2;

/* =================================================================
 * Address validation
 * ================================================================= */

static __forceinline BOOLEAN IsValidUserAddress(ULONG64 Address, ULONG Size)
{
    if (Address < UM_LOW)                   return FALSE;
    if (Address > UM_HIGH)                  return FALSE;
    if (Address + Size < Address)           return FALSE;  /* overflow */
    if (Address + Size > UM_HIGH)           return FALSE;
    return TRUE;
}

/* =================================================================
 * Read process memory
 * ================================================================= */

static NTSTATUS KernelReadProcessMemory(
    ULONG   TargetPid,
    ULONG64 SourceAddress,
    PVOID   DestBuffer,
    SIZE_T  Size,
    PSIZE_T BytesRead)
{
    NTSTATUS  status;
    PEPROCESS proc = NULL;
    SIZE_T    bytes = 0;

    if (BytesRead) *BytesRead = 0;

    if (!DestBuffer || Size == 0)
        return STATUS_INVALID_PARAMETER;

    // Reject kernel addresses and the null region before touching the process.
    if (!IsValidUserAddress(SourceAddress, (ULONG)Size))
        return STATUS_ACCESS_VIOLATION;

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)TargetPid, &proc);
    if (!NT_SUCCESS(status))
        return status;

    // Best-effort TOCTOU guard. The process could still exit between here and
    // MmCopyVirtualMemory, but that call handles it gracefully.
    if (PsGetProcessExitStatus(proc) != STATUS_PENDING) {
        ObDereferenceObject(proc);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    status = MmCopyVirtualMemory(
        proc,
        (PVOID)(ULONG_PTR)SourceAddress,
        PsGetCurrentProcess(),
        DestBuffer,
        Size,
        KernelMode,         // see declaration note above
        &bytes);

    ObDereferenceObject(proc);

    if (BytesRead) *BytesRead = bytes;
    return status;
}

/* =================================================================
 * Get module base
 * ================================================================= */

static NTSTATUS KernelGetModuleBase(
    ULONG    TargetPid,
    PCWSTR   ModuleName,
    PULONG64 OutBase,
    PULONG   OutSize)
{
    NTSTATUS   status = STATUS_NOT_FOUND;
    PEPROCESS  proc = NULL;
    KAPC_STATE apc;
    int        count = 0;

    *OutBase = 0;
    *OutSize = 0;

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)TargetPid, &proc);
    if (!NT_SUCCESS(status)) return status;

    if (PsGetProcessExitStatus(proc) != STATUS_PENDING) {
        ObDereferenceObject(proc);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    // Attach to the target's address space so PEB/LDR pointers are valid
    // in our current context.
    KeStackAttachProcess(proc, &apc);

    // __try is mandatory here: every pointer we dereference lives in the
    // target's user-mode VA. Any of them could be paged out or corrupt.
    __try {
        PPEB2 peb = (PPEB2)PsGetProcessPeb(proc);
        if (!peb || !peb->Ldr || !peb->Ldr->Initialized) {
            // Process created but loader hasn't run yet, or PEB is invalid.
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        {
            LIST_ENTRY* head = &peb->Ldr->InLoadOrderModuleList;
            LIST_ENTRY* cur = head->Flink;
            UNICODE_STRING target;

            RtlInitUnicodeString(&target, ModuleName);

            // count < 2000: guard against a corrupted or circular LDR list.
            while (cur != head && count < 2000) {
                PLDR_DATA_TABLE_ENTRY2 entry = CONTAINING_RECORD(
                    cur, LDR_DATA_TABLE_ENTRY2, InLoadOrderLinks);

                if (entry->BaseDllName.Buffer &&
                    entry->BaseDllName.Length > 0 &&
                    entry->DllBase)
                {
                    if (RtlCompareUnicodeString(
                        &entry->BaseDllName, &target, TRUE) == 0)
                    {
                        *OutBase = (ULONG64)entry->DllBase;
                        *OutSize = entry->SizeOfImage;
                        status = STATUS_SUCCESS;
                        __leave;
                    }
                }
                cur = cur->Flink;
                count++;
            }
        }
        status = STATUS_NOT_FOUND;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
    return status;
}

/* =================================================================
 * IRP handlers
 * ================================================================= */

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    NTSTATUS           status = STATUS_SUCCESS;
    ULONG              bytesRet = 0;
    PIO_STACK_LOCATION stack;
    PVOID              buf;
    ULONG              inLen, outLen, code;

    UNREFERENCED_PARAMETER(DevObj);

    stack = IoGetCurrentIrpStackLocation(Irp);
    buf = Irp->AssociatedIrp.SystemBuffer;
    inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    code = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (code) {

    case IOCTL_PING:
    {
        if (outLen < sizeof(PING_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        ((PPING_RESPONSE)buf)->magic = PING_MAGIC;
        bytesRet = sizeof(PING_RESPONSE);
        break;
    }

    case IOCTL_READ_MEMORY:
    {
        READ_MEMORY_REQUEST req;
        SIZE_T br = 0;

        if (inLen < sizeof(READ_MEMORY_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        // Copy request to a local before writing anything to buf.
        // With METHOD_BUFFERED, input and output share the same buffer, so
        // we'd corrupt req if we wrote the result in-place first.
        RtlCopyMemory(&req, buf, sizeof(READ_MEMORY_REQUEST));

        if (req.read_size == 0 || req.read_size > MAX_READ_SIZE) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outLen < req.read_size) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = KernelReadProcessMemory(
            req.target_pid,
            req.source_address,
            buf,
            (SIZE_T)req.read_size,
            &br);

        if (NT_SUCCESS(status)) {
            bytesRet = (ULONG)br;
        }
        else {
            // Swallow the error and return a zeroed buffer. Callers treat
            // all-zeros as a failed read rather than checking status codes,
            // which simplifies the usermode side significantly.
            RtlZeroMemory(buf, req.read_size);
            bytesRet = req.read_size;
            status = STATUS_SUCCESS;
        }
        break;
    }

    case IOCTL_GET_MODULE_BASE:
    {
        ULONG64 baseAddr = 0;
        ULONG   modSize = 0;

        if (inLen < sizeof(MODULE_BASE_REQUEST) ||
            outLen < sizeof(MODULE_BASE_REQUEST))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        // Force-null-terminate before passing into the kernel string walker.
        // Usermode can send an unterminated buffer; we own this guarantee.
        ((PMODULE_BASE_REQUEST)buf)->module_name[255] = L'\0';

        status = KernelGetModuleBase(
            ((PMODULE_BASE_REQUEST)buf)->target_pid,
            ((PMODULE_BASE_REQUEST)buf)->module_name,
            &baseAddr,
            &modSize);

        if (NT_SUCCESS(status)) {
            ((PMODULE_BASE_REQUEST)buf)->base_address = baseAddr;
            ((PMODULE_BASE_REQUEST)buf)->module_size = modSize;
            bytesRet = sizeof(MODULE_BASE_REQUEST);
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesRet;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* =================================================================
 * Catch-all dispatch
 * ================================================================= */

 // Registered for every IRP_MJ_* we don't handle. Returning
 // STATUS_NOT_SUPPORTED is cleaner than leaving slots as NULL.
NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);

    irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

/* =================================================================
 * Entry
 * ================================================================= */

 // Called by IoCreateDriver with a properly allocated DRIVER_OBJECT.
 // Not invoked directly by kdmapper - see DriverEntry below.
NTSTATUS RealDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[MemReader] === RealDriverEntry START ===\n");

    UNICODE_STRING devName, symLink;
    PDEVICE_OBJECT devObj = NULL;
    NTSTATUS status;

    RtlInitUnicodeString(&devName, DRIVER_DEVICE_NAME);
    RtlInitUnicodeString(&symLink, DRIVER_SYMBOLIC_LINK);

    DbgPrint("[MemReader] Device name: %wZ\n", &devName);
    DbgPrint("[MemReader] SymLink name: %wZ\n", &symLink);

    // Preemptively delete a stale symlink left by an earlier crash or
    // unclean unload. IoCreateSymbolicLink will fail with NAME_COLLISION
    // if we don't clean up first.
    IoDeleteSymbolicLink(&symLink);

    status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &devObj
    );

    DbgPrint("[MemReader] IoCreateDevice = 0x%08X\n", status);

    if (status == STATUS_OBJECT_NAME_COLLISION) {
        DbgPrint("[MemReader] ERROR: Device name collision - driver already loaded?\n");
        return status;
    }

    if (!NT_SUCCESS(status)) {
        DbgPrint("[MemReader] ERROR: IoCreateDevice failed with 0x%08X\n", status);
        return status;
    }

    DbgPrint("[MemReader] Device created at: %p\n", devObj);

    status = IoCreateSymbolicLink(&symLink, &devName);
    DbgPrint("[MemReader] IoCreateSymbolicLink = 0x%08X\n", status);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[MemReader] ERROR: SymLink creation failed\n");
        IoDeleteDevice(devObj);
        return status;
    }

    DbgPrint("[MemReader] Setting up IRP handlers...\n");

    devObj->Flags |= DO_BUFFERED_IO;

    // Fill all slots first so no major function is ever NULL.
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = UnsupportedDispatch;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = NULL;  // Intentional: no safe unload path for a manually mapped driver.

    // Must clear DO_DEVICE_INITIALIZING or the I/O manager will reject all requests.
    devObj->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[MemReader] === Driver fully initialized ===\n");
    return STATUS_SUCCESS;
}

// kdmapper calls DriverEntry but provides a NULL/invalid DriverObject and no
// registry path. IoCreateDriver allocates a real DRIVER_OBJECT in the kernel
// and invokes RealDriverEntry with it, giving us a proper object to attach
// the device and dispatch table to.
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING drvName;
    RtlInitUnicodeString(&drvName, DRIVER_NAME);

    return IoCreateDriver(&drvName, &RealDriverEntry);
}