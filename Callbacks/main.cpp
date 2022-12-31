#pragma warning(disable : 4172 4189 4244 4702)

#include "global.hpp"
#include "callbacks.hpp"

// The following are for setting up callbacks for Process and Thread filtering
PVOID pCBRegistrationHandle = nullptr;

// For ObRegisterCallbacks
OB_CALLBACK_REGISTRATION CBObRegistration = { 0 };
OB_OPERATION_REGISTRATION CBOperationRegistrations[2] = { { 0 }, { 0 } };
UNICODE_STRING CBAltitude = { 0 };
TD_CALLBACK_REGISTRATION CBCallbackRegistration = { 0 };

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
UNICODE_STRING SymbolName = RTL_CONSTANT_STRING(SYMBOL_NAME);
UNICODE_STRING ProtectedProcessKeyPath = RTL_CONSTANT_STRING(PROTECTED_PROCESSES_KEY_PATH);

// Make our global variables thread safe
KGUARDED_MUTEX CBCallbacksMutex;

ULONG ProcessIds[MAX_LENGTH] = { 0 };
PWCHAR ProcessNames[MAX_LENGTH] = { 0 };
uintptr_t Processes[MAX_LENGTH] = { 0 };

PWCHAR ValueNames[MAX_LENGTH] = { 0 };

ULONG Size = 0;

// For Registry
HANDLE KeyHandle = nullptr;

UNICODE_STRING ProcessUCS = RTL_CONSTANT_STRING(L"Process");

VOID
CreateProcessValueName(_In_ ULONG Num, PUNICODE_STRING VN)
{
    NTSTATUS Status = STATUS_SUCCESS;

    DECLARE_UNICODE_STRING_SIZE(ValueName, MAX_LENGTH);
    DECLARE_UNICODE_STRING_SIZE(Number, MAX_NUM_LEN);

    Status = RtlUnicodeStringCopyString(&ValueName, L"Process");
    if (!NT_SUCCESS(Status))
    {
        ERR_LOG("COULD NOT INITIALIZE VALUENAME");
        goto Log;
    }

    Status = RtlIntegerToUnicodeString(Num, NULL, &Number);
    if (!NT_SUCCESS(Status))
    {
        ERR_LOG("FUCK MEEEE");
        goto Log;
    }

    //LOG("Number: %wZ", Number);

    Status = RtlAppendUnicodeStringToString(&ValueName, &Number);
    if (!NT_SUCCESS(Status))
    {
        ERR_LOG("OH CMONNNNN REEEE");
        goto Log;
    }

    Status = RtlUnicodeStringCopy(VN, &ValueName);
    if (!NT_SUCCESS(Status))
    {
        ERR_LOG("COULD NOT FUCKING COPY STRING");
        VN = nullptr;
        goto Log;
    }

    LOG("ValueName: %wZ", VN);
    return;

Log:
    LOG("Status 0x%x", Status);
    return;
}

constexpr VOID
ClearAll()
{
    int i = 0;
    while (i < MAX_LENGTH)
    {
        ProcessIds[i] = NULL;
        Processes[i] = NULL;
        if (ProcessNames[i])
        {
            LOG("Deleted: %ws", ProcessNames[i]);
            ExFreePool(ProcessNames[i]);
        }

        if (ValueNames[i])
        {
            LOG("Deleted: %ws", ValueNames[i]);
            ExFreePool(ValueNames[i]);
        }

        ++i;
    }
}

// This should not be done LOL
static VOID
CharToWideChar(_In_ PCHAR CharArray, _Out_ PWCHAR WideCharArray)
{
    while (*CharArray)
    {
        *WideCharArray = *CharArray;
        ++WideCharArray;
        ++CharArray;
    }

    *WideCharArray = 0;
}

static NTSTATUS
SetKeyHandleToProtectedProcessKey()
{
    NTSTATUS Status = STATUS_SUCCESS;

    // Initialize object attributes so it points our keyhandle to the process key
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    InitializeObjectAttributes(&ObjectAttributes, &ProtectedProcessKeyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        ERR_LOG("Could not set Key to Process Key");
        KeyHandle = nullptr;
    }

    return Status;
}

//static VOID
//LogDisposition(ULONG Disposition)
//{
//    if (Disposition != NULL)
//    {
//        switch (Disposition)
//        {
//        case REG_CREATED_NEW_KEY:
//            LOG("We created a new key!");
//            break;
//        case REG_OPENED_EXISTING_KEY:
//            LOG("We opened an exisiting key!");
//            break;
//        default:
//            ERR_LOG("We shouldn't be here...");
//            break;
//        }
//    }
//}

// This has only been tested on Windows 10 22H2
NTSTATUS
FindProcessWithProcessID(_In_ ULONG ProcessID, _Out_opt_ PVOID ImageFileName, _Out_opt_ uintptr_t* Process)
{
    PEPROCESS SystemProcess = PsInitialSystemProcess;
    uintptr_t ListHead = *(uintptr_t*)((uintptr_t)(SystemProcess)+0x448);
    uintptr_t ListCurrent = ListHead;

    do {
        uintptr_t ListEntry = ListCurrent - 0x448;
        ULONG EProcessID = 0;
        RtlMoveMemory((PVOID)&EProcessID, (PVOID)((uintptr_t)(ListEntry + 0x440)), sizeof(EProcessID));
        if (ProcessID == EProcessID)
        {
            /*LOG("EPROCESS ID: %d", EProcessID);
            LOG("PROCESS ID: %d", ProcessID);*/
            if (ImageFileName)
                RtlMoveMemory(ImageFileName, (PVOID)((uintptr_t)(ListEntry + 0x5a8)), sizeof(CHAR) * PROCESS_FILE_NAME_LENGTH);

            if (Process)
                *Process = ListEntry;

            return STATUS_SUCCESS;
        }

        ListCurrent = *(uintptr_t*)ListCurrent;
    } while (ListCurrent != ListHead);

    return STATUS_NOT_FOUND;
}

NTSTATUS
FindProcessWithProcessName(_In_ PWCHAR ProcessName, _Out_opt_ PULONG ProcessID, _Out_opt_ uintptr_t* Process)
{
    PEPROCESS SystemProcess = PsInitialSystemProcess;
    uintptr_t ListHead = *(uintptr_t*)((uintptr_t)(SystemProcess)+0x448);
    uintptr_t ListCurrent = ListHead;

    do {
        // Top of the EPROCESS Structure
        uintptr_t ListEntry = ListCurrent - 0x448;

        // EPROCESS ImageFileName EPROCESS + 0x5a8;
        CHAR ImageFileName[15] = { 0 };
        // Wide Character array version because of the Registry
        WCHAR WideImageFileName[15] = { 0 };

        RtlMoveMemory(ImageFileName, (PVOID)((uintptr_t)ListEntry + 0x5a8), sizeof(ImageFileName));
        CharToWideChar((PCHAR)&ImageFileName, (PWCHAR)&WideImageFileName);

        if (!_wcsicmp(ProcessName, WideImageFileName))
        {
            if (ProcessID)
                *(ProcessID) = *(PULONG)((uintptr_t)ListEntry + 0x440);

            if (Process)
                *Process = ListEntry;

            return STATUS_SUCCESS;
        }

        ListCurrent = *(uintptr_t*)ListCurrent;
    } while (ListCurrent != ListHead);

    return STATUS_NOT_FOUND;
}

VOID
DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    IoDeleteSymbolicLink(&SymbolName);
    IoDeleteDevice(DriverObject->DeviceObject);

    KeAcquireGuardedMutex(&CBCallbacksMutex);

    if (!NT_SUCCESS(PsRemoveLoadImageNotifyRoutine(LoadImageNofifyRoutine)))
        LOG("Could not remove callbacks, but das alright");

    if (pCBRegistrationHandle)
        ObUnRegisterCallbacks(pCBRegistrationHandle);

    KeReleaseGuardedMutex(&CBCallbacksMutex);

    ClearAll();

    ZwClose(KeyHandle);

    LOG("Successfully unloaded driver");
}

NTSTATUS
QueryRegistryKey()
{
    Size = 0;

    NTSTATUS Status = STATUS_SUCCESS;
    ULONG KeyLength;
    PKEY_FULL_INFORMATION PKFI = NULL;

    Status = SetKeyHandleToProtectedProcessKey();
    if (!NT_SUCCESS(Status))
        goto Exit;

    ClearAll();

    Status = ZwQueryKey(KeyHandle, KEY_INFORMATION_CLASS::KeyFullInformation, NULL, 0, &KeyLength);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW || KeyLength == 0)
    {
        LOG("First ZwQueryKey Failed");
        goto Exit;
    }

    PKFI = (PKEY_FULL_INFORMATION)ExAllocatePool(PagedPool, KeyLength);
    if (!PKFI)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    Status = ZwQueryKey(KeyHandle, KEY_INFORMATION_CLASS::KeyFullInformation, PKFI, KeyLength, &KeyLength);
    if (!NT_SUCCESS(Status))
    {
        LOG("Second ZwQueryKeyFailed Failed");
        goto Exit;
    }

    for (ULONG i = 0; i < PKFI->Values; ++i)
    {
        PKEY_VALUE_FULL_INFORMATION PKVFI = NULL;
        WCHAR KeyValue[PROCESS_FILE_NAME_LENGTH] = { 0 };
        WCHAR ValueNameHolder[PROCESS_FILE_NAME_LENGTH] = { 0 };
        uintptr_t Process = 0;
        ULONG ProcessID = 0;

        Status = ZwEnumerateValueKey(KeyHandle, i, KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformation, NULL, 0, &KeyLength);
        if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW || KeyLength == 0)
        {
            LOG("First ZwEnumerateValueKey failed");
            goto Exit;
        }

        PKVFI = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePool(PagedPool, KeyLength);
        if (!PKVFI)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        Status = ZwEnumerateValueKey(KeyHandle, i, KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformation, PKVFI, KeyLength, &KeyLength);
        if (!NT_SUCCESS(Status))
        {
            LOG("First ZwEnumerateValueKey failed");
            goto Exit;
        }

        if (PKVFI->Type != REG_SZ)
        {
            goto ExitValueKey;
        }

        if (sizeof(KeyValue) <= PKVFI->DataOffset)
            RtlMoveMemory((PVOID)&KeyValue, (PVOID)((uintptr_t)PKVFI + PKVFI->DataOffset), PKVFI->DataLength);

        ProcessNames[i] = (PWCHAR)ExAllocatePool(PagedPool, sizeof(KeyValue));
        if (ProcessNames[i])
            wcscpy(ProcessNames[i], KeyValue);

        LOG("Key Value: %ws", ProcessNames[i]);

        RtlMoveMemory((PVOID)&ValueNameHolder, (PVOID)(PKVFI->Name), PKVFI->NameLength);
        ValueNames[i] = (PWCHAR)ExAllocatePool(PagedPool, sizeof(ValueNameHolder));
        if (ValueNames[i])
            wcscpy(ValueNames[i], ValueNameHolder);

        LOG("Value Name: %ws", ValueNames[i]);

        Status = FindProcessWithProcessName(KeyValue, &ProcessID, &Process);
        if (!NT_SUCCESS(Status))
        {
            LOG("Could not get process");
            ProcessIds[i] = NULL;
            Processes[i] = NULL;
            ++Size;
            goto ExitValueKey;
        }

        ProcessIds[i] = ProcessID;
        Processes[i] = Process;

        ++Size;

    ExitValueKey:
        if (PKVFI)
            ExFreePool(PKVFI);
    }

Exit:
    if (PKFI)
        ExFreePool(PKFI);

    return Status;
}

NTSTATUS
CreateRegistryKey(_In_ PUNICODE_STRING KeyName, _Out_opt_ PULONG Disposition)
{
    NTSTATUS Status = STATUS_SUCCESS;

    // Create object attributes for registry key querying
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    InitializeObjectAttributes(&ObjectAttributes, KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwCreateKey(&KeyHandle, KEY_ALL_ACCESS, &ObjectAttributes, 0, nullptr, REG_OPTION_NON_VOLATILE, Disposition);
    return Status;
}

NTSTATUS
ClearRegistryKey()
{
    Size = 0;
    // This makes it so we hold the values for as an intermediate, then we place them back later.
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING USValueName = { 0 };

    Status = QueryRegistryKey();
    if (!NT_SUCCESS(Status))
        goto Exit;

    int i = 0;
    while (i < MAX_LENGTH)
    {
        if (ValueNames[i])
        {
            RtlInitUnicodeString(&USValueName, ValueNames[i]);
            Status = ZwDeleteValueKey(KeyHandle, &USValueName);
            if (!NT_SUCCESS(Status))
            {
                ERR_LOG("Could not delete: %ws", ValueNames[i]);
                goto Exit;
            }
        }

        ++i;
    }

Exit:
    return Status;
}

NTSTATUS
UpdateRegistryKey()
{
    NTSTATUS Status = STATUS_SUCCESS;

    Status = SetKeyHandleToProtectedProcessKey();
    if (!NT_SUCCESS(Status))
        goto Exit;

    Status = ClearRegistryKey();
    if (!NT_SUCCESS(Status))
        goto Exit;

    LOG("Deleted all Reg Key Values");

    ULONG i = 0;
    while (ProcessNames[i] && i < Size)
    {
        DECLARE_UNICODE_STRING_SIZE(VN, MAX_LENGTH);
        CreateProcessValueName(i + 1, &VN);

        if (!&VN)
        {
            Status = STATUS_INVALID_ADDRESS;
            ERR_LOG("Could not create process value name");
            goto Exit;
        }

        Status = ZwSetValueKey(KeyHandle, &VN, NULL, REG_SZ, ProcessNames[i], sizeof(WCHAR) * PROCESS_FILE_NAME_LENGTH);
        if (!NT_SUCCESS(Status))
        {
            ERR_LOG("Could not set value in key");
            goto Exit;
        }

        ++i;
    }

    Status = QueryRegistryKey();
    if (!NT_SUCCESS(Status))
        goto Exit;

Exit:
    LOG("Status: 0x%x", Status);

    return Status;
}

//template <typename T>
//NTSTATUS SetValueInKey(PUNICODE_STRING ValueName, ULONG Type, T Data)
//{
//    NTSTATUS Status = STATUS_SUCCESS;
//
//    if (!KeyHandle) return STATUS_UNSUCCESSFUL;
//
//    if (typeid(T) == typeid(WCHAR[]))
//        Status = ZwSetValueKey(KeyHandle, ValueName, NULL, Type, Data, sizeof(Data));
//    else
//        Status = ZwSetValueKey(KeyHandle, ValueName, NULL, Type, Data, sizeof(Data));
//
//    return Status;
//}

BOOLEAN
CheckKeySetup(_In_ PUNICODE_STRING RegistryPathString)
{
    NTSTATUS Status = STATUS_SUCCESS;

    // Check if key was opened or created
    ULONG Disposition = NULL;

    // Create object attributes for registry key querying
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    InitializeObjectAttributes(&ObjectAttributes, RegistryPathString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = CreateRegistryKey(RegistryPathString, &Disposition);
    if (!NT_SUCCESS(Status))
    {
        ERR_LOG("Could not create or open driver registry key");
        return FALSE;
    }

    Status = CreateRegistryKey(&ProtectedProcessKeyPath, &Disposition);
    if (!NT_SUCCESS(Status))
    {
        ERR_LOG("Could not create or open protected process key");
        return FALSE;
    }

    return TRUE;
}

NTSTATUS
ProtectProcess(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS Status = STATUS_SUCCESS;

    if (Size >= MAX_LENGTH)
        return STATUS_BUFFER_OVERFLOW;

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG InputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    //ULONG OutputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    WCHAR WideImageFileName[PROCESS_FILE_NAME_LENGTH] = { 0 };

    KeAcquireGuardedMutex(&CBCallbacksMutex);

    DECLARE_UNICODE_STRING_SIZE(VN, MAX_LENGTH);
    CreateProcessValueName(Size + 1, &VN);

    if (!&VN)
    {
        Status = STATUS_INVALID_ADDRESS;
        ERR_LOG("Could not create process value name");
        goto ProtectExit;
    }

    Status = SetKeyHandleToProtectedProcessKey();
    if (!NT_SUCCESS(Status))
        goto ProtectExit;

    LOG("Value Name: %wZ", VN);

    if (InputLength == sizeof(ULONG))
    {
        LOG("InputLength == sizeof(ULONG)");
        ULONG ProcessID = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        LOG("Process ID: %d", ProcessID);
        CHAR ImageFileName[PROCESS_FILE_NAME_LENGTH] = { 0 };
        Status = FindProcessWithProcessID(ProcessID, ImageFileName, NULL);
        if (!NT_SUCCESS(Status))
        {
            ERR_LOG("Could not find prccess name with that process ID");
            goto ProtectExit;
        }

        //LOG("Image File Name: %s", ImageFileName);

        CharToWideChar((PCHAR)&ImageFileName, (PWCHAR)&WideImageFileName);

        //LOG("Wide Image File Name: %ws", WideImageFileName);

        if (CheckForDuplicateProcess(WideImageFileName))
        {
            Status = STATUS_DUPLICATE_NAME;
            goto ProtectExit;
        }

        Status = ZwSetValueKey(KeyHandle, &VN, NULL, REG_SZ, WideImageFileName, sizeof(WideImageFileName));
        if (!NT_SUCCESS(Status))
        {
            ERR_LOG("Could not set value in key");
            goto ProtectExit;
        }

        LOG("Set Value in Key");
    }
    else if (InputLength == (sizeof(CHAR) * PROCESS_FILE_NAME_LENGTH))
    {
        LOG("InputLength == sizeof(CHAR) * PROCESS_FILE_NAME_LENGTH");
        CHAR ProcessName[PROCESS_FILE_NAME_LENGTH] = { 0 };
        RtlMoveMemory(ProcessName, Irp->AssociatedIrp.SystemBuffer, sizeof(CHAR) * PROCESS_FILE_NAME_LENGTH);

        CharToWideChar((PCHAR)&ProcessName, (PWCHAR)&WideImageFileName);

        if (CheckForDuplicateProcess(WideImageFileName))
        {
            Status = STATUS_DUPLICATE_NAME;
            goto ProtectExit;
        }

        Status = ZwSetValueKey(KeyHandle, &VN, NULL, REG_SZ, WideImageFileName, sizeof(WideImageFileName));
        if (!NT_SUCCESS(Status))
        {
            ERR_LOG("Could not set value in key");
            goto ProtectExit;
        }

        LOG("Set Value in Key");
    }
    else if (InputLength == (sizeof(WCHAR) * PROCESS_FILE_NAME_LENGTH))
    {
        LOG("InputLength == sizeof(WCHAR) * PROCESS_FILE_NAME_LENGTH");
        WCHAR WideProcessName[PROCESS_FILE_NAME_LENGTH] = { 0 };
        RtlMoveMemory(WideProcessName, Irp->AssociatedIrp.SystemBuffer, sizeof(WCHAR) * PROCESS_FILE_NAME_LENGTH);

        if (CheckForDuplicateProcess(WideImageFileName))
        {
            Status = STATUS_DUPLICATE_NAME;
            goto ProtectExit;
        }

        Status = ZwSetValueKey(KeyHandle, &VN, NULL, REG_SZ, WideImageFileName, sizeof(WideImageFileName));
        if (!NT_SUCCESS(Status))
        {
            ERR_LOG("Could not set value in key");
            goto ProtectExit;
        }

        LOG("Set Value in Key");
    }
    else
    {
        ERR_LOG("Invalid Buffer Size");
        Status = STATUS_INVALID_BUFFER_SIZE;
    }

    if (NT_SUCCESS(Status))
    {
        Status = UpdateRegistryKey();
        if (!NT_SUCCESS(Status))
        {
            goto ProtectExit;
        }

        LOG("We successfully protected process");
    }

ProtectExit:
    KeReleaseGuardedMutex(&CBCallbacksMutex);

    return Status;
}

NTSTATUS
UnProtectProcess(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    NTSTATUS Status = STATUS_SUCCESS;

    if (Size == 0)
        return STATUS_NO_MORE_ENTRIES;

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG InputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;

    WCHAR WideImageFileName[PROCESS_FILE_NAME_LENGTH] = { 0 };

    LONG Index = 0;

    KeAcquireGuardedMutex(&CBCallbacksMutex);

    Status = SetKeyHandleToProtectedProcessKey();
    if (!NT_SUCCESS(Status))
        return Status;

    if (InputLength == sizeof(ULONG))
    {
        LOG("InputLength == sizeof(ULONG)");
        ULONG ProcessID = *(PULONG)Irp->AssociatedIrp.SystemBuffer;

        if (!InProtectedProcessIdList(ProcessID, &Index))
        {
            Status = STATUS_NOT_FOUND;
            goto UnProtectExit;
        }

        LOG("Process ID: %d", ProcessID);

        if (!NT_SUCCESS(Status = RemoveIndex(Index)))
        {
            ERR_LOG("Could not remove index: %ld", Index);
            goto UnProtectExit;
        }

    }
    else if (InputLength == (sizeof(CHAR) * PROCESS_FILE_NAME_LENGTH))
    {
        LOG("InputLength == sizeof(CHAR) * PROCESS_FILE_NAME_LENGTH");
        CHAR ProcessName[PROCESS_FILE_NAME_LENGTH] = { 0 };
        RtlMoveMemory(ProcessName, Irp->AssociatedIrp.SystemBuffer, sizeof(CHAR) * PROCESS_FILE_NAME_LENGTH);

        CharToWideChar((PCHAR)&ProcessName, (PWCHAR)&WideImageFileName);

        if (!InProtectedProcessNameList(WideImageFileName, &Index))
        {
            Status = STATUS_NOT_FOUND;
            goto UnProtectExit;
        }

        LOG("Process Name: %ws", WideImageFileName);

        if (!NT_SUCCESS(Status = RemoveIndex(Index)))
        {
            ERR_LOG("Could not remove index: %ld", Index);
            goto UnProtectExit;
        }
    }
    else if (InputLength == (sizeof(WCHAR) * PROCESS_FILE_NAME_LENGTH))
    {
        LOG("InputLength == sizeof(WCHAR) * PROCESS_FILE_NAME_LENGTH");
        WCHAR WideProcessName[PROCESS_FILE_NAME_LENGTH] = { 0 };
        RtlMoveMemory(WideProcessName, Irp->AssociatedIrp.SystemBuffer, sizeof(WCHAR) * PROCESS_FILE_NAME_LENGTH);

        if (!InProtectedProcessNameList(WideImageFileName, &Index))
        {
            Status = STATUS_NOT_FOUND;
            goto UnProtectExit;
        }

        LOG("Process Name: %ws", WideImageFileName);

        if (!NT_SUCCESS(Status = RemoveIndex(Index)))
        {
            ERR_LOG("Could not remove index: %ld", Index);
            goto UnProtectExit;
        }
    }
    else
    {
        ERR_LOG("Invalid Buffer Size");
        Status = STATUS_INVALID_BUFFER_SIZE;
    }

    if (NT_SUCCESS(Status))
    {
        Status = UpdateRegistryKey();
        if (!NT_SUCCESS(Status))
        {
            goto UnProtectExit;
        }

        LOG("We successfully removed protected process");
    }

UnProtectExit:
    KeReleaseGuardedMutex(&CBCallbacksMutex);

    return Status;
}

NTSTATUS
CBDeviceCreate(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
CBDeviceClose(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
CBDeviceCleanup(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
CBDeviceControl(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
    auto CtrlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;

    switch (CtrlCode)
    {
    case CB_IOCTL_PROTECT_PROCESS_ID:
        LOG("Protecting process...");
        Status = ProtectProcess(DeviceObject, Irp);
        break;
    case CB_IOCTL_UNPROTECT_PROCESS_ID:
        LOG("Unprotecting proces...");
        Status = UnProtectProcess(DeviceObject, Irp);
        break;
    default:
        ERR_LOG("Unrecgonized IOCTL Code: 0x%x", CtrlCode);
        break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    LOG("Leaving... Status: 0x%x", Status);

    return STATUS_SUCCESS;
}

EXTERN_C
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPathString)
{
    NTSTATUS Status = STATUS_SUCCESS;

    BOOLEAN SymCreated = FALSE;
    BOOLEAN RegisteredObCallbacks = FALSE;

    PDEVICE_OBJECT DeviceObj = nullptr;

    ULONG i = 0;

    // So we can test obregistercallbacks!
    PKLDR_DATA_TABLE_ENTRY ldr = (PKLDR_DATA_TABLE_ENTRY)(DriverObject->DriverSection);
    ldr->Flags |= 0x20;

    DriverObject->DriverUnload = DriverUnload;

    KeInitializeGuardedMutex(&CBCallbacksMutex);

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CBDeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CBDeviceClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = CBDeviceCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CBDeviceControl;

    // Setup the ObRegistrationCallback calls
    CBOperationRegistrations[0].ObjectType = PsProcessType;
    CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
    CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
    CBOperationRegistrations[0].PreOperation = CBPreOperationCallback;
    CBOperationRegistrations[0].PostOperation = CBPostOperationCallback;

    CBOperationRegistrations[1].ObjectType = PsThreadType;
    CBOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_CREATE;
    CBOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
    CBOperationRegistrations[1].PreOperation = CBPreOperationCallback;
    CBOperationRegistrations[1].PostOperation = CBPostOperationCallback;

    // Initialize altitude
    RtlInitUnicodeString(&CBAltitude, L"20000");

    CBObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    CBObRegistration.OperationRegistrationCount = 2;
    CBObRegistration.Altitude = CBAltitude;
    CBObRegistration.RegistrationContext = &CBCallbackRegistration;
    CBObRegistration.OperationRegistration = CBOperationRegistrations;

    do {
        if (!CheckKeySetup(RegistryPathString))
        {
            ERR_LOG("Could not finish registry setup");
            goto Exit;
        }

        Status = SetKeyHandleToProtectedProcessKey();
        if (!NT_SUCCESS(Status))
        {
            ERR_LOG("Could not set Key Handle to Protected Processes Key");
            goto Exit;
        }

        Status = QueryRegistryKey();
        if (!NT_SUCCESS(Status))
        {
            ERR_LOG("Could not Query Registery");
            goto Exit;
        }

        Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObj);
        if (!NT_SUCCESS(Status))
        {
            ERR_LOG("Could not create device");
            goto Exit;
        }

        Status = IoCreateSymbolicLink(&SymbolName, &DeviceName);
        if (!NT_SUCCESS(Status))
        {
            ERR_LOG("Could not create symbolic link");
            goto Exit;
        }

        SymCreated = TRUE;

        Status = PsSetLoadImageNotifyRoutine(LoadImageNofifyRoutine);
        if (!NT_SUCCESS(Status))
        {
            ERR_LOG("Could set image notify routine");
            goto Exit;
        }

        Status = ObRegisterCallbacks(
            &CBObRegistration,
            &pCBRegistrationHandle
        );

        if (!NT_SUCCESS(Status))
        {
            ERR_LOG("Could not set ObRegisterCallbacks: 0x%x", Status);
            goto Exit;
        }

        RegisteredObCallbacks = TRUE;

    } while (FALSE);

    if (DeviceObj) {
        DeviceObj->Flags |= DO_DIRECT_IO;
        DeviceObj->Flags &= ~DO_DEVICE_INITIALIZING;
    }

    /*i = 0;
    while (ProcessNames[i])
    {
        LOG("Process Names: %ws", ProcessNames[i]);
        ++i;
    }*/

Exit:
    if (!NT_SUCCESS(Status))
    {
        if (RegisteredObCallbacks)
            ObUnRegisterCallbacks(pCBRegistrationHandle);

        if (!NT_SUCCESS(PsRemoveLoadImageNotifyRoutine(LoadImageNofifyRoutine)))
            LOG("Could not remove callbacks, but das alright");

        if (SymCreated)
            IoDeleteSymbolicLink(&SymbolName);

        if (DeviceObj != nullptr)
            IoDeleteDevice(DeviceObj);

        if (KeyHandle != nullptr)
            ZwClose(KeyHandle);

        ClearAll();
    }

    LOG("Status: 0x%x", Status);

    return Status;
}