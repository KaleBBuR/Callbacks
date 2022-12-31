#pragma once
#pragma warning( disable: 6011 6386 )

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#define LOG(x, ...) DbgPrintEx(0, 0, "[+][Callbacks][" __FUNCTION__ "]: " x "\n", __VA_ARGS__)
#define ERR_LOG(x, ...) DbgPrintEx(0, 0, "[-][Callbacks][" __FUNCTION__ "]: " x "\n", __VA_ARGS__)

#define CB_IOCTL_PROTECT_PROCESS_ID CTL_CODE (FILE_DEVICE_UNKNOWN, 0x666, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CB_IOCTL_UNPROTECT_PROCESS_ID CTL_CODE (FILE_DEVICE_UNKNOWN, 0x667, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DRIVER_TAG 'llaC'

#define PROCESS_FILE_NAME_LENGTH 15
#define MAX_LENGTH 10
#define MAX_NUM_LEN 3

#define DEVICE_NAME L"\\Device\\callbacks"
#define SYMBOL_NAME L"\\DosDevices\\callbacks"
#define PROTECTED_PROCESSES_KEY_PATH L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\callbacks\\ProtectedProcess"

// To hold all our current process IDs we want to check on
extern ULONG ProcessIds[MAX_LENGTH];
extern PWCHAR ProcessNames[MAX_LENGTH];
extern uintptr_t Processes[MAX_LENGTH];

extern PWCHAR ValueNames[MAX_LENGTH];

extern ULONG Size;

extern HANDLE KeyHandle;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    UINT32 ExceptionTableSize;
    PVOID GpValue;
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
    PVOID ImageBase;
    PVOID EntryPoint;
    UINT32 SizeOfImage;
    UNICODE_STRING FullImageName;
    UNICODE_STRING BaseImageName;
    UINT32 Flags;
    UINT16 LoadCount;

    union
    {
        UINT16 SignatureLevel : 4;
        UINT16 SignatureType : 3;
        UINT16 Unused : 9;
        UINT16 EntireField;
    } u;

    PVOID SectionPointer;
    UINT32 CheckSum;
    UINT32 CoverageSectionSize;
    PVOID CoverageSection;
    PVOID LoadedImports;
    PVOID Spare;
    UINT32 SizeOfImageNotRounded;
    UINT32 TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

// https://stackoverflow.com/questions/26170523/how-to-convert-int-to-char-in-c
// https://www.geeksforgeeks.org/how-to-convert-given-number-to-a-character-array/
//constexpr PWCHAR
//UnsignedItoa(_In_ ULONG num, ULONG base = 10)
//{
//    PWCHAR arr = { 0 };
//    WCHAR arr_holder[MAX_NUM_LEN] = { 0 };
//
//    ULONG index = 0;
//
//    ULONG m = num;
//    ULONG digit = 0;
//    while (m)
//    {
//        digit++;
//        m /= 10;
//    }
//
//    if (digit > MAX_NUM_LEN)
//        return NULL;
//
//    arr = (PWCHAR)ExAllocatePool(PagedPool, MAX_NUM_LEN * sizeof(WCHAR) + 1);
//    if (!arr)
//        return NULL;
//
//    ULONG i = 0;
//
//    if (num == 0)
//    {
//        arr[i++] = '0';
//        arr[i] = '\0';
//        return arr;
//    }
//
//    // Process individual digits
//    while (num != 0)
//    {
//        arr_holder[index] = (WCHAR)(num % base + '0');
//        LOG("Index: %lu WCHAR: arr_holder[index] = %wc", index, arr_holder[index]);
//        index++;
//
//        num /= 10;
//    }
//
//    for (i = 0; i < index; ++i)
//        arr[i] = arr_holder[index - i];
//
//    arr[i] = '\0';
//
//    LOG("ARR: %ws", arr);
//
//    return arr;
//}

constexpr BOOLEAN
CheckForDuplicateProcess(PWCHAR ProcessName)
{
    for (ULONG i = 0; i < Size; ++i)
        if (!_wcsicmp(ProcessName, ProcessNames[i]))
            return TRUE;

    return FALSE;
}

constexpr BOOLEAN
InProtectedProcessList(_In_ PVOID Object, _Out_ PLONG Index)
{
    for (ULONG i = 0; i < Size; ++i)
    {
        if (Processes[i] == (uintptr_t)Object)
        {
            *Index = i;
            return TRUE;
        }
    }

    *Index = -1;
    return FALSE;
}

constexpr BOOLEAN
InProtectedProcessIdList(_In_ ULONG Id, _Out_ PLONG Index)
{
    for (ULONG i = 0; i < Size; ++i)
    {
        if (ProcessIds[i] == Id)
        {
            *Index = i;
            return TRUE;
        }
    }

    *Index = -1;
    return FALSE;
}

constexpr BOOLEAN
InProtectedProcessNameList(_In_ PWCHAR ProcessName, _Out_ PLONG Index)
{
    for (ULONG i = 0; i < Size; ++i)
    {
        if (wcswcs(ProcessNames[i], ProcessName) != NULL)
        {
            *Index = i;
            return TRUE;
        }
    }

    *Index = -1;
    return FALSE;
}

constexpr NTSTATUS
RemoveIndex(_In_ LONG Index)
{
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING USValueName = { 0 };

    if (ValueNames[Index])
    {
        RtlInitUnicodeString(&USValueName, ValueNames[Index]);
        Status = ZwDeleteValueKey(KeyHandle, &USValueName);
        if (!NT_SUCCESS(Status))
        {
            ERR_LOG("Could not delete: %ws", ValueNames[Index]);
            return Status;
        }

        if (ValueNames[Index])
        {
            LOG("Deleted: %ws", ValueNames[Index]);
            ExFreePool(ValueNames[Index]);
        }

        if (ProcessNames[Index])
        {
            LOG("Deleted: %ws", ProcessNames[Index]);
            ExFreePool(ProcessNames[Index]);
        }

        ProcessIds[Index] = NULL;
        Processes[Index] = NULL;
    }

    return Status;
}