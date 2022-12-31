#pragma warning( disable : 4100 4189 4302 4311)

#include "global.hpp"
#include "callbacks.hpp"

OB_PREOP_CALLBACK_STATUS
CBPreOperationCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
)
{
	PTD_CALLBACK_REGISTRATION CallbackRegistration = nullptr;

	ACCESS_MASK AccessBitsToClear	  = 0;
	ACCESS_MASK AccessBitsToSet		  = 0;
	ACCESS_MASK InitialDesiredAccess  = 0;
	ACCESS_MASK OriginalDesiredAccess = 0;

	PACCESS_MASK DesiredAccess = nullptr;

	LPCWSTR ObjectTypeName = nullptr;
	LPCWSTR OperationName = nullptr;

	// Nothing driver specific
	CallbackRegistration = (PTD_CALLBACK_REGISTRATION)RegistrationContext;

	LONG Index = 0;

	NT_ASSERT(PreInfo->CallContext == NULL);

	// Only want to filter attempts to access protected process
	// all other processes are left untouched

	if (PreInfo->ObjectType == *PsProcessType)
	{
		// Ignore requests for processes other than our target process
		if (!InProtectedProcessList(PreInfo->Object, &Index) || PreInfo->Object == PsGetCurrentProcess())
			goto Exit;

		ObjectTypeName = L"PsProcessType";
		AccessBitsToClear = PROCESS_TERMINATE;
		AccessBitsToSet   = 0;
	}
	else if (PreInfo->ObjectType == *PsThreadType)
	{
		HANDLE Process = IoThreadToProcess((PETHREAD)PreInfo->Object);

		if (!InProtectedProcessList(Process, &Index) || Process == PsGetCurrentProcess())
			goto Exit;

		ObjectTypeName = L"PsObjectType";
		AccessBitsToClear = PROCESS_TERMINATE;
		AccessBitsToSet = 0;
	}
	else
	{
		ERR_LOG("Unexpected object type...");
		goto Exit;
	}

	switch (PreInfo->Operation)
	{
	case OB_OPERATION_HANDLE_CREATE:
		DesiredAccess         = &PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
		OriginalDesiredAccess = PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess;

		OperationName = L"OB_OPERATION_HANDLE_CREATE";
		break;

	case OB_OPERATION_HANDLE_DUPLICATE:
		DesiredAccess         = &PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
		OriginalDesiredAccess = PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess;

		OperationName = L"OB_OPERATION_HANDLE_DUPLICATE";
		break;

	default:
		TD_ASSERT (FALSE);
		break;
	}

	//InitialDesiredAccess = *DesiredAccess;

	// Filter only if request made outside of the kernel
	if (PreInfo->KernelHandle != 1)
	{
		*DesiredAccess &= ~AccessBitsToClear;
	}

	//CBSetCallContext(PreInfo, CallbackRegistration);

	LOG("Protected Process: 0x%llx (ID: %lu) (NAME: %ws)", Processes[Index], ProcessIds[Index], ProcessNames[Index]);

Exit:
	return OB_PREOP_SUCCESS;
}

VOID
CBPostOperationCallback(
	_In_ PVOID RegistrationContext,
	_In_ POB_POST_OPERATION_INFORMATION PostInfo
)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(PostInfo);
}

VOID
LoadImageNofifyRoutine(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessID,
	_In_ PIMAGE_INFO ImageInfo
)
{
	KeAcquireGuardedMutex(&CBCallbacksMutex);

	if (FullImageName)
	{
		LOG("IMAGE NAME: %ws", FullImageName->Buffer);
		LONG Index = -1;
		if (InProtectedProcessNameList(FullImageName->Buffer, &Index))
		{
			if (Processes[Index] == NULL)
				Size++;

			Processes[Index] = reinterpret_cast<uintptr_t>(ImageInfo->ImageBase);
			ProcessIds[Index] = reinterpret_cast<ULONG>(ProcessID);
		}
	}

	KeReleaseGuardedMutex(&CBCallbacksMutex);
}