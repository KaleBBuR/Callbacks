#pragma once

#define TD_CALLBACK_REGISTRATION_TAG '0bCO' // TD_CALLBACK_REGISTRATION structure.
#define TD_CALL_CONTEXT_TAG '1bCO'

#define PROCESS_TERMINATE 0x0001

typedef struct _TD_CALLBACK_PARAMETERS {
	ACCESS_MASK AccessBitsToClear;
	ACCESS_MASK AccessBitsToSet;
} TD_CALLBACK_PARAMETERS, * PTD_CALLBACK_PARAMETERS;

typedef struct _TD_CALLBACK_REGISTRATION {
	// Handle returned by ObRegisterCallbacks
	PVOID RegistrationHandle;

	// If not NULL, filter only requests to open/duplicate handles
	// to this process (or one of its threads)
	PVOID TargetProcess;
	HANDLE TargetProcessId;

	// Currently each TD_CALLBACK_REGISTRATION has at most one process and one
	// thread callback. That is, we can't register more than one callback for
	// the same object type with a single ObRegisterCallbacks call.
	TD_CALLBACK_PARAMETERS ProcessParams;
	TD_CALLBACK_PARAMETERS ThreadParams;

	ULONG RegistrationId; // Index in the global TdCallbacks array.
} TD_CALLBACK_REGISTRATION, * PTD_CALLBACK_REGISTRATION;

typedef struct _TD_CALL_CONTEXT {
	PTD_CALLBACK_REGISTRATION CallbackRegistration;

	OB_OPERATION Operation;
	PVOID Object;
	POBJECT_TYPE ObjectType;
} TD_CALL_CONTEXT, * PTD_CALL_CONTEXT;

extern KGUARDED_MUTEX CBCallbacksMutex;

OB_PREOP_CALLBACK_STATUS
CBPreOperationCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
);

VOID
CBPostOperationCallback(
	_In_ PVOID RegistrationContext,
	_In_ POB_POST_OPERATION_INFORMATION
);

VOID CBSetCallContext(
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo,
	_In_ PTD_CALLBACK_REGISTRATION CallbackRegistration
);

VOID CBCheckAndFreeCallContext(
	_Inout_ POB_POST_OPERATION_INFORMATION PostInfo,
	_In_ PTD_CALLBACK_REGISTRATION CallbackRegistration
);

VOID LoadImageNofifyRoutine(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessID,
	_In_ PIMAGE_INFO ImageInfo
);