#include "global.hpp"
#include "callbacks.hpp"

/*
 * https://github.com/microsoft/Windows-driver-samples/blob/9e1a643093cac60cd333b6d69abc1e4118a12d63/general/obcallback/driver/util.c
 * CBSetCallContext
 *
 * Creates a call context object and stores a pointer to it
 * in the supplied OB_PRE_OPERATION_INFORMATION structure
 *
 * This function is called from a pre-notification. The created call context
 * object then as to be freed in a corresponding post-notification using
 * CBCheckAndFreeCallContext
 */

VOID CBSetCallContext(
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo,
	_In_ PTD_CALLBACK_REGISTRATION CallbackRegistration
)
{
	PTD_CALL_CONTEXT CallContext;

	CallContext = (PTD_CALL_CONTEXT)ExAllocatePoolWithTag(
		PagedPool, sizeof(TD_CALL_CONTEXT), TD_CALL_CONTEXT_TAG
	);

	if (CallContext == NULL)
	{
		return;
	}

	RtlZeroMemory(CallContext, sizeof(TD_CALL_CONTEXT));

	CallContext->CallbackRegistration = CallbackRegistration;
	CallContext->Operation  = PreInfo->Operation;
	CallContext->Object     = PreInfo->Object;
	CallContext->ObjectType = PreInfo->ObjectType;

	PreInfo->CallContext = CallContext;
}

VOID CBCheckAndFreeCallContext(
	_Inout_ POB_POST_OPERATION_INFORMATION PostInfo,
	_In_ PTD_CALLBACK_REGISTRATION CallbackRegistration
)
{
	UNREFERENCED_PARAMETER(PostInfo);
	UNREFERENCED_PARAMETER(CallbackRegistration);
}
