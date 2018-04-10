// PuScTrmLib.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

#ifdef USE_VCOM

BOOL TPMVComStartup(void* context);
UINT32 TPMVComSubmitCommand(
    BOOL CloseContext,
    BYTE* pbCommand,
    UINT32 cbCommand,
    BYTE* pbResponse,
    UINT32 cbResponse,
    UINT32* pcbResponse
);
UINT32 TPMVComShutdown();
void TPMVComTeardown(void);

#define PlatformSubmitTPM20Command(context, ...) \
    (TPMVComSubmitCommand(FALSE, ##__VA_ARGS__) == 0x000)

#define PlatformOpenTPM(context) \
    ((TPMVComStartup(context)) ? 1 : 0)

#define PlatformCloseTPM(context) \
    TPMVComShutdown()

#define PlatformCancelTPM(context) \
    (FALSE)

#else

#define PlatformSubmitTPM20Command(context, pbCmd, cbCmd, pbRsp, cbRsp, pcbRsp ) \
    Tbsip_Submit_Command(context, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, pbCmd, cbCmd, pbRsp, pcbRsp)

#define PlatformOpenTPM(context) \
    TBS_Open()

#define PlatformCloseTPM(context) \
    Tbsip_Context_Close((TBS_HCONTEXT)(context))

#define PlatformCancelTPM(context) \
    (Tbsip_Cancel_Commands((TBS_HCONTEXT)(context)) == TBS_SUCCESS)

#endif  // USE_VCOM

unsigned int
TBS_Open(void)
{
    TBS_RESULT result = 0;
    TBS_HCONTEXT hTBS = 0;

    TPM_DEVICE_INFO info = { TPM_VERSION_20, TPM_VERSION_20, 0, 0 };
    if ((result = Tbsi_GetDeviceInfo(sizeof(info), &info) != TBS_SUCCESS) ||
        (info.structVersion != 1) ||
        (info.tpmVersion != TPM_VERSION_20))
    {
        return (unsigned int)hTBS;
    }

    TBS_CONTEXT_PARAMS2 params = { TPM_VERSION_20, {{0, 0, 1}}};
    if ((((result = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &hTBS)) != TBS_SUCCESS)) ||
        (hTBS == INVALID_HANDLE_VALUE) ||
        (hTBS == 0))
    {
        hTBS = 0;
        return (unsigned int)hTBS;
    }

    return (unsigned int)hTBS;
}

unsigned int
ScTrm_Open(void* context)
{
    return PlatformOpenTPM(context);
}

void
ScTrm_Close(void* context)
{
    PlatformCloseTPM(context);
}

BOOL
ScTrm_Cancel(void* context)
{
    return PlatformCancelTPM(context);
}

BOOL
ScTrm_Execute(
    void* context,
    unsigned char* pbCmd,
    unsigned int cbCmd,
    unsigned char* pbRsp,
    unsigned int cbRsp,
    unsigned int* pcbRsp
)
{
    TBS_HCONTEXT hTBS = (TBS_HCONTEXT)context;
    *pcbRsp = cbRsp;

    return PlatformSubmitTPM20Command(hTBS, pbCmd, cbCmd, pbRsp, cbRsp, pcbRsp);
}
