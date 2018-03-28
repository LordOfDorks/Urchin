// PuScTrmLib.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#define USE_VCOM_TPM
#ifdef USE_VCOM_TPM
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

#define PlatformSubmitTPM20Command(context, ...) (TPMVComSubmitCommand(FALSE, ##__VA_ARGS__) == 0x000);
#define PlatformOpenTPM(context) ((TPMVComStartup(context) == 0) ? 1 : 0);
#define PlatformCloseTPM TPMVComShutdown
#define PlatformCancelTPM
#endif

#ifndef USE_VCOM_TPM
#define PlatformSubmitTPM20Command(context, pbCmd, cbCmd, pbRsp, cbRsp, pcbRsp ) Tbsip_Submit_Command(context, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, pbCmd, cbCmd, pbRsp, pcbRsp)
#define PlatformOpenTPM TBS_Open
#define PlatformCloseTPM(context)  Tbsip_Context_Close((TBS_HCONTEXT)(context))
#define PlatformCancelTPM(context) (Tbsip_Cancel_Commands((TBS_HCONTEXT)(context)) == TBS_SUCCESS);
#endif

unsigned int
TBS_Open( void )
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


__declspec(dllexport) unsigned int ScTrm_Open(unsigned int context)
{
    return PlatformOpenTPM(context);
}

__declspec(dllexport) void ScTrm_Close(unsigned int context)
{
    PlatformCloseTPM(context);
}

__declspec(dllexport) BOOL ScTrm_Cancel(unsigned int context)
{
    return PlatformCancelTPM(context);
}

__declspec(dllexport) BOOL ScTrm_Execute(unsigned int context, unsigned char* pbCmd, unsigned int cbCmd, unsigned char* pbRsp, unsigned int cbRsp, unsigned int* pcbRsp)
{
    TBS_HCONTEXT hTBS = (TBS_HCONTEXT)context;
    *pcbRsp = cbRsp;
    return PlatformSubmitTPM20Command(
        hTBS,
        pbCmd,
        cbCmd,
        pbRsp,
        cbRsp,
        pcbRsp);
}
