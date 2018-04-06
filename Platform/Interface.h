#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
#define DEFAULT_VCOM_PORT "COM6"

#ifdef USE_TPM_SIMULATOR
// Linked Simulator Hookup
UINT32 TPMSimSubmitCommand(
    BOOL CloseContext,
    BYTE* pbCommand,
    UINT32 cbCommand,
    BYTE* pbResponse,
    UINT32 cbResponse,
    UINT32* pcbResponse
);
void TPMSimTeardown(void);
#define PlatformSubmitTPM20Command TPMSimSubmitCommand
#endif

#ifdef USE_VCOM_TPM
BOOL TPMVComStartup();
UINT32 TPMVComSubmitCommand(
    BOOL CloseContext,
    CONST BYTE* pbCommand,
    UINT32 cbCommand,
    BYTE* pbResponse,
    UINT32 cbResponse,
    UINT32* pcbResponse
);
UINT32 TPMVComShutdown();
void TPMVComTeardown(void);
#define PlatformSubmitTPM20Command TPMVComSubmitCommand
#endif

#ifdef __cplusplus
}
#endif
