#include "stdafx.h"
#include "Interface.h"

#ifdef USE_VCOM_TPM

UINT32 TPMVComSubmitCommand(
    BOOL CloseContext,
    BYTE* pbCommand,
    UINT32 cbCommand,
    BYTE* pbResponse,
    UINT32 cbResponse,
    UINT32* pcbResponse
)
{
    UINT32 result = TPM_RC_SUCCESS;
    OpenTpmConnection();

    result = SendTpmSignal(SignalCommand, pbCommand, cbCommand, pbResponse, cbResponse, pcbResponse);

    if (CloseContext)
    {
		CloseTpmConnection();
    }

    return result;
}

BOOL TPMVComStartup()
{
    unsigned char startupClear[] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00 };
    unsigned char response[10];
    unsigned int responseSize;

    return ((TPMVComSubmitCommand(FALSE, startupClear, sizeof(startupClear), response, sizeof(response), &responseSize) == TPM_RC_SUCCESS) &&
        (responseSize == sizeof(response)) &&
        (*((unsigned int*)response) == 0));
}

UINT32 TPMVComShutdown()
{
    unsigned char shutdownClear[] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x45, 0x00, 0x00 };
    unsigned char response[10];
    unsigned int responseSize;

    return ((TPMVComSubmitCommand(TRUE, shutdownClear, sizeof(shutdownClear), response, sizeof(response), &responseSize) == TPM_RC_SUCCESS) &&
        (responseSize == sizeof(response)) &&
        (*((unsigned int*)response) == 0));
}

#endif