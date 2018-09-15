#ifdef VCOM_SIMULATOR

#include "stdafx.h"
#include "Interface.h"

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

BOOLEAN simulatorStarted = FALSE;

// Nucleo-L476RC based TPM on USB-VCOM
#pragma pack(push, 1)
#define TPM_VCOM_PORT TEXT("COM6")
#define SIGNALMAGIC (0x326d7054)
#define MAX_TPM_COMMAND_SIZE (2048)
#define TPM_HEADER_SIZE (10)
#pragma pack(pop)

int _plat__NVEnable(void*);
int TPM_Manufacture(int);
int TPM_TearDown(void);
void _plat__SetNvAvail(void);
int _plat__Signal_PowerOn(bool);
int _plat__Signal_Reset(void);
int _plat__NVDisable(void);
void _plat__RunCommand(
	UINT32 cbCommand,
	BYTE* pbCommand,
	UINT32* cbResponse,
	BYTE** pbResponse
);

unsigned int SendTpmSignal(signalCode_t signal,
	BYTE* dataIn,
	unsigned int dataInSize,
	BYTE* dataOut,
	unsigned int dataOutSize,
	unsigned int* dataOutUsed
)
{
	unsigned int result = 0;
	if (signal == SignalCommand)
	{
		_plat__RunCommand(dataInSize, dataIn, &dataOutSize, &dataOut);
		*dataOutUsed = dataOutSize;
		result = 0;
		goto Cleanup;
	}

Cleanup:
	return result;
}

unsigned int OpenTpmConnection()
{
	int result = 0;
	if (!simulatorStarted)
	{
		if (result = _plat__NVEnable(NULL) != 0)
		{
			goto Cleanup;
		}
		if (result = TPM_Manufacture(1) != 0)
		{
			goto Cleanup;
		}
		_plat__SetNvAvail();
		if (result = _plat__NVDisable() != 0)
		{
			goto Cleanup;
		}
		if (result = _plat__Signal_PowerOn(TRUE) != 0)
		{
			goto Cleanup;
		}
		if (result = _plat__Signal_Reset() != 0)
		{
			goto Cleanup;
		}

		simulatorStarted = TRUE;
	}
Cleanup:
	return result;
}

unsigned int CloseTpmConnection()
{
	int result;
	result = TPM_TearDown();
	simulatorStarted = FALSE;
	return 0;
}

void TPMVComTeardown(void)
{
	if (simulatorStarted)
	{
		CloseTpmConnection();
	}
}
#endif //VCOM_SIMULATOR