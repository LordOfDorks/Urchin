#pragma once

#ifdef __cplusplus
extern "C"
{
#endif


#ifdef USE_VCOM_TPM
#pragma pack(push, 1)
#define MAX_TPM_COMMAND_SIZE (2048)
#define TPM_HEADER_SIZE (10)

typedef enum
{
	SignalNothing = 0,
	SignalShutdown,
	SignalReset,
	SignalSetClock,
	// IN {UINT32 time}
	SignalCancelOn,
	SignalCancelOff,
	SignalCommand,
	// IN {BYTE Locality, UINT32 InBufferSize, BYTE[InBufferSize] InBuffer}
	// OUT {UINT32 OutBufferSize, BYTE[OutBufferSize] OutBuffer}
	SignalResponse,
	// OUT {UINT32 OutBufferSize, BYTE[OutBufferSize] OutBuffer}
} signalCode_t;

typedef union
{
	struct
	{
		unsigned int time;
	} SignalSetClockPayload;
	struct
	{
		unsigned int locality;
		unsigned int cmdSize;
		unsigned char cmd[1];
	} SignalCommandPayload;
} signalPayload_t, *pSignalPayload_t;

#pragma pack(pop)

BOOL TPMVComStartup();
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
#define PlatformSubmitTPM20Command TPMVComSubmitCommand

unsigned int OpenTpmConnection(void);
unsigned int CloseTpmConnection(void);
unsigned int SendTpmSignal(signalCode_t signal,
	BYTE* dataIn,
	unsigned int dataInSize,
	BYTE* dataOut,
	unsigned int dataOutSize,
	unsigned int* dataOutUsed
);

#endif

#ifdef __cplusplus
}
#endif
