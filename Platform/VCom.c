#include "windows.h"
#include "Interface.h"
#ifndef DMSG
#include <stdio.h>
# define DMSG printf
#endif

HANDLE hVCom = INVALID_HANDLE_VALUE;
char* vcomPort = DEFAULT_VCOM_PORT;
unsigned int vcomTimeout = 10 * 60 * 1000;

// Nucleo-L476RC based TPM on USB-VCOM
#pragma pack(push, 1)
#define SIGNALMAGIC (0x326d7054)
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

typedef struct
{
    unsigned int magic;
    signalCode_t signal;
    unsigned int dataSize;
} signalHdr_t;

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

typedef union
{
    signalHdr_t s;
    unsigned char b[sizeof(signalHdr_t)];
} signalWrapper_t, *pSignalWrapper_t;
#pragma pack(pop)

unsigned int GetTimeStamp(void)
{
    FILETIME now = { 0 };
    LARGE_INTEGER convert = { 0 };

    // Get the current timestamp
    GetSystemTimeAsFileTime(&now);
    convert.LowPart = now.dwLowDateTime;
    convert.HighPart = now.dwHighDateTime;
    convert.QuadPart = (convert.QuadPart - (UINT64)(11644473600000 * 10000)) / 10000000;
    return convert.LowPart;
}

unsigned int SetTpmResponseTimeout(unsigned int timeout)
{
    COMMTIMEOUTS to = { 0 };
    to.ReadIntervalTimeout = 0;
    to.ReadTotalTimeoutMultiplier = 0;
    to.ReadTotalTimeoutConstant = timeout;
    to.WriteTotalTimeoutMultiplier = 0;
    to.WriteTotalTimeoutConstant = 0;
    if (!SetCommTimeouts(hVCom, &to))
    {
        return GetLastError();
    }
    else
    {
        return 0;
    }
}

unsigned int SendTpmSignal(signalCode_t signal,
    unsigned int timeout,
    BYTE* dataIn,
    unsigned int dataInSize,
    BYTE* dataOut,
    unsigned int dataOutSize,
    unsigned int* dataOutUsed
)
{
    unsigned int result = 0;
    DWORD written = 0;
    unsigned int signalBufSize = sizeof(signalWrapper_t) + dataInSize;
    BYTE* signalBuf = (BYTE*)malloc(signalBufSize);
    pSignalWrapper_t sig = (pSignalWrapper_t)signalBuf;
    sig->s.magic = SIGNALMAGIC;
    sig->s.signal = signal;
    sig->s.dataSize = dataInSize;
    if (dataInSize > 0)
    {
        memcpy(&signalBuf[sizeof(signalWrapper_t)], dataIn, dataInSize);
    }

    PurgeComm(hVCom, PURGE_RXCLEAR | PURGE_TXCLEAR);
    if (!WriteFile(hVCom, signalBuf, signalBufSize, &written, NULL))
    {
        result = GetLastError();
        goto Cleanup;
    }

    if (signal == SignalCommand)
    {
        DWORD read = 0;
        unsigned int rspSize = 0;

        SetTpmResponseTimeout(timeout - 1000);
        if (!ReadFile(hVCom, &rspSize, sizeof(rspSize), (LPDWORD)&read, NULL))
        {
            result = GetLastError();
            goto Cleanup;
        }
        if (read == 0)
        {
            result = GetLastError();
            goto Cleanup;
        }

        read = 0;
        SetTpmResponseTimeout(1000);
        if ((!ReadFile(hVCom, dataOut, min(rspSize, dataOutSize), (LPDWORD)&read, NULL)) ||
            (read != rspSize))
        {
            result = GetLastError();
            goto Cleanup;
        }
        *dataOutUsed = read;
        PurgeComm(hVCom, PURGE_RXCLEAR);
    }

Cleanup:
    if (signalBuf) free(signalBuf);
    return result;
}

BYTE* GenerateTpmCommandPayload(unsigned int locality,
    CONST BYTE* cmd,
    UINT32 cmdSize,
    unsigned int* dataInSize
)
{
    pSignalPayload_t payload = NULL;
    *dataInSize = sizeof(payload->SignalCommandPayload) - sizeof(unsigned char) + cmdSize;
    BYTE* dataIn = (BYTE*)malloc(*dataInSize);
    payload = (pSignalPayload_t)dataIn;
    payload->SignalCommandPayload.locality = locality;
    payload->SignalCommandPayload.cmdSize = cmdSize;
    memcpy(payload->SignalCommandPayload.cmd, cmd, cmdSize);
    return dataIn;
}

unsigned int OpenTpmConnection(char * comPort)
{
    DCB dcb = { 0 };
    if (hVCom != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hVCom);
        hVCom = INVALID_HANDLE_VALUE;
    }
    dcb.DCBlength = sizeof(DCB);
    dcb.BaudRate = CBR_115200;
    dcb.fBinary = TRUE;
    dcb.fParity = FALSE;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    if (((hVCom = CreateFileA(comPort, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE) ||
        (!SetCommState(hVCom, &dcb)))
    {
        return GetLastError();
    }
    PurgeComm(hVCom, PURGE_RXCLEAR);
    unsigned int time = GetTimeStamp();
    SendTpmSignal(SignalSetClock, 500, (BYTE*)&time, sizeof(time), NULL, 0, NULL);

    return 0;
}

UINT32 TPMVComSubmitCommand(
    BOOL CloseContext,
    const BYTE* pbCommand,
    UINT32 cbCommand,
    BYTE* pbResponse,
    UINT32 cbResponse,
    UINT32* pcbResponse
)
{
    UINT32 result = 0;// TPM_RC_SUCCESS;
    BYTE* dataIn = NULL;
    unsigned int dataInSize = 0;
    if (hVCom == INVALID_HANDLE_VALUE)
    {
        result = OpenTpmConnection(vcomPort);
        if (result != ERROR_SUCCESS)
        {
            DMSG( "Failed to open port %s. Error %d\n", vcomPort, result );
            return result;
        }
    }

    dataIn = GenerateTpmCommandPayload(0, pbCommand, cbCommand, &dataInSize);
    result = SendTpmSignal(SignalCommand, vcomTimeout, dataIn, dataInSize, pbResponse, cbResponse, pcbResponse);

    if (CloseContext)
    {
        CloseHandle(hVCom);
        hVCom = INVALID_HANDLE_VALUE;
    }

    if (dataIn) free(dataIn);
    return result;
}

void TPMVComTeardown(void)
{
    if (hVCom != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hVCom);
        hVCom = INVALID_HANDLE_VALUE;
    }
}

BOOL TPMVComStartup(void* context)
{
    unsigned char startupClear[] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00 };
    unsigned char response[10];
    unsigned int responseSize;

    if (context != NULL) {
        vcomPort = (char *)(context);
    }

    return ((TPMVComSubmitCommand(FALSE, startupClear, sizeof(startupClear), response, sizeof(response), &responseSize) == 0 /*TPM_RC_SUCCESS*/) &&
        (responseSize == sizeof(response)) &&
        (*((unsigned int*)response) == 0));
}

UINT32 TPMVComShutdown()
{
    unsigned char shutdownClear[] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x45, 0x00, 0x00 };
    unsigned char response[10];
    unsigned int responseSize;

    return ((TPMVComSubmitCommand(TRUE, shutdownClear, sizeof(shutdownClear), response, sizeof(response), &responseSize) == 0 /*TPM_RC_SUCCESS*/) &&
        (responseSize == sizeof(response)) &&
        (*((unsigned int*)response) == 0));
}
