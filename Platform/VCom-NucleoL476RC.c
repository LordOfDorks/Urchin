#ifdef VCOM_NUCLEO

#include "stdafx.h"
#include "Interface.h"

HANDLE hVCom = INVALID_HANDLE_VALUE;
LPCTSTR vcomPort = TEXT("COM6");
unsigned int vcomTimeout = 10 * 60 * 1000;

// Nucleo-L476RC based TPM on USB-VCOM
#pragma pack(push, 1)
#define TPM_VCOM_PORT TEXT("COM6")
#define SIGNALMAGIC (0x326d7054)

typedef struct
{
	unsigned int magic;
	signalCode_t signal;
	unsigned int dataSize;
} signalHdr_t;

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

BYTE* GenerateTpmCommandPayload(unsigned int locality,
	BYTE* cmd,
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
	BYTE* dataIn,
	unsigned int dataInSize,
	BYTE* dataOut,
	unsigned int dataOutSize,
	unsigned int* dataOutUsed
)
{
	

	BYTE* dataInPayload = NULL;
	unsigned int result = 0;
	DWORD written = 0;
	unsigned int signalBufSize = 0;
	BYTE* signalBuf = (BYTE*)malloc(signalBufSize);
	pSignalWrapper_t sig = (pSignalWrapper_t)signalBuf;
	sig->s.magic = SIGNALMAGIC;
	sig->s.signal = signal;
	sig->s.dataSize = dataInSize;
	unsigned int timeout = vcomTimeout;

	dataInPayload = GenerateTpmCommandPayload(0, dataIn, dataInSize, &dataInSize);
	signalBufSize = sizeof(signalWrapper_t) + dataInSize;

	if (dataInSize > 0)
	{
		memcpy(&signalBuf[sizeof(signalWrapper_t)], dataInPayload, dataInSize);
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
	if (dataInPayload) free(dataInPayload);
	return result;
}

unsigned int OpenTpmConnection()
{
	if (hVCom == INVALID_HANDLE_VALUE)
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
		if (((hVCom = CreateFile(vcomPort, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE) ||
			(!SetCommState(hVCom, &dcb)))
		{
			return GetLastError();
		}
		PurgeComm(hVCom, PURGE_RXCLEAR);
		unsigned int time = GetTimeStamp();
		unsigned int oldTimeout = vcomTimeout;
		vcomTimeout = 500;
		SendTpmSignal(SignalSetClock, (BYTE*)&time, sizeof(time), NULL, 0, NULL);
		vcomTimeout = oldTimeout;
	}
	return 0;
}

unsigned int CloseTpmConnection()
{
	CloseHandle(hVCom);
	hVCom = INVALID_HANDLE_VALUE;
	return 0;
}

void TPMVComTeardown(void)
{
	if (hVCom != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hVCom);
		hVCom = INVALID_HANDLE_VALUE;
	}
}
#endif //NUCLEO