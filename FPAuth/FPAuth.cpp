// FPAuth.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#ifdef USE_TPM_SIMULATOR
// Linked Simulator Hookup
extern "C"
{
    UINT32 TPMSimSubmitCommand(
        BOOL CloseContext,
        BYTE* pbCommand,
        UINT32 cbCommand,
        BYTE* pbResponse,
        UINT32 cbResponse,
        UINT32* pcbResponse
    );
    void TPMSimTeardown(void);
}
#define PlatformSubmitTPM20Command TPMSimSubmitCommand
#endif

int __cdecl wmain(int argc, WCHAR* argv[])
{
    UINT32 result = 0;

    _cpri__RngStartup();
    _cpri__HashStartup();
    _cpri__RsaStartup();
    _cpri__SymStartup();

    {
        DEFINE_CALL_BUFFERS;
        UINT32 result = TPM_RC_SUCCESS;
        GetRandom_In getRandomIn = { 0 };
        GetRandom_Out getRandomOut = { 0 };
        StirRandom_In stirRandomIn = { 0 };
        StirRandom_Out stirRandomOut = { 0 };

        // Get some entropy from the PRNG
        INITIALIZE_CALL_BUFFERS(TPM2_GetRandom, &getRandomIn, &getRandomOut);
        getRandomIn.bytesRequested = SHA256_DIGEST_SIZE;
        EXECUTE_TPM_CALL(FALSE, TPM2_GetRandom);

        // Reseed the PRNG
        INITIALIZE_CALL_BUFFERS(TPM2_StirRandom, &stirRandomIn, &stirRandomOut);
        MemoryCopy2B((TPM2B*)&stirRandomIn.inData, (TPM2B*)&getRandomOut.randomBytes, sizeof(stirRandomIn.inData.t.buffer));
        EXECUTE_TPM_CALL(FALSE, TPM2_StirRandom);
    }
Cleanup:
    return result;
}

