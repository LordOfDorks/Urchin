/*
UrchinTSS

Copyright (c) Microsoft Corporation

All rights reserved.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// Note: This code was derived from the TCG TPM 2.0 Library Specification at
// http://www.trustedcomputinggroup.org/resources/tpm_library_specification

#include "stdafx.h"

#ifndef NO_WINDOWS

TBS_HCONTEXT g_hTbs = NULL;
TPM2B_AUTH g_LockoutAuth = { 0 };
TPM2B_AUTH g_EndorsementAuth = { 0 };
TPM2B_AUTH g_StorageAuth = { 0 };

UINT32
PlatformSubmitTPM20Command(
    BOOL CloseContext,
    BYTE* pbCommand,
    UINT32 cbCommand,
    BYTE* pbResponse,
    UINT32 cbResponse,
    UINT32* pcbResponse
)
{
    TBS_RESULT result = 0;
    if (g_hTbs == NULL)
    {
        TBS_CONTEXT_PARAMS2 params = { TPM_VERSION_20, 0, 0, 1 };
        if ((result = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &g_hTbs)) != TBS_SUCCESS)
        {
            return (UINT32)result;
        }
    }

    *pcbResponse = cbResponse;
    if ((result = Tbsip_Submit_Command(g_hTbs,
        TBS_COMMAND_LOCALITY_ZERO,
        TBS_COMMAND_PRIORITY_NORMAL,
        pbCommand,
        cbCommand,
        pbResponse,
        pcbResponse)) != TBS_SUCCESS)
    {
        return (UINT32)result;
    }

    if (CloseContext != FALSE)
    {
        Tbsip_Context_Close(g_hTbs);
        g_hTbs = NULL;
    }
    return (UINT32)result;
}

void
PlattformRetrieveAuthValues(
    void
)
{
    WCHAR authValue[255] = L"";
    DWORD authValueSize = sizeof(authValue);
    DWORD allowedSize = sizeof(g_LockoutAuth.t.buffer);

    if ((RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Admin", L"OwnerAuthFull", RRF_RT_REG_SZ, NULL, authValue, &authValueSize) != ERROR_SUCCESS) ||
        (!CryptStringToBinaryW(authValue, 0, CRYPT_STRING_BASE64, g_LockoutAuth.t.buffer, &allowedSize, NULL, NULL)))
    {
        MemorySet(&g_LockoutAuth, 0x00, sizeof(g_LockoutAuth));
    }
    g_LockoutAuth.t.size = (UINT16)allowedSize;

    authValueSize = sizeof(authValue);
    allowedSize = sizeof(g_StorageAuth.t.buffer);
    if ((RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Admin", L"StorageOwnerAuth", RRF_RT_REG_SZ, NULL, authValue, &authValueSize) != ERROR_SUCCESS) ||
        (!CryptStringToBinaryW(authValue, 0, CRYPT_STRING_BASE64, g_StorageAuth.t.buffer, &allowedSize, NULL, NULL)))
    {
        MemorySet(&g_StorageAuth, 0x00, sizeof(g_StorageAuth));
    }
    g_StorageAuth.t.size = (UINT16)allowedSize;

    authValueSize = sizeof(authValue);
    allowedSize = sizeof(g_EndorsementAuth.t.buffer);
    if ((RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement", L"EndorsementAuth", RRF_RT_REG_SZ, NULL, authValue, &authValueSize) != ERROR_SUCCESS) ||
        (!CryptStringToBinaryW(authValue, 0, CRYPT_STRING_BASE64, g_EndorsementAuth.t.buffer, &allowedSize, NULL, NULL)))
    {
        MemorySet(&g_EndorsementAuth, 0x00, sizeof(g_EndorsementAuth));
    }
    g_EndorsementAuth.t.size = (UINT16)allowedSize;
}

void
_cpri__PlatformRelease(
    void
)
{
    if (g_hTbs != NULL)
    {
        Tbsip_Context_Close(g_hTbs);
        g_hTbs = NULL;
    }

    _cpri__ReleaseCrypt();
}

#endif //NO_WINDOWS

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (P)
#endif

int
TpmFail(
    const char* function,
    int line,
    int code
)
{
    UNREFERENCED_PARAMETER(function);
    UNREFERENCED_PARAMETER(line);
    UNREFERENCED_PARAMETER(code);

    assert(0);
}
