// ScTrmProvision.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

const char dispAuth[] = "SecretDisplayAuthorization";
const char fpReaderAuth[] = "SecretFPReaderAuthorization";
const char fpManageAuth[] = "SecretFPManageAuthorization";

TBS_HCONTEXT g_hTbs = NULL;

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

#define PlatformSubmitTPM20Command TPMVComSubmitCommand

#else

#define PlatformSubmitTPM20Command WinPlatformSubmitTPM20Command

#endif  // USE_VCOM

#define COM_PORT          "VCom"
#define IS_SWITCH(_s)   ((*(_s) == L'/') || (*(_s) == L'-'))

DWORD
GetSwitchWithValue(
    _In_ LONG argc,
    _In_reads_( argc ) LPSTR argv[],
    _In_z_ PSTR SwitchSel,
    _Out_ PSTR *Value
)

/*++

Routine Description:

    Helper. Checks the argument list for a given switch.

--*/

{

    for (INT i = 1; i < argc; i++) {

        if (IS_SWITCH( argv[i] )) {

            if (_stricmp( argv[i] + 1, SwitchSel ) == 0) {
                if ((i + 1) == argc) {
                    break;
                }

                *Value = argv[i + 1];
                return ERROR_SUCCESS;
            }
        }
    }

    *Value = NULL;
    return ERROR_INVALID_PARAMETER;
}

static UINT32
WinPlatformSubmitTPM20Command(
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

BOOL GetLockoutAuth(TPM2B_AUTH* lockout)
{
    WCHAR authValue[255] = L"";
    DWORD authValueSize = sizeof(authValue);
    DWORD allowedSize = sizeof(lockout->t.buffer);

    if ((RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Admin", L"OwnerAuthFull", RRF_RT_REG_SZ, NULL, authValue, &authValueSize) != ERROR_SUCCESS) ||
        (!CryptStringToBinaryW(authValue, 0, CRYPT_STRING_BASE64, lockout->t.buffer, &allowedSize, NULL, NULL)))
    {
        MemorySet(lockout, 0x00, sizeof(TPM2B_AUTH));
        return FALSE;
    }
    lockout->t.size = (UINT16)allowedSize;
    return TRUE;
}

int main(int argc, char *argv[])
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        Clear_In clear;
        HierarchyChangeAuth_In hierarchyChangeAuth;
        ReadPublic_In readPublic;
        CreatePrimary_In createPrimary;
        EvictControl_In evictControl;
        NV_ReadPublic_In nvReadPublic;
        NV_DefineSpace_In nvDefineSpace;
        NV_Read_In nvRead;
        NV_Write_In nvWrite;
    } in;
    union
    {
        Clear_Out clear;
        HierarchyChangeAuth_Out hierarchyChangeAuth;
        ReadPublic_Out readPublic;
        CreatePrimary_Out createPrimary;
        EvictControl_Out evictControl;
        NV_ReadPublic_Out nvReadPublic;
        NV_DefineSpace_Out nvDefineSpace;
        NV_Read_Out nvRead;
        NV_Write_Out nvWrite;
    } out;
    ANY_OBJECT ekObject = { 0 };
    ANY_OBJECT fpManageObject[FP_SLOTS] = { 0 };
    ANY_OBJECT fpReaderObject = { 0 };
    ANY_OBJECT displayObject = { 0 };
    unsigned char templateTable[FP_SLOTS][FP_TEMPLATE_SIZE] = { 0 };
    unsigned int ident = 0;
    PSTR vComPort = NULL;

    if ((argc > 1) &&
        (GetSwitchWithValue( argc, argv, COM_PORT, &vComPort ) != ERROR_SUCCESS))
    {
        wprintf_s(L"Provisions the TPM SecureTerminal\r\n\t/%S\t%s.\n\n", COM_PORT, L"Optional: Specify the communication file to open. e.g. \"COM7\"");
        return;
    }

    // Prepare Urchin
    _cpri__RngStartup();
    _cpri__HashStartup();
    _cpri__RsaStartup();
    _cpri__SymStartup();

#ifdef USE_VCOM
    TPMVComStartup(vComPort);
#endif

    // Clear the TPM if in FORCE mode
    if ((argc == 2) && (!strcmp(argv[1], "-f")))
    {
        ANY_OBJECT lockout = { 0 };
        ANY_OBJECT srkObject = { 0 };
        TPM2B_AUTH lockoutAuth = { 0 };

        lockout.entity.handle = TPM_RH_LOCKOUT;
        buffer = lockout.entity.name.t.name;
        size = sizeof(lockout.entity.name.t.name);
        lockout.entity.name.t.size = TPM_HANDLE_Marshal(&lockout.entity.handle, &buffer, &size);
        if (!GetLockoutAuth(&lockoutAuth))
        {
            printf("Reading lockoutAuth from Registry failed.\n");
            goto Cleanup;
        }
        lockout.entity.authValue = lockoutAuth;
        printf("Clear the TPM.\n");
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_Clear, &in.clear, &out.clear);
        parms.objectTableIn[TPM2_Clear_HdlIn_AuthHandle] = lockout;
        EXECUTE_TPM_CALL(FALSE, TPM2_Clear);
        lockout.entity.authValue.t.size = 0;
        memset(lockout.entity.authValue.t.buffer, 0x00, sizeof(lockout.entity.authValue.t.buffer));

        // Set the old lockoutAuth
        printf("Set the old lockoutAuth.\n");
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_HierarchyChangeAuth, &in.hierarchyChangeAuth, &out.hierarchyChangeAuth);
        parms.objectTableIn[TPM2_Clear_HdlIn_AuthHandle] = lockout;
        in.hierarchyChangeAuth.newAuth = lockoutAuth;
        EXECUTE_TPM_CALL(FALSE, TPM2_HierarchyChangeAuth);
        lockout.entity.authValue = lockoutAuth;

        // Create the SRK
        printf("Create the new SRK.\n");
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_CreatePrimary, &in.createPrimary, &out.createPrimary);
        parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle].entity.handle = TPM_RH_OWNER;
        SetSrkTemplate(&in.createPrimary.inPublic);
        EXECUTE_TPM_CALL(FALSE, TPM2_CreatePrimary);
        srkObject = parms.objectTableOut[TPM2_CreatePrimary_HdlOut_ObjectHandle];

        // Install the SRK
        printf("Install the SRK under TPM_20_SRK_HANDLE.\n");
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_EvictControl, &in.evictControl, &out.evictControl);
        parms.objectTableIn[TPM2_EvictControl_HdlIn_Auth].entity.handle = TPM_RH_OWNER;
        parms.objectTableIn[TPM2_EvictControl_HdlIn_ObjectHandle] = srkObject;
        in.evictControl.persistentHandle = TPM_20_SRK_HANDLE;
        EXECUTE_TPM_CALL(FALSE, TPM2_EvictControl);
    }

    // First make sure that the EK is present
    printf("Read EKpub.\n");
    INITIALIZE_CALL_BUFFERS(TPM2_ReadPublic, &in.readPublic, &out.readPublic);
    parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey].obj.handle = TPM_20_EK_HANDLE;
    TRY_TPM_CALL(FALSE, TPM2_ReadPublic);
    if (result != TPM_RC_SUCCESS)
    {
        // No, create and install it.
        printf("Not found. Create EK.\n");
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_CreatePrimary, &in.createPrimary, &out.createPrimary);
        parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle].entity.handle = TPM_RH_ENDORSEMENT;
        SetEkTemplate(&in.createPrimary.inPublic);
        EXECUTE_TPM_CALL(FALSE, TPM2_CreatePrimary);
        ekObject = parms.objectTableOut[TPM2_CreatePrimary_HdlOut_ObjectHandle];

        // Install the EK in NV.
        printf("Install the EK under TPM_20_EK_HANDLE.\n");
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_EvictControl, &in.evictControl, &out.evictControl);
        parms.objectTableIn[TPM2_EvictControl_HdlIn_Auth].entity.handle = TPM_RH_OWNER;
        parms.objectTableIn[TPM2_EvictControl_HdlIn_ObjectHandle] = ekObject;
        in.evictControl.persistentHandle = TPM_20_EK_HANDLE;
        EXECUTE_TPM_CALL(FALSE, TPM2_EvictControl);

        // Read the new public.
        printf("Read EKpub.\n");
        INITIALIZE_CALL_BUFFERS(TPM2_ReadPublic, &in.readPublic, &in.readPublic);
        parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey].generic.handle = TPM_20_EK_HANDLE;
        EXECUTE_TPM_CALL(FALSE, TPM2_ReadPublic);
    }
    ekObject = parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey];
    
    for (unsigned int n = 0; n < FP_SLOTS; n++)
    {
        fpManageObject[n].nv.handle = NV_FPBASE_INDEX + n;
        fpManageObject[n].nv.authValue.t.size = (UINT16)strlen(fpManageAuth);
        strcpy_s((char*)fpManageObject[n].nv.authValue.t.buffer, sizeof(fpManageObject[n].nv.authValue.t.buffer), fpManageAuth);

        printf("Read NV name for slot[%u].\n", n);
        INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nvReadPublic, &out.nvReadPublic);
        parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = fpManageObject[n];
        TRY_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
        if (result != TPM_RC_SUCCESS)
        {
            printf("Define FP manage space for slot[%u].\n", n);
            sessionTable[0].handle = TPM_RS_PW;
            INITIALIZE_CALL_BUFFERS(TPM2_NV_DefineSpace, &in.nvDefineSpace, &out.nvDefineSpace);
            parms.objectTableIn[TPM2_NV_DefineSpace_HdlIn_AuthHandle].nv.handle = TPM_RH_OWNER;
            in.nvDefineSpace.auth = fpManageObject[n].nv.authValue;
            in.nvDefineSpace.publicInfo.t.nvPublic.nvIndex = fpManageObject[n].nv.handle;
            in.nvDefineSpace.publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA256;
            in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = SET;
            in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHWRITE = SET;
            in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_NO_DA = SET;
            in.nvDefineSpace.publicInfo.t.nvPublic.authPolicy.t.size = 0;
            in.nvDefineSpace.publicInfo.t.nvPublic.dataSize = FP_TEMPLATE_SIZE;
            EXECUTE_TPM_CALL(FALSE, TPM2_NV_DefineSpace);

            printf("Read preliminary NV name for slot[%u].\n", n);
            INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nvReadPublic, &out.nvReadPublic);
            parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = fpManageObject[n];
            EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
            fpManageObject[n] = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

            printf("Initialize index for slot[%u].\n", n);
            sessionTable[0].handle = TPM_RS_PW;
            INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &in.nvWrite, &out.nvWrite);
            parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = fpManageObject[n];
            parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = fpManageObject[n];
            in.nvWrite.offset = 0;
            in.nvWrite.data.t.size = sizeof(unsigned char);
            in.nvWrite.data.t.buffer[0] = FP_SLOT_INITIALIZE_TEMPLATE;
            EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);

            printf("Read NV name for slot[%u].\n", n);
            INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nvReadPublic, &out.nvReadPublic);
            parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = fpManageObject[n];
            EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
        }
        fpManageObject[n] = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];
    }

    fpReaderObject.nv.handle = FP_AUTHORIZE_INDEX;
    fpReaderObject.nv.authValue.t.size = (UINT16)strlen(fpReaderAuth);
    strcpy_s((char*)fpReaderObject.nv.authValue.t.buffer, sizeof(fpReaderObject.nv.authValue.t.buffer), fpReaderAuth);

    printf("Read NV name for fpReader.\n");
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nvReadPublic, &out.nvReadPublic);
    parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = fpReaderObject;
    TRY_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
    if (result != TPM_RC_SUCCESS)
    {
        printf("Define FP reader space.\n");
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_NV_DefineSpace, &in.nvDefineSpace, &out.nvDefineSpace);
        parms.objectTableIn[TPM2_NV_DefineSpace_HdlIn_AuthHandle].nv.handle = TPM_RH_OWNER;
        in.nvDefineSpace.auth = fpReaderObject.nv.authValue;
        in.nvDefineSpace.publicInfo.t.nvPublic.nvIndex = fpReaderObject.nv.handle;
        in.nvDefineSpace.publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA256;
        in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = SET;
        in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHWRITE = SET;
        in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_NO_DA = SET;
        in.nvDefineSpace.publicInfo.t.nvPublic.authPolicy.t.size = 0;
        in.nvDefineSpace.publicInfo.t.nvPublic.dataSize = FP_TEMPLATE_SIZE;
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_DefineSpace);

        printf("Read preliminary NV name.\n");
        INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nvReadPublic, &out.nvReadPublic);
        parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = fpReaderObject;
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
        fpReaderObject = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

        printf("Initialize index.\n");
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &in.nvWrite, &out.nvWrite);
        parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = fpReaderObject;
        parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = fpReaderObject;
        in.nvWrite.offset = 0;
        in.nvWrite.data.t.size = sizeof(unsigned int);
        in.nvWrite.data.t.buffer[0] = FP_AUTHORIZE_INITIALIZE;
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);

        printf("Read NV name.\n");
        INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nvReadPublic, &out.nvReadPublic);
        parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = fpReaderObject;
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
    }
    fpReaderObject = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    displayObject.nv.handle = FP_DISPLAY_INDEX;
    displayObject.nv.authValue.t.size = (UINT16)strlen(dispAuth);
    strcpy_s((char*)displayObject.nv.authValue.t.buffer, sizeof(displayObject.nv.authValue.t.buffer), dispAuth);

    printf("Read NV name for display.\n");
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nvReadPublic, &out.nvReadPublic);
    parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = displayObject;
    TRY_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
    if (result != TPM_RC_SUCCESS)
    {
        printf("Define display space.\n");
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_NV_DefineSpace, &in.nvDefineSpace, &out.nvDefineSpace);
        parms.objectTableIn[TPM2_NV_DefineSpace_HdlIn_AuthHandle].nv.handle = TPM_RH_OWNER;
        in.nvDefineSpace.auth = displayObject.nv.authValue;
        in.nvDefineSpace.publicInfo.t.nvPublic.nvIndex = displayObject.nv.handle;
        in.nvDefineSpace.publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA256;
        in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = SET;
        in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHWRITE = SET;
        in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_NO_DA = SET;
        in.nvDefineSpace.publicInfo.t.nvPublic.authPolicy.t.size = 0;
        in.nvDefineSpace.publicInfo.t.nvPublic.dataSize = FP_TEMPLATE_SIZE;
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_DefineSpace);

        printf("Read preliminary NV name.\n");
        INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nvReadPublic, &out.nvReadPublic);
        parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = displayObject;
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
        displayObject = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

        printf("Initialize index.\n");
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &in.nvWrite, &out.nvWrite);
        parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = displayObject;
        parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = displayObject;
        in.nvWrite.offset = 0;
        in.nvWrite.data.t.size = 0;
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);

        printf("Read NV name.\n");
        INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nvReadPublic, &out.nvReadPublic);
        parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = displayObject;
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
    }
    displayObject = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    // Empty the fingerprint reader template database
    printf("Empty the FP reader database.\n");
    sessionTable[0].handle = TPM_RS_PW;
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &in.nvWrite, &out.nvWrite);
    parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = fpManageObject[0];
    parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = fpManageObject[0];
    in.nvWrite.offset = 0;
    in.nvWrite.data.t.size = sizeof(unsigned char);
    in.nvWrite.data.t.buffer[0] = FP_SLOT_DELETE_ALL_TEMPLATE;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);

    for (unsigned int n = 0; n < FP_SLOTS; n++)
    {
        char enrollMsg[128];
        sprintf_s(enrollMsg, sizeof(enrollMsg), "Enroll finger in slot[%u]\n", n);

        printf("Show enroll message %u.\n", n);
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &in.nvWrite, &out.nvWrite);
        parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = displayObject;
        parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = displayObject;
        in.nvWrite.offset = 0;
        in.nvWrite.data.t.size = (UINT16)(strlen(enrollMsg) + 1);
        strcpy_s((char*)in.nvWrite.data.t.buffer, sizeof(in.nvWrite.data.t.buffer), enrollMsg);
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);

        printf("Enroll slot[%u].\n", n);
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &in.nvWrite, &out.nvWrite);
        parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = fpManageObject[n];
        parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = fpManageObject[n];
        in.nvWrite.offset = 0;
        in.nvWrite.data.t.size = sizeof(unsigned char);
        in.nvWrite.data.t.buffer[0] = FP_SLOT_ENROLL_TEMPLATE;
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);

        printf("Wipe enroll message %u.\n", n);
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &in.nvWrite, &out.nvWrite);
        parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = displayObject;
        parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = displayObject;
        in.nvWrite.offset = 0;
        in.nvWrite.data.t.size = 0;
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);

        //printf("Read template from slot[%u].\n", n);
        //sessionTable[0].handle = TPM_RS_PW;
        //INITIALIZE_CALL_BUFFERS(TPM2_NV_Read, &in.nvRead, &out.nvRead);
        //parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = fpManageObject[n];
        //parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = fpManageObject[n];
        //in.nvRead.offset = 0;
        //in.nvRead.size = FP_TEMPLATE_SIZE;
        //EXECUTE_TPM_CALL(FALSE, TPM2_NV_Read);
        //memcpy(templateTable[n], out.nvRead.data.t.buffer, out.nvRead.data.t.size);

        //printf("Write template back to slot[%u].\n", n);
        //sessionTable[0].handle = TPM_RS_PW;
        //INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &in.nvWrite, &out.nvWrite);
        //parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = displayObject;
        //parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = displayObject;
        //in.nvWrite.offset = 0;
        //in.nvWrite.data.t.size = FP_TEMPLATE_SIZE;
        //memcpy(in.nvWrite.data.t.buffer, templateTable[n], in.nvWrite.data.t.size);
        //EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);

        Sleep(1000);
    }

    Sleep(3000);
    BOOL done = FALSE;
    do
    {
        char identifyMsg[128];
        sprintf_s(identifyMsg, sizeof(identifyMsg), "Identifying finger %u\n", ident++);

        printf("Show identify message.\n");
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &in.nvWrite, &out.nvWrite);
        parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = displayObject;
        parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = displayObject;
        in.nvWrite.offset = 0;
        in.nvWrite.data.t.size = (UINT16)(strlen(identifyMsg) + 1);
        strcpy_s((char*)in.nvWrite.data.t.buffer, sizeof(in.nvWrite.data.t.buffer), identifyMsg);
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);

        printf("Identify finger.\n");
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_NV_Read, &in.nvRead, &out.nvRead);
        parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = fpReaderObject;
        parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = fpReaderObject;
        in.nvRead.offset = 0;
        in.nvRead.size = sizeof(unsigned int);
        TRY_TPM_CALL(FALSE, TPM2_NV_Read);
        if (result == TPM_RC_SUCCESS)
        {
            int slot = *((int*)out.nvRead.data.t.buffer);
            if ((slot >= 0) && (slot <= 199)) printf("Match slot[%u].\n", slot);
            else if (slot == -1) printf("Unmatched.\n");
            else printf("Error.\n");
        }
        else if (result != TPM_RC_CANCELED)
        {
            printf("Reader error.\n");
        }
        else if (result == TPM_RC_CANCELED)
        {
            printf("Canceled.\n");
            done = TRUE;
        }

        printf("Wipe identify message.\n");
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &in.nvWrite, &out.nvWrite);
        parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = displayObject;
        parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = displayObject;
        in.nvWrite.offset = 0;
        in.nvWrite.data.t.size = 0;
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);

        if (!done)
        {
            Sleep(3000);
        }
    } while (!done);

    printf("char dispAuth[%d]        = \"%s\";\n", sizeof(dispAuth), dispAuth);
    printf("char fpReaderAuth[%d]    = \"%s\";\n", sizeof(fpReaderAuth), fpReaderAuth);
    printf("char fpManageAuth[%d]    = \"%s\";\n", sizeof(fpManageAuth), fpManageAuth);
    printf("unsigned char ekName[%u] = {", ekObject.obj.name.t.size);
    for (UINT32 n = 0; n < ekObject.obj.name.t.size; n++)
    {
        if (n > 0) printf(", ");
        if ((n % 16) == 0) printf("\n");
        printf("0x%02x", ekObject.obj.name.t.name[n]);
    }
    printf("\n};\n");

Cleanup:
#ifdef USE_VCOM
    TPMVComShutdown();
#endif

    if (result != TPM_RC_SUCCESS) {
        printf("Last command failed, status %d (0x%x)\n", result, result);
    }

    return 0;
}
