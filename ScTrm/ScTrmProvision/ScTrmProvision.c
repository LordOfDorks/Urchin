// ScTrmProvision.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Cmdline.h"
#include "TrScTrmLib.h"
#include "Windows.h"
#include "Interface.h"

const char dispAuth[] = "SecretDisplayAuthorization";
const char fpReaderAuth[] = "SecretFPReaderAuthorization";
const char fpManageAuth[] = "SecretFPManageAuthorization";

// todo: move to a common header
#define ESC_FONT_BLACK      "\x1B[30m"
#define ESC_FONT_BLUE       "\x1B[31m"
#define ESC_FONT_RED        "\x1B[32m"
#define ESC_FONT_GREEN      "\x1B[33m"
#define ESC_FONT_CYAN       "\x1B[34m"
#define ESC_FONT_MAGENTA    "\x1B[35m"
#define ESC_FONT_YELLOW     "\x1B[36m"
#define ESC_FONT_WHITE      "\x1B[37m"
//
#define ESC_FONT_BGR_BLACK      "\x1B[40m"
#define ESC_FONT_BGR_BLUE       "\x1B[41m"
#define ESC_FONT_BGR_RED        "\x1B[42m"
#define ESC_FONT_BGR_GREEN      "\x1B[43m"
#define ESC_FONT_BGR_CYAN       "\x1B[44m"
#define ESC_FONT_BGR_MAGENTA    "\x1B[45m"
#define ESC_FONT_BGR_YELLOW     "\x1B[46m"
#define ESC_FONT_BGR_WHITE      "\x1B[47m"
// Font Size
#define FONT_SIZE_1       "\x1B[51m"
#define FONT_SIZE_2       "\x1B[52m"
#define FONT_SIZE_3       "\x1B[53m"
#define FONT_SIZE_4       "\x1B[54m"
#define FONT_SIZE_5       "\x1B[55m"
#define FONT_SIZE_6       "\x1B[56m"
#define FONT_SIZE_7       "\x1B[57m"
#define FONT_SIZE_8       "\x1B[58m"
#define FONT_SIZE_9       "\x1B[59m"

#define ASCII_DEGREE       "\xF8"

#define CLEAR_DISPLAY WriteToDisplay(&ctx, NULL);

TBS_HCONTEXT g_hTbs = NULL;


typedef union
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
} TPM_IN;

typedef union
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
} TPM_OUT;

typedef struct _SCTRM_CTX
{
    TPM_IN in;
    TPM_OUT out;
    URCHIN_CALLBUFFERS cb;

    ANY_OBJECT displayObject;
    ANY_OBJECT fpReaderObject;
    ANY_OBJECT ekObject;

} SCTRM_CTX;

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

BOOL
GetLockoutAuth(
    TPM2B_AUTH* lockout
)
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

int
WriteToDisplay(
    SCTRM_CTX *ctx,
    char* msgFmt,
    ...
)
{
    char *string = NULL;
    int allocSize;
    va_list argList;
    UINT32 result = TPM_RC_SUCCESS;
    NV_Write_In *nvWriteIn = &ctx->in.nvWrite;
    URCHIN_CALLBUFFERS *cb = &ctx->cb;

    // Format the string if we have one.
    // A null string instructs the display to clear.
    if (msgFmt != NULL) {
        va_start( argList, msgFmt );
        allocSize = vsnprintf( NULL, 0, msgFmt, argList ) + 1;

        string = malloc( allocSize );
        if (string == NULL) {
            goto Cleanup;
        }
        ZeroMemory( string, allocSize );

        vsnprintf( string, allocSize, msgFmt, argList );
        va_end( argList );
    }

    // NV Write
    cb->sessionTable[0].handle = TPM_RS_PW;
    INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_NV_Write, nvWriteIn, &ctx->out.nvWrite);
    cb->parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = ctx->displayObject;;
    cb->parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = ctx->displayObject;;
    nvWriteIn->offset = 0;
    nvWriteIn->data.t.size = 0;

    if (string != NULL) {
        nvWriteIn->data.t.size = allocSize;
        strcpy_s((char*)nvWriteIn->data.t.buffer, sizeof(nvWriteIn->data.t.buffer), string);
    }

    EXECUTE_TPM_CALL_CTX(cb, FALSE, TPM2_NV_Write);

Cleanup:

    if (result != TPM_RC_SUCCESS) {
        printf("Last command failed, status %d (0x%x)\n", result, result);
    }

    if (string != NULL) {
        free( string );
    }

    return 0;
}

int
InitializeNvSpace( 
    SCTRM_CTX *ctx,
    const char *Auth,
    ANY_OBJECT *NvObject,
    unsigned int NvIndex,
    unsigned int Size,
    BOOLEAN *Created
)
{
    UINT32 result = TPM_RC_SUCCESS;
    URCHIN_CALLBUFFERS *cb = &ctx->cb;

    *Created = FALSE;
    NvObject->nv.handle = NvIndex;
    NvObject->nv.authValue.t.size = (UINT16)strlen(Auth);
    strcpy_s((char*)NvObject->nv.authValue.t.buffer, sizeof(NvObject->nv.authValue.t.buffer), Auth);

    INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_NV_ReadPublic, &ctx->in.nvReadPublic, &ctx->in.nvReadPublic);
    cb->parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = *NvObject;

    TRY_TPM_CALL_CTX(cb, FALSE, TPM2_NV_ReadPublic);
    if (result != TPM_RC_SUCCESS) {
        cb->sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_NV_DefineSpace, &ctx->in.nvDefineSpace, &ctx->out.nvDefineSpace);
        cb->parms.objectTableIn[TPM2_NV_DefineSpace_HdlIn_AuthHandle].nv.handle = TPM_RH_OWNER;
        ctx->in.nvDefineSpace.auth = NvObject->nv.authValue;
        ctx->in.nvDefineSpace.publicInfo.t.nvPublic.nvIndex = NvObject->nv.handle;
        ctx->in.nvDefineSpace.publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA256;
        ctx->in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = SET;
        ctx->in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHWRITE = SET;
        ctx->in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_NO_DA = SET;
        ctx->in.nvDefineSpace.publicInfo.t.nvPublic.authPolicy.t.size = 0;
        ctx->in.nvDefineSpace.publicInfo.t.nvPublic.dataSize = Size;
        EXECUTE_TPM_CALL_CTX(cb, FALSE, TPM2_NV_DefineSpace);

        INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_NV_ReadPublic, &ctx->in.nvReadPublic, &ctx->out.nvReadPublic);
        cb->parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = *NvObject;
        EXECUTE_TPM_CALL_CTX(cb, FALSE, TPM2_NV_ReadPublic);
        *NvObject = cb->parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

        cb->sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_NV_Write, &ctx->in.nvWrite, &ctx->out.nvWrite);
        cb->parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = *NvObject;
        cb->parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = *NvObject;
        ctx->in.nvWrite.offset = 0;
        ctx->in.nvWrite.data.t.size = 0;
        EXECUTE_TPM_CALL_CTX(cb, FALSE, TPM2_NV_Write);

        INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_NV_ReadPublic, &ctx->in.nvReadPublic, &ctx->out.nvReadPublic);
        cb->parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = *NvObject;
        EXECUTE_TPM_CALL_CTX(cb, FALSE, TPM2_NV_ReadPublic);
        *Created = TRUE;
    }

    *NvObject = cb->parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

Cleanup:

    if (result != TPM_RC_SUCCESS) {
        printf("Last command failed, status %d (0x%x)\n", result, result);
    }

    return result;
}

int
InitializeNvDisplay(
    SCTRM_CTX *ctx 
)
{
    BOOLEAN created;
    return InitializeNvSpace( ctx, dispAuth, &ctx->displayObject, FP_DISPLAY_INDEX, FP_TEMPLATE_SIZE, &created );
}

int
InitializeFBReader(
    SCTRM_CTX *ctx
)
{
    BOOLEAN created;
    return InitializeNvSpace( ctx, fpReaderAuth, &ctx->fpReaderObject, FP_AUTHORIZE_INDEX, FP_TEMPLATE_SIZE, &created );
}

int
ClearTPM(
    SCTRM_CTX *ctx
)
{
    UINT32 result = TPM_RC_SUCCESS;
    URCHIN_CALLBUFFERS *cb = &ctx->cb;
    ANY_OBJECT lockout = { 0 };
    ANY_OBJECT srkObject = { 0 };
    TPM2B_AUTH lockoutAuth = { 0 };

    lockout.entity.handle = TPM_RH_LOCKOUT;
    cb->buffer = lockout.entity.name.t.name;
    cb->size = sizeof(lockout.entity.name.t.name);
    lockout.entity.name.t.size = TPM_HANDLE_Marshal(&lockout.entity.handle, &cb->buffer, &cb->size);
    // Lockout value for a VCOM device is not stored in the registry. This will need to be managed another way.
#ifndef USE_VCOM
    if (!GetLockoutAuth(&lockoutAuth)) {
        printf("Reading lockoutAuth from Registry failed.\n");
        goto Cleanup;
    }
#endif
    lockout.entity.authValue = lockoutAuth;

    WriteToDisplay( ctx, "Clearing the TPM\n" );

    printf("Clear the TPM.\n");
    cb->sessionTable[0].handle = TPM_RS_PW;
    INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_Clear, &ctx->in.clear, &ctx->out.clear);
    cb->parms.objectTableIn[TPM2_Clear_HdlIn_AuthHandle] = lockout;
    EXECUTE_TPM_CALL_CTX(cb, FALSE, TPM2_Clear);
    lockout.entity.authValue.t.size = 0;
    memset(lockout.entity.authValue.t.buffer, 0x00, sizeof(lockout.entity.authValue.t.buffer));

    // Set the old lockoutAuth
    printf("Set the old lockoutAuth.\n");
    cb->sessionTable[0].handle = TPM_RS_PW;
    INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_HierarchyChangeAuth, &ctx->in.hierarchyChangeAuth, &ctx->out.hierarchyChangeAuth);
    cb->parms.objectTableIn[TPM2_Clear_HdlIn_AuthHandle] = lockout;
    ctx->in.hierarchyChangeAuth.newAuth = lockoutAuth;
    EXECUTE_TPM_CALL_CTX(cb, FALSE, TPM2_HierarchyChangeAuth);
    lockout.entity.authValue = lockoutAuth;

    // Create the SRK
    WriteToDisplay( ctx, "Creating SRK\n" );
    printf("Create the new SRK.\n");
    cb->sessionTable[0].handle = TPM_RS_PW;
    INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_CreatePrimary, &ctx->in.createPrimary, &ctx->out.createPrimary);
    cb->parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle].entity.handle = TPM_RH_OWNER;
    SetSrkTemplate(&ctx->in.createPrimary.inPublic);
    EXECUTE_TPM_CALL_CTX(cb, FALSE, TPM2_CreatePrimary);
    srkObject = cb->parms.objectTableOut[TPM2_CreatePrimary_HdlOut_ObjectHandle];

    // Install the SRK
    printf("Install the SRK under TPM_20_SRK_HANDLE.\n");
    cb->sessionTable[0].handle = TPM_RS_PW;
    INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_EvictControl, &ctx->in.evictControl, &ctx->out.evictControl);
    cb->parms.objectTableIn[TPM2_EvictControl_HdlIn_Auth].entity.handle = TPM_RH_OWNER;
    cb->parms.objectTableIn[TPM2_EvictControl_HdlIn_ObjectHandle] = srkObject;
    ctx->in.evictControl.persistentHandle = TPM_20_SRK_HANDLE;
    EXECUTE_TPM_CALL_CTX(cb, FALSE, TPM2_EvictControl);

Cleanup:

    if (result != TPM_RC_SUCCESS) {
        printf("Last command failed, status %d (0x%x)\n", result, result);
    }

    return result;
}

BOOLEAN
ValidateFB(
    SCTRM_CTX *ctx,
    unsigned int *slotID
)
{ 
    UINT32 result = TPM_RC_SUCCESS;
    URCHIN_CALLBUFFERS *cb = &ctx->cb;
    BOOLEAN valid = FALSE;

    WriteToDisplay(ctx, "\nIdentifying finger\n");

    cb->sessionTable[0].handle = TPM_RS_PW;
    INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_NV_Read, &ctx->in.nvRead, &ctx->out.nvRead);
    cb->parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = ctx->fpReaderObject;
    cb->parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = ctx->fpReaderObject;
    ctx->in.nvRead.offset = 0;
    ctx->in.nvRead.size = sizeof(unsigned int);
    TRY_TPM_CALL_CTX(cb, FALSE, TPM2_NV_Read);
    if (result == TPM_RC_SUCCESS)
    {
        int slot = *((int*)ctx->out.nvRead.data.t.buffer);
        if ((slot >= 0) && (slot <= 199))
        {
            printf( "Match slot[%u].\n", slot );
            valid = TRUE;
            *slotID = slot;
        }
        else if (slot == -1) printf("Unmatched.\n");
        else printf( "Error.\n" );
    }
    else if (result != TPM_RC_CANCELED)
    {
        printf("Reader error.\n");
    }
    else if (result == TPM_RC_CANCELED)
    {
        printf("Canceled.\n");
    }

    WriteToDisplay(ctx, NULL);

    return valid;
}

int
ReadFPTemplate(
    SCTRM_CTX *ctx,
    ANY_OBJECT *fpManageObject,
    unsigned char *templateBuffer,
    unsigned int templateBufferSize,
    unsigned int *written
)
{
    UINT32 result = TPM_RC_SUCCESS;
    URCHIN_CALLBUFFERS *cb = &ctx->cb;

    cb->sessionTable[0].handle = TPM_RS_PW;
    INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_NV_Read, &ctx->in.nvRead, &ctx->out.nvRead);
    cb->parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = *fpManageObject;
    cb->parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = *fpManageObject;
    ctx->in.nvRead.offset = 0;
    ctx->in.nvRead.size = FP_TEMPLATE_SIZE;
    TRY_TPM_CALL_CTX(cb, FALSE, TPM2_NV_Read);
    if (result == TPM_RC_SUCCESS)
    {
        if (templateBufferSize < ctx->out.nvRead.data.t.size)
        {
            printf( "Internal Error. Unexpected template size.\n" );
            return -1;
        }
        memcpy( templateBuffer, ctx->out.nvRead.data.t.buffer, ctx->out.nvRead.data.t.size );
    }

    *written = ctx->out.nvRead.data.t.size;
    return result;
}

int
WriteFPTemplate(
    SCTRM_CTX *ctx,
    ANY_OBJECT *fpManageObject,
    unsigned char *templateBuffer,
    unsigned int templateBufferSize
)
{
    UINT32 result = TPM_RC_SUCCESS;
    URCHIN_CALLBUFFERS *cb = &ctx->cb;

    cb->sessionTable[0].handle = TPM_RS_PW;

    INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_NV_Write, &ctx->in.nvWrite, &ctx->out.nvWrite);
    cb->parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = *fpManageObject;
    cb->parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = *fpManageObject;
    ctx->in.nvWrite.offset = 0;
    ctx->in.nvWrite.data.t.size = FP_TEMPLATE_SIZE;
    memcpy(ctx->in.nvWrite.data.t.buffer, templateBuffer, templateBufferSize);
    EXECUTE_TPM_CALL_CTX(cb, FALSE, TPM2_NV_Write);

Cleanup:

    if (result != TPM_RC_SUCCESS) {
        printf("WriteFPTemplate: TPM2_NV_Write command  failed, status %d (0x%x)\n", result, result);
    }

    return result;
}

int
LoadBufferFromFile(
    char * filePath,
    UINT16 size,
    BYTE *buffer
)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD result;
    BOOL success;
    DWORD read;
    LARGE_INTEGER sizeOnDisk;

    file = CreateFileA( filePath,
                        GENERIC_READ,
                        FILE_SHARE_READ,
                        NULL,
                        OPEN_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL );

    if (file == INVALID_HANDLE_VALUE) {
        result = GetLastError();
        printf("ERROR: Failed to open file. 0x%08x\n", result);
        goto Cleanup;
    }

    if (!GetFileSizeEx( file, &sizeOnDisk ))
    {
        result = GetLastError();
        printf( "ERROR: Failed to read file size. 0x%08x\n", result );
        goto Cleanup;
    }

    if ((sizeOnDisk.LowPart > size) ||
        (sizeOnDisk.HighPart != 0))
    {
        result = ERROR_OUTOFMEMORY;
        printf( "ERROR: Template larger then expected.. 0x%08x\n", result );
        goto Cleanup;
    }

    success = ReadFile( file,
                        buffer,
                        sizeOnDisk.LowPart,
                        &read,
                        NULL );

    if (!success)
    {
        result = GetLastError();
        printf( "ERROR: Failed to read file. 0x%08x\n", result );
        goto Cleanup;
    }

    result = ERROR_SUCCESS;

Cleanup:

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle( file );
    }

    return result;
}

int
DumpBufferToFile(
    char * filePath,
    UINT16 size,
    BYTE *buffer
)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD result;
    BOOL success;
    DWORD written;

    file = CreateFileA( filePath,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL );

    if (file == INVALID_HANDLE_VALUE) {
        result = GetLastError();
        printf( "ERROR: Failed to write file. 0x%08x\n", result );
        goto Cleanup;
    }

    success = WriteFile( file,
                         buffer,
                         size,
                         &written,
                         NULL );

    if (!success)
    {
        result = GetLastError();
        printf( "ERROR: Failed to write file. 0x%08x\n", result );
        goto Cleanup;
    }

    result = ERROR_SUCCESS;

Cleanup:

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle( file );
    }

    return result;
}

int
ReadEK(
    SCTRM_CTX *ctx
)
{
    UINT32 result = TPM_RC_SUCCESS;
    URCHIN_CALLBUFFERS *cb = &ctx->cb;
    ANY_OBJECT ekObject = { 0 };

    // First make sure that the EK is present
    INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_ReadPublic, &ctx->in.readPublic, &ctx->out.readPublic);
    cb->parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey].obj.handle = TPM_20_EK_HANDLE;
    TRY_TPM_CALL_CTX(cb, FALSE, TPM2_ReadPublic);
    if (result != TPM_RC_SUCCESS) {
        // No, create and install it.
        printf("EK not found.\n");
        WriteToDisplay( ctx, "Creating EK...\n" );
        cb->sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_CreatePrimary, &ctx->in.createPrimary, &ctx->out.createPrimary);
        cb->parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle].entity.handle = TPM_RH_ENDORSEMENT;
        SetEkTemplate(&ctx->in.createPrimary.inPublic);
        EXECUTE_TPM_CALL_CTX(cb, FALSE, TPM2_CreatePrimary);
        ekObject = cb->parms.objectTableOut[TPM2_CreatePrimary_HdlOut_ObjectHandle];

        // Install the EK in NV.
        printf("Install the EK under TPM_20_EK_HANDLE.\n");
        cb->sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_EvictControl, &ctx->in.evictControl, &ctx->out.evictControl);
        cb->parms.objectTableIn[TPM2_EvictControl_HdlIn_Auth].entity.handle = TPM_RH_OWNER;
        cb->parms.objectTableIn[TPM2_EvictControl_HdlIn_ObjectHandle] = ekObject;
        ctx->in.evictControl.persistentHandle = TPM_20_EK_HANDLE;
        EXECUTE_TPM_CALL_CTX(cb, FALSE, TPM2_EvictControl);

        // Read the new public.
        printf("Read EKpub.\n");
        INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_ReadPublic, &ctx->in.readPublic, &ctx->in.readPublic);
        cb->parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey].generic.handle = TPM_20_EK_HANDLE;
        EXECUTE_TPM_CALL_CTX(cb, FALSE, TPM2_ReadPublic);
    }
    ekObject = cb->parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey];

    printf( "-- Device Info ---------------------------------------\n" );
    printf("char dispAuth[%d]        = \"%s\";\n", sizeof(dispAuth), dispAuth);
    printf("char fpReaderAuth[%d]    = \"%s\";\n", sizeof(fpReaderAuth), fpReaderAuth);
    printf("char fpManageAuth[%d]    = \"%s\";\n", sizeof(fpManageAuth), fpManageAuth);
    printf("unsigned char ekName[%u] = {", ekObject.obj.name.t.size);
    for (UINT32 n = 0; n < ekObject.obj.name.t.size; n++) {
        if (n > 0) printf(", ");
        if ((n % 16) == 0) printf("\n");
        printf("0x%02x", ekObject.obj.name.t.name[n]);
    }
    printf("\n};\n");
    printf( "-------------------------------------------------------\n" );

    ctx->ekObject = ekObject;

Cleanup:

    if (result != TPM_RC_SUCCESS) {
        printf("Last command failed, status %d (0x%x)\n", result, result);
    }

    return result;
}

int
GetSlot(
    SCTRM_CTX *ctx,
    ANY_OBJECT *fpManageObject,
    unsigned int slotID
)
{
    BOOLEAN created = FALSE;
    return InitializeNvSpace( ctx, fpManageAuth, fpManageObject, NV_FPBASE_INDEX + slotID, FP_TEMPLATE_SIZE, &created );
}

int
FindEmpptySlot(
    SCTRM_CTX *ctx,
    ANY_OBJECT *fpManageObject,
    unsigned int *slotID
)
{
    UINT32 result = TPM_RC_SUCCESS;
    ANY_OBJECT localObj = { 0 };
    unsigned int localID = -1;
    BOOLEAN created = FALSE;

    for (unsigned int n = 0; n < FP_SLOTS; n++) {
        result = InitializeNvSpace( ctx, fpManageAuth, &localObj, NV_FPBASE_INDEX + n, FP_TEMPLATE_SIZE, &created );
        if (result != TPM_RC_SUCCESS) {
            goto Cleanup;
        }

        if (created) {
            // TODO: || "Slot exits"
            // By either fixing read template, or add additional FP_VALIDATE_TEMPLATE command.
            localID = n;
            break;
        }
        ZeroMemory( &localObj, sizeof( localObj ) );
    }

    if (localID == -1) {
        result = TPM_RC_INSUFFICIENT;
        goto Cleanup;
    }

    *fpManageObject = localObj;
    if (slotID != NULL) {
        *slotID = localID;
    }

Cleanup:

    return result;
}

ScTrmStateObject_t secState = { 0 };

int
RunConfirmation(
    SCTRM_CTX *ctx,
    char* msgFmt,
    ...
)
{
     // Secure side: variables
    ScTrmResult_t secReturn = ScTrmResult_Ongoing;
    char* message = NULL;
    int allocSize;
    va_list argList;

    // Format the string if we have one.
    // A null string instructs the display to clear.
    if (msgFmt != NULL) {
        va_start( argList, msgFmt );
        allocSize = vsnprintf( NULL, 0, msgFmt, argList ) + 1;

        message = malloc( allocSize );
        if (message == NULL) {
            goto Cleanup;
        }
        ZeroMemory( message, allocSize );

        vsnprintf( message, allocSize, msgFmt, argList );
        va_end( argList );
    }

    // Secure side: Fill out the parameters for the call
    secState.param.func.GetConfirmation.displayAuth.t.size = (UINT16)strlen(dispAuth); // Display authorization
    strcpy_s((char*)secState.param.func.GetConfirmation.displayAuth.t.buffer,
        sizeof(secState.param.func.GetConfirmation.displayAuth.t.buffer),
        dispAuth);

    secState.param.func.GetConfirmation.fpReaderAuth.t.size = (UINT16)strlen(fpReaderAuth); // FP reader authorization
    strcpy_s((char*)secState.param.func.GetConfirmation.fpReaderAuth.t.buffer,
        sizeof(secState.param.func.GetConfirmation.fpReaderAuth.t.buffer),
        fpReaderAuth);
    secState.param.func.GetConfirmation.displayMessage.t.size = (UINT16)strlen(message) + 1; // Include the terminator
    strcpy_s((char*)secState.param.func.GetConfirmation.displayMessage.t.buffer,
        sizeof(secState.param.func.GetConfirmation.displayMessage.t.buffer),
        message);

    secState.param.func.GetConfirmation.ekName.t.size = ctx->ekObject.obj.name.t.size; // Expected EK to ensure we are talking to the right device
    memcpy(&secState.param.func.GetConfirmation.ekName, &ctx->ekObject.obj.name, sizeof(ctx->ekObject.obj.name));
    secState.param.func.GetConfirmation.timeout = 20 * 1000; // 20 second timeout to wait for a fingerprint

    secState.param.func.GetConfirmation.verifyEk = true;

    do
    {
        // Secure side: Crank the state machine 
        if ((secReturn = ScTrmGetConfirmation( &secState )) == ScTrmResult_Ongoing)
        {
            if (PlatformSubmitTPM20Command( FALSE, secState.param.pbCmd, secState.param.cbCmd, secState.param.pbRsp, sizeof( secState.param.pbRsp ), &secState.param.cbRsp ) != TPM_RC_SUCCESS)
            {
                secReturn = ScTrmResult_CommError;
                break;
            }
        }
    } while (secReturn == ScTrmResult_Ongoing);
    // Secure side: The ping-pong has completed, let's parse the result to see what happend
    if (secReturn < 0)
    {
        printf( "ERROR: Sec error 0x%08x\n", secReturn );
    }
    else if (secReturn <= ScTrmResult_MatchMax)
    {
        printf( "Finger %u recognized, operation confirmed.\n", secReturn );
    }
    else if (secReturn == ScTrmResult_Unrecognized)
    {
        printf( "Unrecognized finger pressed, operation canceled.\n" );
    }
    else if (secReturn == ScTrmResult_Timeout)
    {
        printf( "No finger pressed, operation canceled.\n" );
    }
    else
    {
        printf( "Error occurred.\n" );
    }

Cleanup:

    if (message != NULL) {
        free( message );
    }

    return secReturn;
}

int
SendFPCommand(
    SCTRM_CTX *ctx,
    ANY_OBJECT *fpObject,
    BYTE CmdByte
)
{
    UINT32 result = TPM_RC_SUCCESS;
    URCHIN_CALLBUFFERS *cb = &ctx->cb;

    if (fpObject->nv.handle == 0) {
        result = TPM_RC_BAD_AUTH;
        goto Cleanup;
    }

    cb->sessionTable[0].handle = TPM_RS_PW;
    INITIALIZE_CALL_BUFFERS_CTX(cb, TPM2_NV_Write, &ctx->in.nvWrite, &ctx->out.nvWrite);
    cb->parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = *fpObject;
    cb->parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = *fpObject;
    ctx->in.nvWrite.offset = 0;
    ctx->in.nvWrite.data.t.size = sizeof(unsigned char);
    ctx->in.nvWrite.data.t.buffer[0] = CmdByte;
    EXECUTE_TPM_CALL_CTX(cb, FALSE, TPM2_NV_Write);

Cleanup:

    if (result != TPM_RC_SUCCESS) {
        printf("Last command failed, status %d (0x%x)\n", result, result);
    }

    return result;
}

int main(int argc, char *argv[])
{
    SCTRM_CTX ctx;
    UINT32 result = TPM_RC_SUCCESS;
    unsigned int slot = 0xFFFF;
    ANY_OBJECT fbObj = { 0 };
    CMD_PARAM cmd = { 0 };
    unsigned char template[FP_TEMPLATE_SIZE] = { 0 };
    int templateSize = FP_TEMPLATE_SIZE;

    ZeroMemory(&ctx, sizeof(SCTRM_CTX));

    // Prepare Urchin
    _cpri__RngStartup();
    _cpri__HashStartup();
    _cpri__RsaStartup();
    _cpri__SymStartup();

    // Parse all cmd line options.
    if (GetCmdlineParams( argc, argv, &cmd ) != 0) {
        return;
    }
#ifdef USE_VCOM
    printf("Connecting to TPM on %s\n", cmd.vComPort == NULL ? DEFAULT_VCOM_PORT : cmd.vComPort );
    if (!TPMVComStartup( cmd.vComPort )) {
        printf("Connection failed. Unable to continue.\n" );
        return;
    }
#endif

    // Perform a factory reset.
    if (cmd.force) {
        char prompt[20];
        printf("Factory reset. This will clear the TPM, and will require a new ek be generated.\nAre you sure? (yes/no) ");
        scanf_s( "%s", prompt, _countof(prompt) );
        if (_stricmp( prompt, "yes" ) != 0) {
            return;
        }
        ClearTPM(&ctx);
        cmd.readEK = true;
    }

    printf("Initializing NV space...\n");
    if (((result = InitializeNvDisplay( &ctx )) != TPM_RC_SUCCESS) ||
        ((result = InitializeFBReader( &ctx )) != TPM_RC_SUCCESS)) {
        goto Cleanup;
    }

    // Reading the EK will create one if needed.
    if (cmd.readEK) {
        printf("Read EKpub.\n");
        if((result = ReadEK( &ctx )) != TPM_RC_SUCCESS)
        {
            printf( "Failed to read the EK. Terminating.\n" );
            goto Cleanup;
        }

        if (cmd.ekFilePath != NULL) {
            printf( "Dumping EK name to: %s\n", cmd.ekFilePath );
            result = DumpBufferToFile( cmd.ekFilePath, ctx.ekObject.obj.name.t.size, ctx.ekObject.obj.name.t.name );
            if (result != ERROR_SUCCESS) {
                printf( "Error writting EK to file: status %d (0x%x)\n", result, result );
                goto Cleanup;
            }
        }
    }

    //
    //  Clear any slot as the initial operation.
    //
    if (cmd.clear) {
        if (cmd.slot == CLEAR_ALL_SLOTS) {

            printf( "Clearing all Slots.\n" );

            if (((result = GetSlot( &ctx, &fbObj, 0 )) != TPM_RC_SUCCESS) ||
                ((result = SendFPCommand( &ctx, &fbObj, FP_SLOT_DELETE_ALL_TEMPLATE )) != TPM_RC_SUCCESS)) {
                printf( "Failed to clear all slots.\n" );
                goto Cleanup;
            }
        }
        else {
            printf( "Clearing slot %d.\n", cmd.slot );

            if (((result = GetSlot( &ctx, &fbObj, cmd.slot )) != TPM_RC_SUCCESS) ||
                ((result = SendFPCommand( &ctx, &fbObj, FP_SLOT_DELETE_TEMPLATE )) != TPM_RC_SUCCESS)) {
                printf( "Failed to clear slot.\n" );
                goto Cleanup;
            }
        }
    }

    //
    //  We can either write a template to a slot, or enroll. We will not do both.
    //
    if (cmd.enrollTemplate) {

        result = GetSlot(&ctx, &fbObj, cmd.slot);
        if (result != TPM_RC_SUCCESS) {
            printf( "Failed to open slot %d.\n", cmd.slot );
            goto Cleanup;
        }

        printf( "Reading template from: %s\n", cmd.templatePath );
        result = LoadBufferFromFile( cmd.templatePath, templateSize, template );
        if (result != ERROR_SUCCESS) {
            printf( "Error reading template from file: status %d (0x%x)\n", result, result );
            goto Cleanup;
        }

        printf( "Writting template to slot[%u].\n", cmd.slot );
        result = WriteFPTemplate(&ctx, &fbObj,template, templateSize );
        if (result != TPM_RC_SUCCESS) {
            printf( "Failed to open slot %d.\n", cmd.slot );
            goto Cleanup;
        }
    }
    else if (cmd.enroll) {
        printf("Enrolling finger. Scan finger three times.\n");

        result = GetSlot(&ctx, &fbObj, cmd.slot);
        if (result != TPM_RC_SUCCESS) {
            printf( "Failed to open slot %d.\n", cmd.slot );
            goto Cleanup;
        }

        WriteToDisplay(&ctx, "\nEnroll finger in slot[%u]\n", cmd.slot );

        result = SendFPCommand( &ctx, &fbObj, FP_SLOT_ENROLL_TEMPLATE);
        if (result != TPM_RC_SUCCESS) {
            printf( "Failed to enroll slot %d.\n", cmd.slot );
            goto Cleanup;
        }

        CLEAR_DISPLAY;
        printf("Validating enrollment.\n");
        if (!ValidateFB( &ctx, &slot )) {

            printf("Validation failed!\n");
            WriteToDisplay(&ctx, "\n%sError. Enroll failed.\n", ESC_FONT_RED);
            goto Cleanup;

        }else if (slot != cmd.slot) {

            printf("Validation failed! Slot %d reported. Expected %d\n", slot, cmd.slot);
            WriteToDisplay(&ctx, "\n%sError. Enroll failed.\n", ESC_FONT_RED);
            goto Cleanup;
        }
        else {
            WriteToDisplay(&ctx, "\n%sSuccess. slot[%d] enrolled.\n", ESC_FONT_GREEN, cmd.slot);
        }

        Sleep( 1000 );
    }

    //
    //  Test if requested
    //
    while (cmd.test > 0) {
        int rSlot;
        printf( "Running Confirmation\n" );
        rSlot = RunConfirmation( &ctx, "%s\n%s%sOk to set:\n%s\n%s%s Temperature\n\n%s%sTo:\n%s\n%s%s %d\xF8\x43",
                        FONT_SIZE_1,
                        ESC_FONT_YELLOW,    FONT_SIZE_3,  // okay to set
                        FONT_SIZE_1,
                        ESC_FONT_WHITE,     FONT_SIZE_4, // Temp
                        ESC_FONT_YELLOW,    FONT_SIZE_3, //to
                        FONT_SIZE_1,
                        ESC_FONT_RED,       FONT_SIZE_5, //#
                        30+cmd.test/*, ASCII_DEGREE*/ );
        if (rSlot > 199 || rSlot < 0) {
            printf( "Error: Failed to validate finger.\n" );
        }
        else {
            printf( "Validation succeeded. Fingerprint is enrolled in slot %d.\n", rSlot );
        }
        CLEAR_DISPLAY;
        cmd.test--;
    }

    //
    // Read and a Finger Print template from the reader
    //
    if (cmd.saveTemplate) {

        result = GetSlot(&ctx, &fbObj, cmd.slot);
        if (result != TPM_RC_SUCCESS) {
            printf( "Failed to open slot %d.\n", cmd.slot );
            goto Cleanup;
        }

        printf( "Read template from slot[%u].\n", cmd.slot );
        if (ReadFPTemplate( &ctx, &fbObj, template, templateSize, &templateSize ) != TPM_RC_SUCCESS) {
            printf( "Failed to read template slot %d.\n", cmd.slot );
            goto Cleanup;
        }

        printf( "Writting template to: %s\n", cmd.templatePath );
        result = DumpBufferToFile( cmd.templatePath, templateSize, template );
        if (result != ERROR_SUCCESS) {
            printf( "Error writting template to file: status %d (0x%x)\n", result, result );
            goto Cleanup;
        }
    }

    printf( "Complete.\n" );

Cleanup:

    CLEAR_DISPLAY;

#ifdef USE_VCOM
    TPMVComShutdown();
#endif

    if (result != TPM_RC_SUCCESS) {
        printf("Last command failed, status %d (0x%x)\n", result, result);
    }

    return 0;
}
