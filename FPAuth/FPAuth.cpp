// FPAuth.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#define NV_FPBASE_INDEX (0x00008000)
#define FP_TEMPLATE_SIZE (498)
#define FP_SLOTS_MAX (200)
#define FP_SLOTS (1)
#define FP_AUTHORIZE_INDEX (NV_FPBASE_INDEX + FP_SLOTS_MAX)
#define FP_DISPLAY_INDEX (FP_AUTHORIZE_INDEX + 1)
#define FP_DISPLAY_MAX_TEXT (256)

#define FP_SLOT_INITIALIZE_TEMPLATE (0x00)
#define FP_SLOT_DELETE_ALL_TEMPLATE (0x01)
#define FP_SLOT_DELETE_TEMPLATE (0x02)
#define FP_SLOT_ENROLL_TEMPLATE (0x03)
#define FP_AUTHORIZE_INITIALIZE (0x00)
#define FP_AUTHORIZE_VERIFY (0x01)
#define FP_AUTHORIZE_TIMEOUT (0x02)

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
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        NV_ReadPublic_In NV_ReadPublic;
        NV_DefineSpace_In NV_DefineSpace;
        NV_Write_In NV_Write;
        NV_Read_In NV_Read;
    } cmd;
    union
    {
        NV_ReadPublic_Out NV_ReadPublic;
        NV_DefineSpace_Out NV_DefineSpace;
        NV_Write_Out NV_Write;
        NV_Read_Out NV_Read;
    } rsp;
    DEFINE_CALL_BUFFERS;
    ANY_OBJECT storageOwner = { 0 };
    ANY_OBJECT nvIndex = { 0 };

    _cpri__RngStartup();
    _cpri__HashStartup();
    _cpri__RsaStartup();
    _cpri__SymStartup();

    PlattformRetrieveAuthValues();

    storageOwner.entity.handle = TPM_RH_OWNER;
    buffer = storageOwner.entity.name.t.name;
    size = sizeof(storageOwner.entity.name.t.name);
    storageOwner.entity.name.t.size = TPM_HANDLE_Marshal(&storageOwner.entity.handle, &buffer, &size);
    storageOwner.entity.authValue = g_StorageAuth;

    // Provision the NV indices if required
    for (unsigned int n = 0; n < FP_SLOTS; n++)
    {
        nvIndex.nv.handle = ((TPM_HT_NV_INDEX << 24) | NV_FPBASE_INDEX + n);
        INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &cmd.NV_ReadPublic, &rsp.NV_ReadPublic);
        parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = nvIndex;
        TRY_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
        printf("TPM2_NV_ReadPublic(0x%08x) = 0x%08x\n", nvIndex.nv.handle, result);
        if (result != TPM_RC_SUCCESS)
        {
            sessionTable[0].handle = TPM_RS_PW;
            INITIALIZE_CALL_BUFFERS(TPM2_NV_DefineSpace, &cmd.NV_DefineSpace, &rsp.NV_DefineSpace);
            parms.objectTableIn[TPM2_NV_DefineSpace_HdlIn_AuthHandle] = storageOwner;
            cmd.NV_DefineSpace.publicInfo.t.nvPublic.nvIndex = nvIndex.nv.handle;
            cmd.NV_DefineSpace.publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA256;
            cmd.NV_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHWRITE = SET;
            cmd.NV_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = SET;
            cmd.NV_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_NO_DA = SET;
            cmd.NV_DefineSpace.publicInfo.t.nvPublic.dataSize = FP_TEMPLATE_SIZE;
            //cmd.NV_DefineSpace.auth.t.size = sizeof(g_UsageAuth);
            //MemoryCopy(nv_DefineSpaceIn.auth.t.buffer, g_UsageAuth, sizeof(g_UsageAuth), sizeof(nv_DefineSpaceIn.auth.t.buffer));
            //MemoryRemoveTrailingZeros(&nv_DefineSpaceIn.auth);
            EXECUTE_TPM_CALL(FALSE, TPM2_NV_DefineSpace);
            printf("TPM2_NV_DefineSpace(0x%08x) = TPM_RC_SUCCESS\n", nvIndex.nv.handle);
            do
            {
                sessionTable[0].handle = TPM_RS_PW;
                INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &cmd.NV_Write, &rsp.NV_Write);
                parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = nvIndex;
                parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = nvIndex;
                cmd.NV_Write.offset = 0;
                cmd.NV_Write.data.t.size = sizeof(unsigned char);
                cmd.NV_Write.data.t.buffer[0] = FP_SLOT_INITIALIZE_TEMPLATE;
                TRY_TPM_CALL(FALSE, TPM2_NV_Write);
            } while (result == TPM_RC_RETRY);
            printf("TPM2_NV_Write(0x%08x) = 0x%08x\n", nvIndex.nv.handle, result);
            if (result != TPM_RC_SUCCESS)
            {
                goto Cleanup;
            }
        }
    }
    nvIndex.nv.handle = ((TPM_HT_NV_INDEX << 24) | FP_AUTHORIZE_INDEX);
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &cmd.NV_ReadPublic, &rsp.NV_ReadPublic);
    parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = nvIndex;
    TRY_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
    printf("TPM2_NV_ReadPublic(0x%08x) = 0x%08x\n", nvIndex.nv.handle, result);
    if (result != TPM_RC_SUCCESS)
    {
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_NV_DefineSpace, &cmd.NV_DefineSpace, &rsp.NV_DefineSpace);
        parms.objectTableIn[TPM2_NV_DefineSpace_HdlIn_AuthHandle] = storageOwner;
        cmd.NV_DefineSpace.publicInfo.t.nvPublic.nvIndex = nvIndex.nv.handle;
        cmd.NV_DefineSpace.publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA256;
        cmd.NV_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHWRITE = SET;
        cmd.NV_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = SET;
        cmd.NV_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_NO_DA = SET;
        cmd.NV_DefineSpace.publicInfo.t.nvPublic.dataSize = sizeof(unsigned int);
        //cmd.NV_DefineSpace.auth.t.size = sizeof(g_UsageAuth);
        //MemoryCopy(nv_DefineSpaceIn.auth.t.buffer, g_UsageAuth, sizeof(g_UsageAuth), sizeof(nv_DefineSpaceIn.auth.t.buffer));
        //MemoryRemoveTrailingZeros(&nv_DefineSpaceIn.auth);
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_DefineSpace);
        printf("TPM2_NV_DefineSpace(0x%08x) = TPM_RC_SUCCESS\n", nvIndex.nv.handle);
        do
        {
            sessionTable[0].handle = TPM_RS_PW;
            INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &cmd.NV_Write, &rsp.NV_Write);
            parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = nvIndex;
            parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = nvIndex;
            cmd.NV_Write.offset = 0;
            cmd.NV_Write.data.t.size = sizeof(unsigned int);
            cmd.NV_Write.data.t.buffer[0] = FP_AUTHORIZE_INITIALIZE;
            TRY_TPM_CALL(FALSE, TPM2_NV_Write);
        } while (result == TPM_RC_RETRY);
        printf("TPM2_NV_Write(0x%08x) = 0x%08x\n", nvIndex.nv.handle, result);
        if (result != TPM_RC_SUCCESS)
        {
            goto Cleanup;
        }
    }
    nvIndex.nv.handle = ((TPM_HT_NV_INDEX << 24) | FP_DISPLAY_INDEX);
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &cmd.NV_ReadPublic, &rsp.NV_ReadPublic);
    parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = nvIndex;
    TRY_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
    printf("TPM2_NV_ReadPublic(0x%08x) = 0x%08x\n", nvIndex.nv.handle, result);
    if (result != TPM_RC_SUCCESS)
    {
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_NV_DefineSpace, &cmd.NV_DefineSpace, &rsp.NV_DefineSpace);
        parms.objectTableIn[TPM2_NV_DefineSpace_HdlIn_AuthHandle] = storageOwner;
        cmd.NV_DefineSpace.publicInfo.t.nvPublic.nvIndex = nvIndex.nv.handle;
        cmd.NV_DefineSpace.publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA256;
        cmd.NV_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHWRITE = SET;
        cmd.NV_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = SET;
        cmd.NV_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_NO_DA = SET;
        cmd.NV_DefineSpace.publicInfo.t.nvPublic.dataSize = FP_DISPLAY_MAX_TEXT;
        //cmd.NV_DefineSpace.auth.t.size = sizeof(g_UsageAuth);
        //MemoryCopy(nv_DefineSpaceIn.auth.t.buffer, g_UsageAuth, sizeof(g_UsageAuth), sizeof(nv_DefineSpaceIn.auth.t.buffer));
        //MemoryRemoveTrailingZeros(&nv_DefineSpaceIn.auth);
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_DefineSpace);
        printf("TPM2_NV_DefineSpace(0x%08x) = TPM_RC_SUCCESS\n", nvIndex.nv.handle);
        do
        {
            sessionTable[0].handle = TPM_RS_PW;
            INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &cmd.NV_Write, &rsp.NV_Write);
            parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = nvIndex;
            parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = nvIndex;
            cmd.NV_Write.offset = 0;
            cmd.NV_Write.data.t.size = FP_DISPLAY_MAX_TEXT;
            memset(cmd.NV_Write.data.t.buffer, 0x00, FP_DISPLAY_MAX_TEXT);
            TRY_TPM_CALL(FALSE, TPM2_NV_Write);
        } while (result == TPM_RC_RETRY);
        printf("TPM2_NV_Write(0x%08x) = 0x%08x\n", nvIndex.nv.handle, result);
        if (result != TPM_RC_SUCCESS)
        {
            goto Cleanup;
        }
    }

    // Make sure NV is up and running
    nvIndex.nv.handle = ((TPM_HT_NV_INDEX << 24) | FP_AUTHORIZE_INDEX);
    do
    {
        sessionTable[0].handle = TPM_RS_PW;
        INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &cmd.NV_Write, &rsp.NV_Write);
        parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = nvIndex;
        parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = nvIndex;
        cmd.NV_Write.offset = 0;
        cmd.NV_Write.data.t.size = sizeof(unsigned int);
        cmd.NV_Write.data.t.buffer[0] = FP_AUTHORIZE_INITIALIZE;
        TRY_TPM_CALL(FALSE, TPM2_NV_Write);
        printf("TPM2_NV_Write(0x%08x) = 0x%08x\n", nvIndex.nv.handle, result);
    } while (result == TPM_RC_RETRY);

    // Delete all templates
    printf("Deleting all finger print templates...");
    sessionTable[0].handle = TPM_RS_PW;
    nvIndex.nv.handle = ((TPM_HT_NV_INDEX << 24) | NV_FPBASE_INDEX);
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &cmd.NV_Write, &rsp.NV_Write);
    parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = nvIndex;
    parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = nvIndex;
    cmd.NV_Write.offset = 0;
    cmd.NV_Write.data.t.size = sizeof(unsigned char);
    cmd.NV_Write.data.t.buffer[0] = FP_SLOT_DELETE_ALL_TEMPLATE;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);
    printf("TPM2_NV_Write(0x%08x) = 0x%08x\n", nvIndex.nv.handle, result);
    printf("Done.\n");

    // Enroll a template
    printf("Enrolling a finger print template...");
    sessionTable[0].handle = TPM_RS_PW;
    nvIndex.nv.handle = ((TPM_HT_NV_INDEX << 24) | NV_FPBASE_INDEX);
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &cmd.NV_Write, &rsp.NV_Write);
    parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = nvIndex;
    parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = nvIndex;
    cmd.NV_Write.offset = 0;
    cmd.NV_Write.data.t.size = sizeof(unsigned char);
    cmd.NV_Write.data.t.buffer[0] = FP_SLOT_ENROLL_TEMPLATE;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);
    printf("TPM2_NV_Write(0x%08x) = 0x%08x\n", nvIndex.nv.handle, result);
    printf("Done.\n");
    Sleep(5000);

    // Identify a finger
    printf("Identifying a finger...");
    sessionTable[0].handle = TPM_RS_PW;
    nvIndex.nv.handle = ((TPM_HT_NV_INDEX << 24) | FP_AUTHORIZE_INDEX);
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Read, &cmd.NV_Read, &rsp.NV_Read);
    parms.objectTableIn[TPM2_NV_Read_HdlIn_NvIndex] = nvIndex;
    parms.objectTableIn[TPM2_NV_Read_HdlIn_AuthHandle] = nvIndex;
    cmd.NV_Read.offset = 0;
    cmd.NV_Read.size = sizeof(unsigned int);
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_Read);
    printf("TPM2_NV_read(0x%08x) = 0x%08x\n", nvIndex.nv.handle, result);
    printf("Read(%d) = 0x%08x.\n", rsp.NV_Read.data.t.size, *((unsigned int*)rsp.NV_Read.data.t.buffer));

Cleanup:
    return result;
}

