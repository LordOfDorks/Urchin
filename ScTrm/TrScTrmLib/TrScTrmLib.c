// TrScTrmLib.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#ifdef USE_SGX
# define DMSG printf
#endif

int
ScTrmFunc_MyBreakPointHere(void)
{
    return 0;
}

#undef DEFINE_CALL_BUFFERS
#define DEFINE_CALL_BUFFERS \
    BYTE *buffer; \
    INT32 size;\

#undef INITIALIZE_CALL_BUFFERS
#define INITIALIZE_CALL_BUFFERS(__CommandType, __InParm, __OutParm) \
    state->intern.urchin.sessionCnt = __CommandType##_SessionCnt; \
    buffer = state->param.pbCmd; \
    size = sizeof(state->param.pbCmd); \
    MemorySet(&state->intern.urchin.parms, 0x00, sizeof(state->intern.urchin.parms)); \
    MemorySet(__InParm, 0x00, sizeof(*__InParm)); \
    MemorySet(__OutParm, 0x00, sizeof(*__OutParm)); \
    state->intern.urchin.parms.parmIn = (void*)__InParm; \
    state->intern.urchin.parms.parmOut = (void*)__OutParm; \
    state->intern.urchin.parms.objectCntIn = __CommandType##_HdlCntIn; \
    state->intern.urchin.parms.objectCntOut = __CommandType##_HdlCntOut; \

#define MARSHAL_CMD(__CommandType) \
    state->param.cbCmd = __CommandType##_Marshal(state->intern.urchin.sessionTable, state->intern.urchin.sessionCnt, &state->intern.urchin.parms, &buffer, &size); \

#define TRY_UNMARSHAL_RSP(__CommandType) \
    buffer = state->param.pbRsp; \
    size = state->param.cbRsp; \
    result = __CommandType##_Unmarshal(state->intern.urchin.sessionTable, state->intern.urchin.sessionCnt, &state->intern.urchin.parms, &buffer, &size) \

#define UNMARSHAL_RSP(__CommandType) \
    buffer = state->param.pbRsp; \
    size = state->param.cbRsp; \
    if ((result = __CommandType##_Unmarshal(state->intern.urchin.sessionTable, state->intern.urchin.sessionCnt, &state->intern.urchin.parms, &buffer, &size)) != TPM_RC_SUCCESS) \
    { \
        goto Cleanup; \
    } \

static ScTrmResult_t ScTrmFunc_GetConfirmation_Cleanup(ScTrmStateObject_t* state);

static ScTrmResult_t ScTrmFunc_GetConfirmation_None(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    state->intern.result = ScTrmResult_Error;

    // Request the EK information
    state->intern.func.GetConfirmation.ek.obj.handle = TPM_20_EK_HANDLE;
    INITIALIZE_CALL_BUFFERS(TPM2_ReadPublic, &state->intern.urchin.in.readPublic, &state->intern.urchin.out.readPublic);
    state->intern.urchin.parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey] = state->intern.func.GetConfirmation.ek;
    MARSHAL_CMD(TPM2_ReadPublic);

    state->intern.state++;

//Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_GetEkPubUntrusted(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    TPM2B_NAME calculatedEkName = { 0 };

    // Retrive the EK information
    UNMARSHAL_RSP(TPM2_ReadPublic);
    state->intern.func.GetConfirmation.ek = state->intern.urchin.parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey];

    // Check all the EK properties against the default EK template here. Skip for now.

#if 0
    // Make sure we are looking at the EK the caller is expecting
    ObjectComputeName(&state->intern.func.GetConfirmation.ek.obj.publicArea.t.publicArea, &calculatedEkName);
    if ((state->intern.func.GetConfirmation.ek.obj.name.t.size != calculatedEkName.t.size) ||
        (memcmp(state->intern.func.GetConfirmation.ek.obj.name.t.name, calculatedEkName.t.name, calculatedEkName.t.size)) ||
        (state->param.func.GetConfirmation.ekName.t.size != calculatedEkName.t.size) ||
        (memcmp(state->param.func.GetConfirmation.ekName.t.name, calculatedEkName.t.name, calculatedEkName.t.size)))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }
#endif

    // Start the seeded authorization session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &state->intern.urchin.in.startAuthSession, &state->intern.urchin.out.startAuthSession);
    state->intern.urchin.parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = state->intern.func.GetConfirmation.ek;  // Encrypt salt to EK
    state->intern.urchin.parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    state->intern.urchin.in.startAuthSession.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, state->intern.urchin.in.startAuthSession.nonceCaller.t.buffer);
    state->intern.urchin.in.startAuthSession.sessionType = TPM_SE_HMAC;
    state->intern.urchin.in.startAuthSession.symmetric.algorithm = TPM_ALG_AES;
    state->intern.urchin.in.startAuthSession.symmetric.keyBits.aes = 128;
    state->intern.urchin.in.startAuthSession.symmetric.mode.aes = TPM_ALG_CFB;
    state->intern.urchin.in.startAuthSession.authHash = TPM_ALG_SHA256;
    MARSHAL_CMD(TPM2_StartAuthSession);

    DMSG("SCTRM: GetEkPubUntrusted state passed\n");
    state->intern.state++;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_StartSeededSession(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    UNMARSHAL_RSP(TPM2_StartAuthSession);
    state->intern.func.GetConfirmation.seededSession = state->intern.urchin.parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Request the EK information again but this time with auditing so the information can be trusted
    state->intern.urchin.sessionTable[0] = state->intern.func.GetConfirmation.seededSession;
    state->intern.urchin.sessionTable[0].attributes.audit = SET;
    state->intern.urchin.sessionTable[0].attributes.continueSession = SET;
    INITIALIZE_CALL_BUFFERS(TPM2_ReadPublic, &state->intern.urchin.in.readPublic, &state->intern.urchin.out.readPublic);
    state->intern.urchin.parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey] = state->intern.func.GetConfirmation.ek;
    MARSHAL_CMD(TPM2_ReadPublic);

    DMSG("SCTRM: StartSeededSession state passed\n");
    state->intern.state++;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_GetEkPub(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    // When this call succeeds then we can really trust the EK we checked above.
    UNMARSHAL_RSP(TPM2_ReadPublic);
    state->intern.func.GetConfirmation.ek = state->intern.urchin.parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey];

    // We park the session briefly the next call is untrusted
    state->intern.urchin.sessionTable[0].attributes.audit = CLEAR;
    state->intern.func.GetConfirmation.seededSession = state->intern.urchin.sessionTable[0];
    state->intern.urchin.sessionTable[0].handle = TPM_RS_PW;

    // Get the name of the NVIndex for the display
    state->intern.func.GetConfirmation.nvDisplay.nv.handle = FP_DISPLAY_INDEX;
    state->intern.func.GetConfirmation.nvDisplay.nv.authValue = state->param.func.GetConfirmation.displayAuth;
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &state->intern.urchin.in.nv_ReadPublic, &state->intern.urchin.out.nv_ReadPublic);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = state->intern.func.GetConfirmation.nvDisplay;
    MARSHAL_CMD(TPM2_NV_ReadPublic);

    DMSG("SCTRM: GetEkPub state passed with nvhandle %x\n", state->intern.func.GetConfirmation.nvDisplay.nv.handle);
    state->intern.state++;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_GetNvPublicForDisplayUntrusted(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    // This will give us the NV name
    UNMARSHAL_RSP(TPM2_NV_ReadPublic);
    state->intern.func.GetConfirmation.nvDisplay = state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    // Check the NV index properties here. We skip that for now.

    // Get the name of the NVIndex for the FPReader
    state->intern.func.GetConfirmation.nvFPReader.nv.handle = FP_AUTHORIZE_INDEX;
    state->intern.func.GetConfirmation.nvFPReader.nv.authValue = state->param.func.GetConfirmation.fpReaderAuth;
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &state->intern.urchin.in.nv_ReadPublic, &state->intern.urchin.out.nv_ReadPublic);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = state->intern.func.GetConfirmation.nvFPReader;
    MARSHAL_CMD(TPM2_NV_ReadPublic);

    DMSG("SCTRM: GetNvPublicForDisplayUntrusted state passed\n");
    state->intern.state++;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("SCTRM: GetNvPublicForDisplayUntrusted state failed with result %x\n", result);
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_GetNvPublicForFPReaderUntrusted(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    // This will give us the NV name
    UNMARSHAL_RSP(TPM2_NV_ReadPublic);
    state->intern.func.GetConfirmation.nvFPReader = state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    // Check the NV index properties here. We skip that for now.

    // We read the NV public again with the seeded session to make sure nobody is playing tricks with us
    state->intern.urchin.sessionTable[0] = state->intern.func.GetConfirmation.seededSession;
    state->intern.urchin.sessionTable[0].attributes.audit = SET;
    state->intern.urchin.sessionTable[0].attributes.continueSession = SET;
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &state->intern.urchin.in.nv_ReadPublic, &state->intern.urchin.out.nv_ReadPublic);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = state->intern.func.GetConfirmation.nvDisplay;
    MARSHAL_CMD(TPM2_NV_ReadPublic);

    DMSG("SCTRM: GetNvPublicForFPReaderUntrusted state passed\n");
    state->intern.state++;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("SCTRM: GetNvPublicForFPReaderUntrusted state failed with result %x\n", result);
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_GetNvPublicForDisplay(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    // This will give us the trusted NV name
    UNMARSHAL_RSP(TPM2_NV_ReadPublic);
    state->intern.func.GetConfirmation.nvDisplay = state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];
    state->intern.urchin.sessionTable[0].attributes.audit = CLEAR;
    state->intern.func.GetConfirmation.seededSession = state->intern.urchin.sessionTable[0];

    // We read the NV public again with the seeded session to make sure nobody is playing tricks with us
    state->intern.urchin.sessionTable[0] = state->intern.func.GetConfirmation.seededSession;
    state->intern.urchin.sessionTable[0].attributes.audit = SET;
    state->intern.urchin.sessionTable[0].attributes.continueSession = SET;
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &state->intern.urchin.in.nv_ReadPublic, &state->intern.urchin.out.nv_ReadPublic);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = state->intern.func.GetConfirmation.nvFPReader;
    MARSHAL_CMD(TPM2_NV_ReadPublic);

    DMSG("SCTRM: GetNvPublicForDisplay state passed\n");
    state->intern.state++;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("SCTRM: GetNvPublicForDisplay state failed with result %x\n", result);
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_GetNvPublicForFPReader(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    // This will give us the trusted NV name
    UNMARSHAL_RSP(TPM2_NV_ReadPublic);
    state->intern.func.GetConfirmation.nvFPReader = state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];
    state->intern.urchin.sessionTable[0].attributes.audit = CLEAR;
    state->intern.func.GetConfirmation.seededSession = state->intern.urchin.sessionTable[0];

    // Write the timeout to the fpReader
    state->intern.urchin.sessionTable[0] = state->intern.func.GetConfirmation.seededSession;
    state->intern.urchin.sessionTable[0].attributes.decrypt = SET;
    state->intern.urchin.sessionTable[0].attributes.continueSession = SET;
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &state->intern.urchin.in.nv_Write, &state->intern.urchin.out.nv_Write);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = state->intern.func.GetConfirmation.nvFPReader;
    state->intern.urchin.parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = state->intern.func.GetConfirmation.nvFPReader;
    state->intern.urchin.in.nv_Write.offset = 0;
    state->intern.urchin.in.nv_Write.data.t.size = sizeof(state->param.func.GetConfirmation.timeout);
    *((unsigned int*)state->intern.urchin.in.nv_Write.data.t.buffer) = state->param.func.GetConfirmation.timeout;
    MARSHAL_CMD(TPM2_NV_Write);

    state->intern.state++;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_SetTimeout(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    // See if the write was successful
    UNMARSHAL_RSP(TPM2_NV_Write);
    state->intern.urchin.sessionTable[0].attributes.decrypt = CLEAR;
    state->intern.func.GetConfirmation.seededSession = state->intern.urchin.sessionTable[0];

    // Write the message to the display
    state->intern.urchin.sessionTable[0] = state->intern.func.GetConfirmation.seededSession;
    state->intern.urchin.sessionTable[0].attributes.decrypt = SET;
    state->intern.urchin.sessionTable[0].attributes.continueSession = SET;
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &state->intern.urchin.in.nv_Write, &state->intern.urchin.out.nv_Write);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = state->intern.func.GetConfirmation.nvDisplay;
    state->intern.urchin.parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = state->intern.func.GetConfirmation.nvDisplay;
    state->intern.urchin.in.nv_Write.offset = 0;
    state->intern.urchin.in.nv_Write.data = state->param.func.GetConfirmation.displayMessage;
    MARSHAL_CMD(TPM2_NV_Write);

    state->intern.state++;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_WriteToDisplay(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    // See if the write was successful
    UNMARSHAL_RSP(TPM2_NV_Write);
    state->intern.urchin.sessionTable[0].attributes.decrypt = CLEAR;
    state->intern.func.GetConfirmation.seededSession = state->intern.urchin.sessionTable[0];

    // Read a fingerprint from the sensor
    state->intern.urchin.sessionTable[0] = state->intern.func.GetConfirmation.seededSession;
    state->intern.urchin.sessionTable[0].attributes.continueSession = SET;
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Read, &state->intern.urchin.in.nv_Read, &state->intern.urchin.out.nv_Read);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_Read_HdlIn_AuthHandle] = state->intern.func.GetConfirmation.nvFPReader;
    state->intern.urchin.parms.objectTableIn[TPM2_NV_Read_HdlIn_NvIndex] = state->intern.func.GetConfirmation.nvFPReader;
    state->intern.urchin.in.nv_Read.offset = 0;
    state->intern.urchin.in.nv_Read.size = sizeof(unsigned int);
    MARSHAL_CMD(TPM2_NV_Read);

    state->intern.state++;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_ReadFPId(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    // See if the write was successful
    TRY_UNMARSHAL_RSP(TPM2_NV_Read);
    state->intern.func.GetConfirmation.seededSession = state->intern.urchin.sessionTable[0];
    if (result == TPM_RC_CANCELED)
    {
        state->intern.result = ScTrmResult_Timeout;
        goto Cleanup;
    }
    else if ((result != TPM_RC_SUCCESS) ||
             (state->intern.urchin.out.nv_Read.data.t.size != sizeof(unsigned int)))
    {
        state->intern.result = ScTrmResult_Error;
        goto Cleanup;
    }
    state->intern.result = ScTrmResult_Match0 + *((unsigned int*)state->intern.urchin.out.nv_Read.data.t.buffer);

Cleanup:
    state->intern.state = ScTrmState_GetConfirmation_ClearDisplay;
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete;
        return ScTrmResult_Error;
    }
    return ScTrmFunc_GetConfirmation_Cleanup(state);
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_Cleanup(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    // Clear the display
    state->intern.urchin.sessionTable[0] = state->intern.func.GetConfirmation.seededSession;
    state->intern.urchin.sessionTable[0].attributes.continueSession = CLEAR;
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &state->intern.urchin.in.nv_Write, &state->intern.urchin.out.nv_Write);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = state->intern.func.GetConfirmation.nvDisplay;
    state->intern.urchin.parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = state->intern.func.GetConfirmation.nvDisplay;
    state->intern.urchin.in.nv_Write.offset = 0;
    state->intern.urchin.in.nv_Write.data.t.size = 0;
    memset(state->intern.urchin.in.nv_Write.data.t.buffer, 0x00, sizeof(state->intern.urchin.in.nv_Write.data.t.buffer));
    MARSHAL_CMD(TPM2_NV_Write);

    state->intern.state = ScTrmState_GetConfirmation_ClearDisplay;

//Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_ClearDisplay(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    // See if the clear was successful
    UNMARSHAL_RSP(TPM2_NV_Write);
    state->intern.func.GetConfirmation.seededSession = state->intern.urchin.sessionTable[0];

    state->intern.state = ScTrmState_Complete;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete;
        return ScTrmResult_Error;
    }
    return state->intern.result;
}

#ifndef USE_OPTEE
__declspec(dllexport) 
#endif
ScTrmResult_t ScTrmGetConfirmation(ScTrmStateObject_t* state)
{
    _cpri__RngStartup();
    _cpri__HashStartup();
    _cpri__RsaStartup();
    _cpri__SymStartup();

    switch(state->intern.state)
    {
        case ScTrmState_None:
        {
            return ScTrmFunc_GetConfirmation_None(state);
        }
        case ScTrmState_GetConfirmation_GetEkPubUntrusted:
        {
            return ScTrmFunc_GetConfirmation_GetEkPubUntrusted(state);
        }
        case ScTrmState_GetConfirmation_StartSeededSession:
        {
            return ScTrmFunc_GetConfirmation_StartSeededSession(state);
        }
        case ScTrmState_GetConfirmation_GetEkPub:
        {
            return ScTrmFunc_GetConfirmation_GetEkPub(state);
        }
        case ScTrmState_GetConfirmation_GetNvPublicForDisplayUntrusted:
        {
            return ScTrmFunc_GetConfirmation_GetNvPublicForDisplayUntrusted(state);
        }
        case ScTrmState_GetConfirmation_GetNvPublicForFPReaderUntrusted:
        {
            return ScTrmFunc_GetConfirmation_GetNvPublicForFPReaderUntrusted(state);
        }
        case ScTrmState_GetConfirmation_GetNvPublicForDisplay:
        {
            return ScTrmFunc_GetConfirmation_GetNvPublicForDisplay(state);
        }
        case ScTrmState_GetConfirmation_GetNvPublicForFPReader:
        {
            return ScTrmFunc_GetConfirmation_GetNvPublicForFPReader(state);
        }
        case ScTrmState_GetConfirmation_SetTimeout:
        {
            return ScTrmFunc_GetConfirmation_SetTimeout(state);
        }
        case ScTrmState_GetConfirmation_WriteToDisplay:
        {
            return ScTrmFunc_GetConfirmation_WriteToDisplay(state);
        }
        case ScTrmState_GetConfirmation_ReadFPId:
        {
            return ScTrmFunc_GetConfirmation_ReadFPId(state);
        }
        case ScTrmState_GetConfirmation_ClearDisplay:
        {
            return ScTrmFunc_GetConfirmation_ClearDisplay(state);
        }
        case ScTrmState_Complete:
        default:
        {
            ScTrmFunc_MyBreakPointHere();
            return ScTrmResult_Error;
        }
    }
}
