// TrScTrmLib.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#ifndef DMSG
# define DMSG printf
#endif
#ifndef USE_SGX
# include <stdio.h>
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

inline void ScTrmFunc_UseSeededSession( ScTrmStateObject_t* state )
{
    state->intern.urchin.sessionTable[0] = state->intern.func.GetConfirmation.seededSession;
    state->intern.urchin.sessionTable[0].attributes.audit = SET;
    state->intern.urchin.sessionTable[0].attributes.continueSession = SET;
}

static ScTrmResult_t ScTrmFunc_Session_Start(ScTrmStateObject_t* state)
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
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_Session_GetEkPubUntrusted(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    TPM2B_NAME calculatedEkName = { 0 };

    // Retrive the EK information
    UNMARSHAL_RSP(TPM2_ReadPublic);
    state->intern.func.GetConfirmation.ek = state->intern.urchin.parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey];

    // Check all the EK properties against the default EK template here. Skip for now.

    if (state->param.func.GetConfirmation.verifyEk) {
        // Make sure we are looking at the EK the caller is expecting
        ObjectComputeName(&state->intern.func.GetConfirmation.ek.obj.publicArea.t.publicArea, &calculatedEkName);
        if ((state->intern.func.GetConfirmation.ek.obj.name.t.size != calculatedEkName.t.size) ||
            (memcmp(state->intern.func.GetConfirmation.ek.obj.name.t.name, calculatedEkName.t.name, calculatedEkName.t.size)) ||
             (state->param.func.GetConfirmation.ekName.t.size != calculatedEkName.t.size) ||
             (memcmp(state->param.func.GetConfirmation.ekName.t.name, calculatedEkName.t.name, calculatedEkName.t.size)))
        {
            DMSG("ERROR: EK validation failed. Device not authenticated.\n");
            result = TPM_RC_FAILURE;
            goto Cleanup;
        }
        DMSG( "SCTRM: EK verification succeeded. Safe to continue.\n" );
    }

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
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static void ScTrmFunc_GetConfirmation_Marshal_GetCapability( ScTrmStateObject_t* state )
{
    DEFINE_CALL_BUFFERS

    // Recovery. Read all the open sessions so we can close them.
    INITIALIZE_CALL_BUFFERS( TPM2_GetCapability, &state->intern.urchin.in.getCapability, &state->intern.urchin.out.getCapability );
    state->intern.urchin.in.getCapability.capability = TPM_CAP_HANDLES;
    state->intern.urchin.in.getCapability.property = 0x02000000;
    state->intern.urchin.in.getCapability.propertyCount = 1;
    MARSHAL_CMD(TPM2_GetCapability);

    state->intern.state = ScTrmState_GetConfirmation_Recovery_GetCapability;

}

static ScTrmResult_t ScTrmFunc_GetConfirmation_StartRecovery( ScTrmStateObject_t* state )
{
    // Only attempt recovery once.
    if (state->intern.recovery == 1) {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }

    state->intern.recovery = 1;
    ScTrmFunc_GetConfirmation_Marshal_GetCapability( state );

    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_Recovery_FlushHandle( ScTrmStateObject_t* state )
{
    DEFINE_CALL_BUFFERS
    UINT32 result = TPM_RC_SUCCESS;
    UNMARSHAL_RSP(TPM2_FlushContext);

    ScTrmFunc_GetConfirmation_Marshal_GetCapability( state );

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_Recovery_GetCapability( ScTrmStateObject_t* state )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    UNMARSHAL_RSP(TPM2_GetCapability);

    if (state->intern.urchin.out.getCapability.capabilityData.capability != TPM_CAP_HANDLES) {
        result = TPM_RC_VALUE;
        goto Cleanup;
    }

    if (state->intern.urchin.out.getCapability.capabilityData.data.handles.count > 0) {
        INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &state->intern.urchin.in.flushContext, &state->intern.urchin.out.flushContext);
        state->intern.urchin.parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle].obj.handle = state->intern.urchin.out.getCapability.capabilityData.data.handles.handle[0];
        MARSHAL_CMD(TPM2_FlushContext);

        state->intern.state = ScTrmState_GetConfirmation_Recovery_FlushHandle;
    }
    else {
        state->intern.state = ScTrmState_None;
        return ScTrmFunc_Session_Start(state);
    }

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_Session_StartSeededSession(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    UNMARSHAL_RSP(TPM2_StartAuthSession);
    state->intern.func.GetConfirmation.seededSession = state->intern.urchin.parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Request the EK information again but this time with auditing so the information can be trusted
    ScTrmFunc_UseSeededSession(state);
    INITIALIZE_CALL_BUFFERS(TPM2_ReadPublic, &state->intern.urchin.in.readPublic, &state->intern.urchin.out.readPublic);
    state->intern.urchin.parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey] = state->intern.func.GetConfirmation.ek;
    MARSHAL_CMD(TPM2_ReadPublic);

    DMSG("SCTRM: StartSeededSession state passed\n");
    state->intern.state++;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        if (result == TPM_RC_SESSION_MEMORY) {
            return ScTrmFunc_GetConfirmation_StartRecovery( state );
        }
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_Session_GetEkPub( ScTrmStateObject_t* state )
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
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_Session_GetNvPublicForDisplayUntrusted(ScTrmStateObject_t* state)
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
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_Session_GetNvPublicForFPReaderUntrusted(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    // This will give us the NV name
    UNMARSHAL_RSP(TPM2_NV_ReadPublic);
    state->intern.func.GetConfirmation.nvFPReader = state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    // Check the NV index properties here. We skip that for now.

    // We read the NV public again with the seeded session to make sure nobody is playing tricks with us
    ScTrmFunc_UseSeededSession(state);
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
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_Session_GetNvPublicForDisplay(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    // This will give us the trusted NV name
    UNMARSHAL_RSP(TPM2_NV_ReadPublic);
    state->intern.func.GetConfirmation.nvDisplay = state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];
    state->intern.urchin.sessionTable[0].attributes.audit = CLEAR;
    state->intern.func.GetConfirmation.seededSession = state->intern.urchin.sessionTable[0];

    // We read the NV public again with the seeded session to make sure nobody is playing tricks with us
    ScTrmFunc_UseSeededSession(state);
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
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_Start( ScTrmStateObject_t* state )
{
    DEFINE_CALL_BUFFERS;

    // Write the timeout to the fpReader
    ScTrmFunc_UseSeededSession(state);
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &state->intern.urchin.in.nv_Write, &state->intern.urchin.out.nv_Write);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = state->intern.func.GetConfirmation.nvFPReader;
    state->intern.urchin.parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = state->intern.func.GetConfirmation.nvFPReader;
    state->intern.urchin.in.nv_Write.offset = 0;
    state->intern.urchin.in.nv_Write.data.t.size = sizeof(UINT32);
    *((UINT16*)&state->intern.urchin.in.nv_Write.data.t.buffer[0]) = state->param.func.GetConfirmation.timeout;
    state->intern.urchin.in.nv_Write.data.t.buffer[3] = FP_AUTHORIZE_TIMEOUT;
    MARSHAL_CMD(TPM2_NV_Write);

    state->intern.state = ScTrmState_GetConfirmation_SetTimeout;
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_Session_GetNvPublicForFPReader(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    // This will give us the trusted NV name
    UNMARSHAL_RSP(TPM2_NV_ReadPublic);
    state->intern.func.GetConfirmation.nvFPReader = state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];
    state->intern.urchin.sessionTable[0].attributes.audit = CLEAR;
    state->intern.func.GetConfirmation.seededSession = state->intern.urchin.sessionTable[0];

    state->intern.state = ScTrmState_Session_Complete;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static void ScTrmFunc_GetConfirmation_Marshal_WriteToDisplay(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;

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
}

static ScTrmResult_t ScTrmFunc_GetConfirmation_ReadyToDisplay(ScTrmStateObject_t* state)
{
    // Make sure we really are ready to display by validating required state.
    if (state->intern.func.GetConfirmation.nvDisplay.nv.handle != 0 &&
        state->intern.func.GetConfirmation.nvFPReader.nv.handle != 0 &&
        state->intern.func.GetConfirmation.ek.nv.handle != 0 &&
        state->intern.func.GetConfirmation.seededSession.handle != 0)
    {
        ScTrmFunc_GetConfirmation_Marshal_WriteToDisplay( state );
        state->intern.state = ScTrmState_GetConfirmation_WriteToDisplay;
        return ScTrmResult_Ongoing;
    }

    // Unexpected. Reset the state machine and create the session state anew.
    // todo: read and clear all active TPM sessions
    state->intern.state = ScTrmState_None;
    return ScTrmFunc_Session_Start(state);
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
    ScTrmFunc_GetConfirmation_Marshal_WriteToDisplay( state );
    state->intern.state++;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
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
        state->intern.state = ScTrmState_Complete_Error;
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
        // Timeout detected. Reset the TPM state so that the statemachine resumes to Clear the display
        state->intern.result = ScTrmResult_Timeout;
        result = TPM_RC_SUCCESS;
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
        state->intern.state = ScTrmState_Complete_Error;
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
        state->intern.state = ScTrmState_Complete_Error;
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

    // Transition to ScTrmState_None when we are done.
    // This will preserve TPM session state for the next run.
    state->intern.state = ScTrmState_GetConfirmation_Ready;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return state->intern.result;
}

static ScTrmResult_t ScTrmFunc_ProvisionFP_Start(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;

    // Marshal a NV_ReadPublic to see if the slot is already defined.
    state->intern.func.ProvisionFP.nvFPSlot.nv.handle = state->param.func.ProvisionFP.fpSlot + NV_FPBASE_INDEX;
    state->intern.func.ProvisionFP.nvFPSlot.nv.authValue = state->param.func.ProvisionFP.fpManageAuth;
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &state->intern.urchin.in.nv_ReadPublic, &state->intern.urchin.out.nv_ReadPublic);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = state->intern.func.ProvisionFP.nvFPSlot;
    MARSHAL_CMD(TPM2_NV_ReadPublic);

    state->intern.state = ScTrmState_ProvisionFP_ReadSlotNameUntrusted;

    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_ProvisionFP_ReadSlotNameUntrusted(ScTrmStateObject_t* state)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    //  Get the read result.
    TRY_UNMARSHAL_RSP(TPM2_NV_ReadPublic);

    if (result != TPM_RC_SUCCESS) {
        //  No slot defined. We need to define it.
        ScTrmFunc_UseSeededSession(state);
        INITIALIZE_CALL_BUFFERS(TPM2_NV_DefineSpace, &state->intern.urchin.in.nvDefineSpace, &state->intern.urchin.out.nvDefineSpace);

        state->intern.urchin.in.nvDefineSpace.auth =  state->intern.func.ProvisionFP.nvFPSlot.nv.authValue;
        state->intern.urchin.in.nvDefineSpace.publicInfo.t.nvPublic.nvIndex = state->intern.func.ProvisionFP.nvFPSlot.nv.handle;
        state->intern.urchin.in.nvDefineSpace.publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA256;
        state->intern.urchin.in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = SET;
        state->intern.urchin.in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHWRITE = SET;
        state->intern.urchin.in.nvDefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_NO_DA = SET;
        state->intern.urchin.in.nvDefineSpace.publicInfo.t.nvPublic.authPolicy.t.size = 0;
        state->intern.urchin.in.nvDefineSpace.publicInfo.t.nvPublic.dataSize = FP_TEMPLATE_SIZE;
        MARSHAL_CMD(TPM2_NV_DefineSpace);

        state->intern.state = ScTrmState_ProvisionFP_DefineSlot;
    }
    else {
        // Slot defined. Read it using the seeded session.
        state->intern.func.ProvisionFP.nvFPSlot = state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

        ScTrmFunc_UseSeededSession(state);
        INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &state->intern.urchin.in.nv_ReadPublic, &state->intern.urchin.out.nv_ReadPublic);
        state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = state->intern.func.ProvisionFP.nvFPSlot;
        MARSHAL_CMD(TPM2_NV_ReadPublic);

        state->intern.state = ScTrmState_ProvisionFP_ReadSlotTrusted;
    }

    DMSG("SCTRM: ProvisionFP_Start state passed\n");

//Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("SCTRM: GetSlotNameUntrusted state failed with result %x\n", result);
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_ProvisionFP_DefineSlot( ScTrmStateObject_t* state )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    UNMARSHAL_RSP(TPM2_NV_DefineSpace);

    //  Read back the newly defined object name.
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &state->intern.urchin.in.nv_ReadPublic, &state->intern.urchin.out.nv_ReadPublic);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = state->intern.func.ProvisionFP.nvFPSlot;
    MARSHAL_CMD(TPM2_NV_ReadPublic);

    state->intern.state = ScTrmState_ProvisionFP_ReadDefinedSlotUntrusted;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("SCTRM: ReadDefinedSlotUntrusted state failed with result %x\n", result);
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_ProvisionFP_ReadDefinedSlotUntrusted( ScTrmStateObject_t* state )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    UNMARSHAL_RSP(TPM2_NV_ReadPublic);
    state->intern.func.ProvisionFP.nvFPSlot = state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    //  Now that we have the name, read it again using a seeded session.
    //  The HMAC associated with the seeded session requires we know the actual name before hand.
    ScTrmFunc_UseSeededSession(state);
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &state->intern.urchin.in.nv_ReadPublic, &state->intern.urchin.out.nv_ReadPublic);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = state->intern.func.ProvisionFP.nvFPSlot;
    MARSHAL_CMD(TPM2_NV_ReadPublic);

    state->intern.state = ScTrmState_ProvisionFP_ReadDefinedSlotTrusted;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("SCTRM: ReadDefinedSlotTrusted state failed with result %x\n", result);
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_ProvisionFP_ReadDefinedSlotTrusted( ScTrmStateObject_t* state )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    UNMARSHAL_RSP(TPM2_NV_ReadPublic);
    state->intern.func.ProvisionFP.nvFPSlot = state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    // Create the object
    ScTrmFunc_UseSeededSession(state);
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &state->intern.urchin.in.nv_Write, &state->intern.urchin.out.nv_Write);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = state->intern.func.ProvisionFP.nvFPSlot;
    state->intern.urchin.parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = state->intern.func.ProvisionFP.nvFPSlot;
    state->intern.urchin.in.nv_Write.offset = 0;
    state->intern.urchin.in.nv_Write.data.t.size = 0;
    MARSHAL_CMD(TPM2_NV_Write);

    state->intern.state = ScTrmState_ProvisionFP_CreateSlot;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("SCTRM: CreateSlot state failed with result %x\n", result);
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_ProvisionFP_CreateSlot( ScTrmStateObject_t* state )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    UNMARSHAL_RSP(TPM2_NV_Write);

    //  Read back the newly created object name.
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &state->intern.urchin.in.nv_ReadPublic, &state->intern.urchin.out.nv_ReadPublic);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = state->intern.func.ProvisionFP.nvFPSlot;
    MARSHAL_CMD(TPM2_NV_ReadPublic);

    state->intern.state = ScTrmState_ProvisionFP_ReadCreatedSlotUntrusted;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("SCTRM: ReadCreatedSlotUntrusted state failed with result %x\n", result);
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_ProvisionFP_ReadCreatedSlotUntrusted( ScTrmStateObject_t* state )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    UNMARSHAL_RSP(TPM2_NV_ReadPublic);
    state->intern.func.ProvisionFP.nvFPSlot = state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    //  Now that we have the name, read it again using a seeded session.
    //  The HMAC associated with the seeded session requires we know the actual name before hand.
    ScTrmFunc_UseSeededSession(state);
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &state->intern.urchin.in.nv_ReadPublic, &state->intern.urchin.out.nv_ReadPublic);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = state->intern.func.ProvisionFP.nvFPSlot;
    MARSHAL_CMD(TPM2_NV_ReadPublic);

    state->intern.state = ScTrmState_ProvisionFP_ReadSlotTrusted;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("SCTRM: DefineSlot state failed with result %x\n", result);
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_ProvisionFP_ReadSlotTrusted( ScTrmStateObject_t* state )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    UNMARSHAL_RSP(TPM2_NV_ReadPublic);
    state->intern.func.ProvisionFP.nvFPSlot = state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    // Write the template
    ScTrmFunc_UseSeededSession(state);
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &state->intern.urchin.in.nv_Write, &state->intern.urchin.out.nv_Write);
    state->intern.urchin.parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = state->intern.func.ProvisionFP.nvFPSlot;
    state->intern.urchin.parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = state->intern.func.ProvisionFP.nvFPSlot;
    state->intern.urchin.in.nv_Write.offset = 0;
    state->intern.urchin.in.nv_Write.data = state->param.func.ProvisionFP.fpTemplate;
    MARSHAL_CMD(TPM2_NV_Write);

    state->intern.state = ScTrmState_ProvisionFP_WriteSlotTemplate;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("SCTRM: ReadSlotTrusted state failed with result %x\n", result);
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

static ScTrmResult_t ScTrmFunc_ProvisionFP_WriteSlotTemplate( ScTrmStateObject_t* state )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;

    UNMARSHAL_RSP(TPM2_NV_Write);
    state->intern.func.ProvisionFP.nvFPSlot = state->intern.urchin.parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    state->intern.state = ScTrmState_Session_Complete;

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        DMSG("SCTRM: WriteSlotTemplate state failed with result %x\n", result);
        ScTrmFunc_MyBreakPointHere();
        state->intern.state = ScTrmState_Complete_Error;
        return ScTrmResult_Error;
    }
    return ScTrmResult_Ongoing;
}

ScTrmResult_t ScTrmEstablishSession( ScTrmStateObject_t* state, bool *complete )
{
    *complete = false;

    switch (state->intern.state)
    {
         case ScTrmState_None:
        {
            return ScTrmFunc_Session_Start(state);
        }
        case ScTrmState_Session_GetEkPubUntrusted:
        {
            return ScTrmFunc_Session_GetEkPubUntrusted(state);
        }
        case ScTrmState_Session_StartSeededSession:
        {
            return ScTrmFunc_Session_StartSeededSession(state);
        }
        case ScTrmState_Session_GetEkPub:
        {
            return ScTrmFunc_Session_GetEkPub(state);
        }
        case ScTrmState_Session_GetNvPublicForDisplayUntrusted:
        {
            return ScTrmFunc_Session_GetNvPublicForDisplayUntrusted(state);
        }
        case ScTrmState_Session_GetNvPublicForFPReaderUntrusted:
        {
            return ScTrmFunc_Session_GetNvPublicForFPReaderUntrusted(state);
        }
        case ScTrmState_Session_GetNvPublicForDisplay:
        {
            return ScTrmFunc_Session_GetNvPublicForDisplay(state);
        }
        case ScTrmState_Session_GetNvPublicForFPReader:
        {
            ScTrmFunc_Session_GetNvPublicForFPReader(state);
            // Fall through
        }
        case ScTrmState_Session_Complete:
        default:
        {
            *complete = true;
            return ScTrmResult_Ongoing;
        }
    }
}

ScTrmResult_t ScTrmGetConfirmation(ScTrmStateObject_t* state)
{
    bool sessionEstablished;

    _cpri__RngStartup();
    _cpri__HashStartup();
    _cpri__RsaStartup();
    _cpri__SymStartup();

    if (ScTrmEstablishSession( state, &sessionEstablished ) != ScTrmResult_Ongoing) {
        return ScTrmResult_Error;
    }
    else if (!sessionEstablished) {
        return ScTrmResult_Ongoing;
    }

    switch(state->intern.state)
    {
        case ScTrmState_Session_Complete:
        {
            return ScTrmFunc_GetConfirmation_Start(state);
        }
        case ScTrmState_GetConfirmation_SetTimeout:
        {
            return ScTrmFunc_GetConfirmation_SetTimeout(state);
        }
        case ScTrmState_GetConfirmation_Ready:
        {
            return ScTrmFunc_GetConfirmation_ReadyToDisplay(state);
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
        case ScTrmState_GetConfirmation_Recovery_GetCapability:
        {
            return ScTrmFunc_GetConfirmation_Recovery_GetCapability(state);
        }
        case ScTrmState_GetConfirmation_Recovery_FlushHandle:
        {
            return ScTrmFunc_GetConfirmation_Recovery_FlushHandle(state);
        }
        case ScTrmState_Complete_Error:
        default:
        {
            ScTrmFunc_MyBreakPointHere();
            return ScTrmResult_Error;
        }
    }
}

ScTrmResult_t ScTrmProvisionFP( ScTrmStateObject_t* state )
{
    bool sessionEstablished;

    _cpri__RngStartup();
    _cpri__HashStartup();
    _cpri__RsaStartup();
    _cpri__SymStartup();

    if (ScTrmEstablishSession( state, &sessionEstablished ) != ScTrmResult_Ongoing) {
        return ScTrmResult_Error;
    }
    else if (!sessionEstablished) {
        return ScTrmResult_Ongoing;
    }

    switch(state->intern.state)
    {
        case ScTrmState_Session_Complete:
        {
            // Attempt to NV_READ the slot name
            return ScTrmFunc_ProvisionFP_Start( state );
        }
        case ScTrmState_ProvisionFP_ReadSlotNameUntrusted:
        {
            return ScTrmFunc_ProvisionFP_ReadSlotNameUntrusted( state );
        }
        case ScTrmState_ProvisionFP_DefineSlot:
        {
            return ScTrmFunc_ProvisionFP_DefineSlot( state );
        }
        case ScTrmState_ProvisionFP_ReadDefinedSlotUntrusted:
        {
            return ScTrmFunc_ProvisionFP_ReadDefinedSlotUntrusted( state );
        }
        case ScTrmState_ProvisionFP_ReadDefinedSlotTrusted:
        {
            return ScTrmFunc_ProvisionFP_ReadDefinedSlotTrusted( state );
        }
        case ScTrmState_ProvisionFP_CreateSlot:
        {
            return ScTrmFunc_ProvisionFP_CreateSlot( state );
        }
        case ScTrmState_ProvisionFP_ReadCreatedSlotUntrusted:
        {
            return ScTrmFunc_ProvisionFP_ReadCreatedSlotUntrusted( state );
        }
        case ScTrmState_ProvisionFP_ReadSlotTrusted:
        {
            return ScTrmFunc_ProvisionFP_ReadSlotTrusted( state );
        }
        case ScTrmState_ProvisionFP_WriteSlotTemplate:
        {
            return ScTrmFunc_ProvisionFP_WriteSlotTemplate( state );
        }
        case ScTrmState_Complete_Error:
        default:
        {
            ScTrmFunc_MyBreakPointHere();
            return ScTrmResult_Error;
        }
    }
}

void ScTrmPrepare( ScTrmStateObject_t* state )
{
    // If we are not ready to display, reset to a workable starting point.
    if (state->intern.state != ScTrmState_GetConfirmation_Ready) {
        state->intern.state = ScTrmState_None;
    }
    state->intern.result = ScTrmResult_Ongoing;
    state->intern.recovery = 0;
}