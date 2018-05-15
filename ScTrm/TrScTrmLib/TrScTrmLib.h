#pragma once

#pragma pack(push, 1)
#define TPM2B(__size) struct\
{\
       unsigned short size;\
       unsigned char  buffer[__size];\
}\

typedef enum
{
    ScTrmState_None = 0,

    // Common session establishment.
    ScTrmState_Session_GetEkPubUntrusted,
    ScTrmState_Session_StartSeededSession,
    ScTrmState_Session_GetEkPub,
    ScTrmState_Session_GetNvPublicForDisplayUntrusted,
    ScTrmState_Session_GetNvPublicForFPReaderUntrusted,
    ScTrmState_Session_GetNvPublicForDisplay,
    ScTrmState_Session_GetNvPublicForFPReader,
    ScTrmState_Session_Complete,

    // Function: GetConfirmation
    ScTrmState_GetConfirmation_SetTimeout,
    ScTrmState_GetConfirmation_WriteToDisplay,
    ScTrmState_GetConfirmation_ReadFPId,
    ScTrmState_GetConfirmation_ClearDisplay,

    // The following are not sequential 
    ScTrmState_GetConfirmation_Ready = 0x0FF0,
    ScTrmState_GetConfirmation_Recovery_GetCapability,
    ScTrmState_GetConfirmation_Recovery_FlushHandle,

    // Function: ProvisionFP
    ScTrmState_ProvisionFP_ReadSlotNameUntrusted,
    ScTrmState_ProvisionFP_DefineSlot,
    ScTrmState_ProvisionFP_ReadDefinedSlotUntrusted,
    ScTrmState_ProvisionFP_ReadDefinedSlotTrusted,
    ScTrmState_ProvisionFP_CreateSlot,
    ScTrmState_ProvisionFP_ReadCreatedSlotUntrusted,
    ScTrmState_ProvisionFP_ReadSlotTrusted,
    ScTrmState_ProvisionFP_WriteSlotTemplate,

    ScTrmState_Complete_Error = -1
} ScTrmState_t;

typedef struct
{
    TPM2B_NAME ekName;
    TPM2B_MAX_NV_BUFFER displayMessage;
    TPM2B_AUTH fpReaderAuth;
    TPM2B_AUTH displayAuth;
    UINT16 timeout;
    BOOL verifyEk;
} GetConfirmation_Param_t;

typedef struct
{
    TPM2B_NAME ekName;
    TPM2B_MAX_NV_BUFFER fpTemplate;
    TPM2B_AUTH fpReaderAuth;
    TPM2B_AUTH fpManageAuth;
    UINT16 fpSlot;
    BOOL verifyEk;
} ProvisionFP_Param_t;

typedef struct
{
    SESSION       seededSession;
    ANY_OBJECT    ek;
    ANY_OBJECT    nvDisplay;
    ANY_OBJECT    nvFPReader;
} GetConfirmation_Intern_t;

typedef struct
{
    SESSION       seededSession;
    ANY_OBJECT    ek;
    ANY_OBJECT    nvFPSlot;
    ANY_OBJECT    nvFPReader;
} ProvisionFP_Intern_t;

typedef enum
{
    ScTrmResult_Match0 = 0,           // Procedure complete: Match with template in slot 0
                                      // Procedure complete: Match with template in slot 1-198
    ScTrmResult_MatchMax = 199,       // Procedure complete: Match with template in slot 199
    ScTrmResult_Ongoing = 0x7fffffff, // send msgInOutLen command bytes from msgInOut to proxy;
                                      // overwrite msgInOut with response from proxy and set msgInOutLen
    ScTrmResult_Error = 0x80000000,   // Procedure complete: Error
    ScTrmResult_CommError,            // Procedure incomplete: Communication Error with the TPM
    ScTrmResult_Timeout,              // Procedure complete: Scanner timeout - No finger pressed in time
    ScTrmResult_Unrecognized          // Procedure complete: Unrecognized finger pressed - No authorization
} ScTrmResult_t;

typedef struct
{
    struct
    {
        BYTE pbCmd[1024];
        UINT32 cbCmd;
        BYTE pbRsp[1024];
        UINT32 cbRsp;
        union
        {
            GetConfirmation_Param_t GetConfirmation;
            ProvisionFP_Param_t ProvisionFP;
        } func;
    } param;
    struct
    {
        ScTrmState_t state;
        ScTrmResult_t result;
        int recovery;
        struct
        {
            Marshal_Parms parms;
            SESSION sessionTable[MAX_HANDLE_NUM];
            UINT32 sessionCnt;
            union
            {
                ReadPublic_In readPublic;
                StartAuthSession_In startAuthSession;
                NV_ReadPublic_In nv_ReadPublic;
                NV_DefineSpace_In nvDefineSpace;
                NV_Write_In nv_Write;
                NV_Read_In nv_Read;
                GetCapability_In getCapability;
                FlushContext_In flushContext;
            } in;
            union
            {
                ReadPublic_Out readPublic;
                StartAuthSession_Out startAuthSession;
                NV_ReadPublic_Out nv_ReadPublic;
                NV_DefineSpace_Out nvDefineSpace;
                NV_Write_Out nv_Write;
                NV_Read_Out nv_Read;
                GetCapability_Out getCapability;
                FlushContext_Out flushContext;
            } out;
        } urchin;
        union
        {
            GetConfirmation_Intern_t GetConfirmation;
            ProvisionFP_Intern_t ProvisionFP;
        } func;
    } intern;
} ScTrmStateObject_t;
#pragma pack(pop)

void ScTrmPrepare(ScTrmStateObject_t* state);
ScTrmResult_t ScTrmGetConfirmation(ScTrmStateObject_t* state);
ScTrmResult_t ScTrmProvisionFP(ScTrmStateObject_t* state);

