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

    // Function: GetConfirmation
    ScTrmState_GetConfirmation_GetEkPubUntrusted,
    ScTrmState_GetConfirmation_StartSeededSession,
    ScTrmState_GetConfirmation_GetEkPub,
    ScTrmState_GetConfirmation_GetNvPublicForDisplayUntrusted,
    ScTrmState_GetConfirmation_GetNvPublicForFPReaderUntrusted,
    ScTrmState_GetConfirmation_GetNvPublicForDisplay,
    ScTrmState_GetConfirmation_GetNvPublicForFPReader,
    ScTrmState_GetConfirmation_WriteToDisplay,
    ScTrmState_GetConfirmation_ReadFPId,
    ScTrmState_GetConfirmation_ClearDisplay,

    ScTrmState_Complete = -1
} ScTrmState_t;

typedef struct
{
    TPM2B_NAME ekName;
    TPM2B_MAX_NV_BUFFER displayMessage;
    TPM2B_AUTH fpReaderAuth;
    TPM2B_AUTH displayAuth;
    UINT32 timeout;
} GetConfirmation_Param_t;

typedef struct
{
    SESSION       seededSession;
    ANY_OBJECT    ek;
    ANY_OBJECT    nvDisplay;
    ANY_OBJECT    nvFPReader;
} GetConfirmation_Intern_t;

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
        } func;
    } param;
    struct
    {
        ScTrmState_t state;
        ScTrmResult_t result;
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
                NV_Write_In nv_Write;
                NV_Read_In nv_Read;
            } in;
            union
            {
                ReadPublic_Out readPublic;
                StartAuthSession_Out startAuthSession;
                NV_ReadPublic_Out nv_ReadPublic;
                NV_Write_Out nv_Write;
                NV_Read_Out nv_Read;
            } out;
        } urchin;
        union
        {
            GetConfirmation_Intern_t GetConfirmation;
        } func;
    } intern;
} ScTrmStateObject_t;
#pragma pack(pop)

__declspec(dllexport) ScTrmResult_t ScTrmGetConfirmation(ScTrmStateObject_t* state);
