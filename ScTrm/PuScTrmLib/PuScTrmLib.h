#pragma once

__declspec(dllexport) unsigned int ScTrm_Open(void);
__declspec(dllexport) BOOL ScTrm_Execute(unsigned int context, unsigned char* pbCmd, unsigned int cbCmd, unsigned char* pbRsp, unsigned int cbRsp, unsigned int* pcbRsp);
__declspec(dllexport) BOOL ScTrm_Cancel(unsigned int context);
__declspec(dllexport) void ScTrm_Close(unsigned int context);
