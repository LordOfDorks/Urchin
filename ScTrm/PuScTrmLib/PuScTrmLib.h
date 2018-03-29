#pragma once

__declspec(dllexport) unsigned int ScTrm_Open(void* context);
__declspec(dllexport) BOOL ScTrm_Execute(void* context, unsigned char* pbCmd, unsigned int cbCmd, unsigned char* pbRsp, unsigned int cbRsp, unsigned int* pcbRsp);
__declspec(dllexport) BOOL ScTrm_Cancel(void* context);
__declspec(dllexport) void ScTrm_Close(void* context);
