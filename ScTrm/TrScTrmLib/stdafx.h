// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

//#include "targetver.h"

#ifdef USE_SGX
#include "tcps_t.h"
#else
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#endif
#include "UrchinLib.h"
#include "UrchinPlatform.h"
#include "TrScTrmLib.h"
#include "ScTrmDev.h"
