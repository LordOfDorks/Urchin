// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include <tcps_string_t.h>

#ifndef USE_SGX
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
# include <stdint.h>
# include <stdbool.h>
# include <memory.h>
#endif

#include "UrchinLib.h"
#include "UrchinPlatform.h"
#include "TrScTrmLib.h"
#include "ScTrmDev.h"
