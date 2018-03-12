// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdint.h>
#ifndef NO_WINDOWS
#include <windows.h>
#include <bcrypt.h>
#include <tbs.h>
#include <Wincrypt.h>
#endif
#include "UrchinLib.h"
#include "UrchinPlatform.h"
