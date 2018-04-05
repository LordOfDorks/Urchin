#pragma once

#define CLEAR_ALL_SLOTS 0xFFFF

typedef struct _CMD_PARAM
{
    PSTR vComPort;
    BOOLEAN force;
    BOOLEAN readEK;
    BOOLEAN enroll;
    unsigned int enrollSlot;
    BOOLEAN test;
    BOOLEAN clear;
    unsigned int clearSlot;
} CMD_PARAM;

int
GetCmdlineParams( 
    int argc, 
    char *argv[],
    CMD_PARAM *param
);