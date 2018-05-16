#pragma once

#define ALL_SLOTS 0xFFFF

typedef struct _CMD_PARAM
{
    PSTR vComPort;
    BOOLEAN force;
    BOOLEAN readEK;
    PSTR ekFilePath;
    PSTR templatePath;
    BOOLEAN enroll;
    BOOLEAN clear;
    BOOLEAN saveTemplate;
    BOOLEAN enrollTemplate;
    unsigned int slot;
    unsigned int test;
} CMD_PARAM;

int
GetCmdlineParams( 
    int argc, 
    char *argv[],
    CMD_PARAM *param
);