#include "stdafx.h"
#include "Cmdline.h"


#define SW_COM_PORT          "VCom"
#define SW_COM_PORT_INFO     "COM port connected to the secure display. e.g. \"COM6\""
#define SW_FORCE             "Force"
#define SW_FORCE_INFO        "Hard reset the TPM, recreated all keys."
#define SW_READ_EK           "ReadEK"
#define SW_READ_EK_INFO      "Reads (and creates if missing) the EK and prints it to the screen."
#define SW_ENROLL            "Enroll"
#define SW_ENROLL_INFO       "Enrolls a new fingerprint in the given slot # (max 200)."
#define SW_VALIDATE_FP       "TestFp"
#define SW_VALIDATE_FP_INFO  "Validates a specific fingerprint is enrolled"
#define SW_CLEAR_FP          "Clear"
#define SW_CLEAR_FP_INFO     "Clear slot #. If no number provided, clear all enrolled fingerprint templates."
#define IS_SWITCH(_s)   ((*(_s) == '/') || (*(_s) == '-'))

VOID
PrintUsage(
    int argc, char *argv[]
)
{
    printf_s( "\nUsage:  %s ", argv[0]);
    printf_s( " /%s <slot#> /%s <COM> /%s <slot#>\n\n",
              SW_ENROLL, SW_COM_PORT, SW_CLEAR_FP);
    printf_s( "\t%s\t%s\n", SW_ENROLL, SW_ENROLL_INFO);
    printf_s( "\t%s\t%s\n", SW_VALIDATE_FP, SW_VALIDATE_FP_INFO);
    printf_s( "\t%s\t%s\n", SW_COM_PORT, SW_COM_PORT_INFO);
    printf_s( "\t%s\t%s\n", SW_FORCE, SW_FORCE_INFO);
    printf_s( "\t%s\t%s\n", SW_READ_EK, SW_READ_EK_INFO);
    printf_s( "\t%s\t%s\n", SW_CLEAR_FP, SW_CLEAR_FP_INFO);
    printf_s( "\n");
}

BOOLEAN
IsSwitchActive(
    int argc, char *argv[],
    _In_z_ PSTR SwitchSel
)

/*++

Routine Description:

    Helper. Checks if a switch is on.

--*/

{

    for (INT i = 1; i < argc; i++) {
        if (IS_SWITCH( argv[i] ) &&
            (_stricmp( argv[i] + 1, SwitchSel ) == 0)) {
            return TRUE;
        }
    }

    return FALSE;
}

DWORD
GetSwitchWithValue(
    int argc, char *argv[],
    _In_z_ PSTR SwitchSel,
    _Out_ PSTR *Value
)

/*++

Routine Description:

    Helper. Checks the argument list for a given switch.

--*/

{

    for (INT i = 1; i < argc; i++) {

        if (IS_SWITCH( argv[i] )) {

            if (_stricmp( argv[i] + 1, SwitchSel ) == 0) {
                if ((i + 1) == argc) {
                    break;
                }

                *Value = argv[i + 1];
                return ERROR_SUCCESS;
            }
        }
    }

    *Value = NULL;
    return ERROR_INVALID_PARAMETER;
}

DWORD
GetSwitchWithIntValue(
    int argc, char *argv[],
    _In_z_ PSTR SwitchSel,
    _Out_ unsigned int *Value
)

/*++

Routine Description:

    Helper. Checks the argument list for a given switch.

--*/

{

    for (INT i = 1; i < argc; i++) {

        if (IS_SWITCH( argv[i] )) {

            if (_stricmp( argv[i] + 1, SwitchSel ) == 0) {
                if ((i + 1) == argc) {
                    break;
                }

                *Value = atoi(argv[i + 1]);
                return ERROR_SUCCESS;
            }
        }
    }

    return ERROR_INVALID_PARAMETER;
}

int
GetCmdlineParams( 
    int argc, char *argv[],
    CMD_PARAM *param
)
{
    if (argc <= 1)
    {
        return 0;
    }

    if (IsSwitchActive( argc, argv, "?" ))
    {
        PrintUsage(argc, argv);
        return -1;
    }

    GetSwitchWithValue( argc, argv, SW_COM_PORT, &param->vComPort );
    param->force = IsSwitchActive( argc, argv, SW_FORCE );
    param->readEK = IsSwitchActive( argc, argv, SW_READ_EK );
    param->enroll = IsSwitchActive( argc, argv, SW_ENROLL );
    param->test = IsSwitchActive( argc, argv, SW_VALIDATE_FP );
    param->clear = IsSwitchActive( argc, argv, SW_CLEAR_FP );

    if (param->enroll) {
        if (GetSwitchWithIntValue( argc, argv, SW_ENROLL, &param->enrollSlot ) != ERROR_SUCCESS)
        {
            printf_s( "Paramater error: %s requires a slot number\n", SW_READ_EK);
            PrintUsage(argc, argv);
            return -1;
        }
    }

    if (param->clear) {
        if (GetSwitchWithIntValue( argc, argv, SW_CLEAR_FP, &param->clearSlot ) != ERROR_SUCCESS)
        {
            param->clearSlot = CLEAR_ALL_SLOTS;
        }
    }

    return 0;
}