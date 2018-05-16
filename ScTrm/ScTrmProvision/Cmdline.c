#include "stdafx.h"
#include "Cmdline.h"


#define SW_COM_PORT                 "VCom"
#define SW_COM_PORT_INFO            "COM port connected to the secure display. e.g. \"COM6\""
#define SW_FORCE                    "FactoryReset"
#define SW_FORCE_INFO               "Hard reset the TPM, recreated all keys. This will clear all slots and the EK"
#define SW_READ_EK                  "ReadEK"
#define SW_READ_EK_INFO             "Reads (and creates if missing) the EK and prints it to the screen.\n" \
                                    "\t\t\t\t  Specify <Path> to dump the contents to a file."
#define SW_SLOT                     "Slot"
#define SW_SLOT_INFO                "Slot number to provision."
#define SW_ENROLL                   "Enroll"
#define SW_ENROLL_INFO              "Enrolls a new fingerprint in the given slot # (max 200)."
#define SW_VALIDATE_FP              "Test"
#define SW_VALIDATE_FP_INFO         "Validates a specific fingerprint is enrolled. Will repeat <num> times"
#define SW_CLEAR_FP                 "Clear"
#define SW_CLEAR_FP_INFO            "Clear slot. If no slot provided, clear all enrolled fingerprint templates."
#define SW_SAVE_TEMPLATE            "SaveTemplate"
#define SW_SAVE_TEMPLATE_INFO       "Reads the enrolled slot into the provided file path."
#define SW_ENROLL_TEMPLATE          "EnrollTemplate"
#define SW_LOAD_TEMPLATE_INFO       "Enrolls a template from the file proveded into the active slot."

#define IS_SWITCH(_s)   ((*(_s) == '/') || (*(_s) == '-'))

char * g_ValidSwitch[] = { SW_COM_PORT, SW_FORCE, SW_READ_EK, SW_ENROLL, SW_VALIDATE_FP, SW_CLEAR_FP, SW_SAVE_TEMPLATE, SW_SLOT, SW_ENROLL_TEMPLATE };

VOID
PrintUsage(
    int argc, char *argv[]
)
{
    printf_s( "\nUsage:  %s ", argv[0]);
    printf_s( "  [/%s <COM>] [/%s <Path>] [/%s <slot#>] [/%s] [/%s] [/%s <num#>] [/%s <Path>] [/%s <Path>] [/%s] \n\n",
              SW_COM_PORT, SW_READ_EK, SW_SLOT, SW_ENROLL, SW_CLEAR_FP, SW_VALIDATE_FP, SW_SAVE_TEMPLATE, SW_ENROLL_TEMPLATE, SW_FORCE);
    printf_s( "    /%s <COM>\t\t\t- %s\n", SW_COM_PORT, SW_COM_PORT_INFO);
    printf_s( "    /%s <Path>\t\t- %s\n", SW_READ_EK, SW_READ_EK_INFO);
    printf_s( "    /%s <#>\t\t\t- %s\n", SW_SLOT, SW_SLOT_INFO);
    printf_s( "    /%s \t\t\t- %s\n", SW_ENROLL, SW_ENROLL_INFO);
    printf_s( "    /%s \t\t\t- %s\n", SW_CLEAR_FP, SW_CLEAR_FP_INFO);
    printf_s( "    /%s <#>\t\t\t- %s\n", SW_VALIDATE_FP, SW_VALIDATE_FP_INFO);
    printf_s( "    /%s <Path>\t- %s\n", SW_SAVE_TEMPLATE, SW_SAVE_TEMPLATE_INFO);
    printf_s( "    /%s <Path>\t- %s\n", SW_ENROLL_TEMPLATE, SW_LOAD_TEMPLATE_INFO);
    printf_s( "    /%s \t\t- %s\n", SW_FORCE, SW_FORCE_INFO);
    printf_s( "\n");
}

BOOLEAN
IsSwitchUnknown(
    int argc, char *argv[]
)
{
    BOOLEAN valid;
    for (INT i = 1; i < argc; i++) {
        if (IS_SWITCH( argv[i] )) {
            valid = false;
            for (INT j = 0; j < ARRAYSIZE(g_ValidSwitch); j++) {
                if (_stricmp( argv[i] + 1, g_ValidSwitch[j] ) == 0) {
                    valid = true;
                    break;
                }
            }
            if (!valid) {
                printf_s( "ERROR: Invalid option    %s\n", argv[i]);
                return TRUE;
            }
        }
    }
    return FALSE;
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

                // switch, not a value
                if (IS_SWITCH( argv[i + 1] )) {
                    return ERROR_INVALID_PARAMETER;
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

                // switch, not a value
                if (IS_SWITCH( argv[i + 1] )) {
                    return ERROR_INVALID_PARAMETER;
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
        PrintUsage(argc, argv);
        return -1;
    }

    if (IsSwitchActive( argc, argv, "?" ) ||
        IsSwitchUnknown(argc, argv))
    {
        PrintUsage(argc, argv);
        return -1;
    }

    if (GetSwitchWithValue( argc, argv, SW_COM_PORT, &param->vComPort ) != ERROR_SUCCESS)
    {
        printf_s( "%s Required\n", SW_COM_PORT);
        PrintUsage(argc, argv);
        return -1;
    }

    // General
    param->force = IsSwitchActive( argc, argv, SW_FORCE );
    param->readEK = IsSwitchActive( argc, argv, SW_READ_EK );

    // Slot specific
    param->enroll = IsSwitchActive( argc, argv, SW_ENROLL );
    param->test = (IsSwitchActive( argc, argv, SW_VALIDATE_FP ) == TRUE) ? 1 : 0;
    param->clear = IsSwitchActive( argc, argv, SW_CLEAR_FP );
    param->saveTemplate = IsSwitchActive( argc, argv, SW_SAVE_TEMPLATE );
    param->enrollTemplate = IsSwitchActive( argc, argv, SW_ENROLL_TEMPLATE );

    if (param->enrollTemplate && param->enroll)
    {
        printf_s( "ERROR: Options %s and %s are not compatible.\n", SW_ENROLL, SW_ENROLL_TEMPLATE);
        PrintUsage(argc, argv);
        return -1;
    }

    param->slot = ALL_SLOTS;

    if (param->clear) {
        // SLOT is optional
        if (GetSwitchWithIntValue( argc, argv, SW_SLOT, &param->slot ) != ERROR_SUCCESS)
        {
            param->slot = ALL_SLOTS;
        }
    }

    if ((param->enroll || param->test || param->saveTemplate || param->enrollTemplate) &&
        param->slot == ALL_SLOTS) {
        // SLOT is required
        if (GetSwitchWithIntValue( argc, argv, SW_SLOT, &param->slot ) != ERROR_SUCCESS)
        {
            printf_s( "ERROR: Slot number is required with specified option. Call again with /%s <num>\n", SW_SLOT);
            PrintUsage(argc, argv);
            return -1;
        }
    }

    if (param->saveTemplate) {
        if (GetSwitchWithValue( argc, argv, SW_SAVE_TEMPLATE, &param->templatePath ) != ERROR_SUCCESS)
        {
            printf_s( "ERROR: %s requires a path to be specified. \n", SW_SAVE_TEMPLATE);
            PrintUsage(argc, argv);
            return -1;
        }
    }
    else if (param->enrollTemplate) {
        if (GetSwitchWithValue( argc, argv, SW_ENROLL_TEMPLATE, &param->templatePath ) != ERROR_SUCCESS)
        {
            printf_s( "ERROR: %s requires a path to be specified. \n", SW_ENROLL_TEMPLATE);
            PrintUsage(argc, argv);
            return -1;
        }
        param->readEK = TRUE;
    }

    if (param->readEK) {
        // Optional
        GetSwitchWithValue( argc, argv, SW_READ_EK, &param->ekFilePath );
    }

    if (param->test == 1) {
        // Optional
        if (GetSwitchWithIntValue( argc, argv, SW_VALIDATE_FP, &param->test ) != ERROR_SUCCESS) {
            param->test = 1;
        }
        param->readEK = TRUE;
    }

    return 0;
}