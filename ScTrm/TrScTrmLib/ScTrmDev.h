#pragma once

#define NV_FPBASE_INDEX (0x01008000)
#define FP_TEMPLATE_SIZE (498)
#define FP_SLOTS_MAX (200)
#define FP_SLOTS (40)
#define FP_AUTHORIZE_INDEX (NV_FPBASE_INDEX + FP_SLOTS_MAX)
#define FP_DISPLAY_INDEX (FP_AUTHORIZE_INDEX + 1)
#define FP_DISPLAY_MAX_TEXT (256)

#define FP_SLOT_INITIALIZE_TEMPLATE (0x00)
#define FP_SLOT_DELETE_ALL_TEMPLATE (0x01)
#define FP_SLOT_DELETE_TEMPLATE (0x02)
#define FP_SLOT_ENROLL_TEMPLATE (0x03)
#define FP_AUTHORIZE_INITIALIZE (0x00)
#define FP_AUTHORIZE_VERIFY (0x01)
#define FP_AUTHORIZE_TIMEOUT (0x02)
