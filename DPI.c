#include "dpi.h"
#include <stddef.h>

dpi_hook_fn g_dpi_hook = NULL;

void dpi_set_hook(dpi_hook_fn hook)
{
    g_dpi_hook = hook;
}