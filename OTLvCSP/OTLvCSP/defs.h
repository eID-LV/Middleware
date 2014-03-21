#ifndef DEFS_H
#define DEFS_H

#define _WIN32_WINNT	0x0501	/* Minimum : Windows XP */
#define WINVER			0x0501	/* Minimum : Windows XP */
#define _WIN32_IE		0x0500	/* Minimum : Internet Explorer 5.0, 5.0a, 5.0b */

#include <windows.h>
#include <tchar.h>
#ifndef SIGNATURE_RESOURCE_NUMBER
#include "cspdk.h"
#else
#define CRYPT_SIG_RESOURCE_NUMBER SIGNATURE_RESOURCE_NUMBER
#endif




#endif