/* 
 * unistd.h - This is mostly a catch all header that maps standard unix
 *            libc calls to the equivelent win32 functions. 
 *
 */

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#endif

#include <malloc.h>
#include <errno.h>

#include "config.h"

#ifndef _SYS_UNISTD_H_
#define _SYS_UNISTD_H_

#define inline __inline

#define mkdir( A, B )	_mkdir( A )
#define lstat			stat

#ifndef S_ISDIR
#define S_ISDIR(A)		( S_IFDIR & A )
#endif

#ifdef _WIN32
#define S_IXUSR			S_IEXEC
#define S_IXGRP			S_IEXEC
#define S_IXOTH			S_IEXEC
#endif

#define  M_PI			3.14159265358979323846  /* pi */

#ifdef _WIN32
#define bzero( A, B ) memset( A, 0, B )
#endif

#ifndef strcasecmp
#define strcasecmp _stricmp
#endif

#ifndef strncasecmp
#define strncasecmp _strnicmp
#endif

#define snprintf _snprintf
#define vsnprintf _vsnprintf

// FIXME : I dont remember why this is here
#define readlink

#endif
