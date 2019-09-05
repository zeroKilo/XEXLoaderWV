
#ifndef __MYSTDINT_H__
#define __MYSTDINT_H__

#ifdef _WIN32

typedef unsigned long int uint32;
typedef unsigned short    uint16;
typedef unsigned char      uint8;

#else

#include <stdint.h>
typedef uint32_t uint32;
typedef uint16_t uint16;
typedef uint8_t  uint8;

#endif
 
#endif // __MYSTDINT_H__
