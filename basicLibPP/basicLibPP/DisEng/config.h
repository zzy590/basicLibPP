/* config.h.  Mini config for disasm.  */

#ifndef _BX_CONFIG_H_
#define _BX_CONFIG_H_ 1

#include <Windows.h>

// emulate x86-64 instruction set?
#define BX_SUPPORT_X86_64 1

#define BX_64BIT_CONSTANTS_USE_LL 0
#if BX_64BIT_CONSTANTS_USE_LL
// doesn't work on Microsoft Visual C++, maybe others
#define BX_CONST64(x)  (x##LL)
#elif defined(_MSC_VER)
#define BX_CONST64(x)  (x##I64)
#else
#define BX_CONST64(x)  (x)
#endif

typedef unsigned __int8      Bit8u;
typedef   signed __int8      Bit8s;
typedef unsigned __int16     Bit16u;
typedef   signed __int16     Bit16s;
typedef unsigned __int32     Bit32u;
typedef   signed __int32     Bit32s;
typedef unsigned __int64     Bit64u;
typedef   signed __int64     Bit64s;

#define GET32L(val64) ((Bit32u)(((Bit64u)(val64)) & 0xFFFFFFFF))
#define GET32H(val64) ((Bit32u)(((Bit64u)(val64)) >> 32))

// now that Bit32u and Bit64u exist, defined bx_address
#if BX_SUPPORT_X86_64
typedef Bit64u bx_address;
#else
typedef Bit32u bx_address;
#endif

// technically, in an 8 bit signed the real minimum is -128, not -127.
// But if you decide to negate -128 you tend to get -128 again, so it's
// better not to use the absolute maximum in the signed range.
#define BX_MAX_BIT64U ( (Bit64u) -1           )
#define BX_MIN_BIT64U ( 0                     )
#define BX_MAX_BIT64S ( ((Bit64u) -1) >> 1    )
#define BX_MIN_BIT64S ( (Bit64s)-(((Bit64u) -1) >> 1) )
#define BX_MAX_BIT32U ( (Bit32u) -1           )
#define BX_MIN_BIT32U ( 0                     )
#define BX_MAX_BIT32S ( ((Bit32u) -1) >> 1    )
#define BX_MIN_BIT32S ( (Bit32s)-(((Bit32u) -1) >> 1) )
#define BX_MAX_BIT16U ( (Bit16u) -1           )
#define BX_MIN_BIT16U ( 0                     )
#define BX_MAX_BIT16S ( ((Bit16u) -1) >> 1    )
#define BX_MIN_BIT16S ( (Bit16s)-(((Bit16u) -1) >> 1) )
#define BX_MAX_BIT8U  ( (Bit8u) -1            )
#define BX_MIN_BIT8U  ( 0                     )
#define BX_MAX_BIT8S  ( ((Bit8u) -1) >> 1     )
#define BX_MIN_BIT8S  ( (Bit8s)-(((Bit8u) -1) >> 1)  )

// Use a boolean type that will not conflict with the builtin type
// on any system.
typedef Bit32u bx_bool;

// configure will change the definition of "inline" to the value
// that the C compiler allows.  It tests the following keywords to
// see if any is permitted: inline, __inline__, __inline.  If none
// is permitted, it defines inline to be empty.
#define inline __forceinline

// Use BX_CPP_INLINE for all C++ inline functions.  Note that the
// word "inline" itself may now be redefined by the above #define.
#define BX_CPP_INLINE inline

#endif  // _BX_CONFIG_H
