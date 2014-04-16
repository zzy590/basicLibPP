
/************************************************************************/
/* basicLib++ Author:zzy                                                */
/************************************************************************/

#pragma once

//
// Type define
//

typedef unsigned __int8      T_Bit8u , *PT_Bit8u;
typedef   signed __int8      T_Bit8s , *PT_Bit8s;
typedef unsigned __int16     T_Bit16u, *PT_Bit16u;
typedef   signed __int16     T_Bit16s, *PT_Bit16s;
typedef unsigned __int32     T_Bit32u, *PT_Bit32u;
typedef   signed __int32     T_Bit32s, *PT_Bit32s;
typedef unsigned __int64     T_Bit64u, *PT_Bit64u;
typedef   signed __int64     T_Bit64s, *PT_Bit64s;

typedef          int         T_bool,   *PT_bool;
typedef          void        T_void,   *PT_void;
typedef    const void                  *PCT_void;
typedef          char        T_char,   *PT_char;
typedef          PT_char     PT_str;
typedef    const char                  *PCT_char;
typedef          PCT_char    PCT_str;
typedef          wchar_t     T_wchar,  *PT_wchar;
typedef          PT_wchar    PT_wstr;
typedef    const wchar_t               *PCT_wchar;
typedef          PCT_wchar   PCT_wstr;
typedef unsigned char        T_byte,   *PT_byte;
typedef const unsigned char            *PCT_byte;

typedef          T_Bit16u    T_Word,   *PT_Word;
typedef          T_Bit32u    T_Dword,  *PT_Dword;
typedef          T_Bit64u    T_Qword,  *PT_Qword;

//
// Define a status signal.
//
typedef          T_Bit32s    T_status, *PT_status;

#define T_IsSuccess(_S) ((_S) >= 0)

#define T_STATUS_SUCCESS                    ((T_status)0)
#define T_STATUS_YES                        ((T_status)1)
#define T_STATUS_PENDING                    ((T_status)2)

#define T_STATUS_NO                         ((T_status)-1)
#define T_STATUS_UNKOWN_ERROR               ((T_status)-2)
#define T_STATUS_EXCLUDE                    ((T_status)-3)
#define T_STATUS_NOT_FOUND                  ((T_status)-4)
#define T_STATUS_ALREADY_EXISTS             ((T_status)-5)
#define T_STATUS_LOW_PRIVILEGE              ((T_status)-6)
#define T_STATUS_ACCESS_DENIED              ((T_status)-7)
#define T_STATUS_INSUFFICIENT_RESOURCES     ((T_status)-8)
#define T_STATUS_BUFFER_TOO_SMALL           ((T_status)-9)
#define T_STATUS_INVALID_PARAMETER          ((T_status)-10)
#define T_STATUS_DATA_ERROR                 ((T_status)-11)

#if defined(_WIN64)
    typedef T_Bit64u T_address, *PT_address;
#else
    typedef T_Bit32u T_address, *PT_address;
#endif


#define T_MAX_address ( (T_address) -1                    )
#define T_MAX_BIT64U  ( (T_Bit64u) -1                     )
#define T_MIN_BIT64U  ( 0                                 )
#define T_MAX_BIT64S  ( ((T_Bit64u) -1) >> 1              )
#define T_MIN_BIT64S  ( (T_Bit64s)-(((T_Bit64u) -1) >> 1) )
#define T_MAX_BIT32U  ( (T_Bit32u) -1                     )
#define T_MIN_BIT32U  ( 0                                 )
#define T_MAX_BIT32S  ( ((T_Bit32u) -1) >> 1              )
#define T_MIN_BIT32S  ( (T_Bit32s)-(((T_Bit32u) -1) >> 1) )
#define T_MAX_BIT16U  ( (T_Bit16u) -1                     )
#define T_MIN_BIT16U  ( 0                                 )
#define T_MAX_BIT16S  ( ((T_Bit16u) -1) >> 1              )
#define T_MIN_BIT16S  ( (T_Bit16s)-(((T_Bit16u) -1) >> 1) )
#define T_MAX_BIT8U   ( (T_Bit8u) -1                      )
#define T_MIN_BIT8U   ( 0                                 )
#define T_MAX_BIT8S   ( ((T_Bit8u) -1) >> 1               )
#define T_MIN_BIT8S   ( (T_Bit8s)-(((T_Bit8u) -1) >> 1)   )
