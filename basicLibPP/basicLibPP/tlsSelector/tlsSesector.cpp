
#include "../basic_fun.h"

T_Dword SelectTlsSlot()
{
    T_Dword tls;
    PTEB teb;
    PT_void *pSlot;
    tls = TlsAlloc();
    if (TLS_OUT_OF_INDEXES == tls)
    {
        return TLS_OUT_OF_INDEXES;
    }
    teb = NtCurrentTeb();
    if (tls < 64)
    {
        pSlot = &teb->TlsSlots[tls];
    }
    else
    {
        pSlot = &teb->TlsExpansionSlots[tls-64];
    }
    __try
    {
        for (T_Dword i=0;i<5;++i)
        {
            if (!TlsSetValue(tls,(LPVOID)i))
            {
                goto _test_err;
            }
            if (*pSlot != (PT_void)i)
            {
                goto _test_err;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        goto _test_err;
    }
    // OK.
    return tls;
_test_err:
    TlsFree(tls);
    return TLS_OUT_OF_INDEXES;
}

T_void FreeSelectedTls(T_Dword tls)
{
    TlsFree(tls);
}

T_bool IsThreadFlagOn(T_Dword Tls,T_address Flag)
{
    assert(TLS_OUT_OF_INDEXES != Tls);
    PTEB teb = (PTEB)NtCurrentTeb();
    __try
    {
        if (Tls < 64)
        {
            return FlagOn((T_address)teb->TlsSlots[Tls],Flag)?TRUE:FALSE;
        }
        else
        {
            if (teb->TlsExpansionSlots)
            {
                return FlagOn((T_address)teb->TlsExpansionSlots[Tls-64],Flag)?TRUE:FALSE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
    return FALSE;
}

T_bool SetThreadFlag(T_Dword Tls,T_address Flag)
{
    assert(TLS_OUT_OF_INDEXES != Tls);
    PTEB teb = (PTEB)NtCurrentTeb();
    __try
    {
        if (Tls < 64)
        {
            teb->TlsSlots[Tls] = (PT_void)((T_address)teb->TlsSlots[Tls] | Flag);
            return TRUE;
        }
        else
        {
            if (teb->TlsExpansionSlots)
            {
                teb->TlsExpansionSlots[Tls-64] = (PT_void)((T_address)teb->TlsExpansionSlots[Tls-64] | Flag);
                return TRUE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
    return FALSE;
}

T_bool ClearThreadFlag(T_Dword Tls,T_address Flag)
{
    assert(TLS_OUT_OF_INDEXES != Tls);
    PTEB teb = (PTEB)NtCurrentTeb();
    __try
    {
        if (Tls < 64)
        {
            teb->TlsSlots[Tls] = (PT_void)((T_address)teb->TlsSlots[Tls] & (~Flag));
            return TRUE;
        }
        else
        {
            if (teb->TlsExpansionSlots)
            {
                teb->TlsExpansionSlots[Tls-64] = (PT_void)((T_address)teb->TlsExpansionSlots[Tls-64] & (~Flag));
                return TRUE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
    return FALSE;
}

T_bool CheckAndSetThreadFlag(T_Dword Tls,T_address Flag) // If flag is on,return FALSE.
{
    assert(TLS_OUT_OF_INDEXES != Tls);
    PTEB teb = (PTEB)NtCurrentTeb();
    __try
    {
        if (Tls < 64)
        {
            if (FlagOn((T_address)teb->TlsSlots[Tls],Flag))
            {
                return FALSE;
            }
            teb->TlsSlots[Tls] = (PT_void)((T_address)teb->TlsSlots[Tls] | Flag);
            return TRUE;
        }
        else
        {
            if (teb->TlsExpansionSlots)
            {
                if (FlagOn((T_address)teb->TlsExpansionSlots[Tls-64],Flag))
                {
                    return FALSE;
                }
                teb->TlsExpansionSlots[Tls-64] = (PT_void)((T_address)teb->TlsExpansionSlots[Tls-64] | Flag);
                return TRUE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
    return FALSE;
}
