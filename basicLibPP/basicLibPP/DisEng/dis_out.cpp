//////////////////////////////////////////////////////////////////////////
//
// zzy disasm engine
//
// author: zzy
//
//////////////////////////////////////////////////////////////////////////


#include "../basic_fun.h"
#include "disasm.h"
#include "dis_out.h"


//////////////////////////////////////////////////////////////////////////


typedef struct _ZZY_DIS_CONTEXT
{
    disassembler *dis;
    bx_bool is_32;
    bx_bool is_64;
} ZZY_DIS_CONTEXT, *PZZY_DIS_CONTEXT;


//////////////////////////////////////////////////////////////////////////


PZZY_DIS_CONTEXT DisEng_AllocateContext()
{
    PZZY_DIS_CONTEXT pTmp;
    pTmp = (PZZY_DIS_CONTEXT)blpp_mem_alloc(sizeof(ZZY_DIS_CONTEXT));
    if (NULL == pTmp)
    {
        return NULL;
    }
	pTmp->dis = new disassembler();
    pTmp->is_32 = 1;
    pTmp->is_64 = 0;
    return pTmp;
}

T_void DisEng_FreeContext(PZZY_DIS_CONTEXT pContext)
{
	delete pContext->dis;
    blpp_mem_free(pContext);
}

T_void DisEng_SetCpuType(PZZY_DIS_CONTEXT pContext,int n)
{
    switch (n)
    {
	case 16:
		pContext->is_32 = 0;
		pContext->is_64 = 0;
		break;
	case 32:
		pContext->is_32 = 1;
		pContext->is_64 = 0;
		break;
	case 64:
		pContext->is_32 = 1;
		pContext->is_64 = 1;
		break;
	default:
		break;
    }
}

int DisEng_Disasm(
    PZZY_DIS_CONTEXT pContext,
    T_Qword base,
    T_Qword ip,
    PCT_void data,
	PT_str strBuffer,
    PDisEng_DECOMPOSED pDecomposed)
{
	pContext->dis->decode(pContext->is_32,pContext->is_64,base,ip,(const Bit8u *)data,strBuffer,pDecomposed);
    return pDecomposed->InstructLength;
}
