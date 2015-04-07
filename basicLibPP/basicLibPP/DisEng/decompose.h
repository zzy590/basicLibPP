
#pragma once

typedef enum _DisEng_InstructOpcodeClass
{
    I_INVALID = 0,
    I_ERROR,
    I_AAA,
    I_AAD,
    I_AAM,
    I_AAS,
    I_ADC,
    I_ADCX,
    I_ADD,
    I_ADDPD,
    I_ADDPS,
    I_ADDSD,
    I_ADDSS,
    I_ADDSUBPD,
    I_ADDSUBPS,
    I_ADOX,
    I_AESDEC,
    I_AESDECLAST,
    I_AESENC,
    I_AESENCLAST,
    I_AESIMC,
    I_AESKEYGENASSIST,
    I_AND,
    I_ANDN,
    I_ANDNPD,
    I_ANDNPS,
    I_ANDPD,
    I_ANDPS,
    I_ARPL,
    I_ASIZE,
    I_BEXTR,
    I_BLCFILL,
    I_BLCI,
    I_BLCIC,
    I_BLCMSK,
    I_BLCS,
    I_BLENDPD,
    I_BLENDPS,
    I_BLENDVPD,
    I_BLENDVPS,
    I_BLSFILL,
    I_BLSI,
    I_BLSIC,
    I_BLSMSK,
    I_BLSR,
    I_BOUND,
    I_BSF,
    I_BSR,
    I_BSWAP,
    I_BT,
    I_BTC,
    I_BTR,
    I_BTS,
    I_BZHI,
    I_CALL,
    I_CALLF,
    I_CBW,
    I_CDQ,
    I_CDQE,
    I_CLAC,
    I_CLC,
    I_CLD,
    I_CLFLUSH,
    I_CLGI,
    I_CLI,
    I_CLTS,
    I_CMC,
    I_CMOVB,
    I_CMOVBE,
    I_CMOVL,
    I_CMOVLE,
    I_CMOVNB,
    I_CMOVNBE,
    I_CMOVNL,
    I_CMOVNLE,
    I_CMOVNO,
    I_CMOVNP,
    I_CMOVNS,
    I_CMOVNZ,
    I_CMOVO,
    I_CMOVP,
    I_CMOVS,
    I_CMOVZ,
    I_CMP,
    I_CMPPD,
    I_CMPPS,
    I_CMPSB,
    I_CMPSD,
    I_CMPSQ,
    I_CMPSS,
    I_CMPSW,
    I_CMPXCHG,
    I_CMPXCHG16B,
    I_CMPXCHG8B,
    I_COMISD,
    I_COMISS,
    I_CPUID,
    I_CQO,
    I_CRC32,
    I_CS,
    I_CVTDQ2PD,
    I_CVTDQ2PS,
    I_CVTPD2DQ,
    I_CVTPD2PI,
    I_CVTPD2PS,
    I_CVTPI2PD,
    I_CVTPI2PS,
    I_CVTPS2DQ,
    I_CVTPS2PD,
    I_CVTPS2PI,
    I_CVTSD2SI,
    I_CVTSD2SS,
    I_CVTSI2SD,
    I_CVTSI2SS,
    I_CVTSS2SD,
    I_CVTSS2SI,
    I_CVTTPD2DQ,
    I_CVTTPD2PI,
    I_CVTTPS2DQ,
    I_CVTTPS2PI,
    I_CVTTSD2SI,
    I_CVTTSS2SI,
    I_CWD,
    I_CWDE,
    I_DAA,
    I_DAS,
    I_DEC,
    I_DIV,
    I_DIVPD,
    I_DIVPS,
    I_DIVSD,
    I_DIVSS,
    I_DPPD,
    I_DPPS,
    I_DS,
    I_EMMS,
    I_ENTER,
    I_ES,
    I_EXTRACTPS,
    I_EXTRQ,
    I_F2XM1,
    I_FABS,
    I_FADD,
    I_FADDP,
    I_FBLD,
    I_FBSTP,
    I_FCHS,
    I_FCMOVB,
    I_FCMOVBE,
    I_FCMOVE,
    I_FCMOVNB,
    I_FCMOVNBE,
    I_FCMOVNE,
    I_FCMOVNU,
    I_FCMOVU,
    I_FCOM,
    I_FCOMI,
    I_FCOMIP,
    I_FCOMP,
    I_FCOMPP,
    I_FCOS,
    I_FDECSTP,
    I_FDISI, // (287 LEGACY)
    I_FDIV,
    I_FDIVP,
    I_FDIVR,
    I_FDIVRP,
    I_FEMMS,
    I_FENI, // (287 LEGACY)
    I_FFREE,
    I_FFREEP,
    I_FIADD,
    I_FICOM,
    I_FICOMP,
    I_FIDIV,
    I_FIDIVR,
    I_FILD,
    I_FIMUL,
    I_FINCSTP,
    I_FIST,
    I_FISTP,
    I_FISTTP,
    I_FISUB,
    I_FISUBR,
    I_FLD,
    I_FLD1,
    I_FLDCW,
    I_FLDENV,
    I_FLDL2E,
    I_FLDL2T,
    I_FLDLG2,
    I_FLDLN2,
    I_FLDPI,
    I_FLDZ,
    I_FMUL,
    I_FMULP,
    I_FNCLEX,
    I_FNINIT,
    I_FNOP,
    I_FNSAVE,
    I_FNSTCW,
    I_FNSTENV,
    I_FNSTSW,
    I_FPATAN,
    I_FPREM,
    I_FPREM1,
    I_FPTAN,
    I_FRCZPD,
    I_FRCZPS,
    I_FRCZSD,
    I_FRCZSS,
    I_FRNDINT,
    I_FRSTOR,
    I_FS,
    I_FSCALE,
    I_FSETPM, // (287 LEGACY)
    I_FSIN,
    I_FSINCOS,
    I_FSQRT,
    I_FST,
    I_FSTP,
    I_FSUB,
    I_FSUBP,
    I_FSUBR,
    I_FSUBRP,
    I_FTST,
    I_FUCOM,
    I_FUCOMI,
    I_FUCOMIP,
    I_FUCOMP,
    I_FUCOMPP,
    I_FWAIT,
    I_FXAM,
    I_FXCH,
    I_FXRSTOR,
    I_FXSAVE,
    I_FXTRACT,
    I_FYL2X,
    I_FYL2XP1,
    I_GETSEC,
    I_GS,
    I_HADDPD,
    I_HADDPS,
    I_HLT,
    I_HSUBPD,
    I_HSUBPS,
    I_IDIV,
    I_IMUL,
    I_IN,
    I_INC,
    I_INSB,
    I_INSD,
    I_INSERTPS,
    I_INSERTQ,
    I_INSW,
    I_INT,
    I_INT1,
    I_INT3,
    I_INTO,
    I_INVD,
    I_INVEPT,
    I_INVLPG,
    I_INVLPGA,
    I_INVPCID,
    I_INVVPID,
    I_IRET,
    I_JB,
    I_JBE,
    I_JCXZ,
    I_JECXZ,
    I_JL,
    I_JLE,
    I_JMP,
    I_JMPF,
    I_JNB,
    I_JNBE,
    I_JNL,
    I_JNLE,
    I_JNO,
    I_JNP,
    I_JNS,
    I_JNZ,
    I_JO,
    I_JP,
    I_JRCXZ,
    I_JS,
    I_JZ,
    I_LAHF,
    I_LAR,
    I_LDDQU,
    I_LDMXCSR,
    I_LDS,
    I_LEA,
    I_LEAVE,
    I_LES,
    I_LFENCE,
    I_LFS,
    I_LGDT,
    I_LGS,
    I_LIDT,
    I_LLDT,
    I_LMSW,
    I_LOCK,
    I_LODSB,
    I_LODSD,
    I_LODSQ,
    I_LODSW,
    I_LOOP,
    I_LOOPE,
    I_LOOPNE,
    I_LSL,
    I_LSS,
    I_LTR,
    I_LZCNT,
    I_MASKMOVDQU,
    I_MASKMOVQ,
    I_MAXPD,
    I_MAXPS,
    I_MAXSD,
    I_MAXSS,
    I_MFENCE,
    I_MINPD,
    I_MINPS,
    I_MINSD,
    I_MINSS,
    I_MONITOR,
    I_MOV,
    I_MOVAPD,
    I_MOVAPS,
    I_MOVBE,
    I_MOVD,
    I_MOVDDUP,
    I_MOVDQ2Q,
    I_MOVDQA,
    I_MOVDQU,
    I_MOVHLPD,
    I_MOVHLPS,
    I_MOVHPD,
    I_MOVHPS,
    I_MOVLHPD,
    I_MOVLHPS,
    I_MOVLPD,
    I_MOVLPS,
    I_MOVMSKPD,
    I_MOVMSKPS,
    I_MOVNTDQ,
    I_MOVNTDQA,
    I_MOVNTI,
    I_MOVNTPD,
    I_MOVNTPS,
    I_MOVNTQ,
    I_MOVNTSD,
    I_MOVNTSS,
    I_MOVQ,
    I_MOVQ2DQ,
    I_MOVSB,
    I_MOVSD,
    I_MOVSHDUP,
    I_MOVSLDUP,
    I_MOVSQ,
    I_MOVSS,
    I_MOVSW,
    I_MOVSX,
    I_MOVSXD,
    I_MOVUPD,
    I_MOVUPS,
    I_MOVZX,
    I_MPSADBW,
    I_MUL,
    I_MULPD,
    I_MULPS,
    I_MULSD,
    I_MULSS,
    I_MULTIBYTE_NOP,
    I_MULX,
    I_MWAIT,
    I_NEG,
    I_NOP,
    I_NOT,
    I_OR,
    I_ORPD,
    I_ORPS,
    I_OSIZE,
    I_OUT,
    I_OUTSB,
    I_OUTSD,
    I_OUTSW,
    I_PABSB,
    I_PABSD,
    I_PABSW,
    I_PACKSSDW,
    I_PACKSSWB,
    I_PACKUSDW,
    I_PACKUSWB,
    I_PADDB,
    I_PADDD,
    I_PADDQ,
    I_PADDSB,
    I_PADDSW,
    I_PADDUSB,
    I_PADDUSW,
    I_PADDW,
    I_PALIGNR,
    I_PAND,
    I_PANDN,
    I_PAUSE,
    I_PAVGB,
    I_PAVGW,
    I_PBLENDVB,
    I_PBLENDW,
    I_PCLMULQDQ,
    I_PCMPEQB,
    I_PCMPEQD,
    I_PCMPEQQ,
    I_PCMPEQW,
    I_PCMPESTRI,
    I_PCMPESTRM,
    I_PCMPGTB,
    I_PCMPGTD,
    I_PCMPGTQ,
    I_PCMPGTW,
    I_PCMPISTRI,
    I_PCMPISTRM,
    I_PDEP,
    I_PEXT,
    I_PEXTRB,
    I_PEXTRD,
    I_PEXTRQ,
    I_PEXTRW,
    I_PF2ID,
    I_PF2IW,
    I_PFACC,
    I_PFADD,
    I_PFCMPEQ,
    I_PFCMPGE,
    I_PFCMPGT,
    I_PFMAX,
    I_PFMIN,
    I_PFMUL,
    I_PFNACC,
    I_PFPNACC,
    I_PFRCP,
    I_PFRCPIT1,
    I_PFRCPIT2,
    I_PFRSQIT1,
    I_PFRSQRT,
    I_PFSUB,
    I_PFSUBR,
    I_PHADDD,
    I_PHADDSW,
    I_PHADDW,
    I_PHMINPOSUW,
    I_PHSUBD,
    I_PHSUBSW,
    I_PHSUBW,
    I_PI2FD,
    I_PI2FW,
    I_PINSRB,
    I_PINSRD,
    I_PINSRQ,
    I_PINSRW,
    I_PMADDUBSW,
    I_PMADDWD,
    I_PMAXSB,
    I_PMAXSD,
    I_PMAXSW,
    I_PMAXUB,
    I_PMAXUD,
    I_PMAXUW,
    I_PMINSB,
    I_PMINSD,
    I_PMINSW,
    I_PMINUB,
    I_PMINUD,
    I_PMINUW,
    I_PMOVMSKB,
    I_PMOVSXBD,
    I_PMOVSXBQ,
    I_PMOVSXBW,
    I_PMOVSXDQ,
    I_PMOVSXWD,
    I_PMOVSXWQ,
    I_PMOVZXBD,
    I_PMOVZXBQ,
    I_PMOVZXBW,
    I_PMOVZXDQ,
    I_PMOVZXWD,
    I_PMOVZXWQ,
    I_PMULDQ,
    I_PMULHRSW,
    I_PMULHRW,
    I_PMULHUW,
    I_PMULHW,
    I_PMULLD,
    I_PMULLW,
    I_PMULUDQ,
    I_POP,
    I_POPA,
    I_POPCNT,
    I_POPF,
    I_POR,
    I_PREFETCHNTA,
    I_PREFETCHT0,
    I_PREFETCHT1,
    I_PREFETCHT2,
    I_PREFETCHW,
    I_PREFETCH_HINT,
    I_PSADBW,
    I_PSHUFB,
    I_PSHUFD,
    I_PSHUFHW,
    I_PSHUFLW,
    I_PSHUFW,
    I_PSIGNB,
    I_PSIGND,
    I_PSIGNW,
    I_PSLLD,
    I_PSLLDQ,
    I_PSLLQ,
    I_PSLLW,
    I_PSRAD,
    I_PSRAW,
    I_PSRLD,
    I_PSRLDQ,
    I_PSRLQ,
    I_PSRLW,
    I_PSUBB,
    I_PSUBD,
    I_PSUBQ,
    I_PSUBSB,
    I_PSUBSW,
    I_PSUBUSB,
    I_PSUBUSW,
    I_PSUBW,
    I_PSWAPD,
    I_PTEST,
    I_PUNPCKHBW,
    I_PUNPCKHDQ,
    I_PUNPCKHQDQ,
    I_PUNPCKHWD,
    I_PUNPCKLBW,
    I_PUNPCKLDQ,
    I_PUNPCKLQDQ,
    I_PUNPCKLWD,
    I_PUSH,
    I_PUSHA,
    I_PUSHF,
    I_PXOR,
    I_RCL,
    I_RCPPS,
    I_RCPSS,
    I_RCR,
    I_RDFSBASE,
    I_RDGSBASE,
    I_RDMSR,
    I_RDPMC,
    I_RDRAND,
    I_RDSEED,
    I_RDTSC,
    I_RDTSCP,
    I_REP,
    I_REPNE,
    I_RET,
    I_RETF,
    I_REX,
    I_ROL,
    I_ROR,
    I_RORX,
    I_ROUNDPD,
    I_ROUNDPS,
    I_ROUNDSD,
    I_ROUNDSS,
    I_RSM,
    I_RSQRTPS,
    I_RSQRTSS,
    I_SAHF,
    I_SALC,
    I_SAR,
    I_SARX,
    I_SBB,
    I_SCASB,
    I_SCASD,
    I_SCASQ,
    I_SCASW,
    I_SETB,
    I_SETBE,
    I_SETL,
    I_SETLE,
    I_SETNB,
    I_SETNBE,
    I_SETNL,
    I_SETNLE,
    I_SETNO,
    I_SETNP,
    I_SETNS,
    I_SETNZ,
    I_SETO,
    I_SETP,
    I_SETS,
    I_SETZ,
    I_SFENCE,
    I_SGDT,
    I_SHA1MSG1,
    I_SHA1MSG2,
    I_SHA1NEXTE,
    I_SHA1RNDS4,
    I_SHA256MSG1,
    I_SHA256MSG2,
    I_SHA256RNDS2,
    I_SHL,
    I_SHLD,
    I_SHLX,
    I_SHR,
    I_SHRD,
    I_SHRX,
    I_SHUFPD,
    I_SHUFPS,
    I_SIDT,
    I_SKINIT,
    I_SLDT,
    I_SMSW,
    I_SQRTPD,
    I_SQRTPS,
    I_SQRTSD,
    I_SQRTSS,
    I_SS,
    I_STAC,
    I_STC,
    I_STD,
    I_STGI,
    I_STI,
    I_STMXCSR,
    I_STOSB,
    I_STOSD,
    I_STOSQ,
    I_STOSW,
    I_STR,
    I_SUB,
    I_SUBPD,
    I_SUBPS,
    I_SUBSD,
    I_SUBSS,
    I_SWAPGS,
    I_SYSCALL,
    I_SYSENTER,
    I_SYSEXIT,
    I_SYSRET,
    I_T1MSKC,
    I_TEST,
    I_TZCNT,
    I_TZMSK,
    I_UCOMISD,
    I_UCOMISS,
    I_UD2A,
    I_UD2B,
    I_UNPCKHPD,
    I_UNPCKHPS,
    I_UNPCKLPD,
    I_UNPCKLPS,
    I_VADDPD,
    I_VADDPS,
    I_VADDSD,
    I_VADDSS,
    I_VADDSUBPD,
    I_VADDSUBPS,
    I_VAESDEC,
    I_VAESDECLAST,
    I_VAESENC,
    I_VAESENCLAST,
    I_VAESIMC,
    I_VAESKEYGENASSIST,
    I_VANDNPD,
    I_VANDNPS,
    I_VANDPD,
    I_VANDPS,
    I_VBLENDPD,
    I_VBLENDPS,
    I_VBLENDVPD,
    I_VBLENDVPS,
    I_VBROADCASTF128,
    I_VBROADCASTI128,
    I_VBROADCASTSD,
    I_VBROADCASTSS,
    I_VCMPPD,
    I_VCMPPS,
    I_VCMPSD,
    I_VCMPSS,
    I_VCOMISD,
    I_VCOMISS,
    I_VCVTDQ2PD,
    I_VCVTDQ2PS,
    I_VCVTPD2DQ,
    I_VCVTPD2PS,
    I_VCVTPH2PS,
    I_VCVTPS2DQ,
    I_VCVTPS2PD,
    I_VCVTPS2PH,
    I_VCVTSD2SI,
    I_VCVTSD2SS,
    I_VCVTSI2SD,
    I_VCVTSI2SS,
    I_VCVTSS2SD,
    I_VCVTSS2SI,
    I_VCVTTPD2DQ,
    I_VCVTTPS2DQ,
    I_VCVTTSD2SI,
    I_VCVTTSS2SI,
    I_VDIVPD,
    I_VDIVPS,
    I_VDIVSD,
    I_VDIVSS,
    I_VDPPD,
    I_VDPPS,
    I_VERR,
    I_VERW,
    I_VEXTRACTF128,
    I_VEXTRACTI128,
    I_VEXTRACTPS,
    I_VFMADD132PD,
    I_VFMADD132PS,
    I_VFMADD132SD,
    I_VFMADD132SS,
    I_VFMADD213PD,
    I_VFMADD213PS,
    I_VFMADD213SD,
    I_VFMADD213SS,
    I_VFMADD231PD,
    I_VFMADD231PS,
    I_VFMADD231SD,
    I_VFMADD231SS,
    I_VFMADDPD,
    I_VFMADDPS,
    I_VFMADDSD,
    I_VFMADDSS,
    I_VFMADDSUB132PD,
    I_VFMADDSUB132PS,
    I_VFMADDSUB213PD,
    I_VFMADDSUB213PS,
    I_VFMADDSUB231PD,
    I_VFMADDSUB231PS,
    I_VFMADDSUBPD,
    I_VFMADDSUBPS,
    I_VFMSUB132PD,
    I_VFMSUB132PS,
    I_VFMSUB132SD,
    I_VFMSUB132SS,
    I_VFMSUB213PD,
    I_VFMSUB213PS,
    I_VFMSUB213SD,
    I_VFMSUB213SS,
    I_VFMSUB231PD,
    I_VFMSUB231PS,
    I_VFMSUB231SD,
    I_VFMSUB231SS,
    I_VFMSUBADD132PD,
    I_VFMSUBADD132PS,
    I_VFMSUBADD213PD,
    I_VFMSUBADD213PS,
    I_VFMSUBADD231PD,
    I_VFMSUBADD231PS,
    I_VFMSUBADDPD,
    I_VFMSUBADDPS,
    I_VFMSUBPD,
    I_VFMSUBPS,
    I_VFMSUBSD,
    I_VFMSUBSS,
    I_VFNMADD132PD,
    I_VFNMADD132PS,
    I_VFNMADD132SD,
    I_VFNMADD132SS,
    I_VFNMADD213PD,
    I_VFNMADD213PS,
    I_VFNMADD213SD,
    I_VFNMADD213SS,
    I_VFNMADD231PD,
    I_VFNMADD231PS,
    I_VFNMADD231SD,
    I_VFNMADD231SS,
    I_VFNMADDPD,
    I_VFNMADDPS,
    I_VFNMADDSD,
    I_VFNMADDSS,
    I_VFNMSUB132PD,
    I_VFNMSUB132PS,
    I_VFNMSUB132SD,
    I_VFNMSUB132SS,
    I_VFNMSUB213PD,
    I_VFNMSUB213PS,
    I_VFNMSUB213SD,
    I_VFNMSUB213SS,
    I_VFNMSUB231PD,
    I_VFNMSUB231PS,
    I_VFNMSUB231SD,
    I_VFNMSUB231SS,
    I_VFNMSUBPD,
    I_VFNMSUBPS,
    I_VFNMSUBSD,
    I_VFNMSUBSS,
    I_VGATHERDD,
    I_VGATHERDPD,
    I_VGATHERDPS,
    I_VGATHERDQ,
    I_VGATHERQD,
    I_VGATHERQPD,
    I_VGATHERQPS,
    I_VGATHERQQ,
    I_VHADDPD,
    I_VHADDPS,
    I_VHSUBPD,
    I_VHSUBPS,
    I_VINSERTF128,
    I_VINSERTI128,
    I_VINSERTPS,
    I_VLDDQU,
    I_VLDMXCSR,
    I_VMASKMOVD,
    I_VMASKMOVDQU,
    I_VMASKMOVPD,
    I_VMASKMOVPS,
    I_VMASKMOVQ,
    I_VMAXPD,
    I_VMAXPS,
    I_VMAXSD,
    I_VMAXSS,
    I_VMCALL,
    I_VMCLEAR,
    I_VMFUNC,
    I_VMINPD,
    I_VMINPS,
    I_VMINSD,
    I_VMINSS,
    I_VMLAUNCH,
    I_VMLOAD,
    I_VMMCALL,
    I_VMOVAPD,
    I_VMOVAPS,
    I_VMOVD,
    I_VMOVDDUP,
    I_VMOVDQA,
    I_VMOVDQU,
    I_VMOVHLPD,
    I_VMOVHLPS,
    I_VMOVHPD,
    I_VMOVHPS,
    I_VMOVLHPD,
    I_VMOVLHPS,
    I_VMOVLPD,
    I_VMOVLPS,
    I_VMOVMSKPD,
    I_VMOVMSKPS,
    I_VMOVNTDQ,
    I_VMOVNTDQA,
    I_VMOVNTPD,
    I_VMOVNTPS,
    I_VMOVQ,
    I_VMOVSD,
    I_VMOVSHDUP,
    I_VMOVSLDUP,
    I_VMOVSS,
    I_VMOVUPD,
    I_VMOVUPS,
    I_VMPSADBW,
    I_VMPTRLD,
    I_VMPTRST,
    I_VMREAD,
    I_VMRESUME,
    I_VMRUN,
    I_VMSAVE,
    I_VMULPD,
    I_VMULPS,
    I_VMULSD,
    I_VMULSS,
    I_VMWRITE,
    I_VMXOFF,
    I_VMXON,
    I_VORPD,
    I_VORPS,
    I_VPABSB,
    I_VPABSD,
    I_VPABSW,
    I_VPACKSSDW,
    I_VPACKSSWB,
    I_VPACKUSDW,
    I_VPACKUSWB,
    I_VPADDB,
    I_VPADDD,
    I_VPADDQ,
    I_VPADDSB,
    I_VPADDSW,
    I_VPADDUSB,
    I_VPADDUSW,
    I_VPADDW,
    I_VPALIGNR,
    I_VPAND,
    I_VPANDN,
    I_VPAVGB,
    I_VPAVGW,
    I_VPBLENDD,
    I_VPBLENDVB,
    I_VPBLENDW,
    I_VPBROADCASTB,
    I_VPBROADCASTD,
    I_VPBROADCASTQ,
    I_VPBROADCASTW,
    I_VPCLMULQDQ,
    I_VPCMOV,
    I_VPCMPEQB,
    I_VPCMPEQD,
    I_VPCMPEQQ,
    I_VPCMPEQW,
    I_VPCMPESTRI,
    I_VPCMPESTRM,
    I_VPCMPGTB,
    I_VPCMPGTD,
    I_VPCMPGTQ,
    I_VPCMPGTW,
    I_VPCMPISTRI,
    I_VPCMPISTRM,
    I_VPCOMB,
    I_VPCOMD,
    I_VPCOMQ,
    I_VPCOMUB,
    I_VPCOMUD,
    I_VPCOMUQ,
    I_VPCOMUW,
    I_VPCOMW,
    I_VPERM2F128,
    I_VPERM2I128,
    I_VPERMD,
    I_VPERMILPD,
    I_VPERMILPS,
    I_VPERMPD,
    I_VPERMPS,
    I_VPERMQ,
    I_VPEXTRB,
    I_VPEXTRD,
    I_VPEXTRQ,
    I_VPEXTRW,
    I_VPHADDBD,
    I_VPHADDBQ,
    I_VPHADDBW,
    I_VPHADDD,
    I_VPHADDDQ,
    I_VPHADDSW,
    I_VPHADDUBD,
    I_VPHADDUBQ,
    I_VPHADDUBW,
    I_VPHADDUDQ,
    I_VPHADDUWD,
    I_VPHADDUWQ,
    I_VPHADDW,
    I_VPHADDWD,
    I_VPHADDWQ,
    I_VPHMINPOSUW,
    I_VPHSUBBW,
    I_VPHSUBD,
    I_VPHSUBDQ,
    I_VPHSUBSW,
    I_VPHSUBW,
    I_VPHSUBWD,
    I_VPINSRB,
    I_VPINSRD,
    I_VPINSRQ,
    I_VPINSRW,
    I_VPMACSDD,
    I_VPMACSDQH,
    I_VPMACSDQL,
    I_VPMACSSDD,
    I_VPMACSSDQH,
    I_VPMACSSDQL,
    I_VPMACSSWD,
    I_VPMACSSWW,
    I_VPMACSWD,
    I_VPMACSWW,
    I_VPMADCSSWD,
    I_VPMADCSWD,
    I_VPMADDUBSW,
    I_VPMADDWD,
    I_VPMAXSB,
    I_VPMAXSD,
    I_VPMAXSW,
    I_VPMAXUB,
    I_VPMAXUD,
    I_VPMAXUW,
    I_VPMINSB,
    I_VPMINSD,
    I_VPMINSW,
    I_VPMINUB,
    I_VPMINUD,
    I_VPMINUW,
    I_VPMOVMSKB,
    I_VPMOVSXBD,
    I_VPMOVSXBQ,
    I_VPMOVSXBW,
    I_VPMOVSXDQ,
    I_VPMOVSXWD,
    I_VPMOVSXWQ,
    I_VPMOVZXBD,
    I_VPMOVZXBQ,
    I_VPMOVZXBW,
    I_VPMOVZXDQ,
    I_VPMOVZXWD,
    I_VPMOVZXWQ,
    I_VPMULDQ,
    I_VPMULHRSW,
    I_VPMULHUW,
    I_VPMULHW,
    I_VPMULLD,
    I_VPMULLW,
    I_VPMULUDQ,
    I_VPOR,
    I_VPPERM,
    I_VPROTB,
    I_VPROTD,
    I_VPROTQ,
    I_VPROTW,
    I_VPSADBW,
    I_VPSHAB,
    I_VPSHAD,
    I_VPSHAQ,
    I_VPSHAW,
    I_VPSHLB,
    I_VPSHLD,
    I_VPSHLQ,
    I_VPSHLW,
    I_VPSHUFB,
    I_VPSHUFD,
    I_VPSHUFHW,
    I_VPSHUFLW,
    I_VPSIGNB,
    I_VPSIGND,
    I_VPSIGNW,
    I_VPSLLD,
    I_VPSLLDQ,
    I_VPSLLQ,
    I_VPSLLVD,
    I_VPSLLVQ,
    I_VPSLLW,
    I_VPSRAD,
    I_VPSRAVD,
    I_VPSRAW,
    I_VPSRLD,
    I_VPSRLDQ,
    I_VPSRLQ,
    I_VPSRLVD,
    I_VPSRLVQ,
    I_VPSRLW,
    I_VPSUBB,
    I_VPSUBD,
    I_VPSUBQ,
    I_VPSUBSB,
    I_VPSUBSW,
    I_VPSUBUSB,
    I_VPSUBUSW,
    I_VPSUBW,
    I_VPTEST,
    I_VPUNPCKHBW,
    I_VPUNPCKHDQ,
    I_VPUNPCKHQDQ,
    I_VPUNPCKHWD,
    I_VPUNPCKLBW,
    I_VPUNPCKLDQ,
    I_VPUNPCKLQDQ,
    I_VPUNPCKLWD,
    I_VPXOR,
    I_VRCPPS,
    I_VRCPSS,
    I_VROUNDPD,
    I_VROUNDPS,
    I_VROUNDSD,
    I_VROUNDSS,
    I_VRSQRTPS,
    I_VRSQRTSS,
    I_VSHUFPD,
    I_VSHUFPS,
    I_VSQRTPD,
    I_VSQRTPS,
    I_VSQRTSD,
    I_VSQRTSS,
    I_VSTMXCSR,
    I_VSUBPD,
    I_VSUBPS,
    I_VSUBSD,
    I_VSUBSS,
    I_VTESTPD,
    I_VTESTPS,
    I_VUCOMISD,
    I_VUCOMISS,
    I_VUNPCKHPD,
    I_VUNPCKHPS,
    I_VUNPCKLPD,
    I_VUNPCKLPS,
    I_VXORPD,
    I_VXORPS,
    I_VZEROALL,
    I_VZEROUPPER,
    I_WBINVD,
    I_WRFSBASE,
    I_WRGSBASE,
    I_WRMSR,
    I_XADD,
    I_XCHG,
    I_XGETBV,
    I_XLAT,
    I_XOR,
    I_XORPD,
    I_XORPS,
    I_XRSTOR,
    I_XSAVE,
	I_XSAVEC,
    I_XSAVEOPT,
    I_XSETBV,
    //
    // Opcode count.
    //
    I_OPCODE_COUNT
} DisEng_InstructOpcodeClass;

#ifndef FlagOn
    #define FlagOn(_F,_SF) ((_F) & (_SF))
#endif
#ifndef SetFlag
    #define SetFlag(_F,_SF) ((_F) |= (_SF))
#endif
#ifndef ClearFlag
    #define ClearFlag(_F,_SF) ((_F) &= ~(_SF))
#endif

enum {
	IA_TYPE_386 = 0,                 /* 386 or earlier instruction */
	IA_TYPE_X87,                     /* FPU (X87) instruction */
	IA_TYPE_486,                     /* 486 new instruction */
	IA_TYPE_PENTIUM,                 /* Pentium new instruction */
	IA_TYPE_P6,                      /* P6 new instruction */
	IA_TYPE_MMX,                     /* MMX instruction */
	IA_TYPE_3DNOW,                   /* 3DNow! instruction (AMD) */
	IA_TYPE_DEBUG_EXTENSIONS,        /* Debug Extensions support */
	IA_TYPE_VME,                     /* VME support */
	IA_TYPE_PSE,                     /* PSE support */
	IA_TYPE_PAE,                     /* PAE support */
	IA_TYPE_PGE,                     /* Global Pages support */
	IA_TYPE_PSE36,                   /* PSE-36 support */
	IA_TYPE_MTRR,                    /* MTRR support */
	IA_TYPE_PAT,                     /* PAT support */
	IA_TYPE_SYSCALL_SYSRET_LEGACY,   /* SYSCALL/SYSRET in legacy mode (AMD) */
	IA_TYPE_SYSENTER_SYSEXIT,        /* SYSENTER/SYSEXIT instruction */
	IA_TYPE_CLFLUSH,                 /* CLFLUSH instruction */
	IA_TYPE_CLFLUSHOPT,              /* CLFLUSHOPT instruction */
	IA_TYPE_CLWB,                    /* CLWB instruction */
	IA_TYPE_SSE,                     /* SSE  instruction */
	IA_TYPE_SSE2,                    /* SSE2 instruction */
	IA_TYPE_SSE3,                    /* SSE3 instruction */
	IA_TYPE_SSSE3,                   /* SSSE3 instruction */
	IA_TYPE_SSE4_1,                  /* SSE4_1 instruction */
	IA_TYPE_SSE4_2,                  /* SSE4_2 instruction */
	IA_TYPE_POPCNT,                  /* POPCNT instruction */
	IA_TYPE_MONITOR_MWAIT,           /* MONITOR/MWAIT instruction */
	IA_TYPE_VMX,                     /* VMX instruction */
	IA_TYPE_SMX,                     /* SMX instruction */
	IA_TYPE_LONG_MODE,               /* Long Mode (x86-64) support */
	IA_TYPE_LM_LAHF_SAHF,            /* Long Mode LAHF/SAHF instruction */
	IA_TYPE_NX,                      /* No-Execute support */
	IA_TYPE_1G_PAGES,                /* 1Gb pages support */
	IA_TYPE_CMPXCHG16B,              /* CMPXCHG16B instruction */
	IA_TYPE_RDTSCP,                  /* RDTSCP instruction */
	IA_TYPE_FFXSR,                   /* EFER.FFXSR support */
	IA_TYPE_XSAVE,                   /* XSAVE/XRSTOR extensions instruction */
	IA_TYPE_XSAVEOPT,                /* XSAVEOPT instruction */
	IA_TYPE_XSAVEC,                  /* XSAVEC instruction */
	IA_TYPE_XSAVES,                  /* XSAVES instruction */
	IA_TYPE_AES_PCLMULQDQ,           /* AES+PCLMULQDQ instruction */
	IA_TYPE_MOVBE,                   /* MOVBE instruction */
	IA_TYPE_FSGSBASE,                /* FS/GS BASE access instruction */
	IA_TYPE_INVPCID,                 /* INVPCID instruction */
	IA_TYPE_AVX,                     /* AVX instruction */
	IA_TYPE_AVX2,                    /* AVX2 instruction */
	IA_TYPE_AVX_F16C,                /* AVX F16 convert instruction */
	IA_TYPE_AVX_FMA,                 /* AVX FMA instruction */
	IA_TYPE_ALT_MOV_CR8,             /* LOCK CR0 access CR8 (AMD) */
	IA_TYPE_SSE4A,                   /* SSE4A instruction (AMD) */
	IA_TYPE_MISALIGNED_SSE,          /* Misaligned SSE (AMD) */
	IA_TYPE_LZCNT,                   /* LZCNT instruction */
	IA_TYPE_BMI1,                    /* BMI1 instruction */
	IA_TYPE_BMI2,                    /* BMI2 instruction */
	IA_TYPE_FMA4,                    /* FMA4 instruction (AMD) */
	IA_TYPE_XOP,                     /* XOP instruction (AMD) */
	IA_TYPE_TBM,                     /* TBM instruction (AMD) */
	IA_TYPE_SVM,                     /* SVM instruction (AMD) */
	IA_TYPE_RDRAND,                  /* RDRAND instruction */
	IA_TYPE_ADX,                     /* ADCX/ADOX instruction */
	IA_TYPE_SMAP,                    /* SMAP support */
	IA_TYPE_RDSEED,                  /* RDSEED instruction */
	IA_TYPE_SHA,                     /* SHA instruction */
	IA_TYPE_AVX512,                  /* AVX-512 instruction */
	IA_TYPE_AVX512_CD,               /* AVX-512 Conflict Detection instruction */
	IA_TYPE_AVX512_PF,               /* AVX-512 Sparse Prefetch instruction */
	IA_TYPE_AVX512_ER,               /* AVX-512 Exponential/Reciprocal instruction */
	IA_TYPE_AVX512_DQ,               /* AVX-512DQ instruction */
	IA_TYPE_AVX512_BW,               /* AVX-512 Byte/Word instruction */
	IA_TYPE_AVX512_VL,               /* AVX-512 Vector Length extensions */
	IA_TYPE_AVX512_VBMI,             /* AVX-512 Vector Bit Manipulation Instructions */
	IA_TYPE_AVX512_IFMA52,           /* AVX-512 IFMA52 Instructions */
	IA_TYPE_XAPIC,                   /* XAPIC support */
	IA_TYPE_X2APIC,                  /* X2APIC support */
	IA_TYPE_XAPIC_EXT,               /* XAPIC Extensions support */
	IA_TYPE_PCID,                    /* PCID pages support */
	IA_TYPE_SMEP,                    /* SMEP support */
	IA_TYPE_TSC_DEADLINE,            /* TSC-Deadline */
	IA_TYPE_FCS_FDS_DEPRECATION,     /* FCS/FDS Deprecation */
	IA_TYPE_EXTENSION_LAST
};

#define DisEng_PREFIX_LOCK                (0x1)
#define DisEng_SUFFIX_NOT_TAKEN           (0x2)
#define DisEng_SUFFIX_TAKEN               (0x4)
#define DisEng_PREFIX_OPCODE              (0x8)

#define DisEng_ERROR_BAD_VEX_REX_PREFIX   (0x1)
#define DisEng_ERROR_BAD_VEX_SSE_PREFIX   (0x2)
#define DisEng_ERROR_BAD_XOP_REX_PREFIX   (0x4)
#define DisEng_ERROR_BAD_XOP_SSE_PREFIX   (0x8)
#define DisEng_ERROR_UNKNOWN_ATTRIBUTE    (0x10)
#define DisEng_ERROR_BAD_VEX              (0x20)
#define DisEng_ERROR_BAD_EVEX             (0x40)
#define DisEng_ERROR_BAD_XOP              (0x80)

typedef enum _DisEng_NumberSize
{
	NS_None = 0,
	NS_8s,
	NS_8u,
	NS_16s,
	NS_16u,
	NS_32s,
	NS_32u,
	NS_64s,
	NS_64u,
} DisEng_NumberSize;

#define DisEng_IS_NUMBER_SIGNED(_Size) ((_Size)&1)

typedef enum _DisEng_GeneralReg
{
	R_RAX = 0,
	R_RCX,
	R_RDX,
	R_RBX,
	R_RSP,
	R_RBP,
	R_RSI,
	R_RDI,
	R_R8,
	R_R9,
	R_R10,
	R_R11,
	R_R12,
	R_R13,
	R_R14,
	R_R15,
	//
	// Special reg.
	//
	R_RIP,// = 16
} DisEng_GeneralReg;

typedef enum _DisEng_GeneralRegSize
{
	RS_8l = 0,
	RS_8h,
	RS_16,
	RS_32,
	RS_64,
} DisEng_GeneralRegSize;

typedef enum _DisEng_SegmentReg
{
	R_ES = 0,
	R_CS,
	R_SS,
	R_DS,
	R_FS,
	R_GS,
	R_INVALID_SEG1,
	R_INVALID_SEG2
} DisEng_SegmentReg;

typedef enum _DisEng_Index16Reg
{
	R_BX_SI = 0,
	R_BX_DI,
	R_BP_SI,
	R_BP_DI,
	R_SI,
	R_DI,
	R_BP,
	R_BX,
} DisEng_Index16Reg;

typedef enum _DisEng_VectorReg
{
	R_XMM = 0,
	R_YMM,
	R_MM_UNKNOWN,
    R_ZMM,
} DisEng_VectorReg;

#define DisEng_USE_GENERAL_REG           (0x1)
#define DisEng_USE_SEGMENT_REG           (0x2)
#define DisEng_USE_INDEX16_REG           (0x4)
#define DisEng_USE_CONTROL_REG           (0x8)
#define DisEng_USE_DEBUG_REG             (0x10)
#define DisEng_USE_FLOATING_POINT_REG    (0x20)
#define DisEng_USE_MMX_REG               (0x40)
#define DisEng_USE_VECTOR_REG            (0x80)
#define DisEng_USE_BASE_GENERAL_REG      (0x100)

typedef enum _DisEng_PtrSize
{
    PS_None = 0,  /** no size **/
    PS_BytePtr,   /** byte **/
    PS_WordPtr,   /** word **/
    PS_DwordPtr,  /** double word **/
    PS_QwordPtr,  /** quad word **/
    PS_ZwordPtr,  /** double word in 32-bit mode, quad word in 64-bit mode **/
    PS_TbytePtr,  /** 10-byte x87 floating point **/
    PS_DqwordPtr, /** double quad word (XMM) **/
    PS_QqwordPtr, /** quadruple quad word (YMM) **/
} DisEng_PtrSize;

#if defined(_WIN64)
    #include <PshPack8.h>
#else
    #include <PshPack4.h>
#endif

/**
Enum:
cs_selector:imm
GeneralReg
SegmentReg
ControlReg
DebugReg
FloatingPointReg
MMXReg
VectorReg
imm
.+JumpOffset (JumpRealAddr)
ptr SegmentReg:imm
ptr SegmentReg:disp
ptr SegmentReg:[index*scale+disp]
ptr SegmentReg:[index*scale]
ptr SegmentReg:[GeneralReg+disp]
ptr SegmentReg:[GeneralReg]
ptr SegmentReg:[BaseGeneralReg+disp]
ptr SegmentReg:[BaseGeneralReg]
ptr SegmentReg:[BaseGeneralReg+index*scale+disp]
ptr SegmentReg:[BaseGeneralReg+index*scale]
ptr SegmentReg:[BaseGeneralReg+GeneralReg+disp]
ptr SegmentReg:[BaseGeneralReg+GeneralReg]
etc.
Caution: index can be any reg except BaseGeneralReg and SegmentReg
         (eg: GeneralReg Index16Reg VectorReg)
**/

typedef struct _DisEng_Operand
{
    //
    // imm.
    //
    DisEng_NumberSize ImmSize;
    union
    {
        signed __int64 imms;
        unsigned __int64 immu;
    } imm;
    //
    // Reg.
    //
    unsigned __int32 RegType;
    DisEng_GeneralReg BaseGeneralReg;
    DisEng_GeneralRegSize BaseGeneralRegSize;
    DisEng_GeneralReg GeneralReg;
    DisEng_GeneralRegSize GeneralRegSize;
    DisEng_Index16Reg Index16Reg;
    DisEng_SegmentReg SegmentReg;
    unsigned __int32 ControlRegNumber;
    unsigned __int32 DebugRegNumber;
    unsigned __int32 FloatingPointRegNumber;
    unsigned __int32 MMXRegNumber;
    DisEng_VectorReg VectorReg;
    unsigned __int32 VectorRegNumber;
    //
    // Ptr.
    //
    DisEng_PtrSize PtrSize;
    //
    // cs selector.
    //
    unsigned __int32 UseSelector;
    unsigned __int32 cs_selector;
    //
    // Jump.
    //
    unsigned __int32 UseJump;
    signed __int64 JumpOffset;
    unsigned __int64 JumpRealAddr;
    //
    // disp.
    //
    DisEng_NumberSize dispSize;
    union
    {
        signed __int64 disps;
        unsigned __int64 dispu;
    } disp;
    //
    // scale.
    //
    int scale;
    //
    // Error.
    //
    unsigned __int32 Error;
} DisEng_Operand, *PDisEng_Operand;

#define DisEng_MAX_OPERAND (4)

typedef struct _DisEng_DECOMPOSED
{
    unsigned __int32 InstructLength;
	unsigned __int64 OpcodeType;
    DisEng_InstructOpcodeClass Opcode;
    unsigned __int32 PreSuffix;
    DisEng_InstructOpcodeClass PrefixOpcode;
    unsigned __int32 AttirbuteErrorCode;
    unsigned __int32 OperandUsed;
    DisEng_Operand Operand[DisEng_MAX_OPERAND];
} DisEng_DECOMPOSED, *PDisEng_DECOMPOSED;

#include <PopPack.h>

inline void DisEng_DecomposeCleanup(PDisEng_DECOMPOSED pDecomposed)
{
	pDecomposed->InstructLength = 0;
	pDecomposed->OpcodeType = 0;
	pDecomposed->Opcode = I_INVALID;
    pDecomposed->PreSuffix = 0;
	pDecomposed->PrefixOpcode = I_INVALID;
	pDecomposed->AttirbuteErrorCode = 0;
	pDecomposed->OperandUsed = 0;
	for(int i=0;i<DisEng_MAX_OPERAND;i++)
	{
		PDisEng_Operand pOperand = &pDecomposed->Operand[i];
		pOperand->ImmSize = NS_None;
		pOperand->RegType = 0;
		pOperand->PtrSize = PS_None;
		pOperand->UseSelector = 0;
		pOperand->UseJump = 0;
		pOperand->JumpRealAddr = 0;
		pOperand->dispSize = NS_None;
		pOperand->scale = 1;
		pOperand->Error = 0;
	}
}
