#ifndef NET_INC_H
#define NET_INC_H

#include <stdbool.h>
#include "phy_def.h"
#include "common.h"

//mes type
typedef enum mestype{
	STATUS=1,
	DETECT,
	MESS,
	CTRLAGT,
	EXECUT,
	OPTIM,
	HISTORY,
	MIX,
	HEARTBEAT,
}mestype;

//status
typedef enum messta{
	ALLSTAT=1,
	GETASTA,
}messta;

#define MDE_ITEMS \
    X(ENVCK,           0)  \
    X(TMA,             1)  \
    X(NOC,             2)  \
    X(DDR,             3)  \
    X(C2C,             4)  \
    X(PCIE,            5)  \
    X(TOPDOWN,         6)  \
    X(TOPDOWNENVCK,   61)  \
    X(TOPDOWNENSET,   62)  \
    X(TOPDOWNALL,     63)  \
    X(HITSYSENVCK,     7)  \
    X(HITAPIENVCK,    71)  \
    X(ACCMEMSYS,      72)  \
    X(ACCMEMAPI,      73)  \
    X(IOSYS,          74)  \
    X(IOAPI,          75)  \
    X(FS,              8)  \
    X(FSCOMCFG,       81)  \
    X(FSCOMBACK,      82)  \
    X(FSCOMPILE,      83)  \
    X(NUMA,            9)  \
    X(NUMACOMCFG,     91)  \
    X(NUMACOMBACK,    92)  \
    X(NUMACOMPILE,    93)  \
    X(NUMAANA,        94)  \
    X(NUMALAUNCH,     95)  \
    X(NUMAMEMMIG,     96)  \
    X(NUMATHREADMIG,  97)  \
    X(ABINDADD,       98)  \
    X(ABINDLIST,      99)  \
    X(ABINDDEL,      100)  \
    X(ABINDSTA,      101)  \
    X(ABINDSTP,      102)  \
    X(NUMAENVCHECK,  103)  \
    X(DATOP,          10)  \
    X(ENV_CHECK_DATOP,11)  \
    X(ENV,            12)  \
    X(ENVRT,          13)  \
    X(ENVSTP,         14)  \
    X(RMTSAMP,        20)  \
    X(FINISH,         25)

#define X(name, val) name = (val),
typedef enum mesdet { MDE_ITEMS } mesdet;
#undef X

#define X(name, val) [val] = #name,
static const char* const _mde_str_tbl[] = { MDE_ITEMS };
#undef X

#define MDE2STR(v) \
    (((unsigned)(v) < sizeof(_mde_str_tbl)/sizeof(*_mde_str_tbl) && _mde_str_tbl[v]) \
        ? _mde_str_tbl[v] : "UNKNOWN")


//mess
typedef enum mesmes{
	COMM = 1,
	WARNING = 2,
	ERROR = 3,
}mesmes;

//ctrl agent
typedef enum mesctl{
	INSERT=1,
	INSTALL=2,
	UINSTAL=3,
	DELETE=4
}mesctl;

typedef enum mesexe{
	PERFEP=1,
	DATOPEP,
	FILBRSER,
	FBROW,
	RMTEXEC,
	RMTEXIT,
	RMTENV,
	RMTENVEXIT,
	RMTNUMA,
	RMTNUMAEXIT,
	BLKINST,
	StraceINST,
	IORTEXEC,
	IORTEXIT,
	SYSHITRTEXEC,
	SYSMISSRTEXEC,
	APIHITRTEXEC,
	APIMISSRTEXEC,
	MEMACCRTEXIT,
}mesexe;

typedef enum mesopt{
	DEPLOY=1,
	PREPRO,
	RUN,
	RESULT,
}mesopt;


#define HIS_ITEMS \
    	H(HISADD,   0)  \
	H(HISDEL,   1)  \
	H(HISMOD,   2)  \
	H(HISSEL,   3)  \

#define H(name, val) name = (val),
typedef enum meshis { HIS_ITEMS } meshis;
#undef H

#define H(name, val) [val] = #name,
static const char* const _his_str_tbl[] = { HIS_ITEMS };
#undef H

#define HIS2STR(v) \
    (((unsigned)(v) < sizeof(_his_str_tbl)/sizeof(*_his_str_tbl) && _his_str_tbl[v]) \
        ? _his_str_tbl[v] : "UNKNOWN")

//typedef unsigned int messty;

typedef enum mesmix{
    MIXALL=0,
	MIXHDW,
	MIXDRI,
	MIXSOF,
	MIXHIS,
	MIXCON,
	MIXLOD,
	MIXERR,
}mesmix;

typedef struct mesma{
	mestype matp;
	union{
//		messty  stp;
		messta  mst;
		mesdet  mde;
		mesmes  mme;
		mesctl  mct;
		mesexe  mex;
		mesopt	mop;
		meshis  mhi;
		mesmix  mmi;
	};
}mesma;
#if 0
#define MSG_MAKE(main, sub, subsub, subsubsub) \
    (uint32_t)(                          \
        (((uint32_t)(main)      &0xFF) << 24) | \
        (((uint32_t)(sub)       &0xFF) << 16) | \
        (((uint32_t)(subsub)    &0xFF) <<  8) | \
        (((uint32_t)(subsubsub) &0xFF)      )   \
    )
#define MSG_MAIN_TYPE(msg)      ((uint8_t)(((msg) >> 24) & 0xFF))
#define MSG_SUB_TYPE(msg)       ((uint8_t)(((msg) >> 16) & 0xFF))
#define MSG_SUBSUB_TYPE(msg)    ((uint8_t)(((msg) >>  8) & 0xFF))
#define MSG_SUBSUBSUB_TYPE(msg) ((uint8_t)(((msg)      ) & 0xFF))
typedef enum {
    CONTROL   = 1,
    STATUS    = 2,
	TOPDOWN   = 3,
	ACCMEM 	  = 4,
	IO        = 5,
	FS		  = 6,
	NUMA	  = 7,
	ABIND	  = 8,
	DATOP	  = 9,
	RMTSAMP   = 10,
    EXEC      = 11,
    OPTIM     = 12,
	RMTSAMP   = 13
} TypI_t;
typedef enum {
    CON_INSERT    = 1,
	CON_INSTALL   = 2,
	CON_UNINSTALL = 3,
	CON_DELETE    = 4
} Con2_t;
typedef enum {
    STA_ALL       = 1,
    STA_GET       = 2
} Sta2_t;
typedef enum{
	TOP_ALL	= 1,
	TOP_    = 2
} Top2_t;
typedef enum {
    DET_ENV       = 1,
    DET_TMA       = 2,
    DET_NOC       = 3,
    DET_DDR       = 4,
    DET_PCIe      = 5,
    DET_FINISH    = 0xFF  /* ʾ����������� */
} Det2_t;
typedef enum {
    DENV_CHECK    = 1,
    DENV_RT       = 2,
    DENV_STOP     = 3
} DEnv3_t;
typedef enum {
    DECHK_PRE   = 1,
    DECHK_POST  = 2
} DEChk4_t;
typedef struct {
    uint32_t  type;        /* 32 λ����ֶ� */
    uint32_t  length;      /* payload ���� */
} msgh_t;
static inline void example_usage(void) {
    uint32_t msg = MSG_MAKE(
        MT_DETECT,          /* ������ */
        DET_ENV,            /* ������ */
        DENV_CHECK,         /* �������� */
        DENVCHK_POST        /* �������� */
    );
    uint8_t m  = MSG_MAIN_TYPE(msg);       /* =MT_DETECT */
    uint8_t s  = MSG_SUB_TYPE(msg);        /* =DET_ENV */
    uint8_t ss = MSG_SUBSUB_TYPE(msg);     /* =DENV_CHECK */
    uint8_t sss= MSG_SUBSUBSUB_TYPE(msg);  /* =DENVCHK_POST */
    (void)m;(void)s;(void)ss;(void)sss;
}
#endif

typedef struct trandst{
	int affi;
	char sender[20];
	un_int64_t timestamp;
	char date[32];
	char receiver[20];
	char proxy[20];
	uint64_t identifier;
	char mes[1280];
	char skey[20];
	uint32_t eofflag;
}trandst;

typedef struct transfer{
	mesma mma;
	trandst td;
}transfer;

typedef struct ltrandst{
	int affi;
	size_t dln;
	char sender[20];
	uint64_t timestamp;
	char date[32];
	char receiver[20];
	char proxy[20];
	uint64_t identifier;
	char mes[0];
}ltrandst;

typedef struct ltransfer{
	mesma mma;
	ltrandst td;
}ltransfer;


typedef struct msm{
	mestype matp;
	union{
		messta  mst;
		mesdet  mde;
		mesmes  mme;
		mesctl  mct;
		mesexe  mex;
		mesopt	mop;
		meshis  mhi;
		mesmix  mmi;
	};
}msm;

#if 0
typedef struct pst{
	size 	dln;
	ui64	ide;
	char 	sdr[20];
	char 	rcr[20];
	char 	tim[32];
	char 	dat[0];
} pst;
#endif

typedef struct mtd{
	ucha 	mty;
	ucha 	sty;
	ucha 	gty;
}mtd;

typedef struct spmd{
	mtd  mde;
	ui64 ide;
	char sdr[20];
	char rcr[20];
	char tim[32];
}spmd;

typedef struct ntsp{
	char des[m_nspl];
	spmd mdt;
	size dln;
	char dat[0];
} ntsp;

struct messagelist {
	void* data;
	ssize_t  dtlen;
	struct transfer transt;
    struct messagelist *n_next;
};

char* mde2str(mesdet mde);
#endif
