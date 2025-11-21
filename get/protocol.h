#ifndef GET_PROTOCOL_H
#define GET_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#define m_nspdes "phy-server"
#define m_nspl 11

typedef uint8_t ucha;
typedef uint64_t ui64;

typedef enum mestype {
    STATUS = 1,
    DETECT,
    MESS,
    CTRLAGT,
    EXECUT,
    OPTIM,
    HISTORY,
    MIX,
    HEARTBEAT,
} mestype;

typedef enum mesmes {
    COMM = 1,
    WARNING,
    ERROR,
} mesmes;

typedef enum mesctl {
    INSERT = 1,
    INSTALL,
    UINSTAL,
    DELETE,
} mesctl;

typedef enum messta {
    ALLSTAT = 1,
    GETASTA,
} messta;

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
static const char *const _mde_str_tbl[] = { MDE_ITEMS };
#undef X

#define MDE2STR(v) \
    (((unsigned)(v) < sizeof(_mde_str_tbl)/sizeof(*_mde_str_tbl) && _mde_str_tbl[v]) \
        ? _mde_str_tbl[v] : "UNKNOWN")

typedef enum mesmix {
    MIXALL = 0,
    MIXHDW,
    MIXDRI,
    MIXSOF,
    MIXHIS,
    MIXCON,
    MIXLOD,
    MIXERR,
} mesmix;

typedef struct mesma {
    mestype matp;
    union {
        messta mst;
        mesdet mde;
        mesmix mmi;
        mesctl mct;
        mesmes mme;
    };
} mesma;

typedef struct mtd {
    ucha mty;
    ucha sty;
    ucha gty;
} mtd;

typedef struct spmd {
    mtd mde;
    ui64 ide;
    char sdr[20];
    char rcr[20];
    char tim[32];
} spmd;

typedef struct ntsp {
    char des[m_nspl];
    spmd mdt;
    size_t dln;
    char dat[0];
} ntsp;

typedef struct trandst {
    int affi;
    char sender[20];
    int64_t timestamp;
    char date[32];
    char receiver[20];
    char proxy[20];
    uint64_t identifier;
    char mes[1280];
    char skey[20];
    uint32_t eofflag;
} trandst;

typedef struct transfer {
    mesma mma;
    trandst td;
} transfer;

#endif // GET_PROTOCOL_H
