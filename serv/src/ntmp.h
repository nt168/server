#ifndef NTMP_H
#define NTMP_H

#include "hashmap.h"
#include "common.h"
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "phy_def.h"
#include "nttabs.h"

// “预留主键”名称
#define reprimarykey "IP"

typedef struct hml {
    char      *val;
    hmap_t     dat;
    struct hml *next;
} hml;

// 顶层 ntmp 结构
typedef struct ntmp {
    hml *slot;
} ntmp;

// 创建和销毁
ntmp* create_ntmp();
void  destroy_ntmp(ntmp *nmp);


int ins_hash_mk(ntmp* nmp, const char* ip);

int ins_hash_sk(ntmp* nmp, const char* ip, const char* subkey);

int ins_hash_ssv(ntmp* nmp,
                 const char* ip,
                 const char* subkey,
                 const char* ssukey,
                 const char* ssva);

int ins_hash_ssk(ntmp* nmp,
                 const char* ip,
                 const char* subkey,
                 const char* ssukey);

int get_hash_mks(ntmp* nmp, const char* primary, lst** p);

int get_hash_sks(ntmp* nmp, const char* ip, lst** p);

int get_hash_ssks(ntmp* nmp,
                   const char* ip,
                   const char* subkey,
                   lst** p);

int get_hash_ssv(ntmp* nmp,
                 const char* ip,
                 const char* subkey,
                 const char* ssukey,
                 lst** p);

int __ins_hash_ext(ntmp *nmp, ... /* key1, key2, …, keyN, NULL */);
int __get_hash_ext(ntmp *nmp, ... /* key1, …, keyM, NULL, lst** out */);

// 计算可变宏参数个数，上限 22
#define PP_NARG(...)         PP_NARG_(__VA_ARGS__,PP_RSEQ_N())
#define PP_NARG_(...)        PP_ARG_N(__VA_ARGS__)
#define PP_ARG_N(                                     \
     _1, _2, _3, _4, _5, _6, _7, _8, _9,_10,          \
    _11,_12,_13,_14,_15,_16,_17,_18,_19,_20,          \
    _21,_22, N, ...) N
#define PP_RSEQ_N()                                   \
    22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0

#define PRIMITIVE_CAT(a, b) a##b
#define CAT(a, b)         PRIMITIVE_CAT(a, b)

#define INS_HASH_EXT2(r,k1)                                      \
    __ins_hash_ext(r, k1, NULL)
#define INS_HASH_EXT3(r,k1,k2)                                   \
    __ins_hash_ext(r, k1, k2, NULL)
#define INS_HASH_EXT4(r,k1,k2,k3)                                \
    __ins_hash_ext(r, k1, k2, k3, NULL)
#define INS_HASH_EXT5(r,k1,k2,k3,k4)                             \
    __ins_hash_ext(r, k1, k2, k3, k4, NULL)
#define INS_HASH_EXT6(r,k1,k2,k3,k4,k5)                          \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, NULL)
#define INS_HASH_EXT7(r,k1,k2,k3,k4,k5,k6)                       \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, NULL)
#define INS_HASH_EXT8(r,k1,k2,k3,k4,k5,k6,k7)                    \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, NULL)
#define INS_HASH_EXT9(r,k1,k2,k3,k4,k5,k6,k7,k8)                 \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, NULL)
#define INS_HASH_EXT10(r,k1,k2,k3,k4,k5,k6,k7,k8,k9)             \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, NULL)
#define INS_HASH_EXT11(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10)         \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, NULL)
#define INS_HASH_EXT12(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11)     \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, NULL)
#define INS_HASH_EXT13(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12) \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, NULL)
#define INS_HASH_EXT14(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13) \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, NULL)
#define INS_HASH_EXT15(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14) \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, NULL)
#define INS_HASH_EXT16(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15) \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, NULL)
#define INS_HASH_EXT17(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16) \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, NULL)
#define INS_HASH_EXT18(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17) \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, k17, NULL)
#define INS_HASH_EXT19(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17,k18) \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, k17, k18, NULL)
#define INS_HASH_EXT20(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17,k18,k19) \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, k17, k18, k19, NULL)
#define INS_HASH_EXT21(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17,k18,k19,k20) \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, k17, k18, k19, k20, NULL)

#define ins_hash_ext(...) \
    CAT(INS_HASH_EXT, PP_NARG(__VA_ARGS__))(__VA_ARGS__)

#define GET_HASH_EXT2(r,out)                                    \
    __get_hash_ext(r, NULL, out)
#define GET_HASH_EXT3(r,k1,out)                                 \
    __get_hash_ext(r, k1, NULL, out)
#define GET_HASH_EXT4(r,k1,k2,out)                              \
    __get_hash_ext(r, k1, k2, NULL, out)
#define GET_HASH_EXT5(r,k1,k2,k3,out)                           \
    __get_hash_ext(r, k1, k2, k3, NULL, out)
#define GET_HASH_EXT6(r,k1,k2,k3,k4,out)                        \
    __get_hash_ext(r, k1, k2, k3, k4, NULL, out)
#define GET_HASH_EXT7(r,k1,k2,k3,k4,k5,out)                     \
    __get_hash_ext(r, k1, k2, k3, k4, k5, NULL, out)
#define GET_HASH_EXT8(r,k1,k2,k3,k4,k5,k6,out)                  \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, NULL, out)
#define GET_HASH_EXT9(r,k1,k2,k3,k4,k5,k6,k7,out)               \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, NULL, out)
#define GET_HASH_EXT10(r,k1,k2,k3,k4,k5,k6,k7,k8,out)           \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, NULL, out)
#define GET_HASH_EXT11(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,out)        \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, NULL, out)
#define GET_HASH_EXT12(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,out)    \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, NULL, out)
#define GET_HASH_EXT13(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,out)\
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, NULL, out)
#define GET_HASH_EXT14(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,out) \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, NULL, out)
#define GET_HASH_EXT15(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,out) \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, NULL, out)
#define GET_HASH_EXT16(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,out) \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, NULL, out)
#define GET_HASH_EXT17(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,out) \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, NULL, out)
#define GET_HASH_EXT18(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,out) \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, NULL, out)
#define GET_HASH_EXT19(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17,out) \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, k17, NULL, out)
#define GET_HASH_EXT20(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17,k18,out) \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, k17, k18, NULL, out)
#define GET_HASH_EXT21(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17,k18,k19,out) \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, k17, k18, k19, NULL, out)
#define GET_HASH_EXT22(r,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17,k18,k19,k20,out) \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, k17, k18, k19, k20, NULL, out)

#define get_hash_ext(...) \
    CAT(GET_HASH_EXT, PP_NARG(__VA_ARGS__))(__VA_ARGS__)

#if 0
int __ins_hash_ext(ntmp *nmp, ... /* key1, key2, …, keyN, NULL */);
int __get_hash_ext(ntmp *nmp, ... /* key1, …, keyM, NULL, lst** out */);

#define PP_NARG(...) \
         PP_NARG_(__VA_ARGS__, PP_RSEQ_N())
#define PP_NARG_(...) \
         PP_ARG_N(__VA_ARGS__)
#define PP_ARG_N(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,N,...) N
#define PP_RSEQ_N() \
         20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0

#define PRIMITIVE_CAT(a, b) a##b
#define CAT(a, b)         PRIMITIVE_CAT(a, b)

#define INS_HASH_EXT2(r,k1)                      \
    __ins_hash_ext(r, k1, NULL)
#define INS_HASH_EXT3(r,k1,k2)                   \
    __ins_hash_ext(r, k1, k2, NULL)
#define INS_HASH_EXT4(r,k1,k2,k3)                \
    __ins_hash_ext(r, k1, k2, k3, NULL)
#define INS_HASH_EXT5(r,k1,k2,k3,k4)             \
    __ins_hash_ext(r, k1, k2, k3, k4, NULL)
#define INS_HASH_EXT6(r,k1,k2,k3,k4,k5)          \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, NULL)
#define INS_HASH_EXT7(r,k1,k2,k3,k4,k5,k6)       \
    __ins_hash_ext(r, k1, k2, k3, k4, k5, k6, NULL)

#define ins_hash_ext(...) \
    CAT(INS_HASH_EXT, PP_NARG(__VA_ARGS__))(__VA_ARGS__)

#define GET_HASH_EXT2(r,out)                     \
    __get_hash_ext(r, NULL, out)
#define GET_HASH_EXT3(r,k1,out)                  \
    __get_hash_ext(r, k1, NULL, out)
#define GET_HASH_EXT4(r,k1,k2,out)               \
    __get_hash_ext(r, k1, k2, NULL, out)
#define GET_HASH_EXT5(r,k1,k2,k3,out)            \
    __get_hash_ext(r, k1, k2, k3, NULL, out)
#define GET_HASH_EXT6(r,k1,k2,k3,k4,out)         \
    __get_hash_ext(r, k1, k2, k3, k4, NULL, out)
#define GET_HASH_EXT7(r,k1,k2,k3,k4,k5,out)      \
    __get_hash_ext(r, k1, k2, k3, k4, k5, NULL, out)
#define GET_HASH_EXT8(r,k1,k2,k3,k4,k5,k6,out)   \
    __get_hash_ext(r, k1, k2, k3, k4, k5, k6, NULL, out)

#define get_hash_ext(...) \
    CAT(GET_HASH_EXT, PP_NARG(__VA_ARGS__))(__VA_ARGS__)
#endif

int __ins_hash_ext_arr(ntmp *nmp, char *keys[], int nkeys);

// 拆分 path（形如 "/a/b/c"），对每一级前缀都调用 __ins_hash_ext_arr
void ntmp_ins_ext(ntmp *nmp, const char *path);

char* get_mempool( const char* add, const char* typ );
char* get_mempool_devs( const char* add, const char* typ );
bool get_mempool_isenabled( const char* add, const char* typ );
#endif
