#ifndef ENV_CHECK_H
#define ENV_CHECK_H
#include "channel.h"
#include "common.h"
#include "messtype.h"
typedef enum{
	DEPEND = 1,
	PING,
	PMIS,
	telnet
}envcheck;

struct st_table
{
	const char	*key;
	const char	*value;
};

struct det_items
{
	const char	*key;
	const char	*value;
	const char	*tma;
	const char	*ddr;
	const char	*pcie;
	const char	*topdown;
};

struct st_line
{
	const char	*cmd;
};






#define native_section "本机检查"
#define remote_section "远程检查"
#define env_ckfil "/tmp/$addr_envck.res"
#define NATIVEDOMAIN "localhost"

void __env_check(const char *filnm, int line, envcheck type, const char* tplt, const char* rsts, const char* field, const char* user, const char* pass);
#define env_check(res, k1, k2) __env_check(__FILE__, __LINE, type, tplt, rsts, field, user, pass)
//#define env_check(res, k1, k2) __env_check(__FILE__, __LINE__, res, k1, k2)
//#define fchain_sync(const char *filnm, int line, envcheck type, bool isnative, const char* tplt, const char* rsts);
unsigned int env_scanner();
//bool env_checker(const char* addr);
bool env_checker(const char* addr, mestype type);
char* env_checker_plus(const char* addr, const char* des);
struct det_items* cpu_pmu_tp(const char* add, const char* usr, const char* pwd, const char* skey);
char* get_ftc8or6(const char* cputp);
#endif
