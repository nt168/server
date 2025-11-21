#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "common.h"
#include "daemon.h"
#include "setproctitle.h"
//#include "actuator/actuator.h"
#include "log.h"
#include "cfg.h"
#include "mutexs.h"
#include "daemon.h"
#include "results.h"
#include "arg_parser.h"
#include "channel.h"
#include "messtype.h"
#include "phy_sql/phy_sql.h"
#include "phy_sql/sqlite3.h"
#include "phy_ssh.h"
#include "phy_tty.h"
#include "hashmap.h"
#include "history.h"
#include "ntmp.h"
#include "scanner.h"

//#include "phythreads.h"

extern sqlite3 *phydb;
char pwd_path[BUFLEN] = {0} ;
char protop[BUFLEN] = {0};

extern int	CONFIG_ALLOW_ROOT;
char *CONFIG_PID_FILE = "/tmp/server.pid";
//const char	*progname = 0;
const char	syslog_app_name[] = "phy_server";

const char	*usage_message[] = {
	"[-c config-file]", NULL,
	"[-c config-file]", "-R runtime-option", NULL,
	"-h", NULL,
	"-V", NULL,
	NULL	/* end of text */
};

const char	*help_message[] = {
	"The core daemon of Phy software.",
	"  -h --help	Display this help message",
	"  -V --version Display version number",
	"",
	NULL
};

struct datalist *agentlist = NULL;
struct datalist *conf_agentlist = NULL;
char	*CONFIG_ALERT_SCRIPTS_PATH	= NULL;
char	*DEFAULT_CONFIG_FILE	= NULL;
char	*DEFAULT_ALERT_SCRIPTS_PATH = NULL;
char	*DEFAULT_EXTERNAL_SCRIPTS_PATH = NULL;
char	*DEFAULT_SSL_CERT_LOCATION = NULL;
char	*DEFAULT_SSL_KEY_LOCATION = NULL;
char	*DEFAULT_LOAD_MODULE_PATH = NULL;
//static char	*CONFIG_SOCKET_PATH	= NULL;
char	*CONFIG_MESSCHANNEL_DIR	= NULL;
char	*CONFIG_TMP_DIR			= NULL;
char	*CONFIG_LOG_DIR			= NULL;
char	*FIFO_READ   = NULL;
char	*FIFO_WRITE  = NULL;
char	*CONFIG_AGENT_PACKAGE = NULL;
char	*CONFIG_PHYDB = NULL;
char	*CONFIG_PHYDB_CONSOLE   = NULL;
char	*AGENT_RES_DIR = NULL;
char	*AGENT_MOD_BIN = NULL;
char	*CONFIG_REMOTESCPFILE_SH = NULL;
char	*CONFIG_REMOTEVSCPFILE_SH = NULL;
char	*CONFIG_REMOTESCPPROXYFILE_SH = NULL;
char	*CONFIG_REMOTEEXECUTE_SH = NULL;
char	*CONFIG_REMOTEEXECUTEFORK_SH = NULL;
char	*CONFIG_STATEDETECTORPROXY_SH = NULL;
char	*CONFIG_STATEDETECTOR_SH = NULL;
char	*CONFIG_REMOTEEXECUTEFORKPROXY_SH = NULL;
char	*CONFIG_REMOTEPROXYSCPFILE_SH = NULL;
char	*CONFIG_REMOTEPROXYEXECUTE_SH = NULL;
char	*CONFIG_SERVICE_ADDR = NULL;
char	*CONFIG_RESULTS_DIR = NULL;
char	*CONFIG_USER			= NULL;
char	*CONFIG_PAWD			= NULL;
char	*CONFIG_CPUMODEL        = NULL;
char    *CONFIG_CPUARCH         = NULL;

char 	*RESTARTABLE_SCRIPT_PATH = NULL;
unsigned int CONFIG_SERVICE_LISTENING_PORT = 0;
unsigned int CONFIG_PROXY_MODE = 0;
int	CONFIG_LOG_LEVEL = LOG_LEVEL_WARNING;

char AGENT_TMP_DIR[BUFLEN] = {0};
char AGENT_TMP_PATH[BUFLEN] = {0};
char AGENT_TMP_PACKAGE[BUFLEN] = {0};
char AGENT_CONFIG_PATH[BUFLEN] = {0};
char AGENT_SWITCH_PATH[BUFLEN] = {0};
char AGENT_START_PATH[BUFLEN] = {0};
char AGENT_STOP_PATH[BUFLEN] = {0};
char AGENT_RESTARTABLE_SCRIPT_PATH[BUFLEN] = {0};

char CONF_AGENTLIST[BUFLEN] = {0};
const char	*progname = NULL;
char AGENTINFO_FILE[BUFLEN] = {0};
char TASKLIST_FILE[BUFLEN] = {0};
char UNINSTALLSH[BUFLEN] = {0};
char FTC8_NS_TEMPLATE_JSON[BUFLEN] = {0};
char FTC6_NS_TEMPLATE_JSON[BUFLEN] = {0};
char ANAL_NS_TEMPLATE_JSON[BUFLEN] = {0};
char NOC_NS_TEMPLATE_JSON[BUFLEN] = {0};
char DDR_NS_TEMPLATE_JSON[BUFLEN] = {0};
char C2C_NS_TEMPLATE_JSON[BUFLEN] = {0};
char PCIE_NS_TEMPLATE_JSON[BUFLEN] = {0};
char DDR_NS_TEMPLATE_TXT[BUFLEN] = {0};

char phydb_path[BUFLEN] = {0};
char phydb_console[BUFLEN] = {0};
char phy_env_check_template[BUFLEN] = {0};
char phy_env_check_sh[BUFLEN] = {0};

char tpdcsvtran[BUFLEN] = {0};
char tpdrestran[BUFLEN] = {0};
char fs_sourcerestran[BUFLEN] = {0};
char fs_callsiterestran[BUFLEN] = {0};
char fs_cachelinerestran[BUFLEN] = {0};
char fs_objrestran[BUFLEN] = {0};
char numa_callsiterestran[BUFLEN] = {0};
char numa_cachelinerestran[BUFLEN] = {0};
char numa_objrestran[BUFLEN] = {0};

char masrestran[BUFLEN] = {0};
char msevtrestran[BUFLEN] = {0};
char iosysrestran[BUFLEN] = {0};
char ioapirestran[BUFLEN] = {0};

bool local_test_flag = false;
void set_shell_parameters()
{
	char stmp[BUFLEN] = {0};
	phy_snprintf(stmp, BUFLEN, "%s/resource/remoteexecute.sh", protop);
	CONFIG_REMOTEEXECUTE_SH = phy_strdup(NULL, stmp);

	memset(stmp, 0, BUFLEN);
	phy_snprintf(stmp, BUFLEN, "%s/resource/state_detector_proxy.sh", protop);
	CONFIG_STATEDETECTORPROXY_SH = phy_strdup(NULL, stmp);

	memset(stmp, 0, BUFLEN);
	phy_snprintf(stmp, BUFLEN, "%s/resource/state_detector.sh", protop);
	CONFIG_STATEDETECTOR_SH = phy_strdup(NULL, stmp);

	memset(stmp, 0, BUFLEN);
	phy_snprintf(stmp, BUFLEN, "%s/resource/remoteexecute_fork.sh", protop);
	CONFIG_REMOTEEXECUTEFORK_SH = phy_strdup(NULL, stmp);

	memset(stmp, 0, BUFLEN);
	phy_snprintf(stmp, BUFLEN, "%s/resource/remoteexecutex_proxy.sh", protop);
	CONFIG_REMOTEEXECUTEFORKPROXY_SH = phy_strdup(NULL, stmp);

	memset(stmp, 0, BUFLEN);
	phy_snprintf(stmp, BUFLEN, "%s/resource/remotescp.sh", protop);
	CONFIG_REMOTESCPFILE_SH = phy_strdup(NULL, stmp);

	memset(stmp, 0, BUFLEN);
	phy_snprintf(stmp, BUFLEN, "%s/resource/remotescp_proxy.sh", protop);
	CONFIG_REMOTESCPPROXYFILE_SH = phy_strdup(NULL, stmp);

	memset(stmp, 0, BUFLEN);
	phy_snprintf(stmp, BUFLEN, "%s/resource/remote_proxy_scp.sh", protop);
	CONFIG_REMOTEPROXYSCPFILE_SH = phy_strdup(NULL, stmp);

	memset(stmp, 0, BUFLEN);
	phy_snprintf(stmp, BUFLEN, "%s/resource/remote_proxy_ex.sh", protop);
	CONFIG_REMOTEPROXYEXECUTE_SH = phy_strdup(NULL, stmp);

	memset(stmp, 0, BUFLEN);
	phy_snprintf(stmp, BUFLEN, "%s/resource/Serials.sh", protop);
	RESTARTABLE_SCRIPT_PATH = phy_strdup(NULL, stmp);

	phy_snprintf(phy_env_check_template, BUFLEN, "%s/conf/env-check_template.cnf", protop);
	phy_snprintf(UNINSTALLSH, BUFLEN, "%s/resource/uninstall.sh", protop);

	memset(stmp, 0, BUFLEN);
	phy_snprintf(phy_env_check_sh, BUFLEN, "%s/tools/env_check/env_check_all.sh", protop);

	memset(stmp, 0, BUFLEN);
	phy_snprintf(stmp, BUFLEN, "%s/resource/remotevscp.sh", protop);
	CONFIG_REMOTEVSCPFILE_SH = phy_strdup(NULL, stmp);

	phy_snprintf(tpdcsvtran, BUFLEN, "%s/resource/topdown_csv2json.sh", protop);
	phy_snprintf(tpdrestran, BUFLEN, "%s/resource/topdown_res2json.sh", protop);

	phy_snprintf(masrestran, BUFLEN, "%s/resource/hit_res2json.py", protop);
	phy_snprintf(msevtrestran, BUFLEN, "%s/resource/miss_res2json.py", protop);
	phy_snprintf(iosysrestran, BUFLEN, "%s/resource/io_sys_res2json.py", protop);
	phy_snprintf(ioapirestran, BUFLEN, "%s/resource/io_api_res2json.py", protop);
	
	phy_snprintf(fs_sourcerestran, BUFLEN, "%s/resource/fs_source-res2json.sh", protop);
	phy_snprintf(fs_cachelinerestran, BUFLEN, "%s/resource/fs_cacheline-res2json.sh", protop);
	phy_snprintf(fs_callsiterestran, BUFLEN, "%s/resource/fs_callsite-res2json.sh", protop);
	phy_snprintf(fs_objrestran, BUFLEN, "%s/resource/fs_obj-res2json.sh", protop);
	phy_snprintf(numa_cachelinerestran, BUFLEN, "%s/resource/numa_cacheline-res2json.sh", protop);
	phy_snprintf(numa_callsiterestran, BUFLEN, "%s/resource/numa_callsite-res2json.sh", protop);
	phy_snprintf(numa_objrestran, BUFLEN, "%s/resource/numa_obj-res2json.sh", protop);

	phy_snprintf(AGENTINFO_FILE, BUFLEN, "%s/conf/agent", protop);
	phy_snprintf(TASKLIST_FILE, BUFLEN, "%s/conf/task", protop);

}

static void phy_load_general_config(PHY_TASK_EX *task, bool rflag)
{
	static struct cfg_line cfg[] =
	{
			{"LogDir",		&CONFIG_LOG_DIR,			TYPE_STRING,
				PARM_OPT,	0,		0},
			{"LogType",			&CONFIG_LOG_TYPE_STR,		TYPE_STRING,
				PARM_OPT,	0,		0},
			{"LogFile",			&CONFIG_LOG_FILE,			TYPE_STRING,
				PARM_OPT,	0,		0},
			{"LogFileSize",		&CONFIG_LOG_FILE_SIZE,		TYPE_INT,
				PARM_OPT,	0,		1024},
			{"DebugLevel",		&CONFIG_LOG_LEVEL,			TYPE_INT,
				PARM_OPT,	0,		5},
			{"User",			&CONFIG_USER,				TYPE_STRING,
				PARM_OPT,	0,		0},
			{"CpuModel",		&CONFIG_CPUMODEL,				TYPE_STRING,
				PARM_OPT,	0,		0},
			{"CpuArch",			&CONFIG_CPUARCH,				TYPE_STRING,
				PARM_OPT,	0,		0},
			{"Pawd",			&CONFIG_PAWD,				TYPE_STRING,
				PARM_OPT,	0,		0},
			{"MessChannelDir",	&CONFIG_MESSCHANNEL_DIR,	TYPE_STRING,
				PARM_OPT,	0,		0},
			{"TmpDir",			&CONFIG_TMP_DIR,			TYPE_STRING,
				PARM_OPT,	0,		0},
//			{"MessageChannelControllerRead",	&CONFIG_MESSAGE_CHANNEL_CONTROLLER_READ,	TYPE_STRING,
//				PARM_OPT,	0,		0},
//			{"MessageChannelControllerWrite",	&CONFIG_MESSAGE_CHANNEL_CONTROLLER_WRITE,	TYPE_STRING,
//				PARM_OPT,	0,		0},
			{"AgentPackage",					&CONFIG_AGENT_PACKAGE,						TYPE_STRING,
				PARM_OPT,	0,		0},
			{"AgentResdir",						&AGENT_RES_DIR,								TYPE_STRING,
				PARM_OPT,	0,		0},
			{"AgentModbin",						&AGENT_MOD_BIN,								TYPE_STRING,
				PARM_OPT,	0,		0},
			{"PhyDB",							&CONFIG_PHYDB,								TYPE_STRING,
				PARM_OPT,	0,		0},
			{"PhyDbConsole",					&CONFIG_PHYDB_CONSOLE,						TYPE_STRING,
				PARM_OPT,	0,		0},
			{"ServiceListeningPort",			&CONFIG_SERVICE_LISTENING_PORT,				TYPE_INT,
				PARM_OPT,	0,		65535},
			{"ServiceIpAddr",					&CONFIG_SERVICE_ADDR,						TYPE_STRING,
				PARM_OPT,	0,		0},
			{"ResultsDir",						&CONFIG_RESULTS_DIR,						TYPE_STRING,
				PARM_OPT,	0,		0},
			{"ProxyMode",						&CONFIG_PROXY_MODE,							TYPE_INT,
				PARM_OPT,	0,		0},
			{NULL}
	};

	char* config_file_dir = NULL;
	char config_file[BUFLEN] = {0};
	config_file_dir = get_parent_dir(pwd_path);
	phy_snprintf(config_file, BUFLEN, "%s/conf/phy_server.cnf", config_file_dir);
	parse_cfg_file(config_file, cfg, PHY_CFG_FILE_REQUIRED, PHY_CFG_STRICT, true);
	CONFIG_LOG_TYPE = phy_get_log_type(CONFIG_LOG_TYPE_STR);
	set_shell_parameters();
}

int get_exepath()
{
    char buf[BUFLEN];
    char* p=NULL;
    int i;
    int rslt = readlink("/proc/self/exe", buf, BUFLEN);
    if (rslt < 0 || rslt >= BUFLEN)
    {
        return -1;
    }
    buf[rslt] = '\0';
    for (i = rslt; i >= 0; i--)
    {
        if (buf[i] == '/')
        {
            buf[i + 1] = '\0';
            break;
        }
    }
    memcpy(pwd_path, buf, strlen(buf) + 1);
    if(pwd_path[strlen(pwd_path) - 1 ] == '/'){
    	pwd_path[strlen(pwd_path) - 1 ] = '\0';
    }
    p = strrchr(pwd_path, '/');
    strncpy(protop, pwd_path, p - pwd_path);
    return 0;
}


void set_related_parameter()
{
//	char tmp[PHRASELEN] = {0};
	char stmp[BUFLEN] = {0};
	phy_mkdir(CONFIG_TMP_DIR);
//mkdir
	phy_snprintf(stmp, BUFLEN, "%s/%s", CONFIG_TMP_DIR, CONFIG_LOG_DIR);
	phy_mkdir(stmp);
	memset(stmp, 0, BUFLEN);
	phy_snprintf(stmp, BUFLEN, "%s/%s", CONFIG_TMP_DIR, CONFIG_MESSCHANNEL_DIR);
	phy_mkdir(stmp);
	memset(stmp, 0, BUFLEN);

//LogFile
	phy_snprintf(stmp, BUFLEN, "%s/%s/%s", CONFIG_TMP_DIR, CONFIG_LOG_DIR, CONFIG_LOG_FILE);
	phy_free(CONFIG_LOG_FILE);
	CONFIG_LOG_FILE = phy_strdup(NULL, stmp);
	memset(stmp, 0, BUFLEN);

//MessageChannel
	phy_snprintf(stmp, BUFLEN, "%s/%s/%s", CONFIG_TMP_DIR, CONFIG_MESSCHANNEL_DIR, "Read");
	FIFO_READ = phy_strdup(NULL, stmp);
	memset(stmp, 0, BUFLEN);

	phy_snprintf(stmp, BUFLEN, "%s/%s/%s", CONFIG_TMP_DIR, CONFIG_MESSCHANNEL_DIR, "Write");
	FIFO_WRITE = phy_strdup(NULL, stmp);
	memset(stmp, 0, BUFLEN);
//AGENT_TMP_DIR
//	phy_snprintf(AGENT_TMP_DIR, BUFLEN, "/home/%s/phy_tmp_dir", CONFIG_USER);
	phy_snprintf(AGENT_TMP_DIR, BUFLEN, "%s/agent", CONFIG_TMP_DIR);
	phy_mkdir(AGENT_TMP_DIR);
//AGENT_TMP_PATH
	phy_snprintf(AGENT_TMP_PATH, BUFLEN, "%s/pt_agent", AGENT_TMP_DIR);
//AGENT_CONFIG_PATH
	phy_snprintf(AGENT_CONFIG_PATH, BUFLEN, "%s/conf/phy_agent.cnf", AGENT_TMP_PATH);
//AGENT_TMP_PACKAGE
	phy_snprintf(AGENT_TMP_PACKAGE, BUFLEN, "%s.tar.gz", AGENT_TMP_PATH);
//AGENT_SWITCH_PATH
	phy_snprintf(AGENT_SWITCH_PATH, BUFLEN, "%s/phy_agent_switch.sh", CONFIG_AGENT_PACKAGE);
//AGENT_START_PATH
	phy_snprintf(AGENT_START_PATH, BUFLEN, "%s/resource/pt_agent_start.sh", protop);
//AGENT_STOP_PATH
	phy_snprintf(AGENT_STOP_PATH, BUFLEN, "%s/resource/pt_agent_stop.sh", protop);
//AGENT_RESTARTABLE_SCRIPT_PATH
	phy_snprintf(AGENT_RESTARTABLE_SCRIPT_PATH, BUFLEN, "%s/Serials.sh", AGENT_TMP_DIR);
//AGENTLIST
	phy_snprintf(CONF_AGENTLIST, BUFLEN, "%s/conf/agentlist", protop);
//ftc8-ns_template-json
	phy_snprintf(FTC8_NS_TEMPLATE_JSON, BUFLEN, "%s/conf/ftc8-ns_template.json", protop);
//ftc6-ns_template-json
	phy_snprintf(FTC6_NS_TEMPLATE_JSON, BUFLEN, "%s/conf/ftc6-ns_template.json", protop);
//anal-ns_template-json
	phy_snprintf(ANAL_NS_TEMPLATE_JSON, BUFLEN, "%s/conf/anal-ns_template.json", protop);
//noc-ns_template-json
	phy_snprintf(NOC_NS_TEMPLATE_JSON, BUFLEN, "%s/conf/noc-ns_template.json", protop);
//ddr-ns_template-json
	phy_snprintf(DDR_NS_TEMPLATE_JSON, BUFLEN, "%s/conf/ddr-ns_template.json", protop);
//c2c-ns_template-json
	phy_snprintf(C2C_NS_TEMPLATE_JSON, BUFLEN, "%s/conf/c2c-ns_template.json", protop);
//pcie-ns_template-json
	phy_snprintf(PCIE_NS_TEMPLATE_JSON, BUFLEN, "%s/conf/pcie-ns_template.json", protop);
//ddr-ns_template-txt
	phy_snprintf(DDR_NS_TEMPLATE_TXT, BUFLEN, "%s/conf/ddr-ns_template.txt", protop);
//phydb
	phy_snprintf(phydb_path, BUFLEN, "/opt/phytune/server/conf/%s", CONFIG_PHYDB);
//phydb_console
	phy_snprintf(phydb_console, BUFLEN, "%s/%s", CONFIG_TMP_DIR, CONFIG_PHYDB_CONSOLE);

}

void* thread1_func(void *arg)
{
    int i = 0;

    // able to be cancel
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    for(i=0; ; i++) {
        printf("thread1 %d\n", i);
        sleep(1);
    }
    return NULL;
}

hmap_t promap;
hmap_t ldr;
//sqlite3 *phydb = NULL;

int main(int argc, char **argv)
{
#if 0
	bool bl = false;
	char* res = null;
	bl = rmt_exe("10.31.31.217", "zhangw", "zhangw", "test.2025", m_deppth, m_tmpdir, &res, 2, -1, true);
	if(bl == true){
		printf("%s\n", res);
		phy_free(res);
	}
#endif

#if 0
	extern	ntmp *hwmp;
	extern ddlhx *scdh;
	scan_init();
	init_ntmp();
//	scan_start("10.31.31.217");

	lst* lx = null;
	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "driver", "pcie", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "driver", "ddr", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	ddlx_destory(scdh);
	destroy_ntmp(hwmp);
	return 0;

#endif
#if 0
#include "ddr.h"
	char *a = null;
	a = ntcat(m_dimm, " ", "0");
	printf("%s\n", a);
	phy_free(a);
	return 0;
#endif

#if 0
	char* res = null;
	res = int2sstr(12345, ",");
	printf("%s\n", res);
	phy_free(res);
	return 0;
#endif

#if 0
	tbh tb;
	char* rat;
	tb = tab_ldrx("/opt/phytune/agent/arm/pmucnf/S5000C/ddr/hw.cnf");
	rat = tab_search(&tb, "node", "nodes", "DIMM 20");
	free_tbh(&tb);

	tb = tab_ldr("/opt/phytune/agent/arm/pmucnf/S5000C/pcie/hw.cnf");
	rat = tab_search(&tb, "pcie版本", "5.0", "x16带宽(单向)");
	free_tbh(&tb);
	return 0;
#endif

#if 0
	extern	ntmp *hwmp;
	trandst td = {0};
	scan_init();
	init_ntmp();
	snprintf(td.date, 32, "%s", "202506211739");
	snprintf(td.mes, 1280, "%s", "tarpro=l2d_cache_workload;node_id=;pmu_id=Marvell Technology Group Ltd. 88SE9230 PCIe 2.0 x2 4-port SATA 6 Gb/s RAID Controller;ctrler_id=rev05;tra_switch=0;anaopt=");
	run_pcie("10.31.31.217", "zhangw", "zhangw", td);

#if 1
// ddr
	lst* lx = null;
	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", "DIMM 0",  &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", "DIMM 0",  "Part Number", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}
	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", "DIMM 0",  &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", "DIMM 0",  "Part Number", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}
	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", "DIMM 0",  &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", "DIMM 0",  "Part Number", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}
	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", "DIMM 0",  &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", "DIMM 0",  "Part Number", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}
	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", "DIMM 0",  &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", "DIMM 0",  "Part Number", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}
#endif
	run_pcie("10.31.31.217", "zhangw", "zhangw", td);

	destroy_ntmp(hwmp);
	return 0;
#endif

#if 0

	trandst td = {0};
	scan_init();
	init_ntmp();
#if 1
// ddr
	lst* lx = null;
	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", "DIMM 0",  &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "ddr", "DIMM 0",  "Part Number", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}
//	destroy_ntmp(hwmp);
#endif

	snprintf(td.date, 32, "%s", "202506211739");
//	snprintf(td.mes, 1280, "%s", "tarpro=l2d_cache_workload;node_id=0;hm_id=0;anaopt=");
	snprintf(td.mes, 1280, "%s", "tarpro=l2d_cache_workload;node_id=;pmu_id=Marvell Technology Group Ltd. 88SE9230 PCIe 2.0 x2 4-port SATA 6 Gb/s RAID Controller;ctrler_id=rev05;tra_switch=0;anaopt=");

	run_pcie("10.31.31.217", "zhangw", "zhangw", td);
//	run_ddr("10.31.31.217", "zhangw", "zhangw", td);

	destroy_ntmp(hwmp);
	return 0;
#endif

#if 0
#include "nttabs.h"

        tbh hd = tab_ldr("/opt/phytune/agent/arm/pmucnf/S5000C/pcie/hw.cnf");
        printf("[控制器] 控制器,rev08 = %s\n", tab_search(&hd, "控制器", "控制器", "rev08"));
        printf("[控制器] 控制器,rev07 = %s\n", tab_search(&hd, "控制器", "控制器", "rev07"));
        printf("[控制器] 控制器,rev06 = %s\n", tab_search(&hd, "控制器", "控制器", "rev06"));
        printf("[控制器] 控制器,rev05 = %s\n", tab_search(&hd, "控制器", "控制器", "rev05"));

        printf("[pcie版本] 5.0,x16带宽(单向) = %s\n", tab_search(&hd, "pcie版本", "5.0", "x16带宽(单向)"));
        printf("[pcie版本] 4.0,x16带宽(单向) = %s\n", tab_search(&hd, "pcie版本", "4.0", "x16带宽(单向)"));
        printf("[pcie版本] 4.0,x8带宽 = %s\n", tab_search(&hd, "pcie版本", "4.0", "x8带宽"));

        free_tbh(&hd);
        return 0;
#endif

	fil_remove("/tmp/kilflg");

	get_exepath();

	phy_load_general_config(NULL, 1);
	set_related_parameter();

// init log
	char *error = NULL;

	if (SUCCEED != phy_locks_create(&error))
	{
		phy_error("cannot create locks: %s", error);
		phy_free(error);
		exit(EXIT_FAILURE);
	}

	if (SUCCEED != phy_open_log(CONFIG_LOG_TYPE, CONFIG_LOG_LEVEL, CONFIG_LOG_FILE, &error))
	{
		phy_error("cannot open log: %s", error);
		phy_free(error);
		exit(EXIT_FAILURE);
	}
	phy_log(LOG_LEVEL_TRACE, "Starting Phy Server. Phy %s (revision %s).", PHY_VERSION, PHY_REVISION);

	int rc = 0;
	rc = physql_init();
	if(rc != SQLITE_OK){
		phy_log(LOG_LEVEL_ERR, "physql_init err.");
	}

	argv = setproctitle_save_env(argc, argv);
    daemon_start(CONFIG_ALLOW_ROOT, "phytium", 2);
	return 0;
}
