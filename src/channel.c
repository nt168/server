#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <libgen.h>
#include <stdlib.h>
#include <pthread.h>
#include <libssh/libssh.h>

#include "daemon.h"
#include "common.h"
#include "log.h"
#include "env_check.h"
#include "phy_ssh.h"
#include "phy_tty.h"
#include "arg_parser.h"
#include "results.h"
#include "cjson.h"
#include "filebrowser.h"
#include "shmlst.h"
#include "rmt_exec.h"
#include "phy_sql/phy_sql.h"
#include "history.h"
#include "phy_def.h"
#include "phy_mix.h"
#include "scanner.h"

#include "ddr.h"
#include "pcie.h"

extern char *CONFIG_PAWD;
extern char *CONFIG_USER;

volatile bool slgflg = false;
int  slgmst = 0;
bool lcfscomflg = false;
bool rmtfscomflg = false;

extern char *FIFO_READ;
extern char *FIFO_WRITE;
extern char* CONFIG_SERVICE_ADDR;
#define BUF_SIZE 65535
int g_stop = 0;

const char *ptary[] = { "error", "err", NULL };

//全局变量
int envRTReady[4];
char* envRTRes = NULL;
pthread_mutex_t envRTLock;
pthread_cond_t envRTCond;
struct thread_args {
	const char *add;
	const char *usr;
	const char *pwd;
	const char *spwd;
	const char *cmd;
	const char *date;
	int flg;
	char **results;
	int timeout_sec;
};

char* cpuNUM = NULL;

void init_kilchl_fil(const char* kilfil)
{
	FILE* fp = NULL;
	fp = fopen(kilfil, "w+");
	if(fp == NULL){
		return;
	}
	fprintf(fp, "%s", "init");
	fclose(fp);
}

bool kilchl_flg(const char* kilfil)
{
	bool flg = false;
	char buffer[20] = {0};
	FILE* fp = NULL;
	size_t len = 0;
	fp = fopen(kilfil, "r");
	if(fp == NULL){
		return flg;
	}
    len = fread(buffer, sizeof(char), sizeof(buffer) - 1, fp);
    if(len <= 4){
    	fclose(fp);
    	return flg;
    }
    buffer[len] = '\0';
    if(strstr(buffer, "killed")){
    	flg = true;
    }
    fclose(fp);
	return flg;
}

// 信号处理函数
void signal_pipe(int signum) {
    if (SIGPIPE == signum) {
        printf("Received SIGPIPE, shutting down...\n");
        g_stop = 1;
    }
}

bool write_message_to_controller(void* data, size_t lenth)
{
	int wfd = 0;
	size_t wln = 0;
	if ((wfd = open(FIFO_WRITE, O_WRONLY)) < 0) {
		phy_log(LOG_LEVEL_ERR, "write_message_to_controller: Open fifo[%s] for write error: %s", FIFO_WRITE, strerror(errno));
		return false;
	}
	wln = write(wfd, data, lenth);
	close(wfd);
	if(wln != lenth){
		return false;
	}
	return true;
}

void write_messagechannel(struct transfer * trandata)
{
	int  fdw_fifo = -1;
	if ( (fdw_fifo = open(FIFO_READ, O_WRONLY)) < 0) //以只写的形式打开FIFO_READ的写端
	{
		printf("Open fifo[%s] for write error: %s\n", FIFO_READ, strerror(errno));
		return;
	}
	write(fdw_fifo, (const void*)trandata, sizeof(struct transfer));
	close(fdw_fifo);
}

int write_ptid(pthread_t tid)
{
#define chlpidfil "/tmp/chlpid"
	FILE* fp = NULL;
	size_t len = 0;
	fp = fopen(chlpidfil, "a+");
	if(fp == NULL){
		return 1;
	}
	len = fprintf(fp, "ptid:[%ld]\n", tid);
	fclose(fp);
	if(len > 0){
		return 0;
	}else{
		return 1;
	}
}

void send_message(mestype matp, messta smtp, int affi, const char* mes)
{
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = matp;
	tran.mma.mst = smtp;
	tran.td.affi = affi;

	phy_snprintf(tran.td.mes, 1280, "%s", mes);
	write_message_to_controller(&tran, sizeof(struct transfer));
}

void run_comcfg(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td)
{
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define tmpdir "/tmp/phy/agent"
#define dstdir "/tmp"

	char* compath = NULL;
	char* comname = NULL;
	char lccompath[256] ={0};
	char combakpath[BUFLEN] = {0};
	char cmd[BUFLEN] = {0};
	char* results = NULL;
	char msg[256] = {0};
	char* dtres = NULL;
	FILE* fp = NULL;
	//编译文件路径
	compath = get_str_between_two_words(td.mes, "comfile=", NULL);
	comname = get_str_between_two_words(td.mes, "comfile=", NULL);
	phy_snprintf(combakpath, BUFLEN, "%s_%s.bak", compath, td.date);
	comname = strrchr(comname, '/');
	comname++;
	phy_snprintf(lccompath, 256, "%s/%s", tmpdir, comname);

	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "cp %s %s", compath, combakpath);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);
	phy_free(results);

	//替代传回文件到本地
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "cat %s", compath);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");

	if(strstr(dtres, "No such file or directory") || strstr(dtres, "没有那个文件或目录"))
	{
		send_message(MESS, ERROR, mde, "目标文件不存在");
		goto meserr;
	}

	fp = fopen(lccompath, "w+");

	char *new_results = strchr(dtres, '\n');
	if (new_results != NULL) {
		new_results++;
		fprintf(fp, "%s", new_results);
	}
	else {
		fprintf(fp, "%s", dtres);
	}

	fclose(fp);
	//替换\r字符，自动将文件格式转换为unix
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "sed -i 's/\r//g' %s", lccompath);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 4, &results, -1);
	phy_free(results);
	if(fil_isexist("/tmp/kilflg") == true){
		return;
	}
	//将临时编译文件路径发送给ui
	phy_snprintf(msg, 256, "%s;%s", lccompath, td.receiver);
	send_message(DETECT, FINISH, mde, msg);
//	phy_free(compath);
//	phy_free(comname);
meserr:
	return;
}

void run_comback(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td)
{
#define tmpdir "/tmp/phy/agent"

	char* compath = NULL;
	char* results = NULL;
	char rmtdst[256]={0};
	char srcdst[256]={0};
	char cmd[BUFLEN] = {0};
	//编译文件路径
	compath = get_str_between_two_words(td.mes, "comfile=", NULL);
	memset(rmtdst, 0, 256);
	phy_snprintf(rmtdst, 256, "%s", compath);
	compath = strrchr(compath, '/');
	compath++;
	memset(srcdst, 0, 256);
	phy_snprintf(srcdst, 256, "%s/%s", tmpdir, compath);
	if(fil_isexist("/tmp/kilflg") == true){
		return;
	}
	//推送新的编译文件
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "scp -rp %s %s@%s:%s", srcdst, usr, add, rmtdst);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 4, &results, -1);
	phy_free(results);
	//发送提示信息
	send_message(MESS, COMM, mde, "完成编译配置");
	//清理本地编译文件
	phy_rm_dir(srcdst);
//	phy_free(compath);
}

void run_compile(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char tmpstr[256] = {0};
	char modpath[256] = {0};
	char* compath = NULL;
	char* comopt = NULL;
	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char comres[256] = {0};
	char resdes[256] = {0};
	char* dtres = NULL;
	FILE* fp = NULL;
	//编译命令
	compath = get_str_between_two_words(td.mes, "compath=", ";");
	comopt = get_str_between_two_words(td.mes, "comopt=", NULL);
	//编译结果路径
	phy_snprintf(comres, 256, "%s/compile_%s.res", dstdir, td.date);
	phy_snprintf(resdes, 256, "%s/compile_%s.res", tmpdir, td.date);
	//推送编译资源，应进程结束才清理
	phy_snprintf(modpath, 256, "%s/%s", rsrcdir, cornam);
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "rsync -azu %s %s@%s:%s/", modpath, usr, add, dstdir);
	forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 4, &results, -1);
	phy_free(results);
	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
	}
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s/%s/parsedeb.sh",dstdir, cornam);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);
	phy_free(results);
	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
	}
	//执行编译
	//解压资源+设置环境变量+编译+转储编译结果并传回+删除临时编译结果
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "export LD_LIBRARY_PATH=\"%s/%s/phy_clang/lib/:$LD_LIBRARY_PATH\"; make clean -C %s; make %s -C %s > %s 2>&1",
		dstdir, cornam, compath, comopt, compath, comres);
	send_message(MESS, COMM, mde, "开始编译...");
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);
	phy_free(results);

	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "cat %s", comres);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");

	if(strstr(dtres, "No such file or directory") || strstr(dtres, "没有那个文件或目录"))
	{
		send_message(MESS, ERROR, mde, "编译结果不存在");
		goto meserr;
	}

	fp = fopen(resdes, "w+");

	char *new_results = strchr(dtres, '\n');
	if (new_results != NULL) {
		new_results++;
		fprintf(fp, "%s", new_results);
	}
	else {
		fprintf(fp, "%s", dtres);
	}

	fclose(fp);

	//删除临时文件
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "rm -rf %s", comres);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);
	phy_free(results);

	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
	}
	//发送编译结果文件路径
	send_message(DETECT, FINISH, mde, resdes);
	phy_free(compath);
	phy_free(comopt);
texit:
	phy_rm_dir(resdes);
	phy_free(compath);
	phy_free(comopt);
	return;
meserr:
	return;
}

void run_numa_local(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char tmpstr[256] = {0};
	char tmpresfile[256] = {0};
	char modpath[256] = {0};
	char* pidArg = NULL;
	char* intervalArg = NULL;
	char* timesArg = NULL;
	FILE* fp = NULL;

	pidArg = get_str_between_two_words(td.mes, "pid=", ";");
	intervalArg = get_str_between_two_words(td.mes, "interval=", ";");
	timesArg = get_str_between_two_words(td.mes, "times=", NULL);
	//创建结果存放目录
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "mkdir -p %s/%s", resdir, add);
	forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
	phy_free(results);
	//推送资源
	phy_snprintf(modpath, 256, "%s/%s", rsrcdir, cornam);
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "cp -rp %s %s/", modpath, dstdir);
	forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
	phy_free(results);
	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "sudo %s/%s/numa_analysis.sh %s %s %s", dstdir, cornam, pidArg, intervalArg, timesArg);
	forkpty_local(pwd, td.skey, cmd, 0, &results, -1);

	//停止按钮
	if(fil_isexist("/tmp/kilflg") == true){
		phy_free(results);
		return;
	}

	//将json结果存入/tmp/临时路径下，与ui端通信
	phy_snprintf(tmpresfile, 256, "%s/%s/numa_%s.res", resdir, add, td.date);
	fp = fopen(tmpresfile, "w");
	fprintf(fp, "%s", results);
	phy_free(results);
	fclose(fp);
	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = DETECT;
	tran.mma.mst = FINISH;
	tran.td.affi = NUMAANA;
	phy_snprintf(tran.td.mes, 1024, "%s;", tmpresfile);
	write_message_to_controller(&tran, sizeof(struct transfer));

	insert_history(td.receiver, MDE2STR(mde), td.date, cmd, tran.td.mes);

	return;
}

void run_numa(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char tmpstr[256] = {0};
	char tmpresfile[256] = {0};
	char modpath[256] = {0};
	char* pidArg = NULL;
	char* intervalArg = NULL;
	char* timesArg = NULL;
	FILE* fp = NULL;

	pidArg = get_str_between_two_words(td.mes, "pid=", ";");
	intervalArg = get_str_between_two_words(td.mes, "interval=", ";");
	timesArg = get_str_between_two_words(td.mes, "times=", NULL);
	//创建结果存放目录
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "mkdir -p %s/%s", resdir, add);
	forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 4, &results, -1);
	phy_free(results);
	//推送资源
	phy_snprintf(modpath, 256, "%s/%s", rsrcdir, cornam);
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "rsync -azu %s %s@%s:%s/", modpath, usr, add, dstdir);
	forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 4, &results, -1);
	phy_free(results);
	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "sudo %s/%s/numa_analysis.sh %s %s %s", dstdir, cornam, pidArg, intervalArg, timesArg);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);

	//停止按钮
	if(fil_isexist("/tmp/kilflg") == true){
		phy_free(results);
		return;
	}

	//将json结果存入/tmp/临时路径下，与ui端通信
	phy_snprintf(tmpresfile, 256, "%s/%s/numa_%s.res", resdir, add, td.date);
	fp = fopen(tmpresfile, "w");
	fprintf(fp, "%s", results);
	phy_free(results);
	fclose(fp);
	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = DETECT;
	tran.mma.mst = FINISH;
	tran.td.affi = NUMAANA;
	phy_snprintf(tran.td.mes, 1024, "%s;", tmpresfile);
	write_message_to_controller(&tran, sizeof(struct transfer));

	insert_history(td.receiver, MDE2STR(mde), td.date, cmd, tran.td.mes);

	return;
}

void run_numaenvcheck_local(const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char tmpstr[256] = {0};
	char modpath[256] = {0};

	//推送资源
	phy_snprintf(modpath, 256, "%s/%s", rsrcdir, cornam);
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "cp -rp %s %s/", modpath, dstdir);
	forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
	phy_free(results);

	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "/tmp/numa/numa_memnode.sh > /tmp/memnode.res");
	forkpty_local(pwd, td.skey, cmd, 0, &results, -1);
	phy_free(results);

	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "/tmp/numa/numa_cpucore.sh > /tmp/cpucore.res");
	forkpty_local(pwd, td.skey, cmd, 0, &results, -1);
	phy_free(results);

	//发送结果路径，代表已分析结束
	slgflg = true;

	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = MESS;
	tran.mma.mst = FINISH;
	tran.td.affi = NUMAENVCHECK;
	phy_snprintf(tran.td.mes, 1024, "检查成功");
	write_message_to_controller(&tran, sizeof(struct transfer));

	return;
}

void run_numaenvcheck(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* dtres = NULL;
	FILE* fp = NULL;
	char tmpstr[256] = {0};
	char modpath[256] = {0};

	//推送资源
	phy_snprintf(modpath, 256, "%s/%s", rsrcdir, cornam);
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "rsync -azu %s %s@%s:%s/", modpath, usr, add, dstdir);
	forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 4, &results, -1);
	phy_free(results);

	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "/tmp/numa/numa_memnode.sh");
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);
	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	trim(dtres);
	//将json结果存入/tmp/临时路径下，与ui端通信
	fp = fopen("/tmp/memnode.res", "w");//先清空内容
	fprintf(fp, "%s", dtres);
	fclose(fp);
	phy_free(dtres);
	phy_free(results);

	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "/tmp/numa/numa_cpucore.sh");
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);
	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	trim(dtres);
	//将json结果存入/tmp/临时路径下，与ui端通信
	fp = fopen("/tmp/cpucore.res", "w");//先清空内容
	fprintf(fp, "%s", dtres);
	fclose(fp);
	phy_free(dtres);
	phy_free(results);

	//发送结果路径，代表已分析结束
	slgflg = true;

	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = MESS;
	tran.mma.mme = FINISH;
	tran.td.affi = NUMAENVCHECK;
	phy_snprintf(tran.td.mes, 1024, "检查成功");
	write_message_to_controller(&tran, sizeof(struct transfer));

	return;
}

void run_numalaunch_local(const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char tmpstr[256] = {0};
	char modpath[256] = {0};
	char* pidSchedLabel = NULL;
	char* pidSchedEdit = NULL;
	char* memAllocLabel = NULL;
	char* memAllocEdit = NULL;
	char* appPathEdit = NULL;
	char pidSchedArg[256] = {0};
	char memAllocArg[256] = {0};
	char outpath[256] = {0};
	char* dtres = NULL;

	pidSchedLabel = get_str_between_two_words(td.mes, "pidSchedLabel=", ";");
	pidSchedEdit = get_str_between_two_words(td.mes, "pidSchedEdit=", ";");
	memAllocLabel = get_str_between_two_words(td.mes, "memAllocLabel=", ";");
	memAllocEdit = get_str_between_two_words(td.mes, "memAllocEdit=", ";");
	appPathEdit = get_str_between_two_words(td.mes, "appPathEdit=", NULL);

	if(strstr(pidSchedLabel, "1")){
		phy_snprintf(pidSchedArg, 256, "-N");
	}else if(strstr(pidSchedLabel, "2")){
		phy_snprintf(pidSchedArg, 256, "-C");
	}else{
		phy_snprintf(pidSchedArg, 256, "");
	}

	if(strstr(memAllocLabel, "1")){
		phy_snprintf(memAllocArg, 256, "-l");
	}else if(strstr(memAllocLabel, "2")){
		phy_snprintf(memAllocArg, 256, "-i");
	}else if(strstr(memAllocLabel, "3")){
		phy_snprintf(memAllocArg, 256, "--preferred");
	}else if(strstr(memAllocLabel, "4")){
		phy_snprintf(memAllocArg, 256, "-m");
	}else{
		phy_snprintf(memAllocArg, 256, "");
	}

	//推送资源
	phy_snprintf(modpath, 256, "%s/%s", rsrcdir, cornam);
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "cp -rp %s %s/", modpath, dstdir);
	forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
	phy_free(results);

	phy_snprintf(outpath, 256, "%s/%s/nohup.out", dstdir, cornam);

	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "nohup %s/%s/numalaunch.sh \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" > %s 2> /dev/null; %s/%s/numa_getpid.sh %s",
			dstdir, cornam, pidSchedArg, pidSchedEdit, memAllocArg, memAllocEdit, appPathEdit, outpath, dstdir, cornam, outpath);

	forkpty_local(pwd, td.skey, cmd, 0, &results, -1);
	dtres = parse_results(results, "<<<This is a beautiful segmentation line2>>>", "<<<This is a beautiful segmentation line2>>>");
	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = MESS;
	tran.mma.mst = FINISH;
	tran.td.affi = NUMALAUNCH;
	phy_snprintf(tran.td.mes, 1024, "%s启动成功", dtres);
	write_message_to_controller(&tran, sizeof(struct transfer));

	phy_free(dtres);
	phy_free(results);
	phy_free(pidSchedLabel);
	phy_free(pidSchedEdit);
	phy_free(memAllocLabel);
	phy_free(memAllocEdit);
	phy_free(appPathEdit);
	return;
}

void run_numalaunch(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char tmpstr[256] = {0};
	char modpath[256] = {0};
	char* pidSchedLabel = NULL;
	char* pidSchedEdit = NULL;
	char* memAllocLabel = NULL;
	char* memAllocEdit = NULL;
	char* appPathEdit = NULL;
	char pidSchedArg[256] = {0};
	char memAllocArg[256] = {0};
	char outpath[256] = {0};
	char* dtres = NULL;

	pidSchedLabel = get_str_between_two_words(td.mes, "pidSchedLabel=", ";");
	pidSchedEdit = get_str_between_two_words(td.mes, "pidSchedEdit=", ";");
	memAllocLabel = get_str_between_two_words(td.mes, "memAllocLabel=", ";");
	memAllocEdit = get_str_between_two_words(td.mes, "memAllocEdit=", ";");
	appPathEdit = get_str_between_two_words(td.mes, "appPathEdit=", NULL);

	if(strstr(pidSchedLabel, "1")){
		phy_snprintf(pidSchedArg, 256, "-N");
	}else if(strstr(pidSchedLabel, "2")){
		phy_snprintf(pidSchedArg, 256, "-C");
	}else{
		phy_snprintf(pidSchedArg, 256, "");
	}

	if(strstr(memAllocLabel, "1")){
		phy_snprintf(memAllocArg, 256, "-l");
	}else if(strstr(memAllocLabel, "2")){
		phy_snprintf(memAllocArg, 256, "-i");
	}else if(strstr(memAllocLabel, "3")){
		phy_snprintf(memAllocArg, 256, "--preferred");
	}else if(strstr(memAllocLabel, "4")){
		phy_snprintf(memAllocArg, 256, "-m");
	}else{
		phy_snprintf(memAllocArg, 256, "");
	}

	//推送资源
	phy_snprintf(modpath, 256, "%s/%s", rsrcdir, cornam);
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "rsync -azu %s %s@%s:%s/", modpath, usr, add, dstdir);
	forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 4, &results, -1);
	phy_free(results);

	phy_snprintf(outpath, 256, "%s/%s/nohup.out", dstdir, cornam);
	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "nohup %s/%s/numalaunch.sh \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" > %s 2> /dev/null; %s/%s/numa_getpid.sh %s",
			dstdir, cornam, pidSchedArg, pidSchedEdit, memAllocArg, memAllocEdit, appPathEdit,  outpath, dstdir, cornam, outpath);

	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);
	dtres = parse_results(results, "<<<This is a beautiful segmentation line2>>>", "<<<This is a beautiful segmentation line2>>>");
	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = MESS;
	tran.mma.mme = FINISH;
	tran.td.affi = NUMALAUNCH;
	phy_snprintf(tran.td.mes, 1024, "%s启动成功", dtres);
	write_message_to_controller(&tran, sizeof(struct transfer));
	phy_free(dtres);
	phy_free(results);
	phy_free(pidSchedLabel);
	phy_free(pidSchedEdit);
	phy_free(memAllocLabel);
	phy_free(memAllocEdit);
	phy_free(appPathEdit);
	return;
}

void run_numamemmig_local(const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* pidMemMigBox = NULL;
	char* oriNodeMemMigEdit = NULL;
	char* objNodeMemMigEdit = NULL;

	pidMemMigBox = get_str_between_two_words(td.mes, "pidMemMigBox=", ";");
	oriNodeMemMigEdit = get_str_between_two_words(td.mes, "oriNodeMemMigEdit=", ";");
	objNodeMemMigEdit = get_str_between_two_words(td.mes, "objNodeMemMigEdit=", NULL);

	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "migratepages %s %s %s", pidMemMigBox, oriNodeMemMigEdit, objNodeMemMigEdit);
	forkpty_local(pwd, td.skey, cmd, 0, &results, -1);

	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = MESS;
	tran.mma.mme = FINISH;
	tran.td.affi = NUMAMEMMIG;
	phy_snprintf(tran.td.mes, 1024, "内存迁移成功");
	write_message_to_controller(&tran, sizeof(struct transfer));


	phy_free(results);
	phy_free(pidMemMigBox);
	phy_free(oriNodeMemMigEdit);
	phy_free(objNodeMemMigEdit);

	return;;
}

void run_numamemmig(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* pidMemMigBox = NULL;
	char* oriNodeMemMigEdit = NULL;
	char* objNodeMemMigEdit = NULL;

	pidMemMigBox = get_str_between_two_words(td.mes, "pidMemMigBox=", ";");
	oriNodeMemMigEdit = get_str_between_two_words(td.mes, "oriNodeMemMigEdit=", ";");
	objNodeMemMigEdit = get_str_between_two_words(td.mes, "objNodeMemMigEdit=", NULL);

	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "migratepages %s %s %s", pidMemMigBox, oriNodeMemMigEdit, objNodeMemMigEdit);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);

	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = MESS;
	tran.mma.mme = FINISH;
	tran.td.affi = NUMAMEMMIG;
	phy_snprintf(tran.td.mes, 1024, "内存迁移成功");
	write_message_to_controller(&tran, sizeof(struct transfer));


	phy_free(results);
	phy_free(pidMemMigBox);
	phy_free(oriNodeMemMigEdit);
	phy_free(objNodeMemMigEdit);

	return;
}

void run_numathreadmig_local(const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* tidThreadMigBox = NULL;
	char* objCoreThreadMigEdit = NULL;

	tidThreadMigBox = get_str_between_two_words(td.mes, "tidThreadMigBox=", ";");
	objCoreThreadMigEdit = get_str_between_two_words(td.mes, "objCoreThreadMigEdit=", NULL);

	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "taskset -pc %s %s", objCoreThreadMigEdit, tidThreadMigBox);
	forkpty_local(pwd, td.skey, cmd, 0, &results, -1);

	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = MESS;
	tran.mma.mme = FINISH;
	tran.td.affi = NUMATHREADMIG;
	phy_snprintf(tran.td.mes, 1024, "线程迁移成功");
	write_message_to_controller(&tran, sizeof(struct transfer));

	phy_free(results);
	phy_free(tidThreadMigBox);
	phy_free(objCoreThreadMigEdit);

	return;
}

void run_numathreadmig(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* tidThreadMigBox = NULL;
	char* objCoreThreadMigEdit = NULL;

	tidThreadMigBox = get_str_between_two_words(td.mes, "tidThreadMigBox=", ";");
	objCoreThreadMigEdit = get_str_between_two_words(td.mes, "objCoreThreadMigEdit=", NULL);

	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "taskset -pc %s %s", objCoreThreadMigEdit, tidThreadMigBox);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);

	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = MESS;
	tran.mma.mme = FINISH;
	tran.td.affi = NUMATHREADMIG;
	phy_snprintf(tran.td.mes, 1024, "线程迁移成功");
	write_message_to_controller(&tran, sizeof(struct transfer));

	phy_free(results);
	phy_free(tidThreadMigBox);
	phy_free(objCoreThreadMigEdit);

	return;
}

void run_autobindadd_local(const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* appname = NULL;
	char* memnode = NULL;
	char* cpucore = NULL;
	char* dtres = NULL;

	appname = get_str_between_two_words(td.mes, "appname=", ";");
	memnode = get_str_between_two_words(td.mes, "memnode=", ";");
	cpucore = get_str_between_two_words(td.mes, "cpucore=", NULL);

	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s/%s/exec_reload_config -a -p %s -n %s -c %s; %s/%s/exec_reload_config -l", dstdir, cornam, appname, memnode, cpucore, dstdir, cornam);
	forkpty_local(pwd, td.skey, cmd, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line2>>>", "<<<This is a beautiful segmentation line2>>>");

	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = DETECT;
	tran.mma.mst = FINISH;
	tran.td.affi = ABINDADD;
	phy_snprintf(tran.td.mes, 1024, dtres);
	write_message_to_controller(&tran, sizeof(struct transfer));

	phy_free(results);
	phy_free(dtres);
	phy_free(appname);
	phy_free(memnode);
	phy_free(cpucore);
	return;
}

void run_autobindadd(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* appname = NULL;
	char* memnode = NULL;
	char* cpucore = NULL;
	char* dtres = NULL;

	appname = get_str_between_two_words(td.mes, "appname=", ";");
	memnode = get_str_between_two_words(td.mes, "memnode=", ";");
	cpucore = get_str_between_two_words(td.mes, "cpucore=", NULL);

	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s/%s/exec_reload_config -a -p %s -n %s -c %s; %s/%s/exec_reload_config -l", dstdir, cornam, appname, memnode, cpucore, dstdir, cornam);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line2>>>", "<<<This is a beautiful segmentation line2>>>");

	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = DETECT;
	tran.mma.mst = FINISH;
	tran.td.affi = ABINDADD;
	phy_snprintf(tran.td.mes, 1024, dtres);
	write_message_to_controller(&tran, sizeof(struct transfer));

	phy_free(results);
	phy_free(dtres);
	phy_free(appname);
	phy_free(memnode);
	phy_free(cpucore);
	return;
}

void run_autobinddel(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* dtres = NULL;
	char delcmd[BUFLEN] = {0};
	char* token = NULL;
	char delcmdlst[BUFLEN] = {0};
	int segflg = 0;
	char segstr[BUFLEN] = {0};

	phy_snprintf(delcmd, BUFLEN, "%s/%s/exec_reload_config -d -p ", dstdir, cornam);
	token = strtok(td.mes, ";");
	while(token != NULL){
		strcat(delcmdlst, delcmd);
		strcat(delcmdlst, token);
		strcat(delcmdlst, ";");
		token = strtok(NULL, ";");
		segflg++;
	}

	phy_snprintf(segstr, BUFLEN, "<<<This is a beautiful segmentation line%d>>>", ++segflg);

	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s%s/%s/exec_reload_config -l", delcmdlst, dstdir, cornam);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);//cmd必须以";"结尾，不能有空格

	dtres = parse_results(results, segstr, segstr);

	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = DETECT;
	tran.mma.mst = FINISH;
	tran.td.affi = ABINDDEL;
	phy_snprintf(tran.td.mes, 1024, dtres);
	write_message_to_controller(&tran, sizeof(struct transfer));

	phy_free(results);
	phy_free(dtres);

	return;
}

void run_autobinddel_local(const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* dtres = NULL;
	char delcmd[BUFLEN] = {0};
	char* token = NULL;
	char delcmdlst[BUFLEN] = {0};
	int segflg = 0;
	char segstr[BUFLEN] = {0};

	phy_snprintf(delcmd, BUFLEN, "%s/%s/exec_reload_config -d -p ", dstdir, cornam);
	token = strtok(td.mes, ";");
	while(token != NULL){
		strcat(delcmdlst, delcmd);
		strcat(delcmdlst, token);
		strcat(delcmdlst, ";");
		token = strtok(NULL, ";");
		segflg++;
	}

	phy_snprintf(segstr, BUFLEN, "<<<This is a beautiful segmentation line%d>>>", ++segflg);

	//执行脚本
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s%s/%s/exec_reload_config -l", delcmdlst, dstdir, cornam);
	forkpty_local(pwd, td.skey, cmd, 0, &results, -1);//cmd必须以";"结尾，不能有空格

	dtres = parse_results(results, segstr, segstr);

	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = DETECT;
	tran.mma.mst = FINISH;
	tran.td.affi = ABINDDEL;
	phy_snprintf(tran.td.mes, 1024, dtres);
	write_message_to_controller(&tran, sizeof(struct transfer));

	phy_free(results);
	phy_free(dtres);

	return;
}
char curusr[256] = "";
void run_autobindlst(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* dtres = NULL;
	char modpath[256] = {0};
	char tmpstr[256] = {0};

	if(strcmp(curusr, usr) != 0){//切换用户
		memset(curusr, 0, sizeof(curusr));
		strcpy(curusr, usr);
		//删除资源
		memset(cmd, 0, BUFLEN);
		phy_snprintf(cmd, BUFLEN, "sudo rm -rf %s/%s", dstdir, cornam);
		forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);
		phy_free(results);
	}
	//推送资源
	phy_snprintf(modpath, 256, "%s/%s", rsrcdir, cornam);
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "rsync -azu %s %s@%s:%s/", modpath, usr, add, dstdir);
	forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 4, &results, -1);
	phy_free(results);

	//执行命令
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s/%s/exec_reload_config -l", dstdir, cornam);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");

	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = DETECT;
	tran.mma.mst = FINISH;
	tran.td.affi = ABINDLIST;
	phy_snprintf(tran.td.mes, 1024, dtres);
	write_message_to_controller(&tran, sizeof(struct transfer));

	phy_free(results);
	phy_free(dtres);

	return;
}

void run_autobindlst_local(const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* dtres = NULL;
	char modpath[256] = {0};
	char tmpstr[256] = {0};

	if(strcmp(curusr, usr) != 0){//切换用户
		memset(curusr, 0, sizeof(curusr));
		strcpy(curusr, usr);
		//删除资源
		memset(cmd, 0, BUFLEN);
		phy_snprintf(cmd, BUFLEN, "sudo rm -rf %s/%s", dstdir, cornam);
		forkpty_local(pwd, td.skey, cmd, 0, &results, -1);
		phy_free(results);
	}

	//推送资源
	phy_snprintf(modpath, 256, "%s/%s", rsrcdir, cornam);
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "cp -rp %s %s/", modpath, dstdir);
	forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
	phy_free(results);

	//执行命令
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s/%s/exec_reload_config -l", dstdir, cornam);
	forkpty_local(pwd, td.skey, cmd, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");

	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = DETECT;
	tran.mma.mst = FINISH;
	tran.td.affi = ABINDLIST;
	phy_snprintf(tran.td.mes, 1024, dtres);
	write_message_to_controller(&tran, sizeof(struct transfer));

	phy_free(results);
	phy_free(dtres);

#undef resdir
#undef rsrcdir
#undef dstdir
#undef tmpdir

	return;
}

void run_autobindsta_local(const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* appname = NULL;
	char* appargs = NULL;
	char* dtres = NULL;
	char outpath[256] = {0};

	appname = get_str_between_two_words(td.mes, "appname=", ";");
	appargs = get_str_between_two_words(td.mes, "appargs=", NULL);

	phy_snprintf(outpath, 256, "%s/%s/nohup.out", dstdir, cornam);

	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "nohup %s/%s/staapp.sh \"%s %s\" > %s 2> /dev/null; %s/%s/autobind_getpid.sh %s", dstdir, cornam, appname, appargs, outpath, dstdir, cornam, outpath);
	forkpty_local(pwd, td.skey, cmd, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line2>>>", "<<<This is a beautiful segmentation line2>>>");
	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = MESS;
	tran.mma.mme = FINISH;
	tran.td.affi = ABINDSTA;
	phy_snprintf(tran.td.mes, 1024, "%s启动成功", dtres);
	write_message_to_controller(&tran, sizeof(struct transfer));

	phy_free(results);
	phy_free(appname);
	phy_free(appargs);
#undef resdir
#undef rsrcdir
#undef dstdir
#undef tmpdir
}

void run_autobindsta(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{//numa启动绑核
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* appname = NULL;
	char* appargs = NULL;
	char* dtres = NULL;
	char outpath[256] = {0};

	appname = get_str_between_two_words(td.mes, "appname=", ";");
	appargs = get_str_between_two_words(td.mes, "appargs=", NULL);

	phy_snprintf(outpath, 256, "%s/%s/nohup.out", dstdir, cornam);

	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "nohup %s/%s/staapp.sh \"%s %s\" > %s 2> /dev/null; %s/%s/autobind_getpid.sh %s", dstdir, cornam, appname, appargs, outpath, dstdir, cornam, outpath);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line2>>>", "<<<This is a beautiful segmentation line2>>>");

	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = MESS;
	tran.mma.mme = FINISH;
	tran.td.affi = ABINDSTA;
	phy_snprintf(tran.td.mes, 1024, "%s启动成功", dtres);
	write_message_to_controller(&tran, sizeof(struct transfer));

	phy_free(dtres);
	phy_free(results);
	phy_free(appname);
	phy_free(appargs);
#undef resdir
#undef rsrcdir
#undef dstdir
#undef tmpdir
}

void run_autobindstp_local(const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* appname = NULL;

	appname = get_str_between_two_words(td.mes, "appname=", NULL);

	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "killall %s", appname);
	forkpty_local(pwd, td.skey, cmd, 0, &results, -1);

	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = MESS;
	tran.mma.mme = FINISH;
	tran.td.affi = ABINDSTP;
	phy_snprintf(tran.td.mes, 1024, "已终止 %s", appname);
	write_message_to_controller(&tran, sizeof(struct transfer));

	phy_free(results);
	phy_free(appname);
#undef resdir
#undef rsrcdir
#undef dstdir
#undef tmpdir
}

void run_autobindstp(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* appname = NULL;

	appname = get_str_between_two_words(td.mes, "appname=", NULL);

	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "killall %s", appname);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);

	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = MESS;
	tran.mma.mme = FINISH;
	tran.td.affi = ABINDSTP;
	phy_snprintf(tran.td.mes, 1024, "已终止 %s", appname);
	write_message_to_controller(&tran, sizeof(struct transfer));

	phy_free(results);
	phy_free(appname);

#undef resdir
#undef rsrcdir
#undef dstdir
#undef tmpdir
}

void run_envstp_local(const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* appname = NULL;

	appname = get_str_between_two_words(td.mes, "appname=", NULL);

	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "sudo killall %s", appname);
	forkpty_local(pwd, td.skey, cmd, 0, &results, -1);
	phy_free(results);

#undef resdir
#undef rsrcdir
#undef dstdir
#undef tmpdir
}

void run_envstp(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char* appname = NULL;

	appname = get_str_between_two_words(td.mes, "appname=", NULL);

	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "sudo killall %s", appname);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);
	phy_free(results);

#undef resdir
#undef rsrcdir
#undef dstdir
#undef tmpdir
}

void envpid_func(void *arg)
{
	struct thread_args *args = (struct thread_args *)arg;
	const char *add = args->add;
	const char *usr = args->usr;
	const char *pwd = args->pwd;
	const char *spwd = args->spwd;
	const char *cmd = args->cmd;
	int flg = args->flg;
	char **results = args->results;
	int timeout_sec = args->timeout_sec;
	forkpty_cutlines(add, usr, pwd, spwd, cmd, flg, results, timeout_sec);
}

void run_env_local(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char tmpstr[256] = {0};
	char tmpresfile[256] = {0};
	char tmptopopngfile[256] = {0};
	char modpath[256] = {0};
	char* pidArg = NULL;
	char* intervalArg = NULL;
	char* timesArg = NULL;
	FILE* fp = NULL;

	pidArg = get_str_between_two_words(td.mes, "pid=", ";");
	intervalArg = get_str_between_two_words(td.mes, "interval=", ";");
	timesArg = get_str_between_two_words(td.mes, "times=", NULL);
	//创建结果存放目录
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "mkdir -p %s/%s", resdir, add);
	forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
	phy_free(results);
	//推送资源
	phy_snprintf(modpath, 256, "%s/%s", rsrcdir, cornam);
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "cp -rp %s %s/", modpath, dstdir);
	forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
	phy_free(results);

	//for 记录模式 topopng resfile
	phy_snprintf(tmptopopngfile, 256, "%s/%s/env_%s.png", resdir, add, td.date);

	//主线程
	memset(cmd, 0, BUFLEN);
	if(pidArg == NULL){
		phy_snprintf(cmd, BUFLEN, "sudo %s/%s/env_monitor.sh \"%s\" \"%s\"; lstopo %s", dstdir, cornam, intervalArg, timesArg, tmptopopngfile);
	}else{
		phy_snprintf(cmd, BUFLEN, "sudo %s/%s/env_monitor.sh \"%s\" \"%s\" \"%s\"; lstopo %s", dstdir, cornam, intervalArg, timesArg, pidArg, tmptopopngfile);
	}

	forkpty_local(pwd, td.skey, cmd, 0, &results, -1);

	//停止按钮
	if(fil_isexist("/tmp/kilflg") == true){
		phy_free(results);
		return;
	}

	//将json结果存入/tmp/临时路径下，与ui端通信
	phy_snprintf(tmpresfile, 256, "%s/%s/env_%s.res", resdir, add, td.date);
	fp = fopen(tmpresfile, "w");
	fprintf(fp, "%s", results);
	phy_free(results);
	fclose(fp);
	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = DETECT;
	tran.mma.mst = FINISH;
	tran.td.affi = ENV;
	phy_snprintf(tran.td.mes, 1024, "%s;", tmpresfile);
	write_message_to_controller(&tran, sizeof(struct transfer));

	insert_history(td.receiver, MDE2STR(mde), td.date, cmd, tran.td.mes);
#undef resdir
#undef rsrcdir
#undef dstdir
#undef tmpdir
	return;
}

void run_env(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	char tmpstr[256] = {0};
	char tmpresfile[256] = {0};
	char tmptopopngfile[256] = {0};
	char modpath[256] = {0};
	char* pidArg = NULL;
	char* intervalArg = NULL;
	char* timesArg = NULL;
	FILE* fp = NULL;

	pidArg = get_str_between_two_words(td.mes, "pid=", ";");
	intervalArg = get_str_between_two_words(td.mes, "interval=", ";");
	timesArg = get_str_between_two_words(td.mes, "times=", NULL);
	//创建结果存放目录
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "mkdir -p %s/%s", resdir, add);
	forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 4, &results, -1);
	phy_free(results);
	//推送资源
	phy_snprintf(modpath, 256, "%s/%s", rsrcdir, cornam);
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "rsync -azu %s %s@%s:%s/", modpath, usr, add, dstdir);
	forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 4, &results, -1);
	phy_free(results);

	//主线程
	memset(cmd, 0, BUFLEN);
	if(pidArg == NULL){
		phy_snprintf(cmd, BUFLEN, "sudo %s/%s/env_monitor.sh \"%s\" \"%s\"; sudo rm -f /tmp/env/numatopo.png; lstopo /tmp/env/numatopo.png", dstdir, cornam, intervalArg, timesArg);
	}else{
		phy_snprintf(cmd, BUFLEN, "sudo %s/%s/env_monitor.sh \"%s\" \"%s\" \"%s\"; sudo rm -f /tmp/env/numatopo.png; lstopo /tmp/env/numatopo.png", dstdir, cornam, intervalArg, timesArg, pidArg);
	}

	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);

	//停止按钮
	if(fil_isexist("/tmp/kilflg") == true){
		phy_free(results);
		return;
	}

	//将json结果存入/tmp/临时路径下，与ui端通信4
	phy_snprintf(tmptopopngfile, 256, "%s/%s/env_%s.png", resdir, add, td.date);
	phy_snprintf(tmpresfile, 256, "%s/%s/env_%s.res", resdir, add, td.date);
	fp = fopen(tmpresfile, "w");
	fprintf(fp, "%s", results);
	phy_free(results);
	fclose(fp);

	//回传numatopo.png
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "scp %s@%s:/tmp/env/numatopo.png %s", usr, add, tmptopopngfile);
	forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 4, &results, -1);
	phy_free(results);

	//发送结果路径，代表已分析结束
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = DETECT;
	tran.mma.mst = FINISH;
	tran.td.affi = ENV;
	phy_snprintf(tran.td.mes, 1024, "%s;", tmpresfile);
	write_message_to_controller(&tran, sizeof(struct transfer));

	insert_history(td.receiver, MDE2STR(mde), td.date, cmd, tran.td.mes);

#undef resdir
#undef rsrcdir
#undef dstdir
#undef tmpdir
	return;
}

void send_envmonitor(mestype matp, messta smtp, int affi, char* mes)
{
	struct transfer tran;
	memset(&tran, 0, sizeof(struct transfer));
	tran.mma.matp = matp;
	tran.mma.mst = smtp;
	tran.td.affi = affi;

	phy_snprintf(tran.td.mes, 1024, "%s", mes);
	write_message_to_controller(&tran, sizeof(struct transfer));
}

void* envmonitor_func(void *arg) {
	struct thread_args *args = (struct thread_args *)arg;
	const char *add = args->add;
	const char *usr = args->usr;
	const char *pwd = args->pwd;
	const char *spwd = args->spwd;
	const char *date = args->date;
	const char *cmd = args->cmd;
	int flg = args->flg;
	char **results = args->results;
	int timeout_sec = args->timeout_sec;
	forkpty_envmonitor(add, usr, pwd, spwd, cmd, flg, results, timeout_sec, date);
	return NULL;
}

void run_envmonitor(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char modpath[256] = {0};
	char tmpstr[256] = {0};
	char cmd[BUFLEN] = {0};
	char cmd2[BUFLEN] = {0};
	char cmd3[BUFLEN] = {0};
	char cmd4[BUFLEN] = {0};
	char* results = NULL;
	char* pidArg = NULL;

	pidArg = get_str_between_two_words(td.mes, "pid=", ";");
	char static_table_filename[256] = {0};
	memset(static_table_filename, 0, 256);
	phy_snprintf(static_table_filename, 256, "/opt/phytune/server/results/%s/envrt_sta_table_%s_res", add, td.date);

	fil_remove("/tmp/kilflg");
	fil_remove("/tmp/chlpid");
	fil_remove("/tmp/stopflg");

	//创建结果存放目录
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "mkdir -p %s/%s", resdir, add);
	forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 4, &results, -1);
	phy_free(results);

	//远程清理，确保正确运行
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "sudo killall env_monitorRT.sh sar mpstat; sudo rm -rf /tmp/envrt");
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);
	phy_free(results);

	//推送系统设置表格脚本
	phy_snprintf(modpath, 256, "%s/%s", rsrcdir, cornam);
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "rsync -azu %s %s@%s:%s/", modpath, usr, add, dstdir);
	forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 4, &results, -1);
	phy_free(results);

	//静态表格信息
	memset(cmd4, 0, BUFLEN);
	phy_snprintf(cmd4, BUFLEN, "sudo %s/%s/env_monitor.sh", dstdir, cornam);
	forkpty_cutlines(add, usr, pwd, td.skey, cmd4, 0, &results, -1);
	FILE* fp = NULL;
	fp = fopen(static_table_filename, "w");
	fprintf(fp, "%s", results);
	phy_free(results);
	fclose(fp);

	//初始化
	pthread_mutex_init(&envRTLock, NULL);
	pthread_cond_init(&envRTCond, NULL);
	envRTReady[0] = 0;
	envRTReady[1] = 0;
	envRTReady[2] = 0;//pidkillflg
	envRTReady[3] = 0;
	phy_free(envRTRes);

	//table子线程
	memset(cmd3, 0, BUFLEN);
	if(pidArg == NULL){
		phy_snprintf(cmd3, BUFLEN, "sudo bash %s/%s/env_monitorRT.sh", dstdir, cornam);
	}else{
		phy_snprintf(cmd3, BUFLEN, "sudo bash %s/%s/env_monitorRT.sh %s", dstdir, cornam, pidArg);
	}

	struct thread_args tableArgs;
	tableArgs.add = add;
	tableArgs.usr = usr;
	tableArgs.pwd = pwd;
	tableArgs.spwd = td.skey;
	tableArgs.date = td.date;
	tableArgs.cmd = cmd3;
	tableArgs.flg = 0;
	tableArgs.results = &results;
	tableArgs.timeout_sec = -1;
	pthread_t tableThread;
	if (pthread_create(&tableThread, NULL, envmonitor_func, (void *)&tableArgs) != 0) {
		perror("pthread_create");
		return;
	}

	//mpstat线程
	memset(cmd, 0, BUFLEN);
	//tail -f是为了将转存的文件实时打印，如果直接使用mpstat -P ALL 1结果存在系统转义符
	//mpstat -P ALL 1 > /tmp/mpstat.res & tail -f /tmp/mpstat.res
	phy_snprintf(cmd, BUFLEN, "mpstat -P ALL 1 > /tmp/envrt/mpstat.res & tail -f /tmp/envrt/mpstat.res");
	struct thread_args mpstatArgs;
	mpstatArgs.add = add;
	mpstatArgs.usr = usr;
	mpstatArgs.pwd = pwd;
	mpstatArgs.spwd = td.skey;
	mpstatArgs.date = td.date;
	mpstatArgs.cmd = cmd;
	mpstatArgs.flg = 0;
	mpstatArgs.results = &results;
	mpstatArgs.timeout_sec = -1;
	//创建子线程，执行forkpty_cutlines历程函数
	pthread_t mpstatThread;
    if (pthread_create(&mpstatThread, NULL, envmonitor_func, (void *)&mpstatArgs) != 0) {
        perror("pthread_create");
        return;
    }
	//sar线程
    //sar -q -r -B -d -S -W -n DEV -n EDEV 1 > /tmp/sar.res & tail -f /tmp/sar.res
	memset(cmd2, 0, BUFLEN);
	phy_snprintf(cmd2, BUFLEN, "sar -q -r -B -d -S -W -n DEV -n EDEV 1 > /tmp/envrt/sar.res & tail -f /tmp/envrt/sar.res");
	struct thread_args sarArgs;
	sarArgs.add = add;
	sarArgs.usr = usr;
	sarArgs.pwd = pwd;
	sarArgs.spwd = td.skey;
	sarArgs.date = td.date;
	sarArgs.cmd = cmd2;
	sarArgs.flg = 0;
	sarArgs.results = &results;
	sarArgs.timeout_sec = -1;
	//创建子线程，执行forkpty_cutlines历程函数
	pthread_t sarThread;
    if (pthread_create(&sarThread, NULL, envmonitor_func, (void *)&sarArgs) != 0) {
        perror("pthread_create");
        return;
    }

    pthread_join(mpstatThread, NULL);
    pthread_join(sarThread, NULL);
    pthread_join(tableThread, NULL);

	pthread_mutex_destroy(&envRTLock);
	pthread_cond_destroy(&envRTCond);
	//删除临时文件
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "rm -rf /tmp/envrt");
	forkpty_cutlines(add, usr, pwd, td.skey, cmd, 0, &results, -1);
	phy_free(results);

	//停止标记
	FILE* stopfp = NULL;
	stopfp = fopen("/tmp/stopflg", "w");
	fprintf(stopfp, "1");
	fclose(stopfp);
	return;
}

void run_datop_local(const char* usr, const char* pwd, const char* spwd)
{
#define dstdir "/tmp"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"

	char modpath[256] = {0};
	char tmpstr[256] = {0};
	char* results = NULL;
	//推送资源
	phy_snprintf(modpath, 256, "%s/fs-datop", rsrcdir);
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "cp -rp %s %s/", modpath, dstdir);
	forkpty_local(pwd, spwd, tmpstr, 0, &results, -1);
	phy_free(results);
	//运行datopinstall.sh
	FILE* fp = NULL;
	fp = fopen("/tmp/datop_ins_flg", "w");
	fprintf(fp, "1");
	fclose(fp);
}

void run_datop(const char* add, const char* usr, const char* pwd, const char* spwd)
{
#define dstdir "/tmp"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"

	char modpath[256] = {0};
	char tmpstr[256] = {0};
	char* results = NULL;
	//推送资源
	phy_snprintf(modpath, 256, "%s/fs-datop", rsrcdir);
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "rsync -azu %s %s@%s:%s/", modpath, usr, add, dstdir);
	forkpty_cutlines(add, usr, pwd, spwd, tmpstr, 4, &results, -1);
	phy_free(results);
	//运行datopinstall.sh
	FILE* fp = NULL;
	fp = fopen("/tmp/datop_ins_flg", "w");
	fprintf(fp, "1");
	fclose(fp);
}

void env_check_datop_local(const char* usr, const char* pwd, const char* spwd)
{
#define dstdir "/tmp"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	//DAMON检测
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "sudo ls /sys/kernel/debug/damon");
	forkpty_local(pwd, 0, cmd, 0, &results, -1);
	FILE* fp = NULL;
	fp = fopen("/tmp/datop_envcheck_flg", "w");
	if(strstr(results, "cannot") || strstr(results, "无法访问")){
		fprintf(fp, "1");
		fclose(fp);
		phy_free(results);
		return;
	}else if(!strstr(results, "init_regions")){
		fprintf(fp, "2");
		fclose(fp);
		phy_free(results);
		return;
	}else{
		fprintf(fp, "0");
		fclose(fp);
		phy_free(results);
		return;
	}
}

void env_check_datop(const char* add, const char* usr, const char* pwd, const char* spwd)
{
#define dstdir "/tmp"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"

	char* results = NULL;
	char cmd[BUFLEN] = {0};
	//DAMON检测
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "sudo ls /sys/kernel/debug/damon");
	forkpty_cutlines(add, usr, pwd, 0, cmd, 0, &results, -1);
	FILE* fp = NULL;
	fp = fopen("/tmp/datop_envcheck_flg", "w");
	if(strstr(results, "cannot") || strstr(results, "无法访问")){
		fprintf(fp, "1");
		fclose(fp);
		phy_free(results);
		return;
	}else if(!strstr(results, "init_regions")){
		fprintf(fp, "2");
		fclose(fp);
		phy_free(results);
		return;
	}else{
		fprintf(fp, "0");
		fclose(fp);
		phy_free(results);
		return;
	}
}

void run_detect_topdown_local(const char* add, const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resfil "/opt/phytune/server/results/$add/$type_$date.res"
#define moddir "/opt/phytune/agent/arm/modules"
#define resdir "/opt/phytune/server/results"
#define dstdir "/tmp"

	char tmpstr[512] = {0};
	char tmppro[256] = {0};
	char* results = NULL;
	char* dtres = NULL;

	char resdes[256] = {0};

	char* pinstr = NULL;
	char* ponstr= NULL;

	char* modpath = NULL;
	char* tarpro = NULL;
	char* tarpth = NULL;

	char* pcmd = NULL;
	FILE* fp = NULL;

	char* jsonfl = NULL;
	char* chartjsonfile = NULL;
	char* interval = NULL;
//建立结果文件夹
	memset(tmpstr, 0, sizeof(tmpstr));
	phy_snprintf(tmpstr, sizeof(tmpstr), "mkdir -p %s/%s",  resdir, add);
	forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
	phy_free(results);

//推送topdown
	modpath = load_filpath(moddir, cornam);
	memset(tmpstr, 0, sizeof(tmpstr));
	phy_snprintf(tmpstr, sizeof(tmpstr), "cp -rp %s %s/", modpath, dstdir);
	forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
	phy_free(results);
//推送tarpro
	tarpro = get_str_between_two_words(td.mes, "tarpro=", ";");
	if(tarpro != NULL){
		tarpth = load_filpath(moddir, tarpro);
		if(NULL != tarpth){
			memset(tmpstr, 0, sizeof(tmpstr));
			phy_snprintf(tmpstr, sizeof(tmpstr), "cp -rp %s %s/", tarpth, dstdir);
			forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
			phy_free(results);
		}
	}

//执行topdown
//结果路径
	memset(tmpstr, 0, sizeof(tmpstr));
	phy_snprintf(tmpstr, sizeof(tmpstr), "%s/%s/topdown-tool", dstdir, cornam);

	interval = get_str_between_two_words(td.mes, "interval=", ";");

	pinstr = string_replace(resfil, "$add", add);
	ponstr = string_replace(pinstr, "$type", cornam);
	phy_free(pinstr);
	pinstr = string_replace(ponstr, "$date", td.date);
	phy_free(ponstr);

	if(interval == NULL){
		phy_snprintf(resdes, 256, "%s", pinstr);
		jsonfl = string_replace(pinstr, ".res", "_table.json");
	}else{
		jsonfl = string_replace(pinstr, ".res", "_table.json");
		ponstr = string_replace(pinstr, ".res", ".csv");
		phy_snprintf(resdes, 256, "%s", ponstr);
		phy_free(ponstr);
	}
	phy_free(pinstr);

	memset(tmppro, 0, 256);
	if(tarpth != NULL){
		phy_snprintf(tmppro, 256, "/tmp/%s", tarpro);
	}else{
		if(tarpro != NULL){
			phy_snprintf(tmppro, 256, "%s", tarpro);
		}
	}
//参数
	if(interval == NULL){
		pcmd = arg_parser(td.mes, tmppro, TOPDOWN);
		if(pcmd == NULL){
			slgflg = true;
			return;
		}
		memset(tmpstr, 0, sizeof(tmpstr));
		phy_snprintf(tmpstr, sizeof(tmpstr), "%s/%s/topdown-tool %s", dstdir, cornam, pcmd);
	}else{
		memset(tmpstr, 0, sizeof(tmpstr));
		phy_snprintf(tmpstr, sizeof(tmpstr), "/tmp/topdown_csv.res %s", tmppro);
		pcmd = arg_parser(td.mes, tmpstr, TOPDOWN);
		if(pcmd == NULL){
			slgflg = true;
			return;
		}
	}

//运行
	if(interval == NULL){
		forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
	}else{
		phy_snprintf(tmpstr, sizeof(tmpstr), "%s/%s/topdown-tool %s", dstdir, cornam, pcmd);
		forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);

		memset(tmpstr, 0, sizeof(tmpstr));
		phy_free(results);

		phy_snprintf(tmpstr, sizeof(tmpstr), "cat %s", "/tmp/topdown_csv.res", pcmd);
		forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
	}

	slgflg = true;

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL || (fil_isexist("/tmp/kilflg") == true)){
		send_message(MESS, ERROR, TOPDOWN, "发生执行错误！");
		goto texit;
	}
	fp = fopen(resdes, "w+");
		fprintf(fp, "%s", dtres);
	fclose(fp);

	if(interval != NULL){
		phy_snprintf(tmpstr, sizeof(tmpstr), "rm -f %s", "/tmp/topdown_csv.res", pcmd);
		forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
		phy_free(results);
	}
	phy_snprintf(tmpstr, sizeof(tmpstr), "rm -rf %s %s", "/tmp/topdown /tmp/%s", pcmd, tarpro);
	forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
	phy_free(results);
//解析
	if(false == topdown_orig_to_json(resdes, jsonfl, &chartjsonfile)){
		sleep(1);
		phy_log(LOG_LEVEL_ERR, "run_detect_topdown: %s json file error.", resdes);
		send_message(MESS, ERROR, TOPDOWN, "json file error.");
		phy_free(jsonfl);
		phy_free(chartjsonfile);

		return;
	}
	memset(tmpstr, 0, sizeof(tmpstr));
	phy_snprintf(tmpstr, sizeof(tmpstr), "%s;%s", jsonfl, chartjsonfile);
	if( !is_json(jsonfl) || !is_json(chartjsonfile)){
		send_message(MESS, ERROR, TOPDOWN, "json file error.");
	}else{
		send_message(DETECT, FINISH, TOPDOWN, tmpstr);
	}
texit:
	forkpty_local(pwd, td.skey, "rm -rf /tmp/topdown", 0, &results, -1);
	phy_free(results);
	if(tarpth != NULL){
		memset(tmpstr, 0, sizeof(tmpstr));
		phy_snprintf(tmpstr, sizeof(tmpstr), "rm -f %s", tmppro);
		forkpty_local(pwd, td.skey, tmpstr, 0, &results, -1);
		phy_free(results);
	}
	phy_free(jsonfl);
	phy_free(chartjsonfile);
}

void run_detect_topdown(const char* add, const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{

#define resfil "/opt/phytune/server/results/$add/$type_$date.res"
#define moddir "/opt/phytune/agent/arm/modules"
#define resdir "/opt/phytune/server/results"
#define dstdir "/tmp"

	char tmpstr[512] = {0};
	char tmppro[256] = {0};
	char* results = NULL;
	char* dtres = NULL;

	char resdes[256] = {0};

	char* pinstr = NULL;
	char* ponstr= NULL;

	char* modpath = NULL;
	char* tarpro = NULL;
	char* tarpth = NULL;

	char* pcmd = NULL;
	FILE* fp = NULL;

	char* jsonfl = NULL;
	char* chartjsonfile = NULL;
	char* interval = NULL;
//建立结果文件夹
	memset(tmpstr, 0, sizeof(tmpstr));
	phy_snprintf(tmpstr, sizeof(tmpstr), "mkdir -p %s/%s",  resdir, add);
	forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 4, &results, -1);
	phy_free(results);
//	system(tmpstr);
//	exit(0);
//推送topdown
	modpath = load_filpath(moddir, cornam);
	memset(tmpstr, 0, sizeof(tmpstr));
	phy_snprintf(tmpstr, sizeof(tmpstr), "scp -rp %s %s@%s:%s/", modpath, usr, add, dstdir);
	forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 4, &results, -1);
	phy_free(results);
//推送tarpro
	tarpro = get_str_between_two_words(td.mes, "tarpro=", ";");
	if(tarpro != NULL){
		tarpth = load_filpath(moddir, tarpro);
		if(NULL != tarpth){
			memset(tmpstr, 0, sizeof(tmpstr));
			phy_snprintf(tmpstr, sizeof(tmpstr), "scp -rp %s %s@%s:%s/", tarpth, usr, add, dstdir);
			forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 4, &results, -1);
			phy_free(results);
		}
	}

//执行topdown

//结果路径
	memset(tmpstr, 0, sizeof(tmpstr));
	phy_snprintf(tmpstr, sizeof(tmpstr), "%s/%s/topdown-tool", dstdir, cornam);

	interval = get_str_between_two_words(td.mes, "interval=", ";");

	pinstr = string_replace(resfil, "$add", add);
	ponstr = string_replace(pinstr, "$type", cornam);
	phy_free(pinstr);
	pinstr = string_replace(ponstr, "$date", td.date);
	phy_free(ponstr);

	if(interval == NULL){
		phy_snprintf(resdes, 256, "%s", pinstr);
		jsonfl = string_replace(pinstr, ".res", "_table.json");
	}else{
		jsonfl = string_replace(pinstr, ".res", "_int_table.json");
		ponstr = string_replace(pinstr, ".res", ".csv");
		phy_snprintf(resdes, 256, "%s", ponstr);
		phy_free(ponstr);
	}
	phy_free(pinstr);

	memset(tmppro, 0, 256);
	if(tarpth != NULL){
		phy_snprintf(tmppro, 256, "/tmp/%s", tarpro);
	}else{
		if(tarpro != NULL){
			phy_snprintf(tmppro, 256, "%s", tarpro);
		}
	}
//参数
	if(interval == NULL){
		pcmd = arg_parser(td.mes, tmppro, TOPDOWN);
		if(pcmd == NULL){
			slgflg = true;
			return;
		}
		memset(tmpstr, 0, sizeof(tmpstr));
		phy_snprintf(tmpstr, sizeof(tmpstr), "%s/%s/topdown-tool %s", dstdir, cornam, pcmd);
	}else{
		memset(tmpstr, 0, sizeof(tmpstr));
		phy_snprintf(tmpstr, sizeof(tmpstr), "/tmp/topdown_csv.res %s", tmppro);
		pcmd = arg_parser(td.mes, tmpstr, TOPDOWN);
		if(pcmd == NULL){
			slgflg = true;
			return;
		}
	}

//运行
	if(interval == NULL){
		forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 1, &results, -1);
	}else{
		phy_snprintf(tmpstr, sizeof(tmpstr), "%s/%s/topdown-tool %s", dstdir, cornam, pcmd);
		forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 1, &results, -1);

		memset(tmpstr, 0, sizeof(tmpstr));
		phy_free(results);

		phy_snprintf(tmpstr, sizeof(tmpstr), "cat %s", "/tmp/topdown_csv.res", pcmd);
		forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 1, &results, -1);
	}

	slgflg = true;

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL || (fil_isexist("/tmp/kilflg") == true)){
		send_message(MESS, ERROR, TOPDOWN, "发生执行错误！");
		goto texit;
	}else if(strstr(dtres,"insufficient time to collect information on all events")){
		send_message(MESS, ERROR, TOPDOWN, "可能由于没有足够的时间收集所有事件的信息，请尝试运行时间更长的程序！");
		goto texit;
	}
	fp = fopen(resdes, "w+");
		fprintf(fp, "%s", dtres);
	fclose(fp);

	if(interval != NULL){
		phy_snprintf(tmpstr, sizeof(tmpstr), "rm -f %s", "/tmp/topdown_csv.res", pcmd);
		forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 1, &results, -1);
		phy_free(results);
	}
	phy_snprintf(tmpstr, sizeof(tmpstr), "rm -rf %s %s", "/tmp/topdown /tmp/%s", pcmd, tarpro);
	forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 1, &results, -1);
	phy_free(results);
//解析
	if(false == topdown_orig_to_json(resdes, jsonfl, &chartjsonfile)){
		sleep(1);
		phy_log(LOG_LEVEL_ERR, "run_detect_topdown: %s json file error.", resdes);
		send_message(MESS, ERROR, TOPDOWN, "json file error.");
		phy_free(jsonfl);
		phy_free(chartjsonfile);

		return;
	}
	memset(tmpstr, 0, sizeof(tmpstr));
	phy_snprintf(tmpstr, sizeof(tmpstr), "%s;%s", jsonfl, chartjsonfile);
    if( get_file_size(resdes) < 128 ){
		send_message(MESS, ERROR, TOPDOWN, "此次计数有误，请重试！");
	} else if ( !is_json(jsonfl) || !is_json(chartjsonfile)){
		send_message(MESS, ERROR, TOPDOWN, "json file error.");
	} else {
		send_message(DETECT, FINISH, TOPDOWN, tmpstr);
	}
texit:
	forkpty_cutlines(add, usr, pwd, td.skey, "rm -rf /tmp/topdown", 1, &results, -1);
	phy_free(results);
	if(tarpth != NULL){
		memset(tmpstr, 0, sizeof(tmpstr));
		phy_snprintf(tmpstr, sizeof(tmpstr), "rm -f %s", tmppro);
		forkpty_cutlines(add, usr, pwd, td.skey, tmpstr, 1, &results, -1);
		phy_free(results);
	}
	phy_free(jsonfl);
	phy_free(chartjsonfile);
}

void run_detect_local(const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resfil "/opt/phytune/server/results/$add/$type_$date.res"
#define resdir "/opt/phytune/server/results"
#define moddir "/opt/phytune/agent/arm/modules"
#define dstdir "/tmp"
#define kilflg "/tmp/kilflg"

	char* results = NULL;
	char* dtres = NULL;
	char* results1 = NULL;
	char* type = NULL;
	FILE *fp = NULL;

	char* pinresfil = NULL;
	char* ponresfil = NULL;

	char* jsonfl = NULL;
	char* chartjsonfile = NULL;

	struct transfer tran = {0};
	char inscmd[256] = {0};

	char* modpath = NULL;
	char* tarpro = NULL;
	char* tarpth = NULL;
	char* pcmd = NULL;
	//type
	type = get_str_between_two_words(cornam, "pmu_", ".");
	//core path
	modpath = load_filpath(moddir, cornam);
	//target program
	tarpro = get_str_between_two_words(td.mes, "tarpro=", ";");

	if(tarpro != NULL){
		tarpth = load_filpath(moddir, tarpro);
		if(NULL != tarpth){
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "%s/%s", dstdir, tarpro);
			pcmd = arg_parser(td.mes, inscmd, mde);
		}else{
			pcmd = arg_parser(td.mes, tarpro, mde);
		}
	}else{
		pcmd = arg_parser(td.mes, tarpro, mde);
	}

	if(pcmd == NULL){
		phy_free(tarpro);
		goto meserr;
	}

//推送pmu
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "cp -rp %s %s/", modpath, dstdir);
	forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
	phy_free(results);

//推送agent中存在的待测程序
	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "cp -rp %s %s/", tarpth, dstdir);
		forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
		phy_free(results);
	}

	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "%s/%s %s", dstdir, cornam, pcmd);

//远程执行
	forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
	slgflg = true;
//解析结果
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "mkdir -p %s/%s", resdir, td.receiver);
	forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
	free(results1);

	pinresfil = string_replace(resfil, "$add", td.receiver);
	ponresfil = string_replace(pinresfil, "$type", type);
	phy_free(pinresfil);
	pinresfil = string_replace(ponresfil, "$date", td.date);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL){
		goto texit;
	}

	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
	}

	if(strstr(dtres, "[ERR]") || strstr(dtres, "failed:")){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "结果内容有错!");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}

	fp = fopen(pinresfil, "w+");
	fprintf(fp, "%s", dtres);
	fclose(fp);

	jsonfl = string_replace(pinresfil, ".res", ".json");
	pmu_orig_struct_to_json_p(pinresfil, jsonfl, &chartjsonfile);

	if(false == is_json(jsonfl) || false == is_json(chartjsonfile)){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "json file format error!");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}

	memset(tran.td.mes, 0, 1280);
	snprintf(tran.td.mes, 1280, "%s;%s", jsonfl, chartjsonfile);

	tran.mma.matp = DETECT;
	tran.mma.mde = FINISH;
	tran.td.affi = mde;

	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
	}

//insert history
	insert_history(td.receiver, MDE2STR(mde), td.date, pcmd, tran.td.mes);
	phy_free(pcmd);

	write_message_to_controller((char*)(&tran), sizeof(struct transfer));
	phy_free(jsonfl);
	phy_free(chartjsonfile);
	phy_free(type);

texit:
//清理临时文件
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, cornam);
	forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
	phy_free(results);

	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, tarpro);
		forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
		phy_free(results);
	}

	phy_free(tarpro);
#undef resfil
#undef resdir
#undef moddir
#undef dstdir
#undef pmsdir
#undef kilflg
	return;
meserr:
	goto texit;
}

void run_detect(const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resfil "/opt/phytune/server/results/$add/$type_$date.res"
#define resdir "/opt/phytune/server/results"
#define moddir "/opt/phytune/agent/arm/modules"
#define dstdir "/tmp"
#define kilflg "/tmp/kilflg"

	char* results = NULL;
	char* dtres = NULL;
	char* results1 = NULL;
	char* type = NULL;
	FILE *fp = NULL;

	char* pinresfil = NULL;
	char* ponresfil = NULL;

	char* jsonfl = NULL;
	char* chartjsonfile = NULL;

	struct transfer tran = {0};
	char inscmd[256] = {0};

	char* modpath = NULL;
	char* tarpro = NULL;
	char* tarpth = NULL;
	char* pcmd = NULL;
	//type
	type = get_str_between_two_words(cornam, "pmu_", ".");
	//core path
	modpath = load_filpath(moddir, cornam);
	//target program
	tarpro = get_str_between_two_words(td.mes, "tarpro=", ";");

	if(tarpro != NULL){
		tarpth = load_filpath(moddir, tarpro);
		if(NULL != tarpth){
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "%s/%s", dstdir, tarpro);
			pcmd = arg_parser(td.mes, inscmd, mde);
		}else{
			pcmd = arg_parser(td.mes, tarpro, mde);
		}
	}else{
		pcmd = arg_parser(td.mes, tarpro, mde);
	}

	if(pcmd == NULL){
		phy_free(tarpro);
		goto meserr;
	}

//推送pmu
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "scp -rp %s %s@%s:%s/", modpath, usr, td.receiver, dstdir);
	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 4, &results, -1);
	phy_free(modpath);
	phy_free(results);

//推送agent中存在的待测程序
	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "scp -rp %s %s@%s:/%s/", tarpth, usr, td.receiver, dstdir);
		forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 4, &results, -1);
		phy_free(results);
	}

	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "%s/%s %s", dstdir, cornam, pcmd);

//远程执行
//	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 0, &results, -1);
	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 1, &results, -1);
	slgflg = true;

//解析结果
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "mkdir -p %s/%s", resdir, td.receiver);
//	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 0, &results1, -1);
	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 4, &results1, -1);
	free(results1);


	pinresfil = string_replace(resfil, "$add", td.receiver);
	ponresfil = string_replace(pinresfil, "$type", type);
	phy_free(pinresfil);
	phy_free(type);
	pinresfil = string_replace(ponresfil, "$date", td.date);
	phy_free(ponresfil);
	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL){
		goto texit;
	}

	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
	}

	phy_free(results);

	search_and_extlin(dtres, ptary, &results);
	if(results != NULL){
		send_message(MESS, ERROR, mde, results);
		phy_free(results);
		goto texit;
	}

#if 0
	if(strstr(dtres, "[ERR]") || strstr(dtres, "failed:")){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "结果内容有错!");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}
#endif

	fp = fopen(pinresfil, "w+");
	fprintf(fp, "%s", dtres);
	fclose(fp);

	jsonfl = string_replace(pinresfil, ".res", ".json");
	pmu_orig_struct_to_json_p(pinresfil, jsonfl, &chartjsonfile);

	if(false == is_json(jsonfl) || false == is_json(chartjsonfile)){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "json file format error!");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}

	memset(tran.td.mes, 0, 1280);
	snprintf(tran.td.mes, 1280, "%s;%s", jsonfl, chartjsonfile);

	tran.mma.matp = DETECT;
	tran.mma.mde = FINISH;
	tran.td.affi = mde;

	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
	}

	write_message_to_controller((char*)(&tran), sizeof(struct transfer));
	phy_free(jsonfl);
	phy_free(chartjsonfile);
//	phy_free(type);

//insert history
	insert_history(td.receiver, MDE2STR(mde), td.date, pcmd, tran.td.mes);
	phy_free(pcmd);

texit:
	phy_free(pinresfil);
//清理临时文件
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, cornam);
	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 0, &results, -1);
	phy_free(results);

	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, tarpro);
		forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 0, &results, -1);
		phy_free(results);
	}

	phy_free(tarpro);
#undef resfil
#undef resdir
#undef moddir
#undef dstdir
#undef pmsdir
#undef kilflg
	return;

meserr:
//
	goto texit;
}

void run_detect_memacc(const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resfil "/opt/phytune/server/results/$add/$type_$date.res"
#define resdir "/opt/phytune/server/results"
#define moddir "/opt/phytune/agent/arm/modules"
#define dstdir "/tmp"
#define kilflg "/tmp/kilflg"


	char* results = NULL;
	char* dtres = NULL;

	char* type = NULL;
	FILE *fp = NULL;

	char* pinresfil = NULL;
	char* ponresfil = NULL;

	char* jsonfl = NULL;
	char* chartjsonfile = NULL;

	struct transfer tran = {0};
	char inscmd[256] = {0};

	char* modpath = NULL;
	char* tarpro = NULL;
	char* tarpth = NULL;
	char* pcmd = NULL;
	//type
	type = get_str_between_two_words(cornam, "memacc_", NULL);
	//core path
	modpath = load_filpath(moddir, cornam);
	//target program
	tarpro = get_str_between_two_words(td.mes, "tarpro=", ";");

	forkpty_cutlines(td.receiver, usr, pwd, td.skey, "nproc", 0, &results, -1);
	cpuNUM = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	phy_free(results);
	trim(cpuNUM);

	if(tarpro != NULL){
		tarpth = load_filpath(moddir, tarpro);
		if(NULL != tarpth){
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "%s/%s", dstdir, tarpro);
			pcmd = arg_parser(td.mes, inscmd, mde);
		}else{
			pcmd = arg_parser(td.mes, tarpro, mde);
		}
	}else{
		pcmd = arg_parser(td.mes, tarpro, mde);
	}

	if(pcmd == NULL){
		phy_free(tarpro);
		goto meserr;
	}

//推送pmu
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "scp -rp %s %s@%s:%s/", modpath, usr, td.receiver, dstdir);
	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 4, &results, -1);

	phy_free(results);

//推送agent中存在的待测程序
	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "scp -rp %s %s@%s:/%s/", tarpth, usr, td.receiver, dstdir);
		forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 4, &results, -1);
		phy_free(results);
	}

	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "%s/%s %s", dstdir, cornam, pcmd);

//远程执行
	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 1, &results, -1);
//	FILE * fp1 = NULL;
//	fp1 = fopen("/tmp/memacc.res", "w+");
//	fprintf(fp1, "%s", results);
//	fclose(fp1);
	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "res文件内存溢出，请适当减小采样时长!");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}

	slgflg = true;
//解析结果
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "mkdir -p %s/%s", resdir, td.receiver);
	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 4, &results, -1);
	phy_free(results);

	pinresfil = string_replace(resfil, "$add", td.receiver);

	char new_type[20];
	if(mde==ACCMEMSYS){
		strcpy(new_type, "sys_");
		strcat(new_type, type);
	}else{
		strcpy(new_type, "api_");
		strcat(new_type, type);
	}
	ponresfil = string_replace(pinresfil, "$type", new_type);
	phy_free(pinresfil);
	pinresfil = string_replace(ponresfil, "$date", td.date);

	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
	}

	if(strstr(type,"hit") && strstr(dtres,"linesize")==NULL){
		if(strstr(td.mes,"L1") || strstr(td.mes,"L2") || strstr(td.mes,"L3")){
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "%s", "该机器无法成功获取缓存部件的linesize大小，计算带宽失败。");
			send_message(MESS, ERROR, mde, inscmd);
			goto texit;
		}
	}else if(strstr(dtres,"sys_perf_event_open")){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "该进程不支持DDR相关事件的计数，请取消勾选DDR!");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}else if(strstr(dtres,"-p, --pid <pid>")){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "该进程活动已结束。");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}else if(strstr(type,"miss") && strstr(dtres,"has no samples")){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "该进程未捕获到相关miss事件。");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}else if(strstr(type,"miss") && strstr(dtres,"failed to set cpu bitmap")){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "该进程未捕获到相关miss事件。");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}

	fp = fopen(pinresfil, "w+");
	fprintf(fp, "%s", dtres);
	fclose(fp);

	jsonfl = string_replace(pinresfil, ".res", ".json");
	chartjsonfile= string_replace(pinresfil, ".res", "_chart.json");
	char cmd[1024] = {0};
	if (strstr(pinresfil, "hit") != NULL){
		phy_snprintf(cmd, 1024, "/opt/phytune/server/resource/hit_cpu_res2json %s %s %s",pinresfil, jsonfl, chartjsonfile);
	}else if (strstr(pinresfil, "miss") != NULL){
		phy_snprintf(cmd, 1024, "/opt/phytune/server/resource/miss_res2json %s %s %s",pinresfil, jsonfl, chartjsonfile);
	}
	forkpty_cutlines(td.receiver, usr, pwd, td.skey, cmd, 4, &results, -1);
	FILE * fp1 = NULL;
	fp1 = fopen("/tmp/memacc.res", "w+");
	fprintf(fp1, "%s", results);
	fclose(fp1);
	phy_free(results);

	if(false==not_empty_json(jsonfl) || false == not_empty_json(chartjsonfile)){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "相关性能计数器未成功计数!");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}
	if(false == is_json(jsonfl) || false == is_json(chartjsonfile)){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "json file format error!");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}

	memset(tran.td.mes, 0, 1280);
	snprintf(tran.td.mes, 1280, "%s;%s", jsonfl, chartjsonfile);

	tran.mma.matp = DETECT;
	tran.mma.mde = FINISH;
	tran.td.affi = mde;

	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
	}

	write_message_to_controller((char*)(&tran), sizeof(struct transfer));
	phy_free(jsonfl);
	phy_free(chartjsonfile);
	phy_free(type);

texit:
//清理临时文件
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, cornam);
	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 0, &results, -1);

	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, tarpro);
		forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 0, &results, -1);
	}

	phy_free(tarpro);
#undef resfil
#undef resdir
#undef moddir
#undef dstdir
#undef kilflg
	return;

meserr:
//
	goto texit;
}

void run_detect_memacc_local(const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resfil "/opt/phytune/server/results/$add/$type_$date.res"
#define resdir "/opt/phytune/server/results"
#define moddir "/opt/phytune/agent/arm/modules"
#define dstdir "/tmp"
#define kilflg "/tmp/kilflg"


	char* results = NULL;
	char* dtres = NULL;

	char* type = NULL;
	FILE *fp = NULL;

	char* pinresfil = NULL;
	char* ponresfil = NULL;

	char* jsonfl = NULL;
	char* chartjsonfile = NULL;

	struct transfer tran = {0};
	char inscmd[256] = {0};

	char* modpath = NULL;
	char* tarpro = NULL;
	char* tarpth = NULL;
	char* pcmd = NULL;
	//type
	type = get_str_between_two_words(cornam, "memacc_", NULL);
	//core path
	modpath = load_filpath(moddir, cornam);
	//target program
	tarpro = get_str_between_two_words(td.mes, "tarpro=", ";");

	forkpty_local(pwd, td.skey, "nproc", 0, &results, -1);
	cpuNUM = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	phy_free(results);
	trim(cpuNUM);

	if(tarpro != NULL){
		tarpth = load_filpath(moddir, tarpro);
		if(NULL != tarpth){
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "%s/%s", dstdir, tarpro);
			pcmd = arg_parser(td.mes, inscmd, mde);
		}else{
			pcmd = arg_parser(td.mes, tarpro, mde);
		}
	}else{
		pcmd = arg_parser(td.mes, tarpro, mde);
	}

	if(pcmd == NULL){
		phy_free(tarpro);
		goto meserr;
	}

//推送pmu
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "cp -rp %s %s/", modpath, dstdir);
	forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
	phy_free(results);

//推送agent中存在的待测程序
	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "cp -rp %s %s/", tarpth, dstdir);
		forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
		phy_free(results);
	}

	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "%s/%s %s", dstdir, cornam, pcmd);

//远程执行
//	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 1, &results, -1);
	forkpty_local(pwd, td.skey, inscmd, 1, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "res文件内存溢出，请适当减小采样时长!");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}

	slgflg = true;
//解析结果
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "mkdir -p %s/%s", resdir, td.receiver);
	forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
	phy_free(results);

	pinresfil = string_replace(resfil, "$add", td.receiver);

	char new_type[20];
	if(mde==ACCMEMSYS){
		strcpy(new_type, "sys_");
		strcat(new_type, type);
	}else{
		strcpy(new_type, "api_");
		strcat(new_type, type);
	}
	ponresfil = string_replace(pinresfil, "$type", new_type);
	phy_free(pinresfil);
	pinresfil = string_replace(ponresfil, "$date", td.date);

	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
	}

	if(strstr(type,"hit") && strstr(dtres,"linesize")==NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "该机器无法成功获取缓存部件的linesize大小，计算带宽失败。");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}else if(strstr(dtres,"-p, --pid <pid>")){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "该进程活动已结束。");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}else if(strstr(type,"miss") && strstr(dtres,"has no samples")){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "该进程未捕获到相关miss事件。");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}else if(strstr(type,"miss") && strstr(dtres,"failed to set cpu bitmap")){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "该进程未捕获到相关miss事件。");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}

	fp = fopen(pinresfil, "w+");
	fprintf(fp, "%s", dtres);
	fclose(fp);

	jsonfl = string_replace(pinresfil, ".res", ".json");
	chartjsonfile= string_replace(pinresfil, ".res", "_chart.json");
	char cmd[1024] = {0};
	if (strstr(pinresfil, "hit") != NULL){
		phy_snprintf(cmd, 1024, "/opt/phytune/server/resource/hit_cpu_res2json %s %s %s",pinresfil, jsonfl, chartjsonfile);
	}else if (strstr(pinresfil, "miss") != NULL){
		phy_snprintf(cmd, 1024, "/opt/phytune/server/resource/miss_res2json %s %s %s",pinresfil, jsonfl, chartjsonfile);
	}
	forkpty_local(pwd, td.skey, cmd, 0, &results, -1);
//	FILE * fp1 = NULL;
//	fp1 = fopen("/tmp/memacc.res", "w+");
//	fprintf(fp1, "%s", results);
//	fclose(fp1);
	phy_free(results);

	if(false==not_empty_json(jsonfl) || false == not_empty_json(chartjsonfile)){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "相关性能计数器未成功计数!");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}
	if(false == is_json(jsonfl) || false == is_json(chartjsonfile)){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "json file format error!");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}

	memset(tran.td.mes, 0, 1280);
	snprintf(tran.td.mes, 1280, "%s;%s", jsonfl, chartjsonfile);

	tran.mma.matp = DETECT;
	tran.mma.mde = FINISH;
	tran.td.affi = mde;

	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
	}

	write_message_to_controller((char*)(&tran), sizeof(struct transfer));
	phy_free(jsonfl);
	phy_free(chartjsonfile);
	phy_free(type);

texit:
//清理临时文件
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, cornam);
	forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
	phy_free(results);
	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, tarpro);
		forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
		phy_free(results);
	}

	phy_free(tarpro);
#undef resfil
#undef resdir
#undef moddir
#undef dstdir
#undef kilflg
	return;

meserr:
//
	goto texit;
}

char* env_analyzer_ex(const char* filpt, const char* addr, const char* des)
{
	struct strlist *stdshs = NULL;
	struct strlist *p = NULL;
	char* res = NULL;
	char strcmd[PHRASE] = {0};
	phy_snprintf(strcmd, PHRASE, "cat %s", filpt);
	create_strlist(&stdshs);
	get_result_strlist(strcmd, stdshs, false);
	p = stdshs->next;
	while(p){
		if(strstr(p->data, des)){
			res = get_str_between_two_words(p->data, "|", NULL);
			destory_strlist(stdshs);
			return res;
		}
		p = p->next;
	}

	destory_strlist(stdshs);
	return res;
}

int env_check_ex(const char* add, const char* usr, const char* pwd, const char* spwd)
{
	const char* ec_perf = "perf";
	const char* ec_pyth = "python3";
	const char* ec_pfnr = "perf(non-root)";
	const char* ec_ksnr = "kallsyms(non-root)";
	const char* ec_cptp = "cputp";

#define envchecker_ex "/opt/phytune/server/tools/env_check/env_check_alls.sh"
#define envchkres "/opt/phytune/server/results/envcheck.res"
#define dstdir "/tmp"

	FILE *fp = NULL;
	char* results = NULL;
	char* dtres = NULL;
	char* res = NULL;
	char* ec_cur = NULL;
	int rc = 0;
	char cmdstr[256] = {0};
	memset(cmdstr, 0, 256);

	rc = create_sshsession(add, usr, pwd);
	if(rc != 0){
		send_message(MESS, ERROR, ENVCK, "SSH connection error!");
		goto err;
	}

	phy_snprintf(cmdstr, 256, "scp -rp %s %s@%s:%s/", envchecker_ex, usr, add, dstdir);
	forkpty_cutlines(add, usr, pwd, spwd, cmdstr, 4, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s/env_check_alls.sh", dstdir);
	forkpty_cutlines(add, usr, pwd, spwd, cmdstr, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL || (fil_isexist("/tmp/kilflg") == true)){
		goto texit;
	}
	fp = fopen(envchkres, "w+");
	fprintf(fp, "%s", dtres);
	fclose(fp);

#if 1
	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s/env_check_alls.sh", dstdir);
	forkpty_cutlines(add, usr, pwd, spwd, cmdstr, 0, &results, -1);
#endif

//解析环境检查结果
	ec_cur = (char*)ec_perf;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_pyth;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_pfnr;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_ksnr;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_cptp;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

#undef envchecker_ex
	phy_free(res);
	phy_free(results);
	phy_free(dtres);
	if(fil_isexist("/tmp/kilflg") == true)
	{
		return 1;
	}

	return 0;
err:
	phy_log(LOG_LEVEL_ERR, "envcheck: %s err", ec_cur);
texit:
	return 1;

notsupported:
	phy_free(res);
	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s not supported.", ec_cur);
	return 1;
}

int env_check_rtcputp(const char* add, const char* usr, const char* pwd, const char* spwd, int affi, char** ecrt)
{
	const char* ec_perf = "perf";
	const char* ec_pyth = "python3";
	const char* ec_pfnr = "perf(non-root)";
	const char* ec_ksnr = "kallsyms(non-root)";
	const char* ec_cptp = "cputp";

#define envchecker "/opt/phytune/server/tools/env_check/env_check_alls.sh"
#define envchkres "/opt/phytune/server/results/envcheck.res"
#define dstdir "/tmp"

	FILE *fp = NULL;
	char* results = NULL;
	char* dtres = NULL;
	char* res = NULL;
	char* ec_cur = NULL;
	int rc = 0;
	char cmdstr[256] = {0};
	memset(cmdstr, 0, 256);

	rc = create_sshsession(add, usr, pwd);
	if(rc != 0){
		send_message(MESS, ERROR, affi, "SSH connection error!");
		goto err;
	}

	phy_snprintf(cmdstr, 256, "scp -rp %s %s@%s:%s/", envchecker, usr, add, dstdir);
	forkpty_envcheck(add, usr, pwd, spwd, cmdstr, 4, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s/env_check_alls.sh", dstdir);
	forkpty_envcheck(add, usr, pwd, spwd, cmdstr, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL || (fil_isexist("/tmp/kilflg") == true)){
		goto texit;
	}
	fp = fopen(envchkres, "w+");
	fprintf(fp, "%s", dtres);
	fclose(fp);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s/env_check_alls.sh", dstdir);
	forkpty_envcheck(add, usr, pwd, spwd, cmdstr, 0, &results, -1);

//解析环境检查结果
	ec_cur = (char*)ec_perf;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_pyth;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_pfnr;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_ksnr;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_cptp;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}
	*ecrt = strdup(res);

#undef envchecker
	phy_free(res);
	phy_free(results);
	phy_free(dtres);
	if(fil_isexist("/tmp/kilflg") == true)
	{
		return 1;
	}

	return 0;
err:
	phy_log(LOG_LEVEL_ERR, "envcheck: %s err", ec_cur);
texit:
	return 1;

notsupported:
	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s not supported.", ec_cur);
	send_message(MESS, ERROR, affi, cmdstr);
	return 1;
}

int env_check_rtcputp_local(const char* pwd, const char* spwd, int affi, char** ecrt)
{
	const char* ec_perf = "perf";
	const char* ec_pyth = "python3";
	const char* ec_pfnr = "perf(non-root)";
	const char* ec_ksnr = "kallsyms(non-root)";
	const char* ec_cptp = "cputp";

#define envchecker_cty "/opt/phytune/server/tools/env_check/env_check_alls.sh"
#define envchkres "/opt/phytune/server/results/envcheck.res"
#define dstdir "/tmp"

	FILE *fp = NULL;
	char* results = NULL;
	char* dtres = NULL;
	char* res = NULL;
	char* ec_cur = NULL;
	char cmdstr[256] = {0};
	memset(cmdstr, 0, 256);

	phy_snprintf(cmdstr, 256, "cp -rp %s %s/", envchecker_cty, dstdir);
	forkpty_envcheck_local(pwd, spwd, cmdstr, 0, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s/env_check_alls.sh", dstdir);
	forkpty_envcheck_local(pwd, spwd, cmdstr, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL || (fil_isexist("/tmp/kilflg") == true)){
		goto texit;
	}
	fp = fopen(envchkres, "w+");
	fprintf(fp, "%s", dtres);
	fclose(fp);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s/env_check_alls.sh", dstdir);
	forkpty_envcheck_local(pwd, spwd, cmdstr, 0, &results, -1);
	phy_free(results);
//解析环境检查结果
	ec_cur = (char*)ec_perf;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_pyth;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_pfnr;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_ksnr;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_cptp;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}
	*ecrt = strdup(res);

#undef envchecker_cty
	phy_free(res);
	phy_free(results);
	phy_free(dtres);
	if(fil_isexist("/tmp/kilflg") == true)
	{
		return 1;
	}

	return 0;
err:
	phy_log(LOG_LEVEL_ERR, "envcheck: %s err", ec_cur);
texit:
	return 1;

notsupported:
	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s not supported.", ec_cur);
	send_message(MESS, ERROR, affi, cmdstr);
	return 1;
}

int env_check_io_local(const char* pwd, const char* spwd, int affi)
{
	const char* ec_pyth = "python3";
	const char* ec_config_blk="CONFIG_BLK_DEV_IO_TRACE";
	const char* ec_blk="blktrace";
	const char* ec_strace="strace";

#define ioenvchecker_lc "/opt/phytune/server/tools/env_check/env_check_io.sh"
#define envchkres "/opt/phytune/server/results/envcheck.res"
#define dstdir "/tmp"

	FILE *fp = NULL;
	char* results = NULL;
	char* dtres = NULL;
	char* res = NULL;
	char* ec_cur = NULL;
	char cmdstr[256] = {0};
	memset(cmdstr, 0, 256);

	phy_snprintf(cmdstr, 256, "cp -rp %s %s/", ioenvchecker_lc, dstdir);
	forkpty_local(pwd, spwd, cmdstr, 0, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s", envchkres);
	forkpty_local(pwd, spwd, cmdstr, 0, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s/env_check_io.sh", dstdir);
	forkpty_local(pwd, spwd, cmdstr, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL || (fil_isexist("/tmp/kilflg") == true)){
		goto texit;
	}
	fp = fopen(envchkres, "w+");
	fprintf(fp, "%s", dtres);
	fclose(fp);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s/env_check_io.sh", dstdir);
	forkpty_local(pwd, spwd, cmdstr, 0, &results, -1);

//解析环境检查结果

	switch(affi){
		case IOSYS:
			phy_free(res);
			ec_cur = (char*)ec_config_blk;
			res = env_analyzer_ex(envchkres, NULL, ec_cur);
			if(res != NULL){
				if(strstr(res, "no")){
					goto notsupported;
				}
			}

			phy_free(res);
			ec_cur = (char*)ec_blk;
			res = env_analyzer_ex(envchkres, NULL, ec_cur);
			if(res != NULL){
				if(strstr(res, "no")){
					goto notsupported;
				}
			}
		break;
		case IOAPI:
			phy_free(res);
			ec_cur = (char*)ec_strace;
			res = env_analyzer_ex(envchkres, NULL, ec_cur);
			if(res != NULL){
				if(strstr(res, "no")){
					goto notsupported;
				}
			}
		break;
		case IORTEXEC:
			phy_free(res);
			ec_cur = (char*)ec_config_blk;
			res = env_analyzer_ex(envchkres, NULL, ec_cur);
			if(res != NULL){
				if(strstr(res, "no")){
					goto notsupported;
				}
			}

			phy_free(res);
			ec_cur = (char*)ec_blk;
			res = env_analyzer_ex(envchkres, NULL, ec_cur);
			if(res != NULL){
				if(strstr(res, "no")){
					goto notsupported;
				}
			}
		break;
	}

	phy_free(res);
	ec_cur = (char*)ec_pyth;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

#undef ioenvchecker_lc
	phy_free(res);
	phy_free(results);
	phy_free(dtres);
	if(fil_isexist("/tmp/kilflg") == true)
	{
		return 1;
	}

	return 0;
err:
	phy_log(LOG_LEVEL_ERR, "envcheck: %s err", ec_cur);
texit:
	return 1;

notsupported:
	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s not supported.", ec_cur);
	send_message(MESS, ERROR, affi, cmdstr);
	return 1;
}

int env_check_io(const char* add, const char* usr, const char* pwd, const char* spwd, int affi)
{
	const char* ec_pyth = "python3";
	const char* ec_config_blk="CONFIG_BLK_DEV_IO_TRACE";
	const char* ec_blk="blktrace";
	const char* ec_strace="strace";

#define io_envchecker "/opt/phytune/server/tools/env_check/env_check_io.sh"
#define envchkres "/opt/phytune/server/results/envcheck.res"
#define dstdir "/tmp"

	FILE *fp = NULL;
	char* results = NULL;
	char* dtres = NULL;
	char* res = NULL;
	char* ec_cur = NULL;
	int rc = 0;
	char cmdstr[256] = {0};
	memset(cmdstr, 0, 256);

	rc = create_sshsession(add, usr, pwd);
	if(rc != 0){
		send_message(MESS, ERROR, affi, "SSH connection error!");
		goto err;
	}

	phy_snprintf(cmdstr, 256, "scp -rp %s %s@%s:%s/", io_envchecker, usr, add, dstdir);
	forkpty_cutlines(add, usr, pwd, spwd, cmdstr, 4, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s", envchkres);
	forkpty_cutlines(add, usr, pwd, spwd, cmdstr, 4, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s/env_check_io.sh", dstdir);
	forkpty_cutlines(add, usr, pwd, spwd, cmdstr, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL || (fil_isexist("/tmp/kilflg") == true)){
		goto texit;
	}
	fp = fopen(envchkres, "w+");
	fprintf(fp, "%s", dtres);
	fclose(fp);

#if 1
	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s/env_check_io.sh", dstdir);
	forkpty_cutlines(add, usr, pwd, spwd, cmdstr, 0, &results, -1);
#endif

//解析环境检查结果

	switch(affi){
		case IOSYS:
			phy_free(res);
			ec_cur = (char*)ec_config_blk;
			res = env_analyzer_ex(envchkres, NULL, ec_cur);
			if(res != NULL){
				if(strstr(res, "no")){
					goto notsupported;
				}
			}

			phy_free(res);
			ec_cur = (char*)ec_blk;
			res = env_analyzer_ex(envchkres, NULL, ec_cur);
			if(res != NULL){
				if(strstr(res, "no")){
					goto notsupported;
				}
			}
		break;
		case IOAPI:
			phy_free(res);
			ec_cur = (char*)ec_strace;
			res = env_analyzer_ex(envchkres, NULL, ec_cur);
			if(res != NULL){
				if(strstr(res, "no")){
					goto notsupported;
				}
			}
		break;
		case IORTEXEC:
			phy_free(res);
			ec_cur = (char*)ec_config_blk;
			res = env_analyzer_ex(envchkres, NULL, ec_cur);
			if(res != NULL){
				if(strstr(res, "no")){
					goto notsupported;
				}
			}

			phy_free(res);
			ec_cur = (char*)ec_blk;
			res = env_analyzer_ex(envchkres, NULL, ec_cur);
			if(res != NULL){
				if(strstr(res, "no")){
					goto notsupported;
				}
			}
		break;
	}

	phy_free(res);
	ec_cur = (char*)ec_pyth;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}



	phy_free(res);
	phy_free(results);
	phy_free(dtres);
	if(fil_isexist("/tmp/kilflg") == true)
	{
		return 1;
	}

	return 0;
err:
	phy_log(LOG_LEVEL_ERR, "envcheck: %s err", ec_cur);
texit:
	return 1;

notsupported:
	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s not supported.", ec_cur);
	send_message(MESS, ERROR, affi, cmdstr);
	return 1;
}

int env_check_affi_local(const char* pwd, const char* spwd, int affi)
{
	const char* ec_perf = "perf";
	const char* ec_pyth = "python3";
	const char* ec_pfnr = "perf(non-root)";
	const char* ec_ksnr = "kallsyms(non-root)";
	const char* ec_cptp = "cputp";

#define envchecker_lc "/opt/phytune/server/tools/env_check/env_check_alls.sh"
#define envchkres "/opt/phytune/server/results/envcheck.res"
#define dstdir "/tmp"

	FILE *fp = NULL;
	char* results = NULL;
	char* dtres = NULL;
	char* res = NULL;
	char* ec_cur = NULL;
	char cmdstr[256] = {0};
	memset(cmdstr, 0, 256);

	phy_snprintf(cmdstr, 256, "cp -rp %s %s/", envchecker_lc, dstdir);
	forkpty_envcheck_local(pwd, spwd, cmdstr, 0, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s", envchkres);
	forkpty_envcheck_local(pwd, spwd, cmdstr, 0, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s/env_check_alls.sh", dstdir);
	forkpty_envcheck_local(pwd, spwd, cmdstr, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL || (fil_isexist("/tmp/kilflg") == true)){
		goto texit;
	}
	fp = fopen(envchkres, "w+");
	fprintf(fp, "%s", dtres);
	fclose(fp);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s/env_check_alls.sh", dstdir);
	forkpty_envcheck_local(pwd, spwd, cmdstr, 0, &results, -1);

//解析环境检查结果
	ec_cur = (char*)ec_perf;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_pyth;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);

	ec_cur = (char*)ec_pfnr;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_ksnr;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_cptp;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

#undef envchecker_lc
	phy_free(res);
	phy_free(results);
	phy_free(dtres);
	if(fil_isexist("/tmp/kilflg") == true)
	{
		return 1;
	}

	return 0;
err:
	phy_log(LOG_LEVEL_ERR, "envcheck: %s err", ec_cur);
texit:
	return 1;

notsupported:
	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s not supported.", ec_cur);
	send_message(MESS, ERROR, affi, cmdstr);
	return 1;
}

int env_check_affi(const char* add, const char* usr, const char* pwd, const char* spwd, int affi)
{
	const char* ec_perf = "perf";
	const char* ec_pyth = "python3";
	const char* ec_pfnr = "perf(non-root)";
	const char* ec_ksnr = "kallsyms(non-root)";
	const char* ec_cptp = "cputp";

#define envchecker "/opt/phytune/server/tools/env_check/env_check_alls.sh"
#define envchkres "/opt/phytune/server/results/envcheck.res"
#define dstdir "/tmp"

	FILE *fp = NULL;
	char* results = NULL;
	char* dtres = NULL;
	char* res = NULL;
	char* ec_cur = NULL;
	int rc = 0;
	char cmdstr[256] = {0};
	memset(cmdstr, 0, 256);

	rc = create_sshsession(add, usr, pwd);
	if(rc != 0){
		send_message(MESS, ERROR, affi, "SSH connection error!");
		goto err;
	}

	phy_snprintf(cmdstr, 256, "scp -rp %s %s@%s:%s/", envchecker, usr, add, dstdir);
	forkpty_envcheck(add, usr, pwd, spwd, cmdstr, 4, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s", envchkres);
	forkpty_envcheck(add, usr, pwd, spwd, cmdstr, 4, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s/env_check_alls.sh", dstdir);
	forkpty_envcheck(add, usr, pwd, spwd, cmdstr, 0, &results, -1);

	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL || (fil_isexist("/tmp/kilflg") == true)){
		goto texit;
	}
	fp = fopen(envchkres, "w+");
	fprintf(fp, "%s", dtres);
	fclose(fp);

#if 1
	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s/env_check_alls.sh", dstdir);
	forkpty_envcheck(add, usr, pwd, spwd, cmdstr, 0, &results, -1);
#endif

//解析环境检查结果
	ec_cur = (char*)ec_perf;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_pyth;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);

	ec_cur = (char*)ec_pfnr;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_ksnr;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	ec_cur = (char*)ec_cptp;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);
	if(res == NULL){
		goto err;
	}
	if(strstr(res, "no")){
		goto notsupported;
	}

	phy_free(res);
	phy_free(results);
	phy_free(dtres);
	if(fil_isexist("/tmp/kilflg") == true)
	{
		return 1;
	}

	return 0;
err:
	phy_log(LOG_LEVEL_ERR, "envcheck: %s err", ec_cur);
texit:
	return 1;

notsupported:
	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s not supported.", ec_cur);
	send_message(MESS, ERROR, affi, cmdstr);
	return 1;
}

char* env_check_res_local(const char* pwd, const char* spwd, const char* ectp)
{
#define envchecker "/opt/phytune/server/tools/env_check/env_check_alls.sh"
#define envchkres "/opt/phytune/server/results/envcheck.res"
#define dstdir "/tmp"

	FILE *fp = NULL;
	char* results = NULL;
	char* dtres = NULL;
	char* res = NULL;
	char* ec_cur = NULL;
	char cmdstr[256] = {0};
	memset(cmdstr, 0, 256);

	phy_snprintf(cmdstr, 256, "cp -rp %s %s/", envchecker, dstdir);
	forkpty_envcheck_local(pwd, spwd, cmdstr, 0, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s", envchkres);
	forkpty_envcheck_local(pwd, spwd, cmdstr, 0, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s/env_check_alls.sh", dstdir);;
	forkpty_envcheck_local(pwd, spwd, cmdstr, 0, &results, -1);

	fp = fopen(envchkres, "w");
		dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres != NULL){
		fprintf(fp, "%s", dtres);
	}else{
		fclose(fp);
		return NULL;
	}
	fclose(fp);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s/env_check_alls.sh", dstdir);
	forkpty_envcheck_local(pwd, spwd, cmdstr, 0, &results, -1);

//解析环境检查结果
	phy_free(res);
	ec_cur = (char*)ectp;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);

	phy_free(results);
	phy_free(dtres);

	return res;
}

char* env_check_res(const char* add, const char* usr, const char* pwd, const char* spwd, const char* ectp)
{
#define envchecker "/opt/phytune/server/tools/env_check/env_check_alls.sh"
#define envchkres "/opt/phytune/server/results/envcheck.res"
#define dstdir "/tmp"

	FILE *fp = NULL;
	char* results = NULL;
	char* dtres = NULL;
	char* res = NULL;
	char* ec_cur = NULL;
	char cmdstr[256] = {0};
	memset(cmdstr, 0, 256);

	phy_snprintf(cmdstr, 256, "scp -rp %s %s@%s:%s/", envchecker, usr, add, dstdir);
	forkpty_envcheck(add, usr, pwd, spwd, cmdstr, 4, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s", envchkres);
	forkpty_envcheck(add, usr, pwd, spwd, cmdstr, 4, &results, -1);
	phy_free(results);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "%s/env_check_alls.sh", dstdir);
	forkpty_envcheck(add, usr, pwd, spwd, cmdstr, 0, &results, -1);

	fp = fopen(envchkres, "w");
		dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres != NULL){
		fprintf(fp, "%s", dtres);
	}else{
		fclose(fp);
		return NULL;
	}
	fclose(fp);

	memset(cmdstr, 0, 256);
	phy_snprintf(cmdstr, 256, "rm -f %s/env_check_alls.sh", dstdir);
	forkpty_envcheck(add, usr, pwd, spwd, cmdstr, 0, &results, -1);

//解析环境检查结果
	phy_free(res);
	ec_cur = (char*)ectp;
	res = env_analyzer_ex(envchkres, NULL, ec_cur);

	phy_free(results);
	phy_free(dtres);

	return res;
}

#define kilflg "/tmp/kilflg"
#define kilmasflg "/tmp/kilmasflg"

void* spinner(void *arg) {
    char *message = (char *)arg;
    char* spinner_chars[] = {".", "...", "......", ".........."};
    char messlg[128] = {0};
    int i = 0;
    while (1) {
    	if(slgflg == true || fil_isexist(kilflg) == true){
			return NULL;
		}
        i = (i + 1) % 4;
        memset(messlg, 0, 128);
        phy_snprintf(messlg, 128, "%s %s", message, spinner_chars[i]);
        send_message(MESS, COMM, slgmst, messlg);
        usleep(300000); // 500ms
    }
    return NULL;
}

void dynamic_tips(const char* slogan)
{
	pthread_t spinner_thread;
	slgflg = false;
    if (pthread_create(&spinner_thread, NULL, spinner, (void *)slogan) != 0) {
        perror("pthread_create");
        return;
     }
     pthread_detach(spinner_thread);
}

void run_realtime(const char* add, const char* usr, const char* pwd, mesexe mde, ltrandst* td, const char* cornam)
{
#define moddir "/opt/phytune/agent/arm/modules"
#define dstdir "/tmp"
	char* results = NULL;
	char inscmd[256] = {0};

	char* modpath = NULL;
	char* tarpro = NULL;
	char* tarpth = NULL;
	char* pcmd = NULL;
	//core path
	modpath = load_filpath(moddir, cornam);
	//target program
	tarpro = get_str_between_two_words(td->mes, "tarpro=", ";");

	if(tarpro != NULL){
		tarpth = load_filpath(moddir, tarpro);
		if(NULL != tarpth){
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "%s/%s", dstdir, tarpro);
			pcmd = arg_parser(td->mes, inscmd, mde);
		}else{
			pcmd = arg_parser(td->mes, tarpro, mde);
		}
	}else{
		pcmd = arg_parser(td->mes, tarpro, mde);
	}

	if(pcmd == NULL){
		phy_free(tarpro);
		goto texit;
	}
//推送pmu
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "scp -rp %s %s@%s:%s/", modpath, usr, td->receiver, dstdir);
	forkpty_cutlines(td->receiver, usr, pwd, NULL, inscmd, 4, &results, -1);
	phy_free(results);

//推送agent中存在的待测程序
	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "scp -rp %s %s@%s:/%s/", tarpth, usr, td->receiver, dstdir);
		forkpty_cutlines(td->receiver, usr, pwd, NULL, inscmd, 4, &results, -1);
		phy_free(results);
	}

	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "%s/%s %s||1]", dstdir, cornam, pcmd);//执行脚本

	if(fil_isexist(kilflg) == true){
		slgflg = true;
		goto texit;
	}
	slgflg = true;

	realtime_exec_entry(add, usr, pwd, NULL, inscmd, 1,mde);

    sleep(1);
texit:
//清理临时文件
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, cornam);
	forkpty_cutlines(td->receiver, usr, pwd, NULL, inscmd, 0, &results, -1);

	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, tarpro);
		forkpty_cutlines(td->receiver, usr, pwd, NULL, inscmd, 0, &results, -1);
	}
	phy_free(tarpro);
}

void run_realtime_local(const char* add, const char* usr, const char* pwd, mesexe mde, ltrandst* td, const char* cornam)
{
#define resdir "/opt/phytune/server/results"
#define moddir "/opt/phytune/agent/arm/modules"
#define dstdir "/tmp"
	char* results = NULL;
	char inscmd[256] = {0};

	char* modpath = NULL;
	char* tarpro = NULL;
	char* tarpth = NULL;
	char* pcmd = NULL;
	//core path
	modpath = load_filpath(moddir, cornam);
	//target program
	tarpro = get_str_between_two_words(td->mes, "tarpro=", ";");

	if(tarpro != NULL){
		tarpth = load_filpath(moddir, tarpro);
		if(NULL != tarpth){
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "%s/%s", dstdir, tarpro);
			pcmd = arg_parser(td->mes, inscmd, mde);
		}else{
			pcmd = arg_parser(td->mes, tarpro, mde);
		}
	}else{
		pcmd = arg_parser(td->mes, tarpro, mde);
	}
	if(pcmd == NULL){
		phy_free(tarpro);
		goto texit;
	}

//推送pmu
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "cp -rp %s %s/", modpath, dstdir);
	forkpty_local(pwd, NULL, inscmd, 0, &results, -1);
	phy_free(results);

//推送agent中存在的待测程序
	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "cp -rp %s %s/", tarpth, dstdir);
		forkpty_local(pwd, NULL, inscmd, 0, &results, -1);
		phy_free(results);
	}

	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "%s/%s %s||1]", dstdir, cornam, pcmd);//执行脚本

	if(fil_isexist(kilflg) == true){
		goto texit;
		return;
	}
	slgflg = true;
	realtime_exec_entry_local(usr, pwd, NULL, inscmd, 1,mde);

    sleep(1);
texit:
//清理临时文件
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, cornam);
	forkpty_local(pwd, NULL, inscmd, 0, &results, -1);
	phy_free(results);

	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, tarpro);
		forkpty_local(pwd, NULL, inscmd, 0, &results, -1);
		phy_free(results);
	}
	phy_free(tarpro);
}

void run_realtime_multiproc(const char* add, const char* usr, const char* pwd, mesexe mde, ltrandst* td, const char* cornam)
{
#define moddir "/opt/phytune/agent/arm/modules"
#define dstdir "/tmp"
	char* results = NULL;
	char* dtres = NULL;

	char inscmd[256] = {0};

	char* modpath = NULL;
	char* tarpro = NULL;
	char* tarpth = NULL;
	char* pcmd = NULL;
	//core path
	modpath = load_filpath(moddir, cornam);
	//target program
	tarpro = get_str_between_two_words(td->mes, "tarpro=", ";");
	forkpty_cutlines(td->receiver, usr, pwd, NULL, "nproc", 0, &results, -1);
	cpuNUM = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	phy_free(results);
	trim(cpuNUM);
	if(strstr(td->mes,"cpuid=all")){
		FILE * fp1 = NULL;
		fp1 = fopen("/tmp/memacc_cpunum.res", "w");
		fprintf(fp1, "%s", cpuNUM);
		fclose(fp1);
	}

	if(tarpro != NULL){
		tarpth = load_filpath(moddir, tarpro);
		if(NULL != tarpth){
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "%s/%s", dstdir, tarpro);
			pcmd = arg_parser(td->mes, inscmd, mde);
		}else{
			pcmd = arg_parser(td->mes, tarpro, mde);
		}
	}else{
		pcmd = arg_parser(td->mes, tarpro, mde);
	}
	if(pcmd == NULL){
		phy_free(tarpro);
		goto texit;
	}

//推送pmu
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "scp -rp %s %s@%s:%s/", modpath, usr, td->receiver, dstdir);
	forkpty_cutlines(td->receiver, usr, pwd, NULL, inscmd, 4, &results, -1);
	phy_free(results);

//推送agent中存在的待测程序
	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "scp -rp %s %s@%s:/%s/", tarpth, usr, td->receiver, dstdir);
		forkpty_cutlines(td->receiver, usr, pwd, NULL, inscmd, 4, &results, -1);
		phy_free(results);
	}

	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "%s/%s %s", dstdir, cornam, pcmd);

	//远程执行
	forkpty_cutlines(td->receiver, usr, pwd, NULL, inscmd, 1, &results, -1);
	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	phy_free(results);
	trim(dtres);
	if(fil_isexist(kilflg) == true){
		slgflg = true;
		goto texit;
	}
	slgflg = true;

	realtime_exec_entry(add, usr, pwd, NULL, dtres, 1,mde);

    sleep(1);
texit:
//清理临时文件
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, cornam);
	forkpty_cutlines(td->receiver, usr, pwd, NULL, inscmd, 0, &results, -1);

	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, tarpro);
		forkpty_cutlines(td->receiver, usr, pwd, NULL, inscmd, 0, &results, -1);
	}

	phy_free(tarpro);
	phy_free(cpuNUM);
}

void run_realtime_multiproc_local(const char* usr, const char* pwd, mesexe mde, ltrandst* td, const char* cornam)
{
#define moddir "/opt/phytune/agent/arm/modules"
#define dstdir "/tmp"
	char* results = NULL;
	char* dtres = NULL;
	char inscmd[256] = {0};

	char* modpath = NULL;
	char* tarpro = NULL;
	char* tarpth = NULL;
	char* pcmd = NULL;
	//core path
	modpath = load_filpath(moddir, cornam);
	//target program
	tarpro = get_str_between_two_words(td->mes, "tarpro=", ";");

	forkpty_local(pwd, NULL, "nproc", 0, &results, -1);
	cpuNUM = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	phy_free(results);
	trim(cpuNUM);
	if(strstr(td->mes,"cpuid=all")){
		FILE * fp1 = NULL;
		fp1 = fopen("/tmp/memacc_cpunum.res", "w");
		fprintf(fp1, "%s", cpuNUM);
		fclose(fp1);
	}

	if(tarpro != NULL){
		tarpth = load_filpath(moddir, tarpro);
		if(NULL != tarpth){
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "%s/%s", dstdir, tarpro);
			pcmd = arg_parser(td->mes, inscmd, mde);
		}else{
			pcmd = arg_parser(td->mes, tarpro, mde);
		}
	}else{
		pcmd = arg_parser(td->mes, tarpro, mde);
	}
	if(pcmd == NULL){
		phy_free(tarpro);
		goto texit;
	}

	//推送pmu
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "scp -rp %s %s/", modpath, dstdir);
	forkpty_cutlines(td->receiver, usr, pwd, NULL, inscmd, 4, &results, -1);
	phy_free(results);

//推送agent中存在的待测程序
	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "scp -rp %s %s@%s:/%s/", tarpth, usr, td->receiver, dstdir);
		forkpty_cutlines(td->receiver, usr, pwd, NULL, inscmd, 4, &results, -1);
		phy_free(results);
	}

	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "%s/%s %s", dstdir, cornam, pcmd);

	//远程执行
	forkpty_local(pwd, NULL, inscmd, 0, &results, -1);
	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	phy_free(results);
	trim(dtres);
	if(fil_isexist(kilflg) == true){
		slgflg = true;
		goto texit;
	}
	slgflg = true;
	realtime_exec_entry_local(usr, pwd, NULL, dtres,1,mde);

	sleep(1);
texit:
//清理临时文件
	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, tarpro);
		forkpty_local(pwd, NULL, inscmd, 0, &results, -1);
		phy_free(results);
	}
	phy_free(tarpro);
}

void remote_sampling(const char* add, const char* usr, const char* pwd, const char* skey, const char* date, const char* msg)
{
#define pfpsth "/opt/phytune/agent/arm/tools/hotspot-perfparser"

	char* results = NULL;
	char* pfrcd = NULL;
	char* otpth = NULL;
	char* pfarg = NULL;
	char* cmdag = NULL;
	char* tpfpsth = NULL;
	char* pfpsnm = NULL;
	char* totpth = NULL;
	char pfdath[SCMDLEN] = {0};
	char hpdath[SCMDLEN] = {0};
	char pfcmd[BUFLEN] = {0};

	pfpsnm = get_file_name(pfpsth);
	tpfpsth = str_joint("/tmp/", pfpsnm, END);
	pfrcd = get_segment_data(msg, ";", 1);
	otpth = get_segment_data(msg, ";", 2);
	pfarg = get_segment_data(msg, ";", 3);
	cmdag = get_segment_data(msg, ";", 4);

	memset(pfdath, 0, SCMDLEN);
	memset(hpdath, 0, SCMDLEN);
	phy_snprintf(pfdath, SCMDLEN, "/tmp/%s_perf.data", date);
	phy_snprintf(hpdath, SCMDLEN, "/tmp/%s_hotspot.data", date);
	phy_snprintf(pfcmd, BUFLEN, "%s -o %s %s %s", pfrcd, pfdath, pfarg, cmdag);
	forkpty_cutlines(add, usr, pwd, skey, pfcmd, 1, &results, -1);
	phy_free(results);


//推送hotspot_perfparser
	memset(pfcmd, 0, BUFLEN);
	phy_snprintf(pfcmd, BUFLEN, "scp -rp %s %s@%s:/tmp/", pfpsth, usr, add);
	forkpty_cutlines(add, usr, pwd, skey, pfcmd, 4, &results, -1);
	phy_free(results);


//解析data_perf.data文件
	memset(pfcmd, 0, BUFLEN);
	phy_snprintf(pfcmd, BUFLEN, "%s --input %s --output %s --kallsyms /proc/kallsyms", tpfpsth, pfdath, hpdath);
	forkpty_cutlines(add, usr, pwd, skey, pfcmd, 1, &results, -1);
	phy_free(results);

//回传解析过的文件 /home/nt/phytune_tmpx/hotspot_debug/bin/perf.data
    memset(pfcmd, 0, BUFLEN);
	phy_snprintf(pfcmd, BUFLEN, "rmt_%s-", add);
	totpth = insert_string(otpth, "perf.", pfcmd, true);
	memset(pfcmd, 0, BUFLEN);
	phy_snprintf(pfcmd, BUFLEN, "scp -rp %s@%s:%s %s", usr, add, hpdath, totpth);
	forkpty_cutlines(add, usr, pwd, skey, pfcmd, 4, &results, -1);
	phy_free(results);

	send_message(DETECT, FINISH, RMTSAMP, totpth);

	phy_free(pfrcd);
	phy_free(otpth);
	phy_free(totpth);
	phy_free(pfarg);
	phy_free(cmdag);
	phy_free(tpfpsth);

#undef pfpsth
}

void run_detect_io(const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resfil "/opt/phytune/server/results/$add/io_$mode_$date.res"
#define ioresdir "/opt/phytune/server/results/$add/io_$mode_$date_folder"
#define moddir "/opt/phytune/agent/arm/modules"
#define dstdir "/tmp"
#define blkresdir "/tmp/blktrace_result"

	char* results = NULL;
	char* dtres = NULL;

	char* type = NULL;
	char* mode=NULL;
	FILE *fp = NULL;

	char* addresfil = NULL;
	char* moderesfil = NULL;
	char* dateresfil = NULL;

	char* addresdir = NULL;
	char* moderesdir = NULL;
	char* dateresdir = NULL;

	char* jsonfl = NULL;
	char* chartjsonfile = NULL;

	struct transfer tran = {0};
	char inscmd[256] = {0};

	char* modpath = NULL;
	char* tarpro = NULL;
	char* tarpth = NULL;
	char* pcmd = NULL;
	//core path
	modpath = load_filpath(moddir, cornam);
	//target program
	tarpro = get_str_between_two_words(td.mes, "tarpro=", ";");
	if(strstr(td.mes,"记录")){
		mode="record";
	}else{
		mode="api";
	}


	if(tarpro != NULL){
		tarpth = load_filpath(moddir, tarpro);
		if(NULL != tarpth){
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "%s/%s", dstdir, tarpro);
			pcmd = arg_parser(td.mes, inscmd, mde);
		}else{
			pcmd = arg_parser(td.mes, tarpro, mde);
		}
	}else{
		pcmd = arg_parser(td.mes, tarpro, mde);
	}


	if(pcmd == NULL){
		phy_free(tarpro);
		goto meserr;
	}

//推送pmu
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "scp -rp %s %s@%s:%s/", modpath, usr, td.receiver, dstdir);
	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 4, &results, -1);
	phy_free(results);

//推送agent中存在的待测程序
	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "scp -rp %s %s@%s:/%s/", tarpth, usr, td.receiver, dstdir);
		forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 4, &results, -1);
		phy_free(results);
	}

	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "%s/%s %s", dstdir, cornam, pcmd);
	//远程执行
	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 1, &results, -1);
	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL){
		goto texit;
	}

	//本机创建blktrace结果的文件夹
	addresdir = string_replace(ioresdir, "$add", td.receiver);
	moderesdir = string_replace(addresdir, "$mode", mode);
	dateresdir = string_replace(moderesdir, "$date", td.date);
	phy_free(addresdir);
	phy_free(moderesdir);
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "mkdir -p %s", dateresdir);
	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 4, &results, -1);
	phy_free(results);

	//推送目标机器上的/tmp/blktrace_result到本机的blktrace结果文件夹
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "scp -rp %s@%s:%s/* %s", usr, td.receiver, blkresdir,dateresdir);
	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 4, &results, -1);
	phy_free(results);

	slgflg = true;

	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
		return;
	}

	//"系统"对象结果
	if (strstr(pcmd, " -d ") != NULL) {
		//io生成的res文件名
		addresfil = string_replace(resfil, "$add", td.receiver);
		moderesfil = string_replace(addresfil, "$mode", mode);
		dateresfil = string_replace(moderesfil, "$date", td.date);
		phy_free(addresfil);
		phy_free(moderesfil);
		//结果保存到res文件中
		fp = fopen(dateresfil, "w+");
		fprintf(fp, "%s", dtres);
		fclose(fp);
		jsonfl = string_replace(dateresdir, "_folder", ".json");
		chartjsonfile= string_replace(dateresdir, "_folder", "_chart.json");
		char cmd[1024] = {0};
		phy_snprintf(cmd, 1024, "/opt/phytune/server/resource/io_sys_res2json %s %s %s %s",dateresfil,dateresdir, jsonfl, chartjsonfile);
		forkpty_cutlines(td.receiver, usr, pwd, td.skey, cmd, 4, &results, -1);
		phy_free(results);
	}
	else{
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s/%s", dateresdir, "strace.res");
		if(is_file_empty(inscmd)==true){
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "%s", "该进程没有相关IO活动，结果为空");
			send_message(MESS, ERROR, mde, inscmd);
			goto texit;
		}
		jsonfl = string_replace(dateresdir, "_folder", ".json");
		chartjsonfile= string_replace(dateresdir, "_folder", "_chart.json");
		char cmd[1024] = {0};
		phy_snprintf(cmd, 1024, "/opt/phytune/server/resource/io_api_res2json %s %s %s",dateresdir, jsonfl, chartjsonfile);
		forkpty_cutlines(td.receiver, usr, pwd, td.skey, cmd, 4, &results, -1);
		phy_free(results);
	}

	if(false==not_empty_json(jsonfl) || false == not_empty_json(chartjsonfile)){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "该程序/进程正在等待输入事件!");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}

	if(false == is_json(jsonfl) || false == is_json(chartjsonfile)){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "json file format error!");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}

	memset(tran.td.mes, 0, 1280);
	snprintf(tran.td.mes, 1280, "%s;%s", jsonfl, chartjsonfile);

	tran.mma.matp = DETECT;
	tran.mma.mde = FINISH;
	tran.td.affi = mde;

	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
		return;
	}

	write_message_to_controller((char*)(&tran), sizeof(struct transfer));
	phy_free(jsonfl);
	phy_free(chartjsonfile);
	phy_free(type);


	texit:
	//清理临时文件
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, cornam);
		forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 0, &results, -1);

		//删除目标机器上的结果文件夹
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "sudo rm -rf %s", blkresdir);
		forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 0, &results, -1);

		if(tarpth != NULL){
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, tarpro);
			forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 0, &results, -1);
		}

		phy_free(tarpro);
	#undef resfil
	#undef ioresdir
	#undef moddir
	#undef dstdir
		return;

	meserr:
		goto texit;

}

void run_detect_io_local(const char* pwd, mesdet mde, trandst td, const char* cornam)
{
#define resfil "/opt/phytune/server/results/$add/io_$mode_$date.res"
#define ioresdir_lc "/opt/phytune/server/results/$add/io_$mode_$date_folder"
#define moddir "/opt/phytune/agent/arm/modules"
#define dstdir "/tmp"
#define blkresdir "/tmp/blktrace_result"

	char* results = NULL;
	char* dtres = NULL;

	char* type = NULL;
	char* mode=NULL;
	FILE *fp = NULL;

	char* addresfil = NULL;
	char* moderesfil = NULL;
	char* dateresfil = NULL;

	char* addresdir = NULL;
	char* moderesdir = NULL;
	char* dateresdir = NULL;

	char* jsonfl = NULL;
	char* chartjsonfile = NULL;

	struct transfer tran = {0};
	char inscmd[256] = {0};

	char* modpath = NULL;
	char* tarpro = NULL;
	char* tarpth = NULL;
	char* pcmd = NULL;
	//core path
	modpath = load_filpath(moddir, cornam);
	//target program
	tarpro = get_str_between_two_words(td.mes, "tarpro=", ";");
	if(strstr(td.mes,"记录")){
		mode="record";
	}else{
		mode="api";
	}

	if(tarpro != NULL){
		tarpth = load_filpath(moddir, tarpro);
		if(NULL != tarpth){
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "%s/%s", dstdir, tarpro);
			pcmd = arg_parser(td.mes, inscmd, mde);
		}else{
			pcmd = arg_parser(td.mes, tarpro, mde);
		}
	}else{
		pcmd = arg_parser(td.mes, tarpro, mde);
	}


	if(pcmd == NULL){
		phy_free(tarpro);
		goto meserr;
	}

//推送pmu
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "cp -rp %s %s/", modpath, dstdir);
	forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
	phy_free(results);

//推送agent中存在的待测程序
	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "cp -rp %s %s/", tarpth, dstdir);
		forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
		phy_free(results);
	}

	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "%s/%s %s", dstdir, cornam, pcmd);
	//远程执行
//	forkpty_cutlines(td.receiver, usr, pwd, td.skey, inscmd, 1, &results, -1);
	forkpty_local(pwd, td.skey, inscmd, 1, &results, -1);
	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(dtres == NULL){
		goto texit;
	}

	//本机创建blktrace结果的文件夹
	addresdir = string_replace(ioresdir_lc, "$add", td.receiver);
	moderesdir = string_replace(addresdir, "$mode", mode);
	dateresdir = string_replace(moderesdir, "$date", td.date);
	phy_free(addresdir);
	phy_free(moderesdir);
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "mkdir -p %s", dateresdir);
	forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
	phy_free(results);

	//推送目标机器上的/tmp/blktrace_result到本机的blktrace结果文件夹
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "cp -rp %s/* %s", blkresdir,dateresdir);
	forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
	phy_free(results);

	slgflg = true;

	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
		return;
	}

	//"系统"对象结果
	if (strstr(pcmd, " -d ") != NULL) {
		//io生成的res文件名
		addresfil = string_replace(resfil, "$add", td.receiver);
		moderesfil = string_replace(addresfil, "$mode", mode);
		dateresfil = string_replace(moderesfil, "$date", td.date);
		phy_free(addresfil);
		phy_free(moderesfil);
		//结果保存到res文件中
		fp = fopen(dateresfil, "w+");
		fprintf(fp, "%s", dtres);
		fclose(fp);
		jsonfl = string_replace(dateresdir, "_folder", ".json");
		chartjsonfile= string_replace(dateresdir, "_folder", "_chart.json");
//		io_sys_to_json(dateresfil, dateresdir, jsonfl, &chartjsonfile);
		char cmd[1024] = {0};
		phy_snprintf(cmd, 1024, "/opt/phytune/server/resource/io_sys_res2json %s %s %s %s",dateresfil,dateresdir, jsonfl, chartjsonfile);
		forkpty_local(pwd, td.skey, cmd, 0, &results, -1);
		phy_free(results);
	}
	else{
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s/%s", dateresdir, "strace.res");
		if(is_file_empty(inscmd)==true){
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "%s", "该进程没有相关IO活动，结果为空。");
			send_message(MESS, ERROR, mde, inscmd);
			goto texit;
		}
		jsonfl = string_replace(dateresdir, "_folder", ".json");
		chartjsonfile= string_replace(dateresdir, "_folder", "_chart.json");
		char cmd[1024] = {0};
		phy_snprintf(cmd, 1024, "/opt/phytune/server/resource/io_api_res2json %s %s %s",dateresdir, jsonfl, chartjsonfile);
		forkpty_local(pwd, td.skey, cmd, 0, &results, -1);
		phy_free(results);
	}
	if(false==not_empty_json(jsonfl) || false == not_empty_json(chartjsonfile)){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "该程序/进程正在等待输入事件!");
		send_message(MESS, ERROR, mde, inscmd);
		goto texit;
	}
	if(false == is_json(jsonfl) || false == is_json(chartjsonfile)){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "%s", "json file format error!");
		send_message(MESS, ERROR, mde, inscmd);
		return;
	}

	memset(tran.td.mes, 0, 1280);
	snprintf(tran.td.mes, 1280, "%s;%s", jsonfl, chartjsonfile);

	tran.mma.matp = DETECT;
	tran.mma.mde = FINISH;
	tran.td.affi = mde;

	if(fil_isexist("/tmp/kilflg") == true){
		goto texit;
		return;
	}

	write_message_to_controller((char*)(&tran), sizeof(struct transfer));
	phy_free(jsonfl);
	phy_free(chartjsonfile);
	phy_free(type);


texit:
//清理临时文件
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, cornam);
	forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
	phy_free(results);

	//删除目标机器上的结果文件夹
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "sudo rm -rf %s", blkresdir);
	forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
	phy_free(results);

	if(tarpth != NULL){
		memset(inscmd, 0, 256);
		phy_snprintf(inscmd, 256, "rm -rf %s/%s", dstdir, tarpro);
		forkpty_local(pwd, td.skey, inscmd, 0, &results, -1);
		phy_free(results);
	}

	phy_free(tarpro);
#undef resfil
#undef ioresdir_lc
#undef moddir
#undef dstdir
	return;

meserr:
	goto texit;

}

void handle_det(mesdet mde, trandst td)
{
	char* usr = NULL;
	char* pwd = NULL;
	char* sta = NULL;
	char* ecrt = NULL;
	char* cptp = NULL;
	char msg[256] = {0};
//	list* misdep = NULL;
	char* res = NULL;
	int ret = 0;
	int rc = 4;
	char machine_ip[20]={0};

	rc = physql_select(td.receiver, &usr, &pwd, &sta);
	if(rc != SQLITE_OK){
		phy_log(LOG_LEVEL_ERR, "install_agt: Cannot find info of %s.", td.receiver);
		return;
	}

	fil_remove(kilflg);
	switch(mde){
		case TMA:
			slgmst = TMA;
			dynamic_tips("执行环境检查 ");
			if(strstr(td.receiver, "localhost")){
				ret = env_check_rtcputp_local(CONFIG_PAWD, td.skey, TMA, &ecrt);
				if(1 == ret)
				{
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: TMA envcheck err!");
					slgflg = true;
					return;
				}
				slgflg = true;
				sleep(1);
				if(fil_isexist(kilflg) == true){
					return;
				}
				dynamic_tips("性能检测执行中 ");
//				memset(td.receiver, 0, 20);
//				phy_snprintf(td.receiver, 20, "%s", CONFIG_SERVICE_ADDR);
				cptp = get_ftc8or6(ecrt);
				run_detect_local(CONFIG_PAWD, TMA, td, cptp);
				phy_free(cptp);
				phy_free(ecrt);
			}else{
				ret = env_check_rtcputp(td.receiver, usr, pwd, td.skey, TMA, &ecrt);
				if(1 == ret)
				{
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: TMA envcheck err!");
					slgflg = true;
					return;
				}

				slgflg = true;
				sleep(1);
				if(fil_isexist(kilflg) == true){
					return;
				}
				dynamic_tips("性能检测执行中 ");
				cptp = get_ftc8or6(ecrt);
				run_detect(usr, pwd, TMA, td, cptp);
				phy_free(cptp);
				phy_free(ecrt);
			}
		break;

		case DDR:
			slgmst = DDR;
			if(strstr(td.receiver, "localhost")){
				send_message(MESS, ERROR, DDR, "本机暂不支持DDR性能检查！");
				return;
			}
			dynamic_tips("性能检测执行中 ");
			run_ddr(td.receiver, usr, pwd, td);
			phy_free(usr);
			phy_free(pwd);
#if 0
			run_ddr_old(td.receiver, usr, pwd, td);
#endif
		break;

		case PCIE:
			slgmst = PCIE;
			if(strstr(td.receiver, "localhost")){
				send_message(MESS, ERROR, PCIE, "本机暂不支持PCIE性能检查！");
				return;
			}
			dynamic_tips("性能检测执行中 ");
			run_pcie(td.receiver, usr, pwd, td);
			phy_free(usr);
			phy_free(pwd);
#if 0
			run_pcie_old(td.receiver, usr, pwd, td);
#endif
		break;
#if 0
		case TOPDOWN:
			slgmst = TOPDOWN;
			dynamic_tips("执行环境检查 ");
			if(strstr(td.receiver, "localhost")){
				ret = env_check_affi_local(CONFIG_PAWD, td.skey, TOPDOWN);
				if(1 == ret)
				{
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: TOPDOWN envcheck err!");
					return;
				}

				slgflg = true;
				sleep(1);
				if(fil_isexist(kilflg) == true){
					return;
				}

				dynamic_tips("性能检测执行中 ");
//				memset(td.receiver, 0, 20);
//				phy_snprintf(td.receiver, 20, "%s", CONFIG_SERVICE_ADDR);
				run_detect_topdown_local("localhost", CONFIG_PAWD, TOPDOWN, td, "topdown");
//				run_detect_topdown(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, TOPDOWN, td, "topdown");
			}else{
				ret = env_check_affi(td.receiver, usr, pwd, td.skey, TOPDOWN);
				if(1 == ret)
				{
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: TOPDOWN envcheck err!");
					return;
				}

				slgflg = true;
				sleep(1);
				if(fil_isexist(kilflg) == true){
					return;
				}
				dynamic_tips("性能检测执行中 ");
				run_detect_topdown(td.receiver, usr, pwd, TOPDOWN, td, "topdown");
			}
		break;

		case TOPDOWNENVCK:
			slgmst = TOPDOWNENVCK;
			dynamic_tips("TOPDOWN先决条件检查 ");
			if(strstr(td.receiver, "localhost")){
				res = env_check_res_local(CONFIG_PAWD, CONFIG_PAWD, "cputp");
			}else if(strlen(td.receiver) == 0){
				slgflg = true;
				return;
			}else{
				res = env_check_res(td.receiver, usr, pwd, td.skey, "cputp");
			}

			slgflg = true;
			if( res == NULL || strstr(res, "no") )
			{
				memset(msg, 0, 256);
				phy_snprintf(msg, 256, "%s", "TOPDOWN先决条件检查出错.");
				send_message(MESS, ERROR, 0, msg);
			}else{
				memset(msg, 0, 256);
				phy_snprintf(msg, 256, "%s", res);
				send_message(MESS, COMM, TOPDOWNENSET, msg);
				sleep(1);
				memset(msg, 0, 256);
				phy_snprintf(msg, 256, "CPU: %s.", res);
				send_message(MESS, COMM, TOPDOWNENVCK, msg);
			}
		break;
#endif
		case TOPDOWNALL:
			slgmst = TOPDOWNENVCK;
			dynamic_tips("TOPDOWN先决条件检查 ");
			if(strstr(td.receiver, "localhost")){
				res = env_check_res_local(CONFIG_PAWD, CONFIG_PAWD, "cputp");
			}else if(strlen(td.receiver) == 0){
				slgflg = true;
				return;
			}else{
				res = env_check_res(td.receiver, usr, pwd, td.skey, "cputp");
			}

			slgflg = true;
			if( res == NULL || strstr(res, "no") )
			{
				memset(msg, 0, 256);
				phy_snprintf(msg, 256, "%s", "TOPDOWN先决条件检查出错.");
				send_message(MESS, ERROR, 0, msg);
			}else{
				memset(msg, 0, 256);
				phy_snprintf(msg, 256, "%s", res);
				send_message(MESS, COMM, TOPDOWNENSET, msg);
				sleep(1);
				memset(msg, 0, 256);
				phy_snprintf(msg, 256, "CPU: %s.", res);
				send_message(MESS, COMM, TOPDOWNENVCK, msg);
			}

			sleep(2);

			if(!strstr(res, "0x700f8620")){
				phy_free(res);
				send_message(MESS, ERROR, TOPDOWNENVCK, "该cpu类型不支持topdown性能分析！");
				return;
			}

			slgmst = TOPDOWN;
			dynamic_tips("执行环境检查 ");
			if(strstr(td.receiver, "localhost")){
				ret = env_check_affi_local(CONFIG_PAWD, td.skey, TOPDOWN);
				if(1 == ret)
				{
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: TOPDOWN envcheck err!");
					return;
				}

				slgflg = true;
				sleep(1);
				if(fil_isexist(kilflg) == true){
					return;
				}

				dynamic_tips("性能检测执行中 ");
				run_detect_topdown_local("localhost", CONFIG_PAWD, TOPDOWN, td, "topdown");
			}else{
				ret = env_check_affi(td.receiver, usr, pwd, td.skey, TOPDOWN);
				if(1 == ret)
				{
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: TOPDOWN envcheck err!");
					return;
				}

				slgflg = true;
				sleep(1);
				if(fil_isexist(kilflg) == true){
					return;
				}
				dynamic_tips("性能检测执行中 ");
				run_detect_topdown(td.receiver, usr, pwd, TOPDOWN, td, "topdown");
			}

		break;

		case HITSYSENVCK:
			slgmst = ACCMEMSYS;
			dynamic_tips("Hit分析先决环境检查 ");
			if(strstr(td.receiver, "localhost")){
				memset(machine_ip, 0, 20);
				phy_snprintf(machine_ip, 20, "%s", "localhost");
				res = env_check_res_local(CONFIG_PAWD, CONFIG_PAWD, "support_metrics");
			}else if(strlen(td.receiver) == 0){
				slgflg = true;
				return;
			}else{
				memset(machine_ip, 0, 20);
				phy_snprintf(machine_ip, 20, "%s", td.receiver);
				res = env_check_res(td.receiver, usr, pwd, td.skey, "support_metrics");
			}

			slgflg = true;
			sleep(1);

			if( res == NULL || strstr(res, "no") )
			{
				memset(msg, 0, 256);
				phy_snprintf(msg, 256, "%s", "Hit分析先决条件检查出错.");
				send_message(MESS, ERROR, 0, msg);
			}else{
				memset(msg, 0, 256);
				phy_snprintf(msg, 256, "%s", res);
				sleep(1);
				memset(msg, 0, 256);
				phy_snprintf(msg, 256, "%s机器支持的采样指标类型: %s.", machine_ip,res);
				send_message(MESS, COMM, HITSYSENVCK, msg);
			}
		break;

		case HITAPIENVCK:
			slgmst = ACCMEMAPI;
			dynamic_tips("Hit分析先决环境检查 ");
			if(strstr(td.receiver, "localhost")){
				memset(machine_ip, 0, 20);
				phy_snprintf(machine_ip, 20, "%s", "localhost");
				res = env_check_res_local(CONFIG_PAWD, CONFIG_PAWD, "support_metrics");
			}else if(strlen(td.receiver) == 0){
				slgflg = true;
				return;
			}else{
				memset(machine_ip, 0, 20);
				phy_snprintf(machine_ip, 20, "%s", td.receiver);
				res = env_check_res(td.receiver, usr, pwd, td.skey, "support_metrics");
			}

			slgflg = true;
			sleep(1);

			if( res == NULL || strstr(res, "no") )
			{
				memset(msg, 0, 256);
				phy_snprintf(msg, 256, "%s", "Hit分析先决条件检查出错.");
				send_message(MESS, ERROR, 0, msg);
			}else{
				memset(msg, 0, 256);
				phy_snprintf(msg, 256, "%s", res);
				sleep(1);
				memset(msg, 0, 256);
				phy_snprintf(msg, 256, "%s机器支持的采样指标类型: %s.", machine_ip,res);
				send_message(MESS, COMM, HITAPIENVCK, msg);
			}
		break;

		case ACCMEMSYS:
 			slgmst = ACCMEMSYS;
			dynamic_tips("执行环境检查");
			sleep(1);
			if(strstr(td.receiver, "localhost")){
				ret = env_check_affi_local(CONFIG_PAWD, td.skey,ACCMEMSYS);
				if(1 == ret)
				{
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: memoryaccess system analysis envcheck err!");
					return;
				}
				slgflg = true;
				sleep(1);
				if(fil_isexist(kilflg) == true){
					return;
				}

				dynamic_tips("性能检测执行中 ");
				if(strstr(td.mes, "Hit") != NULL){
					run_detect_memacc_local(CONFIG_PAWD, ACCMEMSYS, td, "memacc_hitcpu");
				}else if(strstr(td.mes, "Miss") != NULL){
					run_detect_memacc_local(CONFIG_PAWD, ACCMEMSYS, td, "memacc_miss");
				}
			}else{
				ret = env_check_affi(td.receiver, usr, pwd, td.skey, ACCMEMSYS);
				if(1 == ret)
				{
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: memoryaccess system analysis envcheck err!");
					return;
				}
				slgflg = true;
				sleep(1);
				if(fil_isexist(kilflg) == true){
					return;
				}
				dynamic_tips("性能检测执行中 ");
				if(strstr(td.mes, "Hit") != NULL){
					run_detect_memacc(usr, pwd, ACCMEMSYS, td, "memacc_hitcpu");
				}else if(strstr(td.mes, "Miss") != NULL){
					run_detect_memacc(usr, pwd, ACCMEMSYS, td, "memacc_miss");
				}
			}
		break;

		case ACCMEMAPI:
			slgmst = ACCMEMAPI;
			dynamic_tips("执行环境检查");
			sleep(1);
			if(strstr(td.receiver, "localhost")){
				ret = env_check_affi_local(CONFIG_PAWD, td.skey,ACCMEMAPI);
				if(1 == ret)
				{
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: memoryaccess api analysis envcheck err!");
					return;
				}
				slgflg = true;
				sleep(1);
				if(fil_isexist(kilflg) == true){
					return;
				}

				dynamic_tips("性能检测执行中 ");
				if(strstr(td.mes, "Hit") != NULL){
					run_detect_memacc_local(CONFIG_PAWD, ACCMEMAPI, td, "memacc_hitcpu");
				}else if(strstr(td.mes, "Miss") != NULL){
					run_detect_memacc_local(CONFIG_PAWD, ACCMEMAPI, td, "memacc_miss");
				}
			}else{
				ret = env_check_affi(td.receiver, usr, pwd, td.skey, ACCMEMAPI);
				if(1 == ret)
				{
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: memoryaccess system analysis envcheck err!");
					return;
				}
				slgflg = true;
				sleep(1);
				if(fil_isexist(kilflg) == true){
					return;
				}
				dynamic_tips("性能检测执行中 ");
				if(strstr(td.mes, "Hit") != NULL){
					run_detect_memacc(usr, pwd, ACCMEMAPI, td, "memacc_hitcpu");
				}else if(strstr(td.mes, "Miss") != NULL){
					run_detect_memacc(usr, pwd, ACCMEMAPI, td, "memacc_miss");
				}
			}
		break;

		case IOSYS:
			slgmst = IOSYS;
			dynamic_tips("执行环境检查");
			sleep(1);
			if(strstr(td.receiver, "localhost")){
				ret = env_check_io_local(CONFIG_PAWD, td.skey, IOSYS);
				if(1 == ret)
				{
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: I/O envcheck err!");
					return;
				}
				slgflg = true;
				sleep(1);
				if(fil_isexist(kilflg) == true){
					return;
				}

				dynamic_tips("性能检测执行中 ");
				run_detect_io_local(CONFIG_PAWD, IOSYS, td, "analysis_io");
			}else{
				ret = env_check_io(td.receiver, usr, pwd, td.skey, IOSYS);
				if(1 == ret)
				{
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: IO envcheck err!");
					return;
				}
				slgflg = true;
				sleep(1);
				if(fil_isexist(kilflg) == true){
					return;
				}
				dynamic_tips("性能检测执行中 ");
				run_detect_io(usr, pwd, IOSYS, td, "analysis_io");
			}
		break;


		case IOAPI:
			slgmst = IOAPI;
			dynamic_tips("执行环境检查");
			sleep(1);
			if(strstr(td.receiver, "localhost")){
				ret = env_check_io_local(CONFIG_PAWD, td.skey, IOAPI);
				if(1 == ret)
				{
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: I/O envcheck err!");
					return;
				}
				slgflg = true;
				sleep(1);
				if(fil_isexist(kilflg) == true){
					return;
				}

				dynamic_tips("性能检测执行中 ");
				run_detect_io_local(CONFIG_PAWD, IOAPI, td, "analysis_io");
			}else{
				ret = env_check_io(td.receiver, usr, pwd, td.skey, IOAPI);
				if(1 == ret)
				{
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: IO envcheck err!");
					return;
				}
				slgflg = true;
				sleep(1);
				if(fil_isexist(kilflg) == true){
					return;
				}
				dynamic_tips("性能检测执行中 ");
				run_detect_io(usr, pwd, IOAPI, td, "analysis_io");
			}
		break;

		case FSCOMCFG:
		case NUMACOMCFG:
			send_message(MESS, COMM, mde, "获取编译文件...");
			if(strstr(td.receiver, "localhost"))
				run_comcfg(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, mde, td);
			else
				run_comcfg(td.receiver, usr, pwd, mde, td);
		break;
		case FSCOMBACK:
		case NUMACOMBACK:
			send_message(MESS, COMM, mde, "处理写回...");
			if(strstr(td.receiver, "localhost"))
				run_comback(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, mde, td);
			else
				run_comback(td.receiver, usr, pwd, mde, td);
		break;
		case FSCOMPILE:
		case NUMACOMPILE:
			send_message(MESS, COMM, mde, "准备编译资源...");
			if(strstr(td.receiver, "localhost"))
				run_compile(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, mde, td, "compile");
			else
				run_compile(td.receiver, usr, pwd, mde, td, "compile");
		break;
		case NUMAANA://NUMA分析对外版接口
			//send_message(MESS, COMM, mde, "开始分析...");
			if(strstr(td.receiver, "localhost"))
				run_numa_local("localhost", CONFIG_USER, CONFIG_PAWD, mde, td, "numa");
			else
				run_numa(td.receiver, usr, pwd, mde, td, "numa");
		break;
		case NUMALAUNCH://NUMA启动绑核
			//send_message(MESS, COMM, mde, "开始分析...");
			if(strstr(td.receiver, "localhost"))
				run_numalaunch_local(CONFIG_USER, CONFIG_PAWD, mde, td, "numa");
			else
				run_numalaunch(td.receiver, usr, pwd, mde, td, "numa");
		break;
		case NUMAENVCHECK://NUMA启动绑核
			slgmst = NUMAENVCHECK;
			dynamic_tips("执行环境检查");
			sleep(1);
			//send_message(MESS, COMM, mde, "开始分析...");
			if(strstr(td.receiver, "localhost"))
				run_numaenvcheck_local(CONFIG_USER, CONFIG_PAWD, mde, td, "numa");
			else
				run_numaenvcheck(td.receiver, usr, pwd, mde, td, "numa");
		break;
		case NUMAMEMMIG://NUMA启动绑核
			//send_message(MESS, COMM, mde, "开始分析...");
			if(strstr(td.receiver, "localhost"))
				run_numamemmig_local(CONFIG_USER, CONFIG_PAWD, mde, td, "numa");
			else
				run_numamemmig(td.receiver, usr, pwd, mde, td, "numa");
		break;
		case NUMATHREADMIG://NUMA启动绑核
			//send_message(MESS, COMM, mde, "开始分析...");
			if(strstr(td.receiver, "localhost"))
				run_numathreadmig_local(CONFIG_USER, CONFIG_PAWD, mde, td, "numa");
			else
				run_numathreadmig(td.receiver, usr, pwd, mde, td, "numa");
		break;
		case ABINDADD:
			if(strstr(td.receiver, "localhost"))
				run_autobindadd_local(CONFIG_USER, CONFIG_PAWD, mde, td, "autobind");
			else
				run_autobindadd(td.receiver, usr, pwd, mde, td, "autobind");
		break;
		case ABINDDEL:
			if(strstr(td.receiver, "localhost"))
				run_autobinddel_local(CONFIG_USER, CONFIG_PAWD, mde, td, "autobind");
			else
				run_autobinddel(td.receiver, usr, pwd, mde, td, "autobind");
		break;
		case ABINDLIST:
			if(strstr(td.receiver, "localhost"))
				run_autobindlst_local(CONFIG_USER, CONFIG_PAWD, mde, td, "autobind");
			else
				run_autobindlst(td.receiver, usr, pwd, mde, td, "autobind");
		break;
		case ABINDSTA:
			if(strstr(td.receiver, "localhost"))
				run_autobindsta_local(CONFIG_USER, CONFIG_PAWD, mde, td, "autobind");
			else
				run_autobindsta(td.receiver, usr, pwd, mde, td, "autobind");
		break;
		case ABINDSTP:
			if(strstr(td.receiver, "localhost"))
				run_autobindstp_local(CONFIG_USER, CONFIG_PAWD, mde, td, "autobind");
			else
				run_autobindstp(td.receiver, usr, pwd, mde, td, "autobind");
		break;
		case ENV:
			if(strstr(td.receiver, "localhost"))
				run_env_local("localhost", CONFIG_USER, CONFIG_PAWD, mde, td, "env");
			else
				run_env(td.receiver, usr, pwd, mde, td, "env");
		break;
		case ENVSTP:
			if(strstr(td.receiver, "localhost"))
				run_envstp_local(CONFIG_USER, CONFIG_PAWD, mde, td, "env");
			else
				run_envstp(td.receiver, usr, pwd, mde, td, "env");
		break;
		case ENVRT:
			if(strstr(td.receiver, "localhost"))
				run_envmonitor(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, mde, td, "envrt");
			else
				run_envmonitor(td.receiver, usr, pwd, mde, td, "envrt");
		break;
		case DATOP:
			if(strstr(td.receiver, "localhost"))
				run_datop_local(CONFIG_USER, CONFIG_PAWD, td.skey);
			else
				run_datop(td.receiver, usr, pwd, td.skey);
		break;
		case ENV_CHECK_DATOP:
			if(strstr(td.receiver, "localhost"))
				env_check_datop_local(CONFIG_USER, CONFIG_PAWD, td.skey);
			else
				env_check_datop(td.receiver, usr, pwd, td.skey);
		break;
		case RMTSAMP:
#if 0
//			send_message(MESS, COMM, RMTSAMP, "执行环境检查...");
			misdep = check_dependency(td.receiver, usr, pwd, "/opt/phytune/agent/arm/tools/hotspot-perfparser");
			memset(msg, 0, 256);
			if(misdep != NULL) {
				printf("Missing dependencies:\n");
				list* current = misdep;
				while (current != NULL) {
					phy_snprintf(msg, 256, "Missing dependencies: %s!", current->dependency);
					send_message(MESS, ERROR, RMTSAMP, msg);
//					free_list(misdep);
					break;
					return;
				}
//				free_list(misdep);
			}
#endif
			rc = create_sshsession(td.receiver, usr, pwd);
			if(rc != 0){
				phy_log(LOG_LEVEL_ERR, "Error connecting to localhost: %s", CONFIG_SERVICE_ADDR);
				send_message(MESS, ERROR, RMTSAMP, "SSH connection error!");
				return;
			}
			remote_sampling(td.receiver, usr, pwd, td.skey, td.date, td.mes);
		break;

		default:
//			printf("xxx");
		break;
	}
}
void handle_mes()
{

}

// 执行 shell 命令删除旧主机密钥
int remove_known_host(const char* hostname) {
    char command[256];
    snprintf(command, sizeof(command), "ssh-keygen -f ~/.ssh/known_hosts -R %s", hostname);
    printf("Executing command: %s\n", command);
    int result = system(command);
    return result;
}

// 验证主机密钥
int verify_knownhost(ssh_session session, const char* hostname) {
    enum ssh_known_hosts_e state;
    state = ssh_session_is_known_server(session);

    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            // 主机密钥匹配，一切正常
            break;

        case SSH_KNOWN_HOSTS_CHANGED:
            fprintf(stderr, "Warning: Host key for %s has changed!\n", hostname);
            fprintf(stderr, "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n");
            remove_known_host(hostname);
            return -1;

        case SSH_KNOWN_HOSTS_OTHER:
            fprintf(stderr, "Warning: The host key for %s is unknown!\n", hostname);
            return -1;

        case SSH_KNOWN_HOSTS_NOT_FOUND:
            fprintf(stderr, "Warning: No known_hosts file found, will create new one.\n");
            return 0;

        case SSH_KNOWN_HOSTS_UNKNOWN:
            fprintf(stderr, "Warning: The server is unknown. Do you trust the host key?\n");
            return 0;

        case SSH_KNOWN_HOSTS_ERROR:
            fprintf(stderr, "Error: %s\n", ssh_get_error(session));
            return -1;
    }
    return 0;
}

int ssh_stat(const char* address, const char* user, const char* password, const char* command)
{
    ssh_session session;
    ssh_channel channel;
    int rc;
    char buffer[256];
    int nbytes;

    session = ssh_new();
    if (session == NULL) {
        return -1;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, address);
    ssh_options_set(session, SSH_OPTIONS_USER, user);

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to %s: %s\n", address, ssh_get_error(session));
        ssh_free(session);
        return -1;
    }

    if (verify_knownhost(session, address) < 0) {
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    rc = ssh_userauth_password(session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with password: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    while (nbytes > 0) {
        fwrite(buffer, 1, nbytes, stdout);
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }

    ssh_channel_close(channel);
    ssh_channel_free(channel);

    ssh_disconnect(session);
    ssh_free(session);

    return 0;
}

void insert_agt(trandst td)
{
	char *add=NULL, *usr=NULL, *pwd=NULL, *sta=NULL;
	char **arr = NULL;
	char **stmp = NULL;

	struct transfer tran = {0};
	tran.mma.matp = MIX;
	tran.mma.mst = MIXLOD;
	memset(tran.td.mes, 0, 1280);

	char sql[256] = {0};
	int i = 0;
	int rc = 0;
	phy_strarr_init(&arr);
	str_to_arr(td.mes, ";", &arr);
	for (stmp = arr; NULL != *stmp; stmp++){
		if(i == 0){
			add = *stmp;
			rc = physql_select(add, &usr, &pwd, &sta);
			if(rc != SQLITE_OK){
				phy_log(LOG_LEVEL_ERR, "insert_agt:  err");
				goto out;
			}
			if(usr != NULL){
				send_message(MESS, ERROR, INSERT, "该机器已经添加!");
				goto out;
			}
		}
		if(i == 1){
			usr = *stmp;
		}
		if(i == 2){
			pwd = *stmp;
		}
		i++;
	}
	if(add == NULL || usr == NULL || pwd == NULL){
		phy_log(LOG_LEVEL_ERR, "insert_agt:  err");
		return;
	}
	rc = ssh_stat(add, usr, pwd, "ls /tmp");

	if(rc != 0){
		phy_log(LOG_LEVEL_ERR, "Error connecting to localhost: %s", add);
		tran.mma.matp = MESS;
		tran.mma.mme = ERROR;
		phy_snprintf(tran.td.mes, 1280, "Error connecting to: %s", add);
		write_message_to_controller((char*)(&tran), sizeof(struct transfer));
		return;
	}

	snprintf(sql, sizeof(sql), "INSERT INTO agent (address, user, password, status) VALUES ('%s', '%s', '%s', '%s');", add, usr, pwd, "available");
	rc = phy_sql_exe(m_phydb, sql, 5, 1);
	if(rc != SQLITE_OK){
		phy_log(LOG_LEVEL_ERR, "insert_agt:  err");
	}
//依赖检查插入到缓冲池
	scan_start(add);
	write_message_to_controller((char*)(&tran), sizeof(struct transfer));
out:
	phy_strarr_free(arr);
}

void delete_agt(trandst td)
{
	int rc = 0;
	char inscmd[256] = {0};
	agtrow* head = NULL;
	char **arr = NULL;
	char **stmp = NULL;

	phy_strarr_init(&arr);
	str_to_arr(td.mes, ";", &arr);
	for (stmp = arr; NULL != *stmp; stmp++){
		snprintf(inscmd, 256, "DELETE FROM agent WHERE address = '%s';", *stmp);
		rc = phy_sql_reqagts(m_phydb, inscmd, &head, 5, 1);
		if(rc != SQLITE_OK){
			phy_log(LOG_LEVEL_ERR, "delete_agt: %s err.", inscmd);
			goto out;
		}
		phy_free(head);
	}
out:
	phy_strarr_free(arr);
}

void handle_ctl(mesctl  mct, trandst td)
{
	switch(mct){
		case INSERT:
			insert_agt(td);
		break;
//		case INSTALL:
//			install_agt(td);
//		break;
//		case UINSTAL:
//			uinstal_agt(td);
//		break;
		case DELETE:
			delete_agt(td);
		break;
		default:
		break;
	}
}

void perf_elevatprivi(const char* add, const char* usr, const char* pwd, const char* spwd)
{
	char* results = NULL;
	char* dtres = NULL;
	char inscmd[256] = {0};

//判斷perf是否存在
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "%s", "[ -e /usr/bin/perf ] && echo \"existent\" || echo \"non-existent\"");
	forkpty_cutlines(add, usr, pwd, spwd, inscmd, 0, &results, -1);
	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(strstr(dtres, "non-existent")){
		phy_free(results);
		phy_free(dtres);
		send_message(MESS, ERROR, PERFEP, "未安裝 perf ！");
		return;
	}
	phy_free(results);
	phy_free(dtres);

//判斷是否可以切換到root
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "echo \"%s\" | sudo -S -U %s -k -l &> /dev/null && echo \"support!\" || echo \"unsupport!\"", pwd, usr);
	forkpty_cutlines(add, usr, pwd, spwd, inscmd, 0, &results, -1);
	dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(strstr(dtres, "unsupport")){
		phy_free(results);
		phy_free(dtres);
		send_message(MESS, ERROR, PERFEP, "此用戶不能切到root用戶！");
		return;
	}
	phy_free(results);
	phy_free(dtres);
//執行
	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "%s", "echo 0 > /proc/sys/kernel/kptr_restrict;echo -1 > /proc/sys/kernel/perf_event_paranoid");
	forkpty_cutlines(add, usr, pwd, spwd, inscmd, 2, &results, -1);

//	FILE * fp = NULL;
//	fp = fopen(envchkres, "w+");
//		dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
//	fprintf(fp, "%s", dtres);
//	fclose(fp);
	phy_free(results);
//	phy_free(dtres);
}

void perf_elevatprivi_local(const char *usr, const char* pwd, const char* spwd)
{
        char* results = NULL;
        char* dtres = NULL;
        char inscmd[256] = {0};

//判斷perf是否存在
        memset(inscmd, 0, 256);
        phy_snprintf(inscmd, 256, "%s", "[ -e /usr/bin/perf ] && echo \"existent\" || echo \"non-existent\"");
        forkpty_local(pwd, spwd, inscmd, 0, &results, -1);
        dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
        if(strstr(dtres, "non-existent")){
                phy_free(results);
                phy_free(dtres);
                send_message(MESS, ERROR, PERFEP, "未安裝 perf ！");
                return;
        }
        phy_free(results);
        phy_free(dtres);

//判斷是否可以切換到root
        memset(inscmd, 0, 256);
        phy_snprintf(inscmd, 256, "echo \"%s\" | sudo -S -U %s -k -l &> /dev/null && echo \"support!\" || echo \"unsupport!\"", pwd, usr);
        forkpty_local(pwd, spwd, inscmd, 0, &results, -1);
        dtres = parse_results(results, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
        if(strstr(dtres, "unsupport")){
                phy_free(results);
                phy_free(dtres);
                send_message(MESS, ERROR, PERFEP, "此用戶不能切到root用戶！");
                return;
        }
        phy_free(results);
        phy_free(dtres);
//執行
        memset(inscmd, 0, 256);
        phy_snprintf(inscmd, 256, "%s", "echo 0 > /proc/sys/kernel/kptr_restrict;echo -1 > /proc/sys/kernel/perf_event_paranoid");
        forkpty_local(pwd, spwd, inscmd, 2, &results, -1);
        phy_free(results);
}

int check_remote_root_password(const char *hostname, const char *user, const char *user_password, const char *root_password)
{
    ssh_session session;
    ssh_channel channel;
    int rc;
    char buffer[256];
    unsigned int nbytes;
    int total_read = 0;

    session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "Error: Failed to create SSH session.\n");
        return 0;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
    ssh_options_set(session, SSH_OPTIONS_USER, user);

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to %s: %s\n", hostname, ssh_get_error(session));
        ssh_free(session);
        return 0;
    }
//    free(session->agent_state);
//	ssh_disconnect(session);
//	ssh_free(session);
//	return 0;

    rc = ssh_userauth_password(session, NULL, user_password);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Authentication failed for user %s: %s\n", user, ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return 0;
    }

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        fprintf(stderr, "Error: Failed to create channel.\n");
        ssh_disconnect(session);
        ssh_free(session);
        return 0;
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error: Failed to open channel session: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        return 0;
    }

// 执行验证root密码的命令
// snprintf(buffer, sizeof(buffer), "echo %s | sudo -S -k echo 'root密码正确' 2>&1", root_password);
   snprintf(buffer, sizeof(buffer), "echo %s | su -c \"echo 'root密码正确'\" 2>&1", root_password);
    rc = ssh_channel_request_exec(channel, buffer);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error: Failed to execute command: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        return 0;
    }

    memset(buffer, 0, sizeof(buffer));
    total_read = 0;
    sleep(1);
    while (1) {
        nbytes = ssh_channel_read(channel, buffer + total_read, sizeof(buffer) - total_read - 1, 0);
        if (nbytes == SSH_ERROR) {
            fprintf(stderr, "Error: Failed to read channel: %s\n", ssh_get_error(session));
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            ssh_disconnect(session);
            ssh_free(session);
            return 0;
        }
        if (nbytes == 0) {
            break; // EOF received
        }
        total_read += nbytes;
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    ssh_disconnect(session);
    ssh_free(session);

    if (custom_strstr(buffer, total_read, "root密码正确")) {
        return 1;
    } else {
        return 0;
    }
}

int check_local_root_password(const char *upwd, const char *rpwd)
{
    char inscmd[256];
    char *res = NULL;

// 执行验证root密码的命令
   snprintf(inscmd, sizeof(inscmd), "echo %s | su -c \"echo 'root密码正确'\" 2>&1", rpwd);
   if(0 != get_result_str(inscmd, &res)){
	   phy_log(LOG_LEVEL_ERR, "check_local_root_password: err.");
	   return 0;
   }
    if (strstr(res, "root密码正确")) {
    	phy_free(res);
        return 1;
    } else {
    	phy_free(res);
        return 0;
    }
}

int check_remote_sudo_password(const char *hostname, const char *user, const char *user_password, const char *sudo_password)
{
    ssh_session session;
    ssh_channel channel;
    int rc;
    char buffer[256];
    unsigned int nbytes;
    int total_read = 0;

    session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "Error: Failed to create SSH session.\n");
        return 0;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
    ssh_options_set(session, SSH_OPTIONS_USER, user);

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to %s: %s\n", hostname, ssh_get_error(session));
        ssh_free(session);
        return 0;
    }
//  free(session->agent_state);
//	ssh_disconnect(session);
//	ssh_free(session);
//	return 0;

    rc = ssh_userauth_password(session, NULL, user_password);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Authentication failed for user %s: %s\n", user, ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return 0;
    }

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        fprintf(stderr, "Error: Failed to create channel.\n");
        ssh_disconnect(session);
        ssh_free(session);
        return 0;
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error: Failed to open channel session: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        return 0;
    }

// 执行验证root密码的命令
    snprintf(buffer, sizeof(buffer), "echo %s | sudo -S -k echo 'sudo密码正确' 2>&1", sudo_password);
//   snprintf(buffer, sizeof(buffer), "echo %s | su -c \"echo 'root密码正确'\" 2>&1", root_password);
    rc = ssh_channel_request_exec(channel, buffer);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error: Failed to execute command: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        return 0;
    }

    memset(buffer, 0, sizeof(buffer));
    total_read = 0;
    sleep(1);
    while (1) {
        nbytes = ssh_channel_read(channel, buffer + total_read, sizeof(buffer) - total_read - 1, 0);
        if (nbytes == SSH_ERROR) {
            fprintf(stderr, "Error: Failed to read channel: %s\n", ssh_get_error(session));
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            ssh_disconnect(session);
            ssh_free(session);
            return 0;
        }
        if (nbytes == 0) {
            break; // EOF received
        }
        total_read += nbytes;
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    ssh_disconnect(session);
    ssh_free(session);

    if (custom_strstr(buffer, total_read, "sudo密码正确")) {
        return 1;
    } else {
        return 0;
    }
}

void send_bigdata(mestype matp, messta smtp, int affi, void* dat, size_t len){
	ltransfer* ltran = NULL;
	size_t sdln=0;
	sdln=sizeof(struct ltransfer) + len;
	ltran=(ltransfer*)malloc(sdln);
	memset(ltran, 0, sdln);
	ltran->mma.matp =EXECUT;
	ltran->mma.mst =smtp;
	ltran->td.affi = affi;
	ltran->td.dln=sdln;
	if(len == 0){
	    ltran->td.identifier=7777;
	}
	if(dat != NULL){
	    memcpy(ltran->td.mes, dat, len);
	}
	write_message_to_controller(ltran, sdln);
	phy_free(ltran);
}

void get_fbrow_local(const char* usr, const char* pwd, const char* pth)
{
	vphd* vhd = NULL;
	void* ret = NULL;
	size_t len = 0;
	char* res = NULL;
	vhd = lst_filebrowser_local(usr, pwd, pth);
	if(vhd->len == 0){
		send_bigdata(EXECUT, FBROW, FBROW, NULL, 0);
		lst_free(vhd);
		return;
	}
	filst2mem(vhd, &ret, &len);
#ifdef SENDFBSR
	send_bigdata(EXECUT, FBROW, FBROW, ret, len);
#else
	shm_free(SHM_RMTI, SEM_RMTI);
	if(true == create_shm(SHM_RMTI, SEM_RMTI, RMTSHML)){
		if( false == shm_write(SHM_RMTI, SEM_RMTI, ret, len) ){
			phy_log(LOG_LEVEL_ERR, "get_filebrowser: shm_write err.");
		}
	}else{
		phy_log(LOG_LEVEL_ERR, "get_filebrowser: create_shm err.");
	}
	send_bigdata(EXECUT, FBROW, FBROW, NULL, len);
#endif
	phy_free(ret);
	lst_free(vhd);

	free(res);
}

void get_fbrow(const char* add, const char* usr, const char* pwd, const char* pth)
{
	vphd* vhd = NULL;
	void* ret = NULL;
	size_t len = 0;
	char* res = NULL;
	vhd = lst_filebrowser(add, usr, pwd, pth);
	if(vhd->len == 0){
		send_bigdata(EXECUT, FBROW, FBROW, NULL, 0);
		lst_free(vhd);
		return;
	}
	filst2mem(vhd, &ret, &len);
#ifdef SENDFBSR
	send_bigdata(EXECUT, FBROW, FBROW, ret, len);
#else
	shm_free(SHM_RMTI, SEM_RMTI);
	if(true == create_shm(SHM_RMTI, SEM_RMTI, RMTSHML)){
		if( false == shm_write(SHM_RMTI, SEM_RMTI, ret, len) ){
			phy_log(LOG_LEVEL_ERR, "get_filebrowser: shm_write err.");
		}
	}else{
		phy_log(LOG_LEVEL_ERR, "get_filebrowser: create_shm err.");
	}
	send_bigdata(EXECUT, FBROW, FBROW, NULL, len);
#endif
	phy_free(ret);
	lst_free(vhd);

	free(res);
}

void get_filebrowser(const char* add, const char* usr, const char* pwd, const char* pth)
{
	vphd* vhd = NULL;
	void* ret = NULL;
	size_t len = 0;
	char* res = NULL;
	vhd = lst_filebrowser(add, usr, pwd, pth);
	if(vhd->len == 0){
		send_bigdata(EXECUT, FILBRSER, FILBRSER, NULL, 0);
		lst_free(vhd);
		return;
	}
	filst2mem(vhd, &ret, &len);
#ifdef SENDFBSR
	send_bigdata(EXECUT, FILBRSER, FILBRSER, ret, len);
#else
	shm_free(SHM_RMT, SEM_RMT);
	if(true == create_shm(SHM_RMT, SEM_RMT, RMTSHML)){
		if( false == shm_write(SHM_RMT, SEM_RMT, ret, len) ){
			phy_log(LOG_LEVEL_ERR, "get_filebrowser: shm_write err.");
		}
	}else{
		phy_log(LOG_LEVEL_ERR, "get_filebrowser: create_shm err.");
	}
	send_bigdata(EXECUT, FILBRSER, FILBRSER, NULL, len);
#endif
	phy_free(ret);
	lst_free(vhd);

	free(res);
}

void install_tools(const char* add, const char* usr, const char* pwd, const char* spwd, int  mex)
{
#define in_envchkres "/tmp/install_infos.res"
	char* judge_res = NULL;
	char* results = NULL;
	char inscmd[256] = {0};
	memset(inscmd, 0, 256);
	//1、判断是apt安装还是yum安装
	phy_snprintf(inscmd, 256, "command -v yum");
	forkpty_cutlines(add, usr, pwd, spwd, inscmd, 0, &judge_res, -1);
	FILE * fp = NULL;
	char* dtres = NULL;
	fp = fopen(in_envchkres, "w+");
		dtres = parse_results(judge_res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	fprintf(fp, "%s", dtres);
	fclose(fp);

	char cleaned_dtres[PHRASE];
	int len = strlen(dtres);
	int start = 0;
	int end = len - 1;
	// 去除开头的空格、换行等
	while (isspace(dtres[start])) {
	    start++;
	}
	// 去除结尾的空格、换行等
	while (end > start && isspace(dtres[end])) {
	    end--;
	}
	// 复制有效部分到新字符串
	memcpy(cleaned_dtres, dtres + start, end - start + 1);
	cleaned_dtres[end - start + 1] = '\0';

	switch(mex){
		case BLKINST:
			if (strstr(cleaned_dtres, "bin/yum") != NULL){
				phy_snprintf(inscmd, 256, "yum install blktrace");
				forkpty_cutlines(add, usr, pwd, spwd, inscmd, 1, &results, -1);
			}else{
				phy_snprintf(inscmd, 256, "apt install blktrace");
				forkpty_cutlines(add, usr, pwd, spwd, inscmd, 1, &results, -1);
			}
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "安装完成.");
			send_message(MESS, ERROR, IOSYS, inscmd);
		break;
		case StraceINST:
			if (strstr(cleaned_dtres, "bin/yum") != NULL){
				phy_snprintf(inscmd, 256, "yum install strace");
				forkpty_cutlines(add, usr, pwd, spwd, inscmd, 1, &results, -1);
			}else{
				phy_snprintf(inscmd, 256, "apt install strace");
				forkpty_cutlines(add, usr, pwd, spwd, inscmd, 1, &results, -1);
			}
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "安装完成.");
			send_message(MESS, ERROR, IOAPI, inscmd);
		break;
	}
	phy_free(results);
	phy_free(dtres);
#undef in_envchkres
}

void handle_exe(mesexe  mex, trandst td)
{
	int rc = 0;
	char* usr = NULL;
	char* pwd = NULL;
	char* sta = NULL;
	char inscmd[256] = {0};
	char* results = NULL;
    int riflg = 0;
    int ret = 0;
    ltrandst* ltd = NULL;
    fil_remove(kilflg);

    memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "rm -rf /tmp/rmt");
	forkpty_cutlines(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, NULL, inscmd, 4, &results, -1);
	phy_free(results);

	memset(inscmd, 0, 256);
	phy_snprintf(inscmd, 256, "rm -rf /tmp/rtres_folder");
	forkpty_cutlines(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, NULL, inscmd, 4, &results, -1);
	phy_free(results);
	switch(mex){
		case FILBRSER:
			if(strstr(td.receiver, "localhost")){
				get_filebrowser(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, td.mes);
			} else {
				rc = physql_select(td.receiver, &usr, &pwd, &sta);
				if(rc != SQLITE_OK){
					phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", td.receiver);
					return;
				}
				get_filebrowser(td.receiver, usr, pwd, td.mes);
		   }
		break;
		case FBROW:
			if(strstr(td.receiver, "localhost")){
				get_fbrow_local(CONFIG_USER, CONFIG_PAWD, td.mes);
			} else {
				rc = physql_select(td.receiver, &usr, &pwd, &sta);
				if(rc != SQLITE_OK){
					phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", td.receiver);
					return;
				}
				get_fbrow(td.receiver, usr, pwd, td.mes);
		   }
		break;
		case RMTENV:
			if(strstr(td.receiver, "localhost")){
				loc_env_entry(CONFIG_USER, CONFIG_PAWD, CONFIG_PAWD, td.mes, 0);
//				rmt_env_entry(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, CONFIG_PAWD, td.mes, 0);
			} else {
				rc = physql_select(td.receiver, &usr, &pwd, &sta);//sql查询
				if(rc != SQLITE_OK){
					phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", td.receiver);
					return;
				}
				rmt_env_entry(td.receiver, usr, pwd, pwd, td.mes, 0);//upw(普通密码), rpw(root密码), rfl == 0
				phy_log(LOG_LEVEL_TRACE, "handle_exe: RMTEXEC.");
		   }
		break;

		case RMTNUMA:
			if(strstr(td.receiver, "localhost")){
				loc_numa_entry(CONFIG_USER, CONFIG_PAWD, CONFIG_PAWD, td.mes, 0);
			} else {
				rc = physql_select(td.receiver, &usr, &pwd, &sta);//sql查询
				if(rc != SQLITE_OK){
					phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", td.receiver);
					return;
				}
				rmt_numa_entry(td.receiver, usr, pwd, pwd, td.mes, 0);//upw(普通密码), rpw(root密码), rfl == 0
				phy_log(LOG_LEVEL_TRACE, "handle_exe: RMTNUMA.");
		   }
		break;
		case RMTENVEXIT:
			if(strstr(td.receiver, "localhost")){
				loc_env_exit();
			} else {
				rmt_env_exit();
			}
		break;
		case RMTNUMAEXIT:
			if(strstr(td.receiver, "localhost")){
				loc_numa_exit();
			} else {
				rmt_numa_exit();
			}
		break;
		case PERFEP:
			if(strstr(td.receiver, "localhost")){
				riflg = check_local_root_password(CONFIG_PAWD, td.skey);
				if(riflg == 1){
					perf_elevatprivi_local(CONFIG_USER, CONFIG_PAWD, td.skey);
				}else{
					send_message(MESS, ERROR, PERFEP, "root 密码错误.");
				}
			}else{
				rc = physql_select(td.receiver, &usr, &pwd, &sta);
				if(rc != SQLITE_OK){
					phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", td.receiver);
					return;
				}
				riflg = check_remote_root_password(td.receiver, usr, pwd, td.skey);
				if(riflg == 1){
					perf_elevatprivi(td.receiver, usr, pwd, td.skey);
				}else{
					send_message(MESS, ERROR, PERFEP, "root 密码错误.");
				}
			}
		break;
		case BLKINST:
			if(strstr(td.receiver, "localhost")){
				riflg = check_remote_sudo_password(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, td.skey);
				if(riflg == 1){
					dynamic_tips("正在安装blktrace ");
					install_tools(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, td.skey, BLKINST);
					slgflg = true;
				}else{
					send_message(MESS, ERROR, BLKINST, "sudo 密码错误.");
				}
			}else{
				rc = physql_select(td.receiver, &usr, &pwd, &sta);
				if(rc != SQLITE_OK){
					phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", td.receiver);
					return;
				}
				riflg = check_remote_sudo_password(td.receiver, usr, pwd, td.skey);
				if(riflg == 1){
					dynamic_tips("正在安装blktrace ");
					install_tools(td.receiver, usr, pwd, td.skey, BLKINST);
					slgflg = true;
				}else{
					send_message(MESS, ERROR, BLKINST, "sudo 密码错误.");
				}
			}
		break;
		case StraceINST:
			if(strstr(td.receiver, "localhost")){
				riflg = check_remote_sudo_password(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, td.skey);
				if(riflg == 1){
					dynamic_tips("正在安装strace ");
					install_tools(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, td.skey, StraceINST);
					slgflg = true;
				}else{
					send_message(MESS, ERROR, StraceINST, "root 密码错误.");
				}
			}else{
				rc = physql_select(td.receiver, &usr, &pwd, &sta);
				if(rc != SQLITE_OK){
					phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", td.receiver);
					return;
				}
				riflg = check_remote_sudo_password(td.receiver, usr, pwd, td.skey);
				if(riflg == 1){
					dynamic_tips("正在安装strace ");
					install_tools(td.receiver, usr, pwd, td.skey, StraceINST);
					slgflg = true;
				}else{
					send_message(MESS, ERROR, StraceINST, "root 密码错误.");
				}
			}
		break;

		case RMTEXEC:
			if(strstr(td.receiver, "localhost")){
				rmt_exec_entry(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, NULL, td.mes, 0);
			} else {
				rc = physql_select(td.receiver, &usr, &pwd, &sta);
				if(rc != SQLITE_OK){
					phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", td.receiver);
					return;
				}
				rmt_exec_entry(td.receiver, usr, pwd, NULL, td.mes, 0);
				phy_log(LOG_LEVEL_TRACE, "handle_exe: RMTEXEC.");
		   }
#if 0
			ltd = (ltrandst*)(&td);
			if(strstr(ltd->receiver, "localhost")){
				rmt_exec_entry(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, NULL, ltd->mes, 0);
			} else {
				rc = physql_select(ltd->receiver, &usr, &pwd, &sta);
				if(rc != SQLITE_OK){
					phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", ltd->receiver);
					return;
				}
				rmt_exec_entry(ltd->receiver, usr, pwd, NULL, ltd->mes, 0);
				phy_log(LOG_LEVEL_TRACE, "handle_exe: RMTEXEC.");
		   }
#endif
		break;

		case RMTEXIT:
			rmt_exec_exit();
		break;

		case IORTEXEC:
//			dynamic_tips("实时检测加载中 ");
			send_message(MESS, COMM, IORTEXEC, "实时检测加载中...");

			ltd = (ltrandst*)(&td);
			phy_log(LOG_LEVEL_CRIT, "messagechannel: mestype %d, subtype %d,  td.receiver %s, date %s, mes %s.", EXECUT, IORTEXEC, ltd->receiver, ltd->date, ltd->mes);
			if(strstr(ltd->receiver, "localhost")){
				ret = env_check_io_local(CONFIG_PAWD,NULL, IORTEXEC);
				if(1 == ret)
				{
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: I/O envcheck err!");
					return;
				}
				run_realtime_local(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, IORTEXEC, ltd, "analysis_io");
			} else {
				rc = physql_select(ltd->receiver, &usr, &pwd, &sta);
				if(rc != SQLITE_OK){
					phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", ltd->receiver);
					return;
				}
				ret = env_check_io(ltd->receiver,usr, pwd, NULL, IORTEXEC);
				if(1 == ret)
				{
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: I/O envcheck err!");
					return;
				}
				run_realtime(ltd->receiver,usr, pwd, IORTEXEC,  ltd, "analysis_io");
				phy_log(LOG_LEVEL_TRACE, "handle_exe: IORTEXEC.");
		   }
		break;

		case IORTEXIT:
			rmt_exec_exit();
			send_message(EXECUT, IORTEXIT, IORTEXIT, NULL);
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "rm -rf /tmp/rmt");
			forkpty_cutlines(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, NULL, inscmd, 4, &results, -1);
			phy_free(results);

			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "rm -rf /tmp/rtres_folder");
			forkpty_cutlines(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, NULL, inscmd, 4, &results, -1);
			phy_free(results);
		break;

		case SYSHITRTEXEC:
			dynamic_tips("实时检测加载中 ");

			ltd = (ltrandst*)(&td);
			phy_log(LOG_LEVEL_CRIT, "messagechannel: mestype %d, subtype %d,  td.receiver %s, date %s, mes %s.", EXECUT, SYSHITRTEXEC, ltd->receiver, ltd->date, ltd->mes);
			if(strstr(ltd->receiver, "localhost")){
				ret=env_check_affi_local(CONFIG_PAWD,NULL, SYSHITRTEXEC);
				if(ret==1){
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: memoryaccess api analysis envcheck err!");
					return;
				}
//				run_realtime_local(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, SYSHITRTEXEC, ltd, "memacc_hit");
				run_realtime_multiproc_local(CONFIG_USER, CONFIG_PAWD, SYSHITRTEXEC, ltd, "memacc_hitcpu");
			} else {
				rc = physql_select(ltd->receiver, &usr, &pwd, &sta);
				if(rc != SQLITE_OK){
					phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", ltd->receiver);
					return;
				}
				ret=env_check_affi(ltd->receiver,usr, pwd,NULL, SYSHITRTEXEC);
				if(ret==1){
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: memoryaccess api analysis envcheck err!");
					return;
				}
//				run_realtime(ltd->receiver,usr, pwd, SYSHITRTEXEC,  ltd, "memacc_hit");
				run_realtime_multiproc(ltd->receiver,usr, pwd, SYSHITRTEXEC,  ltd, "memacc_hitcpu");
				phy_log(LOG_LEVEL_TRACE, "handle_exe: HITRTEXEC.");
		   }
		break;

		case SYSMISSRTEXEC:
			dynamic_tips("实时检测加载中 ");

			ltd = (ltrandst*)(&td);
			phy_log(LOG_LEVEL_CRIT, "messagechannel: mestype %d, subtype %d,  td.receiver %s, date %s, mes %s.", EXECUT, SYSMISSRTEXEC, ltd->receiver, ltd->date, ltd->mes);
			if(strstr(ltd->receiver, "localhost")){
				ret=env_check_affi_local(CONFIG_PAWD, NULL, SYSMISSRTEXEC);
				if(ret==1){
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: memoryaccess api analysis envcheck err!");
					return;
				}
				run_realtime_multiproc_local(CONFIG_USER, CONFIG_PAWD, SYSMISSRTEXEC, ltd, "memacc_miss");
			} else {
				rc = physql_select(ltd->receiver, &usr, &pwd, &sta);
				if(rc != SQLITE_OK){
					phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", ltd->receiver);
					return;
				}
				ret=env_check_affi(ltd->receiver,usr, pwd,NULL, SYSMISSRTEXEC);
				if(ret==1){
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: memoryaccess api analysis envcheck err!");
					return;
				}
				run_realtime_multiproc(ltd->receiver,usr, pwd, SYSMISSRTEXEC,  ltd, "memacc_miss");
				phy_log(LOG_LEVEL_TRACE, "handle_exe: MISSRTEXEC.");
		   }
		break;

		case APIHITRTEXEC:
			dynamic_tips("实时检测加载中 ");

			ltd = (ltrandst*)(&td);
			phy_log(LOG_LEVEL_CRIT, "messagechannel: mestype %d, subtype %d,  td.receiver %s, date %s, mes %s.", EXECUT, APIHITRTEXEC, ltd->receiver, ltd->date, ltd->mes);
			if(strstr(ltd->receiver, "localhost")){
				ret=env_check_affi_local(CONFIG_PAWD,NULL, APIHITRTEXEC);
				if(ret==1){
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: memoryaccess api analysis envcheck err!");
					return;
				}
//				run_realtime_local(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, APIHITRTEXEC, ltd, "memacc_hit");
				run_realtime_multiproc_local(CONFIG_USER, CONFIG_PAWD, APIHITRTEXEC, ltd, "memacc_hitcpu");
			} else {
				rc = physql_select(ltd->receiver, &usr, &pwd, &sta);
				if(rc != SQLITE_OK){
					phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", ltd->receiver);
					return;
				}
				ret=env_check_affi(ltd->receiver,usr, pwd,NULL, APIHITRTEXEC);
				if(ret==1){
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: memoryaccess api analysis envcheck err!");
					return;
				}
//				run_realtime(ltd->receiver,usr, pwd, APIHITRTEXEC,  ltd, "memacc_hit");
				run_realtime_multiproc(ltd->receiver,usr, pwd, APIHITRTEXEC,  ltd, "memacc_hitcpu");
				phy_log(LOG_LEVEL_TRACE, "handle_exe: HITRTEXEC.");
		   }
		break;

		case APIMISSRTEXEC:
			dynamic_tips("实时检测加载中 ");

			ltd = (ltrandst*)(&td);
			phy_log(LOG_LEVEL_CRIT, "messagechannel: mestype %d, subtype %d,  td.receiver %s, date %s, mes %s.", EXECUT, APIMISSRTEXEC, ltd->receiver, ltd->date, ltd->mes);
			if(strstr(ltd->receiver, "localhost")){
				ret=env_check_affi_local(CONFIG_PAWD,NULL, APIMISSRTEXEC);
				if(ret==1){
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: memoryaccess api analysis envcheck err!");
					return;
				}
				run_realtime_multiproc_local(CONFIG_USER, CONFIG_PAWD, APIMISSRTEXEC, ltd, "memacc_miss");
			} else {
				rc = physql_select(ltd->receiver, &usr, &pwd, &sta);
				if(rc != SQLITE_OK){
					phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", ltd->receiver);
					return;
				}
				ret=env_check_affi(ltd->receiver,usr, pwd,NULL, APIMISSRTEXEC);
				if(ret==1){
					slgflg = true;
					phy_log(LOG_LEVEL_ERR, "%s", "handle_det: memoryaccess api analysis envcheck err!");
					return;
				}
				run_realtime_multiproc(ltd->receiver,usr, pwd, APIMISSRTEXEC,  ltd, "memacc_miss");
				phy_log(LOG_LEVEL_TRACE, "handle_exe: MISSRTEXEC.");
		   }
		break;

		case MEMACCRTEXIT:
			rmt_exec_exit();
			send_message(EXECUT, MEMACCRTEXIT, MEMACCRTEXIT, NULL);
			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "rm -rf /tmp/rmt");
			forkpty_cutlines(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, NULL, inscmd, 4, &results, -1);
			phy_free(results);

			memset(inscmd, 0, 256);
			phy_snprintf(inscmd, 256, "rm -rf /tmp/rtres_folder");
			forkpty_cutlines(CONFIG_SERVICE_ADDR, CONFIG_USER, CONFIG_PAWD, NULL, inscmd, 4, &results, -1);
			phy_free(results);
		break;

		default:

		break;
	}
	phy_free(usr);
	phy_free(pwd);
	phy_free(sta);
}

void handle_message(struct transfer* tsp)
{
#if 1
	switch (tsp->mma.matp){
		case 	STATUS:
			break;
		case	DETECT:
			handle_det(tsp->mma.mde, tsp->td);
			break;
		case	MESS:
			handle_mes();
			break;
		case	CTRLAGT:
			handle_ctl(tsp->mma.mct, tsp->td);
			break;
		case	EXECUT:
			handle_exe(tsp->mma.mex, tsp->td);
			break;
		case HISTORY:
			handle_his(tsp->mma.mhi, tsp->td);
			break;
		case MIX:
			handle_mix(tsp->mma.mmi, tsp->td);
			break;
		case HEARTBEAT:
			break;
		default:
			printf("Unknown message type\n");
			break;
	}
#endif
}

bool sendmsgx(void* data, size_t len)
{
    int wfd = 0;
    size_t wln = 0;
    if ((wfd = open(FIFO_WRITE, O_WRONLY)) < 0) {
        printf("Open fifo[\"%s\"] for write error: %s\n", FIFO_WRITE, strerror(errno));
        return false;
    }
    wln = write(wfd, data, len);
    close(wfd);
    if(wln != len){
        return false;
    }
    return true;
}

unsigned int phy_channel()
{
    int        fdr_fifo = -1;
    int        fdw_fifo = -1;
    int 	   ret;
    size_t     n;
    fd_set     rdset;
    char buf[BUF_SIZE];
    int        flag  = -1;
    char* dat = null;
    ntsp* pd = null;

    flag = PIPESTARTMODE;
    phy_setproctitle("Channel, Pid:%d", (int)getpid());
    phy_log(LOG_LEVEL_TRACE, "phy_server: Channel, Pid:%d.", (int)getpid());
    if (access(FIFO_READ, F_OK)) //判断FIFO_READ 是否存在
    {
        printf("Fifo file \"%s\" not exist and will create it now.\n", FIFO_READ);
        mkfifo(FIFO_READ, 06666);
    }

    if (access(FIFO_WRITE, F_OK))
    {
        printf("Fifo file \"%s\" not exist and will create it now.\n", FIFO_WRITE);
        mkfifo(FIFO_WRITE, 06666);
    }

    signal(SIGPIPE, signal_pipe);  ///注册信号函数

    if (0 == flag)
    {
        phy_log(LOG_LEVEL_TRACE, "channel: Start open '%s'for read and it will bolcked here untill write pipe opened...", FIFO_READ);
        if ( (fdr_fifo = open(FIFO_READ, O_RDWR)) < 0)
        {
            printf("Open fifo[%s] for read error: %s\n", FIFO_READ, strerror(errno));
            return -1;

        }

        phy_log(LOG_LEVEL_TRACE, "channel: Start open '%s' for write ...", FIFO_WRITE);
        if ( (fdw_fifo = open(FIFO_WRITE, O_RDWR)) < 0)
        {
            printf("Open fifo[%s] for write error: %s\n", FIFO_WRITE, strerror(errno));
            return -1;
        }
    } else {
        phy_log(LOG_LEVEL_TRACE, "channel:  Start open '%s'for write and it will bolcked here untill write pipe opened...", FIFO_READ);
        if ( (fdw_fifo = open(FIFO_READ, O_RDWR)) < 0)
        {
            printf("Open fifo[%s] for write error: %s\n", FIFO_READ, strerror(errno));
            return -1;
        }

        phy_log(LOG_LEVEL_TRACE, "channel:  Start open '%s' for read ...", FIFO_WRITE);
        if ( (fdr_fifo = open(FIFO_WRITE, O_RDWR)) < 0)
        {
            printf("Open fifo[%s] for read error: %s\n", FIFO_WRITE, strerror(errno));
            return -1;
        }
    }

    sleep(5);
    scan_init();
    init_ntmp();

//    lst* slx = null;
//    if(	HMAP_S_OK == get_hash_ext(hwmp, "10.31.31.217", "pcie", nam, "节点号", &slx) ) {
//		lst* scu = slx;
//		while (scu) {
//			nod = strdup(scu->dat);
//			scu = scu->next;
//		}
//	}
//	lst_fre(slx);


    while(!g_stop)
    {
        FD_ZERO(&rdset);
        FD_SET(fdr_fifo, &rdset);
        usleep(1000);
        ret = select(fdr_fifo + 1, &rdset, NULL, NULL, NULL);
        //实时场景下，执行到该处表示管道已就绪，正在监听ui端按钮信号。
        if (ret == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				phy_log(LOG_LEVEL_TRACE, "channel: Select get error: %s\n", strerror(errno));
				break;
			}
		}else if (ret == 0){
			phy_log(LOG_LEVEL_TRACE, "channel:  %s\n", "Select get timeout.");
		} else {
			if (FD_ISSET(fdr_fifo, &rdset))
			{
				memset(buf, 0, BUF_SIZE);
				n  = read(fdr_fifo, buf,sizeof(buf) - 1);
				if (n < 0)
				{
					if(errno == EINTR){
						continue;
					}else{
						phy_log(LOG_LEVEL_TRACE, "channel: Read form fifo get error: %s\n", strerror(errno));
						break;
					}
				}else if (0 == n){
					phy_log(LOG_LEVEL_TRACE, "channel: Another side of fifo get closed and program will exit now.");
					continue;
				}else{
					if( 0 == strncmp(buf, m_nspdes,  m_nspl) ){
						pd = (ntsp*)buf;
						dat = null;
						dat = (char*)malloc(pd->dln);
						memset(dat, 0, pd->dln);
						memcpy(dat, buf + OFFSETOF(ntsp, dat), pd->dln);
						handle(pd->mdt, pd->dln, dat);
						phy_free(dat);
#if 0
						char* sdat = null;
						sdat = (char*)malloc(pd->dln + sizeof(ntsp));
						memset(sdat, 0, pd->dln + sizeof(ntsp));
						memcpy(sdat, pd, sizeof(ntsp));
						memcpy(sdat + OFFSETOF(ntsp, dat), buf + OFFSETOF(ntsp, dat), pd->dln);
						sendmsgx(sdat, pd->dln + sizeof(ntsp));
						phy_free(sdat);
#endif
						continue;
					}
					struct transfer* tsp = NULL;
					tsp = (struct transfer*)buf;
					phy_log(LOG_LEVEL_TRACE, "channel:  --------------- %s\n", tsp->td.mes);
					handle_message(tsp);
				}
			}
		}
    }
    return 0;
}
