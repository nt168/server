#ifndef PHY_TTY_H
#define PHY_TTY_H
#include <pty.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include "phy_ssh.h"
#include "channel.h"
#include "common.h"
#include "log.h"
#include "phy_def.h"

struct cmd_st
{
	char usr[32];
	char pass[32];
	char cmd[256];
	char scmd[256];
	int  ipthd;
	bool prlg;
};

void signal_handle(int sig);
void handle_child(int sig);
void append_result(char** results, const char* buffer);
unsigned int phytty_slave();
unsigned int phytty_master();
void* tty_controller(void* arg);
void phytty_control(const char* smbs);
int phy_tty_server(int port);
int phytty_start(const char* cmd, int port);
void phytty_control_symbols(const char* smbs);
int phy_tty_run(const char* add, const char* usr, const char* pwd, const char* cmd, char** record);
int phy_tty_run_interactive(mltarg* marg, char** record, bool flag);
int phy_tty_run_forkpty(mltarg* marg, char** record, bool flag);
void* tty_pthread_write(void * args);
void* tty_pthread_read(void * args);
void phy_run_cmd(const char* add, const char* usr, const char* pwd, const char* cmd);
int my_forkptys(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results);
int forkpty_addcutlines(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec);
int forkpty_cutlines(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec);
int forkpty_local(const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec);
int forkpty_runpid(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec);
int forkpty_envmonitor(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec, const char* date);
char* parse_results(const char* results, const char* start_marker, const char* end_marker);
int phy_forkpty_realtime(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec);
int tty_execute(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec);
int my_forkpty_ex(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec);
void construct_cmd_local(char* full_cmd, size_t size, const char* cmd, int flg);
int forkpty_envcheck_local(const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec);
bool tty_rcp(const char* add, const char* usr, const char* pwd, const char* ori, const char* dst);
bool rmt_exe(const char* add, const char* usr, const char* pwd, const char* kpw, const char* ori, const char* tmd, char** res, int mod, int tot, bool rfl);
#endif
