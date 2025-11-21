#ifndef CHANNEL_H
#define CHANNEL_H
#include "messtype.h"
#include "channel.h"
#include "phy_def.h"

#define PIPESTARTMODE 0
#define envchkres "/opt/phytune/server/results/envcheck.res"

unsigned int phy_channel();
int write_message(const char* data, int lenth);
void write_messagechannel(struct transfer * trandata);
//int write_message_to_controller(const char* data, int lenth);
bool write_message_to_controller(void* data, size_t lenth);
void generate_restartable_script(const char* loginuser, const char* passwd, const char* rootpasswd, const char* cmdlist, int flag);
void agent_reset(struct transfer * trandata);
void agent_transmitter(const char* ipaddr, unsigned int port, const char* arch, const char* username, const char* userpass, const char* cpumodel);
void agent_install(const char* ipaddr, const char* arch, const char* username, const char* userpass);
void agent_uninstall(const char* ipaddr, const char* arch, const char* username, const char* userpass);
void agent_switch_execution(struct transfer * trandata);
void start_statedetectorsh(void* args);
//void remote_sampling(trandst* td, const char* usr, const char* pwd);
void remote_sampling(const char* add, const char* usr, const char* pwd, const char* skey, const char* date, const char* msg);
void agent_refresh();
int check_remote_root_password(const char *hostname, const char *user, const char *user_password, const char *root_password);
int env_check_affi(const char* add, const char* usr, const char* pwd, const char* spwd, int affi);
char* env_check_res(const char* add, const char* usr, const char* pwd, const char* spwd, const char* ectp);
void handle_exe(mesexe  mex, trandst td);
void get_filebrowser(const char* add, const char* usr, const char* pwd, const char* pth);
void handle_message(struct transfer* tsp);
void send_message(mestype matp, messta smtp, int affi, const char* mes);
void run_pcie(const char* add, const char* usr, const char* pwd, trandst td);
void dynamic_tips(const char* slogan);
int env_check_rtcputp(const char* add, const char* usr, const char* pwd, const char* spwd, int affi, char** ecrt);
int env_check_rtcputp_local(const char* pwd, const char* spwd, int affi, char** ecrt);
void run_detect_local(const char* pwd, mesdet mde, trandst td, const char* cornam);
void run_detect(const char* usr, const char* pwd, mesdet mde, trandst td, const char* cornam);
bool sendmsgx(void* data, size_t len);
#endif
