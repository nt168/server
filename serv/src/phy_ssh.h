#ifndef SSH_SERVERH
#define SSH_SERVERH
unsigned int phy_ssh_server();

typedef void* (*hfun)(void* data, size_t len, void* ass);
enum multip_mode
{
	netlisten=1, stdinput, stdoutput, nttty
};

typedef struct stq{
	void* data;
	size_t len;
	struct stq *next;
}stq;

typedef struct agtst{
	char usr[20];
	char pwd[20];
	char spwd[20];
	char add[20];
	char cmd[512];
}agtst;

typedef struct syncq {
	ssize_t  dtlen;
	struct stq* q;
	struct stq *curr;
	hfun hf;
	pthread_mutex_t mtx;
	pthread_cond_t cond;
}syncq;

typedef struct mltarg{
	int fd;
	agtst ast;
	enum multip_mode mm;
	syncq* wbf;
	syncq* rbf;
	pthread_t conspid;
	pthread_t ctrlpid;
	pthread_t writpid;
}mltarg;

typedef struct mlst{
	hfun hf;
	struct mltarg* mla;
}mlst;

typedef struct sshhdl{
	pid_t pid;
	int fd_in;
	int fd_out;
}sshhdl;

//void run_ssh_cmd_interaction(const char* host, const char* user, const char* pass, const char* cmd, struct mltarg* marg);
void run_ssh_cmd_interaction(struct mltarg* marg);
void init_multiplex_arg(struct mltarg* arg);
void* consume_syncq(void* arg);
void* sshpthread_ctr(void* arg);
void signal_handler(int signum);
void run_phy_ssh(const char* add, const char* usr, const char* pwd, const char* cmd);
void run_ssh_cmd_interaction_record(mltarg* marg);
void run_phy_ssh_record(const char* add, const char* usr, const char* pwd, const char* cmd, char** record);
void phy_ssh_poller(const char* add, const char* usr, const char* pwd, const char* cmd, char** record);
void insert_syncq(struct syncq* psq, void* data, size_t len);
void cleanup_handler(void*arg);
int create_sshsession(const char* host, const char* user, const char* pass);
void physsh_run_elvprivil_perf(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, char** record);
void physsh_runcmd(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, char** record);
char* ssh_run_cmd(const char* add, const char* usr, const char* pwd, const char* rpwd, const char* cmd, int flg);
int forkpty_envcheck(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec);
char* ssh_run_cmd(const char* add, const char* usr, const char* pwd, const char* rpwd, const char* cmd, int flg);
#endif
