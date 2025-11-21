#include "libssh/libssh.h"
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/syscall.h>
#include "phy_ssh.h"
#include "channel.h"
#include "common.h"
#include "messtype.h"
int show_remote_processes(ssh_session session);
int manage_perf_top(ssh_session session);

//struct syncq* sq = NULL;
void cleanup_handler(void*arg) {
    printf("Clean up handler of thread.\n");
#if 1
    struct stq *p=NULL;
    p = (struct stq* )arg;
    if(p != NULL){
    	if(p->data != NULL){
    		phy_free(p->data);
    	}
    	phy_free(p);
    }
#endif
//    (void)pthread_mutex_unlock(&(sq->mtx));
}

void init_syncq(struct syncq** psq)
{
	struct syncq* p = NULL;
	p = (struct syncq*)phy_malloc(p, sizeof(struct syncq));
	memset(p, 0, sizeof(struct syncq));
	p->curr = NULL;
	p->q = NULL;
	pthread_mutex_init(&(p->mtx), NULL);
	pthread_cond_init(&(p->cond), NULL);
	(*psq) = p;
}

//#define inhd
void insert_syncq(struct syncq* psq, void* data, size_t len)
{
//	static int i=0;
	struct stq* p = NULL;
	p = (struct stq*)malloc(sizeof(struct stq));
//拷贝字符串时要len+1
	p->data = malloc(len + 1);
	memset(p->data, 0, len + 1);
	p->next = NULL;
	memcpy(p->data, data, len);
	p->len = len;
	pthread_mutex_lock(&(psq->mtx));//需要操作head这个临界资源，先加锁，
#ifdef inhd //insert p at head of list
	p->next=psq->q;
	psq->q=p;
	psq->dtlen++;
//	printf("===============psq->len = %ld\n", psq->dtlen);
#else   //insert p at end of list
	if(psq->q == NULL){
		psq->q = p;
		psq->curr = p;
		psq->dtlen++;
	}else{
		psq->curr->next = p;
		psq->curr = p;
		psq->dtlen++;
	}
//	printf("===============psq->len = %ld\n", psq->dtlen);
#endif
	pthread_cond_signal(&(psq->cond));
	pthread_mutex_unlock(&(psq->mtx));
}

void* sshpthread_ctr(void* arg)
{
#if 0
	sleep(3);
	struct syncq* psq = NULL;
	psq = (struct syncq*)arg;
	insert_syncq(psq, "ft123123\n", 9);
//	sleep(4);
//	char ctrl_c = 0x03;
////	ssh_channel_write(channel, &ctrl_c, 1);
//	insert_syncq(psq, &ctrl_c, 1);
#endif
	pthread_exit(NULL);
	return NULL;
}

void* consume_syncq(void* arg)
{
	struct sigaction sa;
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if(sigaction(SIGUSR1, &sa, NULL) == -1){
		perror("sigaction");
		pthread_exit(NULL);
	}

	struct stq* p = NULL;
	struct syncq* psq = NULL;
	psq = (struct syncq*)arg;
	pthread_cleanup_push(cleanup_handler,p);
#ifdef inhd
	while(1){
		pthread_mutex_lock(&(psq->mtx));
		if(psq->q == NULL){
			pthread_cond_wait(&(psq->cond), &(psq->mtx));
		}
		p=psq->q;
		psq->q=psq->q->next;
		psq->dtlen--;
		pthread_mutex_unlock(&(psq->mtx));
#ifdef hf_farg
		hf(p, p->len, ass);
#else
//		hf(p->data, p->len, ass);
		printf("----%s", (char*)(p->data));
#endif
		phy_free(p->data);
		phy_free(p);
	}
#else
	while(1){
			pthread_mutex_lock(&(psq->mtx));
			if(psq->q == NULL){
				pthread_cond_wait(&(psq->cond), &(psq->mtx));
			}
			p=psq->q;
			psq->q=psq->q->next;
			psq->dtlen--;
			pthread_mutex_unlock(&(psq->mtx));
			printf("%s\n", (char*)(p->data));
//			fflush(stdout);  也可以这样输出
			phy_free(p->data);
			phy_free(p);
		}
#endif
	pthread_cleanup_pop(0);
	pthread_exit(NULL);
	return NULL;
}
int currdet;
extern int currdet;
void* consume_syncq_record(void* arg)
{
	combptr* cmptr = NULL;
	char** record = NULL;
	struct sigaction sa;
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if(sigaction(SIGUSR1, &sa, NULL) == -1){
		perror("sigaction");
		pthread_exit(NULL);
	}

	struct stq* p = NULL;
	struct syncq* psq = NULL;
	cmptr = (combptr*)arg;
	psq = (struct syncq*)ACCFIELDP(cmptr, 0);
	record = (char **)ACCFIELDP(cmptr, 1);
//	*record = buy_some_mem(*record, NULL);
	pthread_cleanup_push(cleanup_handler,p);
#ifdef inhd
	while(1){
		pthread_mutex_lock(&(psq->mtx));
		if(psq->q == NULL){
			pthread_cond_wait(&(psq->cond), &(psq->mtx));
		}
		p=psq->q;
		psq->q=psq->q->next;
		psq->dtlen--;
		pthread_mutex_unlock(&(psq->mtx));
#ifdef hf_farg
		hf(p, p->len, ass);
#else
//		hf(p->data, p->len, ass);
		printf("----%s", (char*)(p->data));
#endif
		phy_free(p->data);
		phy_free(p);
	}
#else
	while(1){
			pthread_mutex_lock(&(psq->mtx));
			if(psq->q == NULL){
				pthread_cond_wait(&(psq->cond), &(psq->mtx));
			}
			p=psq->q;
			psq->q=psq->q->next;
			psq->dtlen--;
			pthread_mutex_unlock(&(psq->mtx));
//			printf("%s\n", (char*)(p->data));
#if 1 //record
			struct transfer tran;
			memset(&tran, 0, sizeof(struct transfer));
			tran.mma.matp = (mestype)MESS;
			tran.mma.mme  = (mesmes)COMM;
			tran.td.affi = currdet;
			phy_snprintf(tran.td.mes, 1280, "%s", (char*)(p->data));
			write_message_to_controller((char*)(&tran), sizeof(struct transfer));

			*record = buy_some_mem(*record, (char*)(p->data));
			*record = buy_some_mem(*record, "\n");
#endif
//			fflush(stdout);  也可以这样输出
			phy_free(p->data);
			phy_free(p);
		}
#endif
	pthread_cleanup_pop(0);
	pthread_exit(NULL);
	return NULL;
}

void* consume_syncq_poller(void* arg)
{
	combptr* cmptr = NULL;
	char** record = NULL;
	struct sigaction sa;
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if(sigaction(SIGUSR1, &sa, NULL) == -1){
		perror("sigaction");
		pthread_exit(NULL);
	}

	struct stq* p = NULL;
	struct syncq* psq = NULL;
	cmptr = (combptr*)arg;
	psq = (struct syncq*)ACCFIELDP(cmptr, 0);
	record = (char **)ACCFIELDP(cmptr, 1);
//	*record = buy_some_mem(*record, NULL);
	pthread_cleanup_push(cleanup_handler,p);
#ifdef inhd
	while(1){
		pthread_mutex_lock(&(psq->mtx));
		if(psq->q == NULL){
			pthread_cond_wait(&(psq->cond), &(psq->mtx));
		}
		p=psq->q;
		psq->q=psq->q->next;
		psq->dtlen--;
		pthread_mutex_unlock(&(psq->mtx));
#ifdef hf_farg
		hf(p, p->len, ass);
#else
//		hf(p->data, p->len, ass);
		printf("----%s", (char*)(p->data));
#endif
		phy_free(p->data);
		phy_free(p);
	}
#else
	while(1){
			pthread_mutex_lock(&(psq->mtx));
			if(psq->q == NULL){
				pthread_cond_wait(&(psq->cond), &(psq->mtx));
			}
			p=psq->q;
			psq->q=psq->q->next;
			psq->dtlen--;
			pthread_mutex_unlock(&(psq->mtx));
//			printf("%s\n", (char*)(p->data));
#if 1 //record
			*record = buy_some_mem(*record, (char*)(p->data));
			*record = buy_some_mem(*record, "\n");
#endif
//			fflush(stdout);  也可以这样输出
			phy_free(p->data);
			phy_free(p);
		}
#endif
	pthread_cleanup_pop(0);
	pthread_exit(NULL);
	return NULL;
}

void* iterator_syncq_nopthreadsafe(void* arg)
{
	struct stq* p = NULL;
	struct syncq* psq = NULL;
	psq = (struct syncq*)arg;
	p = psq->q;
	while(p!= NULL){
		printf("%s\n", (char*)p->data);
		psq->q = p->next;
		phy_free(p->data);
		phy_free(p);
		p = psq->q;
	}
	return NULL;
}


void* write_channel(void* data, size_t len, void* ass)
{
	ssh_channel channel = (ssh_channel)ass;
	ssh_channel_write(channel, (char*)data, len);
	return NULL;
}

unsigned int phy_ssh_server()
{
    ssh_session my_ssh_session;
    int verbosity = 2;//SSH_LOG_PROTOCOL;
    int port = 22;
    int rc;
 //   char *password;

    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        exit(-1);

    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "10.31.94.247");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "ft");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);

    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to localhost: %s\n",
                ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        exit(-1);
    }

    // Authenticate ourselves
//    password = getpass("Password: ");
    rc = ssh_userauth_password(my_ssh_session, NULL, "ft123123");
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with password: %s\n",
                ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

//    show_remote_processes(my_ssh_session);
    manage_perf_top(my_ssh_session);

    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    return 0;
}

void destroy_sshsession(ssh_session session)
{
	ssh_disconnect(session);
	ssh_free(session);
}

ssh_channel get_ssh_chl(ssh_session session)
{
	ssh_channel channel;
//	char cmdstr[256] = {0};
	int rc;
	channel = ssh_channel_new(session);
	if(channel == NULL){
		return NULL;
	}

	rc = ssh_channel_open_session(channel);
	if(rc != SSH_OK){
		ssh_channel_free(channel);
		return NULL;
	}
	return channel;
}

int create_sshsession(const char* host, const char* user, const char* pass)
{
	ssh_session session;
	int port = 22;
	int rc = 0;

	session = ssh_new();
	if(session == NULL){
		return 1;
	}

	ssh_options_set(session, SSH_OPTIONS_HOST, host);
	ssh_options_set(session, SSH_OPTIONS_USER, user);
//	ssh_options_set(session, SSH_OPTIONS_PASSWORD_AUTH, pass);
//	ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(session, SSH_OPTIONS_PORT, &port);

	rc = ssh_connect(session);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error connecting to localhost: %s\n", ssh_get_error(session));
		ssh_free(session);
		return rc;
	}
	rc = ssh_userauth_password(session, NULL, pass);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error connecting to localhost: %s\n", ssh_get_error(session));
		ssh_disconnect(session);
		ssh_free(session);
		return rc;
	}
	ssh_free(session);
	return rc;
}

 ssh_session new_sshsession(const char* host, const char* user, const char* pass)
 {
	ssh_session session;
//	int verbosity = 2;//SSH_LOG_PROTOCOL;
	int port = 22;
	int rc;

	session = ssh_new();
	if (session == NULL)
	 exit(-1);

	ssh_options_set(session, SSH_OPTIONS_HOST, host);
	ssh_options_set(session, SSH_OPTIONS_USER, user);
//	ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(session, SSH_OPTIONS_PORT, &port);

	rc = ssh_connect(session);
	if (rc != SSH_OK) {
	 fprintf(stderr, "Error connecting to localhost: %s\n",
			 ssh_get_error(session));
	 ssh_free(session);
	 return NULL;
	}

	rc = ssh_userauth_password(session, NULL, pass);
	if (rc != SSH_AUTH_SUCCESS) {
	 fprintf(stderr, "Error authenticating with password: %s\n",
			 ssh_get_error(session));
	 ssh_disconnect(session);
	 ssh_free(session);
	 return NULL;
	}
	return session;
}

 void init_multiplex_arg(mltarg* arg)
 {
 	struct mltarg* mag = NULL;
 	mag = (mltarg*)arg;

 	init_syncq(&(mag->rbf));
 	init_syncq(&(mag->wbf));
 	mag->wbf->hf = write_channel;
 }

void init_multiplex_arg_rwfun(mltarg* arg, hfun rhfun, hfun whfun)
{
	struct mltarg* mag = NULL;
	mag = (mltarg*)arg;

	init_syncq(&(mag->rbf));
	init_syncq(&(mag->wbf));
	mag->wbf->hf = whfun;
	mag->rbf->hf = rhfun;
}


lnbhd* lbhd = NULL;
#define ntbuf 1
//#define directoutput
 void *read_ssh_output(void* args)
 {
 	combptr* cmptr = NULL;
 	ssh_channel chl;
 	mltarg* marg;
 	int nbytes;
 	char buffer[1024];
 	struct syncq* psq = NULL;
 	cmptr = (combptr*)args;
 	chl = (ssh_channel)ACCFIELDP(cmptr, 0);
 	marg = (mltarg*)ACCFIELDP(cmptr, 1);
 	psq = marg->rbf;

 	while(1){
		memset(buffer, 0 ,1024);
		nbytes = ssh_channel_read(chl, buffer, sizeof(buffer), 0);
		if(nbytes > 0) {
//			fwrite(buffer, 1, nbytes, stdout);
#ifdef directoutput
			insert_syncq(psq, buffer, nbytes);
//			fwrite(buffer, 1, nbytes, stdout);
#elif ntbuf
//判断是否有提示及错误
			if(strstr(buffer, "密码") || strstr(buffer, "yes")){
				insert_syncq(psq, buffer, nbytes);
//					write_channel("ft123123\n", 10, chl);
				continue;
			}

//			row_extractor(buffer, strlen(buffer), &lbhd);
			row_extractor(buffer, nbytes, &lbhd);
			lnbuf* lbf = NULL;
			lnbuf* tlbf = NULL;
			lbf = lbhd->lnbl;
			char* s = NULL;
			while(lbf){
				tlbf = lbf->next;
				if(lbf->stflg == false){
					s = (char*)(lbf->data);
//"\0xxx"
					if(s[0] == '\0'){
//						printf("%s\n", s + 1);
//						insert_syncq(psq, s + 1, lbf->len - 1);
					}else{
//						printf("%s\n", s);
						insert_syncq(psq, s, lbf->len);
					}
					phy_free(lbf->data);
					phy_free(lbf);
					lbhd->curr = tlbf;
					lbhd->lnbl = tlbf;
				}
#if 0
				if(strstr((char*)lbf->data, "密码")){
//					printf("%s\n", (char*)lbf->data);
					insert_syncq(psq, lbf->data, lbf->len);
//					write_channel("ft123123\n", 10, chl);
				}
#endif
				lbf = tlbf;
			}

#if 0
			if(lbhd->lnbl == NULL){
				phy_free(lbhd);
				continue;
			}
			phy_free(lbhd->lnbl->data);
			phy_free(lbhd->lnbl);
			phy_free(lbhd);
#endif
//			insert_syncq(psq, buffer, strlen(buffer));
#endif
		}
		if((nbytes == 0) || (nbytes == -1)){
//			pthread_cancel(marg->conspid);
			pthread_kill(marg->writpid, SIGUSR1);
			pthread_kill(marg->conspid, SIGUSR1);
			break;
		}
	}
 	pthread_exit(NULL);
 	return NULL;
 }

 void *read_ssh_autoinput(void* args)
  {
  	combptr* cmptr = NULL;
  	ssh_channel chl;
  	mltarg* marg;
  	int nbytes;
  	char buffer[1024];
  	char iptstr[64] = {0};
  	struct syncq* psq = NULL;
  	cmptr = (combptr*)args;
  	chl = (ssh_channel)ACCFIELDP(cmptr, 0);
  	marg = (mltarg*)ACCFIELDP(cmptr, 1);
  	psq = marg->rbf;

  	while(1){
 		memset(buffer, 0 ,1024);
 		nbytes = ssh_channel_read(chl, buffer, sizeof(buffer), 0);
 		if(nbytes > 0) {
 //			fwrite(buffer, 1, nbytes, stdout);
 #ifdef directoutput
 			insert_syncq(psq, buffer, nbytes);
 //			fwrite(buffer, 1, nbytes, stdout);
 #elif ntbuf
 //判断是否有提示及错误
 			if(strstr(buffer, "yes")){
 				if(strstr(buffer, "|yes")){
 					goto insert_info;
 				}
 				sleep(1);
 				phy_snprintf(iptstr, 128, "%s\n", "yes");
 				write_channel(iptstr, strlen(iptstr) + 1, chl);
 				continue;
 			}

 			if(strstr(buffer, "密码") || strstr(buffer, "password")){
 				sleep(1);
 				phy_snprintf(iptstr, 128, "%s\n", marg->ast.pwd);
 				write_channel(iptstr, strlen(iptstr) + 1, chl);
 				continue;
 			}

			if(strstr(buffer, "No route to host") || strstr(buffer, "Connection refused")){
//				sleep(1);
//				phy_snprintf(iptstr, 128, "%s\n", marg->ast.pwd);
//				write_channel(iptstr, strlen(iptstr) + 1, chl);
				continue;
			}

insert_info:
 			row_extractor(buffer, nbytes, &lbhd);
 			lnbuf* lbf = NULL;
 			lnbuf* tlbf = NULL;
 			lbf = lbhd->lnbl;
 			char* s = NULL;
 			while(lbf){
 				tlbf = lbf->next;
 				if(lbf->stflg == false){
 					s = (char*)(lbf->data);
 //"\0xxx"
 					if(s[0] == '\0'){
 //						printf("%s\n", s + 1);
 //						insert_syncq(psq, s + 1, lbf->len - 1);
 					}else{
 //						printf("%s\n", s);
 						insert_syncq(psq, s, lbf->len);
 					}
 					phy_free(lbf->data);
 					phy_free(lbf);
 					lbhd->curr = tlbf;
 					lbhd->lnbl = tlbf;
 				}
 				lbf = tlbf;
 			}
 #endif
 		}
 		if((nbytes == 0) || (nbytes == -1)){
 			sleep(1); //等待缓存数据从另一个线程获取完
 			pthread_kill(marg->conspid, SIGUSR1);
 			break;
 		}
 	}
  	pthread_exit(NULL);
  	return NULL;
  }

 pid_t gettid()
 {
      return syscall(SYS_gettid);
 }

 void signal_handler(int signum)
 {
	 printf("pthread_id: %d, receive %d signal.\n", gettid(), signum);
	 pthread_exit(NULL);
 }

void *write_ssh_ptfun(void* args)
{
	struct sigaction sa;
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if(sigaction(SIGUSR1, &sa, NULL) == -1){
		perror("sigaction");
		pthread_exit(NULL);
	}

#if 1
	combptr* cmptr = NULL;
	ssh_channel chl;
	mltarg* marg;
	struct stq* p = NULL;
	struct syncq* psq = NULL;
	cmptr = (combptr*)args;
	chl = (ssh_channel)ACCFIELDP(cmptr, 0);
	marg = (mltarg*)ACCFIELDP(cmptr, 1);
	psq = marg->wbf;
	pthread_cleanup_push(cleanup_handler,p);
	while(1){
		pthread_mutex_lock(&(psq->mtx));
		if(psq->q == NULL){
			pthread_cond_wait(&(psq->cond), &(psq->mtx));
		}
		p=psq->q;
		psq->q=psq->q->next;
		psq->dtlen--;
		pthread_mutex_unlock(&(psq->mtx));
		marg->wbf->hf((char*)(p->data), p->len, chl);
		phy_free(p->data);
		phy_free(p);
	}
	pthread_cleanup_pop(0);
	pthread_exit(NULL);
#endif
	return NULL;
}

 //void run_ssh_cmd_interaction(const char* host, const char* user, const char* pass, const char* cmd, struct mltarg* marg)
 void run_ssh_cmd_interaction(mltarg* marg)
 {
	ssh_session session;
	ssh_channel channel;
	pthread_t rpthread_id;
	pthread_t wpthread_id;
	combptr cmptr;
	char cmdstr[512] = {0};
	int rc;
	session = new_sshsession(marg->ast.add, marg->ast.usr, marg->ast.pwd);
	if(session == NULL){
		printf("Create ssh session error!\n");
		return;
	}

	channel = get_ssh_chl(session);
	if(channel == NULL){
		printf("Create ssh channel error!\n");
		return;
	}

	channel = ssh_channel_new(session);
	if (channel == NULL)
		return;

	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK) {
		ssh_channel_free(channel);
		return;
	}

	rc = ssh_channel_request_pty(channel);
	if (rc != SSH_OK) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return;
	}

	phy_snprintf(cmdstr, 512, "stty cols 1000 && %s", marg->ast.cmd);
//	rc = ssh_channel_request_exec(channel, cmdstr);
	rc = ssh_channel_request_exec(channel, marg->ast.cmd);
	if (rc != SSH_OK) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return;
	}

	cmptr = COMBPTR(channel, marg);
	pthread_create(&wpthread_id, NULL, write_ssh_ptfun, &cmptr);
	marg->writpid = wpthread_id;
	cmptr = COMBPTR(channel, marg);
	pthread_create(&rpthread_id, NULL, read_ssh_output, &cmptr);

	pthread_join(wpthread_id, NULL);
	pthread_join(rpthread_id, NULL);

	ssh_channel_send_eof(channel);
	ssh_channel_close(channel);
	ssh_channel_free(channel);
	ssh_disconnect(session);
	destroy_sshsession(session);
 }

 void run_ssh_cmd_interaction_record(mltarg* marg)
 {
	ssh_session session;
	ssh_channel channel;
	pthread_t rpthread_id;
//	pthread_t wpthread_id;
	combptr cmptr;
	char cmdstr[512] = {0};
	int rc;
	session = new_sshsession(marg->ast.add, marg->ast.usr, marg->ast.pwd);
	if(session == NULL){
		sleep(1); //等待缓存数据从另一个线程获取完
		pthread_kill(marg->conspid, SIGUSR1);

		struct transfer tran;
		memset(&tran, 0, sizeof(struct transfer));
		tran.mma.matp = MESS;
		tran.mma.mme = ERROR;
		phy_snprintf(tran.td.mes, 1280, "%s %s\n", marg->ast.add, "Create ssh session error!");
		write_message_to_controller((char*)(&tran), sizeof(struct transfer));
//		printf("Create ssh session error!\n");
		return;
	}

	channel = get_ssh_chl(session);
	if(channel == NULL){
		sleep(1); //等待缓存数据从另一个线程获取完
		pthread_kill(marg->conspid, SIGUSR1);
		printf("Create ssh channel error!\n");
		return;
	}

	channel = ssh_channel_new(session);
	if (channel == NULL)
		return;

	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK) {
		ssh_channel_free(channel);
		return;
	}

	rc = ssh_channel_request_pty(channel);
	if (rc != SSH_OK) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return;
	}

	phy_snprintf(cmdstr, 512, "stty cols 1000 && %s", marg->ast.cmd);
//	rc = ssh_channel_request_exec(channel, cmdstr);
	rc = ssh_channel_request_exec(channel, marg->ast.cmd);
	if (rc != SSH_OK) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return;
	}

//	marg->writpid = wpthread_id;
	cmptr = COMBPTR(channel, marg);
	pthread_create(&rpthread_id, NULL, read_ssh_autoinput, &cmptr);
	pthread_join(rpthread_id, NULL);

	ssh_channel_send_eof(channel);
	ssh_channel_close(channel);
	ssh_channel_free(channel);
	ssh_disconnect(session);
	destroy_sshsession(session);
 }

char* ssh_run_cmd(const char* add, const char* usr, const char* pwd, const char* rpwd, const char* cmd, int flg)
{
	 ssh_session session;
	 ssh_channel channel;
	 int rc;
	 char buffer[256];
	 int nbytes;
	 char* output = NULL;
	 size_t output_size = 0;

	 session = ssh_new();
	 if (session == NULL) {
		 fprintf(stderr, "Error creating SSH session\n");
		 return NULL;
	 }

	 ssh_options_set(session, SSH_OPTIONS_HOST, add);
	 ssh_options_set(session, SSH_OPTIONS_USER, usr);

	 rc = ssh_connect(session);
	 if (rc != SSH_OK) {
		 fprintf(stderr, "Error connecting to %s: %s\n", add, ssh_get_error(session));
		 ssh_free(session);
		 return NULL;
	 }

	 rc = ssh_userauth_password(session, NULL, pwd);
	 if (rc != SSH_AUTH_SUCCESS) {
		 fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));
		 ssh_disconnect(session);
		 ssh_free(session);
		 return NULL;
	 }

	 channel = ssh_channel_new(session);
	 if (channel == NULL) {
		 fprintf(stderr, "Error creating channel\n");
		 ssh_disconnect(session);
		 ssh_free(session);
		 return NULL;
	 }

	 rc = ssh_channel_open_session(channel);
	 if (rc != SSH_OK) {
		 fprintf(stderr, "Error opening channel: %s\n", ssh_get_error(session));
		 ssh_channel_free(channel);
		 ssh_disconnect(session);
		 ssh_free(session);
		 return NULL;
	 }

	char full_cmd[512] = {0};
	if (flg == 1) {
		//snprintf(full_cmd, sizeof(full_cmd), "sudo -S -p '' %s 2>&1", cmd); // Redirect stderr to stdout
		snprintf(full_cmd, sizeof(full_cmd), "echo %s | sudo -S -p '' %s 2>&1", pwd, cmd);
	} else if (flg == 2) {
		snprintf(full_cmd, sizeof(full_cmd), "echo %s | su -c '%s' 2>&1", rpwd, cmd);
	} else {
		snprintf(full_cmd, sizeof(full_cmd), "%s 2>&1", cmd); // Redirect stderr to stdout
	}

	 rc = ssh_channel_request_exec(channel, full_cmd);
	 if (rc != SSH_OK) {
		 fprintf(stderr, "Error executing command: %s\n", ssh_get_error(session));
		 ssh_channel_close(channel);
		 ssh_channel_free(channel);
		 ssh_disconnect(session);
		 ssh_free(session);
		 return NULL;
	 }

	if (flg == 1) {
		ssh_channel_write(channel, pwd, strlen(pwd));
		ssh_channel_write(channel, "\n", 1);
	}
	 sleep(1);
	 while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
		 output = realloc(output, output_size + nbytes + 1);
		 if (output == NULL) {
			 fprintf(stderr, "Error allocating memory\n");
			 ssh_channel_close(channel);
			 ssh_channel_free(channel);
			 ssh_disconnect(session);
			 ssh_free(session);
			 return NULL;
		 }
//		 memcpy(output + output_size, buffer, nbytes);
		 strncpy(output + output_size, buffer, nbytes);
		 output_size += nbytes;
		 output[output_size] = '\0';
	 }

	 if (nbytes < 0) {
		 fprintf(stderr, "Error reading from channel: %s\n", ssh_get_error(session));
		 free(output);
		 ssh_channel_close(channel);
		 ssh_channel_free(channel);
		 ssh_disconnect(session);
		 ssh_free(session);
		 return NULL;
	 }

	 ssh_channel_send_eof(channel);
	 ssh_channel_close(channel);
	 ssh_channel_free(channel);
	 ssh_disconnect(session);
	 ssh_free(session);

	 return output;
}

//	sshhdl *shd;
//	shd = malloc(shd, 0, sizeof(sshhdl));
 void run_ssh_chl(ssh_channel channel, const char* cmd, const char* args)
 {
	 int rc;
	char cmdstr[256] = {0};
	snprintf(cmdstr, 256, "%s %s", cmd, args);
	rc = ssh_channel_request_exec(channel, cmdstr);
	if(rc != SSH_OK){
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return;
	}
 }

int manage_perf_top(ssh_session session) {
    ssh_channel channel;
    int rc;
    char buffer[1024];
    int nbytes;

    channel = ssh_channel_new(session);
    if (channel == NULL)
        return SSH_ERROR;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        return rc;
    }

    rc = ssh_channel_request_pty(channel);
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }

    rc = ssh_channel_request_exec(channel, "perf top");
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }

    // Read output for a while before sending a key
    for (int i = 0; i < 10; i++) {
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        if (nbytes > 0) {
            fwrite(buffer, 1, nbytes, stdout);
        }
        sleep(1);  // Adjust timing as needed
    }

    // Send 'H' key to perf top
    ssh_channel_write(channel, "H", 1);

    // Continue reading output for a while
    for (int i = 0; i < 3; i++) {
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        if (nbytes > 0) {
            fwrite(buffer, 1, nbytes, stdout);
        }
        sleep(1);  // Adjust timing as needed
    }

    // Send Ctrl+C to stop perf top
    char ctrl_c = 0x03;
    ssh_channel_write(channel, &ctrl_c, 1);

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return SSH_OK;
}

int show_remote_processes(ssh_session session) {
    ssh_channel channel;
    int rc;
    char buffer[1024];
    int nbytes;

    channel = ssh_channel_new(session);
    if (channel == NULL)
        return SSH_ERROR;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        return rc;
    }

//	rc = ssh_channel_request_pty(channel, term_type, term_width, term_height, term_pxwidth, term_pxheight);
    rc = ssh_channel_request_pty(channel);
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }

//    rc = ssh_channel_request_exec(channel, "top");
//    rc = ssh_channel_request_exec(channel, "/home/ft/a.out");
//    rc = ssh_channel_request_exec(channel, "/home/ft/agent/modules/Performance/phyTune_core/topdown/topdown-tool /home/ft/agent/modules/Performance/dutpro/l2d_cache_workload");
    rc = ssh_channel_request_exec(channel, "perf top");
//      rc = ssh_channel_write(channel, "ls\n", 3);

    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }

    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
        fwrite(buffer, 1, nbytes, stdout);
    }

    if (nbytes < 0) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return SSH_OK;
}

//	phy_snprintf(marg->ast.cmd, 512, "%s", "sudo /home/ft/agent/modules/Performance/phyTune_core/hwpmu/pmu_ftc8.sh /home/ft/agent/modules/Performance/dutpro/l2d_cache_workload");
//	phy_snprintf(marg->ast.cmd, 512, "%s", "/home/ft/agent/modules/Performance/phyTune_core/hwpmu/pmu_ftc8.sh /home/ft/agent/modules/Performance/dutpro/l2d_cache_workload");

void run_phy_ssh(const char* add, const char* usr, const char* pwd, const char* cmd)
{
	mltarg* marg = NULL;
	marg = (mltarg*)phy_malloc(marg, sizeof(mltarg));
	pthread_t conspid;
	pthread_t ctrlpid;
	memset(marg, 0, sizeof(mltarg));

	phy_snprintf(marg->ast.add, 20, "%s", add);
	phy_snprintf(marg->ast.usr, 20, "%s", usr);
	phy_snprintf(marg->ast.pwd, 20, "%s", pwd);
	phy_snprintf(marg->ast.cmd, 512, "%s", cmd);
	init_multiplex_arg(marg);
	pthread_create(&conspid, NULL, consume_syncq, marg->rbf);
	pthread_create(&ctrlpid, NULL, sshpthread_ctr, marg->wbf);
	marg->conspid = conspid;
	marg->ctrlpid = ctrlpid;
	run_ssh_cmd_interaction(marg);
	pthread_join(conspid, NULL);
	pthread_join(ctrlpid, NULL);

	(void)pthread_mutex_unlock(&(marg->wbf->mtx));
	(void)pthread_mutex_unlock(&(marg->rbf->mtx));
	phy_free(marg->rbf->q);
	phy_free(marg->wbf->q);
	phy_free(marg->rbf);
	phy_free(marg->wbf);
	phy_free(marg);

	if(lbhd != NULL){
		if(lbhd->lnbl != NULL){
			phy_free(lbhd->lnbl->data);
			phy_free(lbhd->lnbl);
		}
		phy_free(lbhd);
		return;
	}
}

void run_phy_ssh_record(const char* add, const char* usr, const char* pwd, const char* cmd, char** record)
{
	mltarg* marg = NULL;
	marg = (mltarg*)phy_malloc(marg, sizeof(mltarg));
	pthread_t conspid;
	combptr cmptr;
	memset(marg, 0, sizeof(mltarg));

	phy_snprintf(marg->ast.add, 20, "%s", add);
	phy_snprintf(marg->ast.usr, 20, "%s", usr);
	phy_snprintf(marg->ast.pwd, 20, "%s", pwd);
	phy_snprintf(marg->ast.cmd, 512, "%s", cmd);
	init_multiplex_arg(marg);
	cmptr = COMBPTR(marg->rbf, record);
	pthread_create(&conspid, NULL, consume_syncq_record, &cmptr);
	marg->conspid = conspid;
	run_ssh_cmd_interaction_record(marg);
	pthread_join(conspid, NULL);

	(void)pthread_mutex_unlock(&(marg->wbf->mtx));
	(void)pthread_mutex_unlock(&(marg->rbf->mtx));
	phy_free(marg->rbf->q);
	phy_free(marg->wbf->q);
	phy_free(marg->rbf);
	phy_free(marg->wbf);
	phy_free(marg);

	if(lbhd != NULL){
		if(lbhd->lnbl != NULL){
			phy_free(lbhd->lnbl->data);
			phy_free(lbhd->lnbl);
		}
		phy_free(lbhd);
		return;
	}
}

void phy_ssh_poller(const char* add, const char* usr, const char* pwd, const char* cmd, char** record)
{
	mltarg* marg = NULL;
	marg = (mltarg*)phy_malloc(marg, sizeof(mltarg));
	pthread_t conspid;
	combptr cmptr;
	memset(marg, 0, sizeof(mltarg));

	phy_snprintf(marg->ast.add, 20, "%s", add);
	phy_snprintf(marg->ast.usr, 20, "%s", usr);
	phy_snprintf(marg->ast.pwd, 20, "%s", pwd);
	phy_snprintf(marg->ast.cmd, 512, "%s", cmd);
	init_multiplex_arg(marg);
	cmptr = COMBPTR(marg->rbf, record);
	pthread_create(&conspid, NULL, consume_syncq_poller, &cmptr);
	marg->conspid = conspid;
	run_ssh_cmd_interaction_record(marg);
	pthread_join(conspid, NULL);

	(void)pthread_mutex_unlock(&(marg->wbf->mtx));
	(void)pthread_mutex_unlock(&(marg->rbf->mtx));
	phy_free(marg->rbf->q);
	phy_free(marg->wbf->q);
	phy_free(marg->rbf);
	phy_free(marg->wbf);
	phy_free(marg);

	if(lbhd != NULL){
		if(lbhd->lnbl != NULL){
			phy_free(lbhd->lnbl->data);
			phy_free(lbhd->lnbl);
		}
		phy_free(lbhd);
		return;
	}
}

bool syncflag = false;
void *autoinput_read(void* args)
  {
  	combptr* cmptr = NULL;
  	ssh_channel chl;
  	mltarg* marg;
  	int nbytes;
  	char buffer[1024];
  	char iptstr[64] = {0};
  	struct syncq* psq = NULL;
  	cmptr = (combptr*)args;
  	chl = (ssh_channel)ACCFIELDP(cmptr, 0);
  	marg = (mltarg*)ACCFIELDP(cmptr, 1);
  	psq = marg->rbf;
  	bool spflg = false;
  	while(1){
 		memset(buffer, 0 ,1024);
 		nbytes = ssh_channel_read(chl, buffer, sizeof(buffer), 0);
 		if(nbytes > 0) {
 //判断是否有提示及错误
 			if(strstr(buffer, "yes")){
 				if(strstr(buffer, "|yes")){
 					goto insert_info;
 				}
 				sleep(1);
 				phy_snprintf(iptstr, 128, "%s\n", "yes");
 				write_channel(iptstr, strlen(iptstr) + 1, chl);
 				continue;
 			}

 			if(strstr(buffer, "su")){
 				spflg = true;
 				if(strstr(buffer, "密码")){
 					goto inputpwd;
 				}
 //				goto insert_info;
			}

 			if(strstr(buffer, "/proc/sys/kernel/kptr_restrict")){
 				syncflag = false;
 				goto insert_info;
			}

 			if(strstr(buffer, "/proc/sys/kernel/perf_event_paranoid")){
 				syncflag = false;
 				goto insert_info;
			}

 			if(strstr(buffer, "exit")){
 				syncflag = false;
 				goto insert_info;
			}

 			if(strstr(buffer, "密码") || strstr(buffer, "password")){
 inputpwd:
 				if(spflg == true){
 					memset(iptstr, 0, 64);
					phy_snprintf(iptstr, 64, "%s\n", marg->ast.spwd);
					write_channel(iptstr, strlen(iptstr) + 1, chl);
					sleep(1);
					syncflag = false;
 				}else{
 					memset(iptstr, 0, 64);
					phy_snprintf(iptstr, 64, "%s\n", marg->ast.pwd);
					write_channel(iptstr, strlen(iptstr) + 1, chl);
				}
// 				continue;
				goto insert_info;
 			}

			if(strstr(buffer, "No route to host") || strstr(buffer, "Connection refused")){
//				sleep(1);
//				phy_snprintf(iptstr, 128, "%s\n", marg->ast.pwd);
//				write_channel(iptstr, strlen(iptstr) + 1, chl);
//				write_messagechannel();
				continue;
			}

insert_info:
 			row_extractor(buffer, nbytes, &lbhd);
 			lnbuf* lbf = NULL;
 			lnbuf* tlbf = NULL;
 			lbf = lbhd->lnbl;
 			char* s = NULL;
 			while(lbf){
 				tlbf = lbf->next;
 				if(lbf->stflg == false){
 					s = (char*)(lbf->data);
 //"\0xxx"
 					if(s[0] == '\0'){
 //						printf("%s\n", s + 1);
 //						insert_syncq(psq, s + 1, lbf->len - 1);
 					}else{
 						printf("%s\n", s);
 						insert_syncq(psq, s, lbf->len);
 						if(strstr(buffer, "exit")){
 		 					phy_free(lbf->data);
 		 					phy_free(lbf);
 		 					lbhd->curr = tlbf;
 		 					lbhd->lnbl = tlbf;
 		 					goto ptexit;
 						}
 					}
 					phy_free(lbf->data);
 					phy_free(lbf);
 					lbhd->curr = tlbf;
 					lbhd->lnbl = tlbf;
 				}
 				lbf = tlbf;
 			}
 		}
 		if((nbytes == 0) || (nbytes == -1)){
ptexit:
 			sleep(1); //等待缓存数据从另一个线程获取完
 			pthread_kill(marg->conspid, SIGUSR1);
 			pthread_kill(marg->writpid, SIGUSR1);
 			break;
 		}
 	}
  	pthread_exit(NULL);
  	return NULL;
}

void *autoinput_write(void* args)
{
	struct sigaction sa;
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if(sigaction(SIGUSR1, &sa, NULL) == -1){
		perror("sigaction");
		pthread_exit(NULL);
	}

  	combptr* cmptr = NULL;
  	ssh_channel chl;
  	mltarg* marg;
  	int rc;
//  	char buffer[1024];
  	struct syncq* psq = NULL;
  	struct stq* p = NULL;
  	cmptr = (combptr*)args;
  	chl = (ssh_channel)ACCFIELDP(cmptr, 0);
  	marg = (mltarg*)ACCFIELDP(cmptr, 1);

  	psq = marg->wbf;
	pthread_cleanup_push(cleanup_handler,p);

	while(1){
		pthread_mutex_lock(&(psq->mtx));
		if(psq->q == NULL){
			pthread_cond_wait(&(psq->cond), &(psq->mtx));
		}
		p=psq->q;
		psq->q=psq->q->next;
		psq->dtlen--;
		pthread_mutex_unlock(&(psq->mtx));

//		rc = ssh_channel_request_exec(chl, (char*)(p->data));
		rc = ssh_channel_write(chl, (char*)(p->data), strlen((char*)(p->data)));
		if(rc < 0) {
			ssh_channel_close(chl);
			goto ptexit;
		}
		syncflag = true;
		while(syncflag){
			sleep(1);
		}
		phy_free(p->data);
		phy_free(p);
	}

ptexit:
	pthread_cleanup_pop(0);
	pthread_exit(NULL);
	return NULL;
}

void ssh_run_elvprivil_perf(mltarg* marg)
{
	ssh_session session;
	ssh_channel channel;
	pthread_t rpthread_id;
	pthread_t wpthread_id;
	combptr cmptr;
//	char cmdstr[512] = {0};
	int rc;
	session = new_sshsession(marg->ast.add, marg->ast.usr, marg->ast.pwd);
	if(session == NULL){
		sleep(1); //等待缓存数据从另一个线程获取完
		pthread_kill(marg->conspid, SIGUSR1);

		struct transfer tran;
		memset(&tran, 0, sizeof(struct transfer));
		tran.mma.matp = MESS;
		tran.mma.mme = ERROR;
		phy_snprintf(tran.td.mes, 1280, "%s\n", "Create ssh session error!");
		write_message_to_controller((char*)(&tran), sizeof(struct transfer));
		printf("Create ssh session error!\n");
		return;
	}

	channel = get_ssh_chl(session);
	if(channel == NULL){
		sleep(1); //等待缓存数据从另一个线程获取完
		pthread_kill(marg->conspid, SIGUSR1);
		printf("Create ssh channel error!\n");
		return;
	}

	channel = ssh_channel_new(session);
	if (channel == NULL)
		return;

	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK) {
		ssh_channel_free(channel);
		return;
	}

	rc = ssh_channel_request_pty(channel);
	if (rc != SSH_OK) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return;
	}

	rc = ssh_channel_request_shell(channel);
	if (rc != SSH_OK) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return;
	}

	cmptr = COMBPTR(channel, marg);
	pthread_create(&wpthread_id, NULL, autoinput_write, &cmptr);
	marg->writpid = wpthread_id;
	pthread_create(&rpthread_id, NULL, autoinput_read, &cmptr);

	pthread_join(rpthread_id, NULL);
	pthread_join(wpthread_id, NULL);

	ssh_channel_send_eof(channel);
	ssh_channel_close(channel);
	ssh_channel_free(channel);
	ssh_disconnect(session);
	destroy_sshsession(session);
}

void physsh_run_elvprivil_perf(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, char** record)
{
	mltarg* marg = NULL;
	marg = (mltarg*)phy_malloc(marg, sizeof(mltarg));
	pthread_t conspid;
	combptr cmptr;
	char **arr = NULL;
	char **stmp = NULL;
	memset(marg, 0, sizeof(mltarg));

	phy_snprintf(marg->ast.add, 20, "%s", add);
	phy_snprintf(marg->ast.usr, 20, "%s", usr);
	phy_snprintf(marg->ast.pwd, 20, "%s", pwd);
	phy_snprintf(marg->ast.spwd, 20, "%s", spwd);
	init_multiplex_arg(marg);

	phy_strarr_init(&arr);
	str_to_arr(cmd, ";", &arr);
	for (stmp = arr; NULL != *stmp; stmp++){
		insert_syncq(marg->wbf, *stmp, strlen(*stmp) + 1);
	}
	phy_strarr_free(arr);

	cmptr = COMBPTR(marg->rbf, record);
	pthread_create(&conspid, NULL, consume_syncq_record, &cmptr);
	marg->conspid = conspid;
	ssh_run_elvprivil_perf(marg);
	pthread_join(conspid, NULL);

	(void)pthread_mutex_unlock(&(marg->wbf->mtx));
	(void)pthread_mutex_unlock(&(marg->rbf->mtx));
	phy_free(marg->rbf->q);
	phy_free(marg->wbf->q);
	phy_free(marg->rbf);
	phy_free(marg->wbf);
	phy_free(marg);

	if(lbhd != NULL){
		if(lbhd->lnbl != NULL){
			phy_free(lbhd->lnbl->data);
			phy_free(lbhd->lnbl);
		}
		phy_free(lbhd);
		return;
	}
}
////////////////////////////////////////////////////////
void* ssh_execute_record(void* arg)
{
	combptr* cmptr = NULL;
	char** record = NULL;
	struct sigaction sa;
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if(sigaction(SIGUSR1, &sa, NULL) == -1){
		perror("sigaction");
		pthread_exit(NULL);
	}

	struct stq* p = NULL;
	struct syncq* psq = NULL;
	cmptr = (combptr*)arg;
	psq = (struct syncq*)ACCFIELDP(cmptr, 0);
	record = (char **)ACCFIELDP(cmptr, 1);
//	*record = buy_some_mem(*record, NULL);
	pthread_cleanup_push(cleanup_handler,p);

	while(1)
	{
		pthread_mutex_lock(&(psq->mtx));
		if(psq->q == NULL){
			pthread_cond_wait(&(psq->cond), &(psq->mtx));
		}
		p=psq->q;
		psq->q=psq->q->next;
		psq->dtlen--;
		pthread_mutex_unlock(&(psq->mtx));
//			printf("%s\n", (char*)(p->data));
#if 1 //record
		*record = buy_some_mem(*record, (char*)(p->data));
		*record = buy_some_mem(*record, "\n");
#endif
		phy_free(p->data);
		phy_free(p);
	}

	pthread_cleanup_pop(0);
	pthread_exit(NULL);
	return NULL;
}

bool fistflg = false;
bool syncflg = false;
char curdcmd[256];
void *cmd_input(void* args)
{
	struct sigaction sa;
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if(sigaction(SIGUSR1, &sa, NULL) == -1){
		perror("sigaction");
		pthread_exit(NULL);
	}

  	combptr* cmptr = NULL;
  	ssh_channel chl;
  	mltarg* marg;
  	int rc;
//  	char buffer[1024];
  	struct syncq* psq = NULL;
  	struct stq* p = NULL;
  	cmptr = (combptr*)args;
  	chl = (ssh_channel)ACCFIELDP(cmptr, 0);
  	marg = (mltarg*)ACCFIELDP(cmptr, 1);

  	psq = marg->wbf;
	pthread_cleanup_push(cleanup_handler,p);

	while(fistflg == false){
		usleep(1000);
	}

	while(1){
		pthread_mutex_lock(&(psq->mtx));
		if(psq->q == NULL){
			pthread_cond_wait(&(psq->cond), &(psq->mtx));
		}
		p=psq->q;
		psq->q=psq->q->next;
		psq->dtlen--;
		pthread_mutex_unlock(&(psq->mtx));
//		memset(curdcmd, 0, 256);
//		snprintf(curdcmd, strlen((char*)(p->data)) - 1, "%s", (char*)(p->data));
		rc = ssh_channel_write(chl, (char*)(p->data), strlen((char*)(p->data)));

		if(rc < 0) {
			ssh_channel_close(chl);
			goto ptexit;
		}

		syncflg = true;
		while(syncflg){
			usleep(1000);
		}
		phy_free(p->data);
		phy_free(p);
	}

ptexit:
	pthread_cleanup_pop(0);
	pthread_exit(NULL);
	return NULL;
}

void *data_output(void* args)
{
  	combptr* cmptr = NULL;
  	ssh_channel chl;
  	mltarg* marg;
  	int nbytes;
  	char buffer[1024];

  	cmptr = (combptr*)args;
  	chl = (ssh_channel)ACCFIELDP(cmptr, 0);
  	marg = (mltarg*)ACCFIELDP(cmptr, 1);

  	while(1){
 		memset(buffer, 0 ,1024);
 		nbytes = ssh_channel_read(chl, buffer, sizeof(buffer), 0);
// 		nbytes = ssh_channel_read_nonblocking(chl, buffer, sizeof(buffer), 0);
 		if(nbytes > 0) {
 			usleep(1000000);	  //等待写入端输入指令
// 			REMOVE_NEWLINE(buffer, nbytes, nlen);
 			printf("%s", buffer);
 			fflush(stdout);
 			if(buffer[nbytes] == '\0'){
 				if (ssh_channel_is_eof(chl)) {
					syncflg = false;
					continue;
				}
 	 			if(fistflg == false){//收到第一个登录信息结束时打开开关，此时写方可输入第一个指令
 	 				fistflg = true;
 	 				continue;
 	 			}
 	 			if (ssh_channel_is_eof(chl)) {
					syncflg = false;
					continue;
				}
// 				syncflg = false;
// 				continue;
 			}
 		}

 		if (nbytes < 0) {
 		// 读取错误
 			syncflag = false;
			continue;
		}else if (nbytes == 0) {
		// 检查频道是否关闭
			if (ssh_channel_is_eof(chl)) {
				break;
			}
			syncflag = false;
			continue;
		}
 	}

	sleep(1); //等待缓存数据从另一个线程获取完
	pthread_kill(marg->conspid, SIGUSR1);
	pthread_kill(marg->writpid, SIGUSR1);
  	pthread_exit(NULL);
  	return NULL;
}

void ssh_execute(mltarg* marg)
{
	ssh_session session;
	ssh_channel channel;
	pthread_t rpthread_id;
	pthread_t wpthread_id;
	combptr cmptr;
//	char cmdstr[512] = {0};
	int rc;
	session = new_sshsession(marg->ast.add, marg->ast.usr, marg->ast.pwd);
	if(session == NULL){
		sleep(1); //等待缓存数据从另一个线程获取完
		pthread_kill(marg->conspid, SIGUSR1);

		struct transfer tran;
		memset(&tran, 0, sizeof(struct transfer));
		tran.mma.matp = MESS;
		tran.mma.mme = ERROR;
		phy_snprintf(tran.td.mes, 1280, "%s\n", "Create ssh session error!");
		write_message_to_controller((char*)(&tran), sizeof(struct transfer));
		printf("Create ssh session error!\n");
		return;
	}

	channel = get_ssh_chl(session);
	if(channel == NULL){
		sleep(1); //等待缓存数据从另一个线程获取完
		pthread_kill(marg->conspid, SIGUSR1);
		printf("Create ssh channel error!\n");
		return;
	}

	channel = ssh_channel_new(session);
	if (channel == NULL)
		return;

	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK) {
		ssh_channel_free(channel);
		return;
	}

	rc = ssh_channel_request_pty(channel);
	if (rc != SSH_OK) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return;
	}

	ssh_channel_set_blocking(channel, 1);

	rc = ssh_channel_request_shell(channel);
	if (rc != SSH_OK) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return;
	}

	cmptr = COMBPTR(channel, marg);
	pthread_create(&wpthread_id, NULL, cmd_input, &cmptr);
	marg->writpid = wpthread_id;
	pthread_create(&rpthread_id, NULL, data_output, &cmptr);

	pthread_join(rpthread_id, NULL);
	pthread_join(wpthread_id, NULL);

	ssh_channel_send_eof(channel);
	ssh_channel_close(channel);
	ssh_channel_free(channel);
	ssh_disconnect(session);
	destroy_sshsession(session);
 }

void phy_ssh_execute(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, char** record)
{
	mltarg* marg = NULL;
	marg = (mltarg*)phy_malloc(marg, sizeof(mltarg));
	pthread_t conspid;
	combptr cmptr;
	char **arr = NULL;
	char **stmp = NULL;
	memset(marg, 0, sizeof(mltarg));

	phy_snprintf(marg->ast.add, 20, "%s", add);
	phy_snprintf(marg->ast.usr, 20, "%s", usr);
	phy_snprintf(marg->ast.pwd, 20, "%s", pwd);
	phy_snprintf(marg->ast.spwd, 20, "%s", spwd);
	init_multiplex_arg(marg);

	phy_strarr_init(&arr);
	str_to_arr(cmd, ";", &arr);
	for (stmp = arr; NULL != *stmp; stmp++){
		insert_syncq(marg->wbf, *stmp, strlen(*stmp) + 1);
	}
	phy_strarr_free(arr);

	cmptr = COMBPTR(marg->rbf, record);
	pthread_create(&conspid, NULL, ssh_execute_record, &cmptr);
	marg->conspid = conspid;
	ssh_execute(marg);
	pthread_join(conspid, NULL);

	(void)pthread_mutex_unlock(&(marg->wbf->mtx));
	(void)pthread_mutex_unlock(&(marg->rbf->mtx));
	phy_free(marg->rbf->q);
	phy_free(marg->wbf->q);
	phy_free(marg->rbf);
	phy_free(marg->wbf);
	phy_free(marg);

	if(lbhd != NULL){
		if(lbhd->lnbl != NULL){
			phy_free(lbhd->lnbl->data);
			phy_free(lbhd->lnbl);
		}
		phy_free(lbhd);
		return;
	}
}

void physsh_runcmd(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, char** record)
{
	mltarg* marg = NULL;
	marg = (mltarg*)phy_malloc(marg, sizeof(mltarg));
	pthread_t conspid;
	combptr cmptr;
	char **arr = NULL;
	char **stmp = NULL;
	memset(marg, 0, sizeof(mltarg));

	phy_snprintf(marg->ast.add, 20, "%s", add);
	phy_snprintf(marg->ast.usr, 20, "%s", usr);
	phy_snprintf(marg->ast.pwd, 20, "%s", pwd);
	phy_snprintf(marg->ast.spwd, 20, "%s", spwd);
	init_multiplex_arg(marg);

	phy_strarr_init(&arr);
	str_to_arr(cmd, ";", &arr);
	for (stmp = arr; NULL != *stmp; stmp++){
		insert_syncq(marg->wbf, *stmp, strlen(*stmp) + 1);
	}
	phy_strarr_free(arr);

	cmptr = COMBPTR(marg->rbf, record);
	pthread_create(&conspid, NULL, ssh_execute_record, &cmptr);
	marg->conspid = conspid;
	ssh_execute(marg);
	pthread_join(conspid, NULL);

	(void)pthread_mutex_unlock(&(marg->wbf->mtx));
	(void)pthread_mutex_unlock(&(marg->rbf->mtx));
	phy_free(marg->rbf->q);
	phy_free(marg->wbf->q);
	phy_free(marg->rbf);
	phy_free(marg->wbf);
	phy_free(marg);

	if(lbhd != NULL){
		if(lbhd->lnbl != NULL){
			phy_free(lbhd->lnbl->data);
			phy_free(lbhd->lnbl);
		}
		phy_free(lbhd);
		return;
	}
}
