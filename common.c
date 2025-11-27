#include "common.h"
#include "setproctitle.h"
#include <pthread.h>
#include <semaphore.h>
#include "log.h"
#include <unistd.h>
#include <signal.h>
#include "libssh/sftp.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "hashmap.h"

static PHY_THREAD_LOCAL volatile sig_atomic_t	phy_timed_out;
extern pthread_t tid;
extern char* CONFIG_REMOTESCPFILE_SH;
extern char	*CONFIG_REMOTEVSCPFILE_SH;
extern char* CONFIG_REMOTEEXECUTE_SH;
extern char* CONFIG_REMOTEEXECUTEFORK_SH;
extern char* CONFIG_REMOTEPROXYSCPFILE_SH;
extern char* CONFIG_REMOTEPROXYEXECUTE_SH;

extern sem_t *p_sem_serv_run;
extern sem_t *p_sem_qwnd_run;

void	phy_free_service_resources(void)
{
	sigset_t	set;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, NULL);
//	sem_close(p_sem_serv_run);
	sem_unlink(SEM_SERVER_RUN);
//	sem_close(p_sem_qwnd_run);
	sem_unlink(SEM_QTWINDOW_RUN);
}

pthread_t tid;
void	server_on_exit(void)
{
	pthread_cancel(tid);
    pthread_join(tid,NULL);
	printf("phy_on_exit() called\n");
	phy_free_service_resources();
	exit(EXIT_SUCCESS);
}

#define NORFILELEN 3
#define MINIMIZESSTRLEN  1

char  *__get_file_name(const char *projectsfile, int line, const char * filename)
{
	const char	*__function_name = "__get_file_suffix";
	size_t flnlen = strlen(filename);
	if( (flnlen < NORFILELEN) || (filename == NULL) ){
		printf("[file:%s,line:%d, func: %s ]_%s : %s  ", projectsfile, line, __function_name, ARG_INPUT_ERR, filename);
		return NULL;
	}

	char *p = (char*)strrchr(filename, (int)'/');
	if(p == NULL){
		return NULL;
	}

	size_t pos = get_rsstr_pos(filename, "/");

	if( pos == flnlen )
	{
		printf("[file:%s,line:%d, func: %s ]_%s : %s ", projectsfile, line, __function_name, ARG_INPUT_ERR, filename);
		return NULL;
	}else{
		p++;
	}
	return p;
}

void clean_file(const char* filepath)
{

	char cmd[CMDLEN]={0};
	char* filedir = NULL;
	char* filename = NULL;
	filedir = get_parent_dir(filepath);
	filename = get_file_name(filepath);
    	if (access(filedir, 0) != 0)
    	{
        	printf("File %s does not exist\n", filedir);
		phy_snprintf(cmd, CMDLEN, "mkdir -p %s", filedir);
		system(cmd);
		strscat(cmd, filename);
		phy_snprintf(cmd, CMDLEN, "touch %s/%s", filedir, filename);
	}
#if 0
    FILE *file=NULL;
	file = fopen(filepath,"w");
	if(!file)
	{
		puts("打开文件失败！");
	}
	else if(!feof(file))
	{
		fclose(file);
		return;
	}
	fclose(file);
#endif
	int file = 0;
	file = open(filepath,O_CREAT|O_RDWR,0666);
	if(!file)
	{
		puts("打开文件失败！");
		return;
	}
	ftruncate(file,0);
	close(file);
}

void clean_dir(const char* dir)
{
	char cmd[CMDLEN]={0};
	if (access(dir, 0) != 0){
		return;
	}
	phy_snprintf(cmd, CMDLEN, "rm -rf %s/*", dir);
	system(cmd);
}

void phy_rm_dir(const char* dir)
{
	char cmd[CMDLEN]={0};
	phy_snprintf(cmd, CMDLEN, "rm -rf %s", dir);
	system(cmd);
}

char* strrstr(const char* dst, const char* src)
{
    assert(dst);
    assert(src);
    const char* pdst = dst;
    const char* psrc = src;
    char*right = NULL;
    while (*dst)
    {
        while (*pdst == *psrc)
        {
            if (*pdst == '\0')
                return right = (char*)dst;
            else
            {
                pdst++;
                psrc++;
            }
        }
        if (*psrc == '\0')
            right = (char*)dst;
        pdst = ++dst;
        psrc = src;
    }
    return right;
}

char *trim_buf(char *buf)
{
    int i = 0;
    for (i = 0; i < strlen(buf); i++) {
        if (buf[i] == '\n' || buf[i] == '\r') {
            buf[i] = '\0';
            break;
        }
    }
    return buf;
}

int get_result_str(const char* cmd, char** dst)
{
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = popen(cmd, "r");
    if (fp == NULL){
        printf("Error cannot popen %s\n", cmd);
        return -1;
    }
    if((read = getline(&line, &len, fp)) != -1)
    {
    	trim_buf(line);
    	*dst = (char*)phy_calloc(*dst,read,sizeof(char));
    	strncpy(*dst, line, read);
    	phy_free(line);
    	pclose(fp);
    	return 0;
    }
    else
    {
    	printf("Error cannot read \n");
    	pclose(fp);
    	return -1;
    }
}

char* __get_str_between_two_words(const char *filename, int line, const char* res, const char* k1, const char* k2)
{
    const char      *__function_name = "get_str_between_two_words";
    char * p = NULL;
    assert(res);
    if(k1 == NULL && k2 == NULL){
    	printf("[file:%s,line:%d, func: %s ]:%s -- %s \n", filename,  line, __function_name, res, ARG_INPUT_ERR);
        return NULL;
    }
    char *pos1 = NULL;
    char *pos2 = NULL;

    size_t len = 0;
    size_t k1l = 0;
        if(k1 == NULL){
        	pos1 = (char*)res;
            pos2 = strstr(pos1, k2);
        }else if(k2 == NULL){
            len = strlen(res);
            k1l = strlen(k1);
            size_t rpos1 = 0;
            rpos1 = get_rsstr_pos(res, k1);
			if(rpos1 == 0){
				if(!strstr(res, k1)){
					return NULL;
				}
			}
			len = len - rpos1 - k1l + 1;
			if(len == 0){
					return NULL;
			}
			p = phy_malloc(p, len);
			memset(p, 0, len);
			snprintf(p, len, "%s", res + rpos1 + k1l);
			return p;
        }else{
			pos1 = strstr(res, k1);
			if(pos1 == NULL){
					return NULL;
			}
			pos2 = strstr(pos1 + strlen(k1), k2);
        }

        if(pos1 == NULL){
        	printf("[file:%s,line:%d, func: %s ]:%s -- %s \n", filename,  line, __function_name, res, ARG_INPUT_ERR);
            return NULL;
        }

        if(pos2 == NULL){
        	return NULL;
        }
        if((pos1 == res) && (k1 == NULL)){
			len = pos2 - pos1 + 1;
			p = phy_malloc(p, len);
			memset(p, 0, len);
			snprintf(p, len, "%s", pos1);
        }else if((pos1 == res) && (k2 != NULL)){
        	pos2 = strstr(pos1 + strlen(k1), k2);
        	if(pos2){
        		len = pos2 - (pos1 + strlen(k1));
        		if(len == 0){
        			return NULL;
        		}
        		p = phy_malloc(p, len + 1);
        		memset(p, 0, len + 1);
        		phy_snprintf(p, len + 1, "%s", pos1 + strlen(k1));
        	}
        	return p;
#if 0
        }else if((pos1 == res) && (k2 != NULL)){
        	pos2 = strstr(pos1 + strlen(k1) + 1, k2);
        	if(pos2){
        		len = pos2 - (pos1 + strlen(k1)) + 1;
        		p = phy_malloc(p, len);
        		memset(p, 0, len);
        		snprintf(p, len, "%s", pos1 + strlen(k1));
        	}
#endif
        }else{
			k1l = strlen(k1);
			len = pos2 - pos1 - k1l + 1;
			p = phy_malloc(p, len);
			memset(p, 0, len);
			snprintf(p, len, "%s", pos1 + k1l);
        }
        p[len - 1] = '\0';
        return p;
}

int do_ping(const char* ipv4)
{
	int res = 0;
	res = is_ip4(ipv4);
	if(res == FAIL){
		printf("The ipv4 format is error\n");
		return FAIL;
	}

	char cmd[CMDLEN] = {0};
#if 1 //correct
	sprintf(cmd, "#! /bin/bash	                               	   \n \
						num=1                                 	   \n \
						while [ $num -le 3 ]                   	   \n \
						do					                  	   \n \
        					if ping -c 1 %s >> pugongyingdeyueding \n \
        					then						      	   \n \
           						echo \"%s Ping is success\"    	   \n \
								rm -f pugongyingdeyueding    	   \n \
								break					      	   \n \
							else						      	   \n \
#								let num++				           \n \
								FALL[$num]=%s		   	           \n \
								break							   \n \
							fi							           \n \
						done							           \n \
						if [ ${#FALL[*]} -eq 3 ]                   \n \
					    then							      	   \n \
							echo \"${FALL[1]} Ping is failure!\"   \n \
							unset FALL[*];fi", ipv4, ipv4, ipv4);
#endif

	char* result = NULL;
	get_result_str(cmd, &result);
	if(result == NULL){
		return 0;
	}
	if(strstr(result, "failure")){
		phy_free(result);
		return 0;
	}
	if(strstr(result, "success")){
		phy_free(result);
		return 1;
	}
	return 0;
}

int remote_cp(const char* src_file, const char* user, const char* ip, const char* dest_file, const char* password)
{
	char cmd[CMDLEN] = {0};
	phy_snprintf(cmd, CMDLEN, "%s %s %s %s %s %s", CONFIG_REMOTESCPFILE_SH, src_file, user, ip, dest_file, password);
	phy_log(LOG_LEVEL_TRACE, "remote_cp: file %s, dest %s.", src_file, dest_file);
	system(cmd);
	return 0;
}

int remote_vcp(const char* src_file, const char* user, const char* ip, const char* dest_file, const char* password)
{
	char cmd[CMDLEN] = {0};
	phy_snprintf(cmd, CMDLEN, "%s %s %s %s %s %s", CONFIG_REMOTEVSCPFILE_SH, src_file, user, ip, dest_file, password);
	phy_log(LOG_LEVEL_TRACE, "remote_vcp: file %s, dest %s.", src_file, dest_file);
	system(cmd);
	return 0;
}

int remote_cp_proxy(const char* src_file, const char* user, const char* ip, const char* proxyusr, const char* proxyip, const char* dest_file, const char* password, const char* proxypass)
{
	char cmd[CMDLEN] = {0};
//	 ./remotescp_proxy.sh "1111xxx" "uos" "10.10.53.92" "uos" "10.10.53.109" "/home/uos/1111xxx" "uosuos" "uosuos"
#if 0
	phy_snprintf(cmd, CMDLEN, "%s %s %s %s %s %s %s %s %s", CONFIG_REMOTESCPPROXYFILE_SH, src_file, user, ip, proxyusr, proxyip, dest_file, password, proxypass);
#endif
	phy_snprintf(cmd, CMDLEN, "%s '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s'", CONFIG_REMOTEPROXYSCPFILE_SH, ip, user, password, proxyip, proxyusr, proxypass, src_file, dest_file);
	phy_log(LOG_LEVEL_TRACE, "remote_cp_proxy: cmd %s.", cmd);
	system(cmd);
	return 0;
}

#if 0
int remote_cp_fork(const char* src_file, const char* user, const char* ip, const char* dest_file, const char* password)
{
	char cmd[CMDLEN] = {0};
	//phy_snprintf(cmd, CMDLEN, "%s %s %s %s %s %s > %s", REMOTESCPFILE, src_file, user, ip, dest_file, password, REMOTESCPLOG);
	phy_snprintf(cmd, CMDLEN, "%s %s %s %s %s %s", CONFIG_REMOTESCPFILE_SH, src_file, user, ip, dest_file, password);
	printf("Remote cp: %s\n", cmd);
	system(cmd);
	return 0;
}
#endif

int remote_execute(const char* remote_ip, const char* command, const char* user, const char* password)
{
	char cmd[CMDLEN] = {0};
	phy_snprintf(cmd, CMDLEN, "%s %s %s %s %s", CONFIG_REMOTEEXECUTE_SH, remote_ip, command, user, password);
	system(cmd);
	return 0;
}

int remote_execute_fork(const char* remote_ip, const char* command, const char* user, const char* password)
{
	char cmd[CMDLEN] = {0};
	phy_snprintf(cmd, CMDLEN, "%s %s %s %s %s", CONFIG_REMOTEEXECUTEFORK_SH, remote_ip, command, user, password);
	phy_log(LOG_LEVEL_TRACE, "remote_execute_fork: cmd %s.", cmd);
	system(cmd);
	return 0;
}
//								 (ipaddr, "/tmp/scptmpdir/insx.sh", username, userpass, proxyip, PROXY_USER, PROXY_PASS)
int remote_execute_fork_proxy(const char* remote_ip, const char* command, const char* user, const char* password, const char* proxy_ip, const char* proxy_user, const char* proxy_pass)
{
	char cmd[CMDLEN] = {0};
//  10.10.53.109 10.10.53.92 "ls -l" uos uosuos uos uosuos
#if 0
	phy_snprintf(cmd, CMDLEN, "%s %s %s %s %s %s %s %s", CONFIG_REMOTEEXECUTEFORKPROXY_SH, proxy_ip, remote_ip, command, proxy_user, proxy_pass, user, password);
#endif
	phy_snprintf(cmd, CMDLEN, "%s '%s' '%s' '%s' '%s' '%s' '%s' '%s'", CONFIG_REMOTEPROXYEXECUTE_SH, remote_ip,  user, password, proxy_ip, proxy_user, proxy_pass, command);
	phy_log(LOG_LEVEL_TRACE, "remote_execute_fork: cmd %s.", cmd);
	system(cmd);
	return 0;
}

#if 0
void	__phy_phy_setproctitle(const char *fmt, ...)
{
#if defined(HAVE_FUNCTION_SETPROCTITLE) || defined(PS_OVERWRITE_ARGV) || defined(PS_PSTAT_ARGV)
//	const char	*__function_name = "__phy_phy_setproctitle";
	char		title[MAX_STRING_LEN];
	va_list		args;

	va_start(args, fmt);
	phy_vsnprintf(title, sizeof(title), fmt, args);
	va_end(args);
//	unbench_log(LOG_LEVEL_DEBUG, "%s() title:'%s'", __function_name, title);
#endif
#if defined(HAVE_FUNCTION_SETPROCTITLE)
	setproctitle("%s", title);
#elif defined(PS_OVERWRITE_ARGV) || defined(PS_PSTAT_ARGV)
	setproctitle_set_status(title);
#endif
}
#endif

void strlist_add(struct strlist** head, const char* str)
{
    struct strlist* p = *head;
    struct strlist* r = NULL;
	struct strlist* q = NULL;
	q = (struct strlist*)phy_malloc(q, sizeof(struct strlist));
    if (NULL==q) return;

    q->data = strdup((const char *)trim_buf((char*)str));
    q->next=NULL;

    while(p){
        r = p;
        p = p->next;
    }
    r->next = q;
    return;
}

void create_strlist(struct strlist** head)
{
    struct strlist* h = (struct strlist*)malloc(sizeof(struct strlist));
    memset(h, 0, sizeof(struct strlist));
    h->data = strdup("This is head");
    h->next = NULL;

    *head = h;
    return;
}

void iterator_strlist(struct strlist* head)
{
    struct strlist* p = NULL;
    p = head->next;
    while(p){
        printf("%s\n", p->data);
        p = p->next;
    }
}

void iterator_strlistah(struct strlist* head)
{
    struct strlist* p = NULL;
    p = head;
    while(p){
        printf("%s\n", p->data);
        p = p->next;
    }
}

void delete_strlist(struct strlist* head, struct strlist* data)
{
    struct strlist* p = NULL;
	  struct strlist* pp = NULL;

    p = head->next;
    pp = head;

    while(p){
        if(data == p){
                pp->next = data->next;
                phy_free(data->data);
                phy_free(data);
                p = pp;
                break;
        }
        pp = p;
        p = p->next;
    }
}

bool strlist_delete_px(struct strlist** head, struct strlist** node)
{
	struct strlist* p = *head;
	struct strlist* q = NULL;

	while(p){
		if(p == *node ){
				q->next = p->next;
				*node = p->next;
				phy_free(p->data);
				phy_free(p);
				return true;
				break;
		}
		q = p;
		p = p->next;
	}
	return false;
}
bool strlist_delete_relkey(struct strlist** head, const char* relkey)
{
	struct strlist* p = *head;
	bool delflg = false;
	while(p){
		if(is_placeholder(p->data)){
			delflg = true;
			if(strlist_delete_px(head, &p)){
				if(p==NULL){
					return delflg;
				}
				continue;
			}
		}
		if(strstr(p->data, relkey)){
			delflg = true;
			if(strlist_delete_px(head, &p)){
				if(p==NULL){
					return delflg;
				}
				continue;
			}
		}
		p = p->next;
	}
	return delflg;
}

bool strlist_delete_tooshort(struct strlist** head, int len)
{
	struct strlist* p = *head;
	bool delflg = false;
	while(p){
		if(is_placeholder(p->data)){
			delflg = true;
			if(strlist_delete_px(head, &p)){
				if(p==NULL){
					return delflg;
				}
				continue;
			}
		}
		if(strlen(p->data) <= len){
			delflg = true;
			if(strlist_delete_px(head, &p)){
				if(p==NULL){
					return delflg;
				}
				continue;
			}
		}
		p = p->next;
	}
	return delflg;
}

void strlist_insert_str(struct strlist** head, const char* str, bool flag)
{
	struct strlist* p = (*head);
	struct strlist* sp = (*head)->next;
	struct strlist* tp = NULL;

	tp = (struct strlist*)phy_malloc(tp, sizeof(struct strlist));
	memset(tp, 0, sizeof(struct strlist));
	tp->data = phy_strdup(tp->data, str);

	if(flag == true){
		p->next = tp;
		tp->next = sp;
	}

	if(flag == false){
		while(p){
			if(p->next == NULL){
				p->next = tp;
				break;
			}
			p = p->next;
		}
	}
}

void strlist_delete_p(struct strlist** head, struct strlist** node)
{
	struct strlist* p = *head;
	struct strlist* q = NULL;

	while(p){
		if(p == *node ){
				q->next = p->next;
				*node = p->next;
				phy_free(p->data);
				phy_free(p);
				break;
		}
		q = p;
		p = p->next;
	}
}

void destory_strlist(struct strlist* head)
{
    struct strlist* p=head;
    while(p){
        head=p->next;
        phy_free(p->data);
        phy_free(p);
        p = head;
    }
}

void create_datalist(struct datalist** head)
{
	struct datalist* h = (struct datalist*)phy_malloc(NULL, sizeof(struct datalist));
	memset(h, 0, sizeof(struct datalist));
	h->data = (void*)strdup("This is head");
	h->next = NULL;
	h->len = 0;
	*head = h;
	h->current = h;
	return;
}

void iterator_datalist(struct datalist* head)
{
	struct datalist *p;
	p = head->next;
//	phy_agent_list* al = NULL;
//	agent_st *al = NULL;
	struct cnfinfo *al = NULL;
	while(p){
		if(p != NULL){
//			al = (phy_agent_list*)p->data;
//			al = (agent_st*)(p->data);
			al = (struct cnfinfo*)(p->data);
			printf("%s\n", al->desc);
			printf("%s\n", al->item);
			printf("%s\n", al->belong);
			printf("%s\n", (al->swch == true) ? "yes" : "no");
		}
		p = p->next;
	}
}

void destory_datalist(struct datalist* head)
{
	struct datalist* p=head;
	while(p){
	    head=p->next;
	    phy_free(p->data);
	    phy_free(p);
	    p = head;
	}
}

void destory_datalistp(struct datalist** head)
{
	struct datalist* p=(*head);
	while(p){
	    (*head)=p->next;
	    phy_free(p->data);
	    phy_free(p);
	    p = (*head);
	}
}

void datalist_add(struct datalist** head, void* data, size_t len)
{
	struct datalist* p = NULL;
	struct datalist* q = NULL;
	q = (struct datalist*)phy_malloc(NULL, sizeof(struct datalist));
	memset(q, 0, sizeof(struct datalist));
	if (NULL==q) return;

	q->data = phy_malloc(NULL, len);
	memcpy(q->data, data, len);
	q->next=NULL;

	p = (*head)->current;
	(*head)->current = q;
	p->next = q;
	(*head)->len++;
	return;
}

void datalist_del(struct datalist** head,  struct datalist** data)
{
	struct datalist* q = NULL;
	struct datalist* r = NULL;
	struct datalist* s = NULL;
	bool flag = false;
	if((*data) == NULL){
		return;
	}

	if((struct datalist*)(*data) == (struct datalist*)(*head)->current){
		flag = true;
	}

	q = (*head)->next;
	s = (*head);
	while(q){
		if(q == ((struct datalist*)*data)){
			r = q->next;
			phy_free(q->data);
			phy_free(q);
			s->next = r;
			(*head)->len --;
			break;
		}
		s = q;
		q = q->next;
	}

	if(flag == true){
		(*head)->current = s;
		(*data) = (struct datalist*)NULL;
	}
}

void str_to_arr(const char* res, const char* spliter, char*** arr)
{
	char tmp[STRING_LEN] = {0};
	const char*s = res;
	const char*p = res;
	size_t spln = 0;
	spln = strlen(spliter);
	while( *p != '\0' ){
		p = strstr(s, spliter);
		if(p != NULL){
			if(p - s + 1 >= 2){
				memset(tmp, 0, STRING_LEN);
				snprintf(tmp, p - s + 1, "%s", s);
				phy_strarr_add(arr, tmp);
			}
			p = p + spln;
			s = p;
		}else{
			memset(tmp, 0, STRING_LEN);
			snprintf(tmp, STRING_LEN, "%s", s);
			phy_strarr_add(arr, tmp);
			break;
		}
	}
	return;
}

long int	phy_get_thread_id()
{
	return (long int)getpid();
}

void delete_file(const char* file)
{
	char cmd[CMDLEN] = {0};
	phy_snprintf(cmd, CMDLEN, "rm -rf %s", file);
	system(cmd);
}


void get_result_strlist(const char* cmd, struct strlist* head, bool display)
{
#define STRTOOSHRT 1
    if(cmd == NULL || head == NULL){
        printf("Parameter error \n");
        return;
    }

    FILE *fp=NULL;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = popen(cmd, "r");
    if (fp == NULL){
        printf("Error cannot popen %s\n", cmd);
        return;
    }

#if 0
    while((read = getline(&line, &len, fp)) != -1) {
        line[read-1] = '\0';
        if(strlen(line) <= STRTOOSHRT){
            len = 0;
            un_free(line);
            continue;
        }
        strlist_add(&head, line);
        len = 0;
        un_free(line);
    }
#endif

        while ((read = getline(&line, &len, fp)) != -1) {
                if(display == true){
                        if(strstr(line, "avg error less than"))
                        {
                                continue;
                        }
                        printf("\r\033[K%s \n", line);
                }
        if(strlen(line) < STRTOOSHRT){
//            un_free(line);
            continue;
        }
        if(line[0] == '\n'){
        	continue;
        }
        if(strlen(line) == 1){
        	strlist_add(&head, line);
        }else{
//        	line[read-1] = '\0';
        	line[read] = '\0';
        	strlist_add(&head, line);
        }
     }
        phy_free(line);
    pclose(fp);
}

void strlist_insert(struct strlist** head, const char* key, const char* str)
{
    struct strlist* p = *head;
    struct strlist* tp = *head;
    struct strlist* np = p->next;

    if( key == NULL || str == NULL ){
        printf("Strlist_insert args Error\n");
        exit(-1);
    }

    while(np){
        if( NULL != strstr(np->data, key) ){

            struct strlist* q = NULL;
            q = (struct strlist*)phy_malloc(q, sizeof(struct strlist));
            if ( NULL== (q)) return;
            ((struct strlist*)(q))->data = strdup((const char *)trim_buf((char*)str));
            tp = np->next;
            np->next = q;
           ((struct strlist*)(q))->next = tp;
           break;
        }
        np = np->next;
    }
    return;
}

void strlist_replace(struct strlist** head, const char* key, const char* str)
{
    struct strlist* np = (*head)->next;

    if( key == NULL || str == NULL ){
        printf("Strlist_insert args Error\n");
        exit(-1);
    }

    while(np){
        if( NULL != strstr(np->data, key) ){
 //       	printf("------------ strlist_replace key:%s, str:%s \n", key, str);
        	phy_free(np->data);
        	np->data = strdup(str);
           break;
        }
        np = np->next;
    }
}

void binary_write_file(const void * data, size_t size, const char* path)
{
	FILE *ftd = NULL;
//	ftd = fopen(path,"w+");
	ftd = fopen(path,"a+");
	if(!ftd)
	{
		puts("打开文件失败！");
		return;
	}
//	fwrite(data, 1, size, ftd);
	fwrite(data, size, 1, ftd);
	fwrite("\n", 1, 1, ftd);
	fclose(ftd);
}

void write_file(const char* filepath, const char* line)
{
	FILE *file=NULL;
//      char cmd[CMDLEN]={0};
	file = fopen(filepath,"a+");
	if(!file)
	{
		puts("打开文件失败！");
		return;
	}
	fprintf(file, "%s\n", line);
	fclose(file);
}

void writes_file(const char* filepath, const char* line, size_t len)
{
	FILE *file=NULL;
//      char cmd[CMDLEN]={0};
	file = fopen(filepath,"a+");
	if(!file)
	{
		puts("打开文件失败！");
		return;
	}
	fwrite(line, len, 1, file);
	fclose(file);
}

void cp_file(const char* srcpath, const char* dstpath)
{
	char cmd[CMDLEN]={0};
	phy_snprintf(cmd, CMDLEN, "cp -rfp %s %s", srcpath, dstpath);
	system(cmd);
}

void insert_content_to_file(const char* filepath, const char* keyline, const char* content)
{
	char cmd[CMDLEN] = {0};
	struct strlist* filecontent = NULL;
	struct strlist* p = NULL;
	create_strlist(&filecontent);
	phy_snprintf(cmd, CMDLEN, "cat %s", filepath);
	get_result_strlist(cmd, filecontent, false);
	strlist_insert(&filecontent, keyline, content);
	clean_file(filepath);
	p = filecontent->next;
	while(p){
		write_file(filepath, p->data);
		p = p->next;
	}
}

void insert_content_to_filex(const char* sfilepath, const char* dfilepath, const char* keyline, const char* content)
{
	char cmd[CMDLEN] = {0};
	struct strlist* filecontent = NULL;
	struct strlist* p = NULL;
	create_strlist(&filecontent);
	phy_snprintf(cmd, CMDLEN, "cat %s", sfilepath);
	get_result_strlist(cmd, filecontent, false);
	strlist_insert(&filecontent, keyline, content);
	clean_file(dfilepath);
	p = filecontent->next;
	while(p){
		write_file(dfilepath, p->data);
		p = p->next;
	}
	destory_strlist(filecontent);
}

static int	is_leap_year(int year)
{
	return 0 == year % 4 && (0 != year % 100 || 0 == year % 400) ? SUCCEED : FAIL;
}


void phy_get_times(struct tm *tm, long *milliseconds, un_int64_t *st, phy_timezone_t *tz)
{
	struct timeval	current_time;

	gettimeofday(&current_time, NULL);
	localtime_r(&current_time.tv_sec, tm);
	*st = current_time.tv_sec;
	*milliseconds = current_time.tv_usec / 1000;

	if (NULL != tz)
	{
#	define UTC_OFF	offset
		long		offset;
		struct tm	tm_utc;

		gmtime_r(&current_time.tv_sec, &tm_utc);

		offset = (tm->tm_yday - tm_utc.tm_yday) * SEC_PER_DAY + (tm->tm_hour - tm_utc.tm_hour) * SEC_PER_HOUR +
				(tm->tm_min - tm_utc.tm_min) * SEC_PER_MIN;

		while (tm->tm_year > tm_utc.tm_year)
			offset += (SUCCEED == is_leap_year(tm_utc.tm_year++) ? SEC_PER_YEAR + SEC_PER_DAY : SEC_PER_YEAR);

		while (tm->tm_year < tm_utc.tm_year)
			offset -= (SUCCEED == is_leap_year(--tm_utc.tm_year) ? SEC_PER_YEAR + SEC_PER_DAY : SEC_PER_YEAR);

		tz->tz_sign = (0 <= UTC_OFF ? '+' : '-');
		tz->tz_hour = labs(UTC_OFF) / SEC_PER_HOUR;
		tz->tz_min = (labs(UTC_OFF) - tz->tz_hour * SEC_PER_HOUR) / SEC_PER_MIN;
#undef UTC_OFF
	}
}

void	un_remove_str(register char *str, const char *charlist)    //  "randreadtest"  "rand"  => readtest   "randreadtestrand"  "rand"  => readtest
{
	register char *p;

	if (NULL == str || NULL == charlist || '\0' == *str || '\0' == *charlist)
		return;

	while( (p = strstr(str, charlist)) != NULL ){
		for(; *(p + strlen(charlist)) != '\0';){
			str[p-str] = *(p + strlen(charlist));
			p++;
		}
		str[p-str] = '\0';
		un_remove_str(str, charlist);
	}
}

char* insert_string(const char *str, const char *key, const char *insertstr, bool foa)
{
	if (NULL == str || NULL == key || NULL == insertstr|| '\0' == *str || '\0' == *key || '\0' == *insertstr)
		return NULL;

	char *p = NULL;
	char *dest = NULL;
	size_t len = 0;
	p = strstr(str, key);
	if(p == NULL){
		printf("insert_string: Please input correct!\n");
		return NULL;
	}

	len = strlen(str) + strlen(insertstr) + 1;
	dest = (char*)phy_malloc(dest, len);
	memset(dest, 0, len);
	if(foa == true){
		if(p == str){
			phy_snprintf(dest, len, "%s", insertstr);
			phy_strlcat(dest, str, len);
		}else{
			phy_snprintf(dest, p - str + 1, "%s", str);
			phy_strlcat(dest, insertstr, len);
			phy_strlcat(dest, p, len);
		}
	}else{
		if( *(p + strlen(key)) == '\0' ){
			phy_snprintf(dest, len, "%s", str);
			phy_strlcat(dest, insertstr, len);
		}else{
			phy_snprintf(dest, p - str + strlen(key) + 1, "%s", str);
			phy_strlcat(dest, insertstr, len);
			phy_strlcat(dest, p + strlen(key), len);
		}
	}
	return dest;
}

bool matches_any_one_of_the_strings(const char* line, ...)
{
	struct strlist* head=NULL;
	create_strlist(&head);
	struct strlist*p=NULL;

	va_list ap;
	va_start(ap, line);

	char* tmp = NULL;
	int i = 0;
	while ((tmp = va_arg(ap, char*)) != END)
	{
		strlist_add(&head, tmp);
		i++;
	}

	if(i == 0){
		destory_strlist(head);
		va_end(ap);
		return false;
	}

	p = head->next;
	while(p){
		if(strstr(line, p->data)){
			destory_strlist(head);
			return true;
		}
		p = p->next;
	}
	destory_strlist(head);
	va_end(ap);
	return false;
}

unsigned int get_pid(const char* keyword)
{
	char* dst = NULL;
	unsigned int pid=0;
	char cmd[BUFLEN] = {0};
	snprintf(cmd, BUFLEN, "ps -gaux | grep \"%s\" | grep -v grep | awk '{print $2}'", keyword);
	get_result_str(cmd, &dst);
	if(dst == NULL){
		printf("Cannot get %s's pid\n", keyword);
		return 0;
	}
	pid = atoi(dst);

	phy_free(dst);
	return pid;
}

bool if_finish(const char* keyword)
{
	char* dst = NULL;
	char cmd[BUFLEN] = {0};
	snprintf(cmd, BUFLEN, "ps -gaux | grep \"%s\" | grep -v grep ", keyword);
	get_result_str(cmd, &dst);
	if(dst == NULL){
		printf("Cannot get %s's pid\n", keyword);
		return true;
	}
	return false;
}

void percentage(int numerator, int denominator, int* dst)
{
	float fn = numerator;
	float fd = denominator;
	if(denominator == 0 || (numerator > denominator)){
		*dst = 0;
		return;
	}
	*dst = (int)((fn/fd)*100);
}

//char* get_pdir_name(const char* path)
char* get_pdir_name(char* path)
{
//	char *path="/dir1/dir2/dir.suffix";
//	dirname(path) ==> /dir1/dir2
//	basename(path) ==> dir.suffix
//	char* pdir = NULL;
	char* pdirnm = NULL;
//	pdir = dirname(path);
	pdirnm = basename(path);
	return pdirnm;
}

#define MAX_DIR_LEN (1024)
void trave_dir(const char* path, struct strlist** head)
{
    DIR *d = NULL;
    struct dirent *dp = NULL; /* readdir函数的返回值就存放在这个结构体中 */
    struct stat st;
    char p[MAX_DIR_LEN] = {0};

    if(stat(path, &st) < 0 || !S_ISDIR(st.st_mode)) {
        printf("invalid path: %s\n", path);
        return;
    }

    if(!(d = opendir(path))) {
        printf("opendir[%s] error: %m\n", path);
        return;
    }

    while((dp = readdir(d)) != NULL) {
        /* 把当前目录.，上一级目录..及隐藏文件都去掉，避免死循环遍历目录 */
        if((!strncmp(dp->d_name, ".", 1)) || (!strncmp(dp->d_name, "..", 2)))
            continue;

        memset(p, 0, MAX_DIR_LEN);
        snprintf(p, sizeof(p) - 1, "%s/%s", path, dp->d_name);
        strlist_add(head, p);
        stat(p, &st);

#if 0
        if(!S_ISDIR(st.st_mode)) {
            printf("%s\n", dp->d_name);
        } else {
            printf("%s/\n", dp->d_name);
            trave_dir(p);
        }
#endif

        if(S_ISDIR(st.st_mode)) {
        	trave_dir(p, head);
        }
    }
    closedir(d);
    return;
}

bool phy_rcmp(const char* rstr, const char* key)
{
	size_t klen = 0;
	size_t rlen = 0;
	char *p = NULL;
	rlen = strlen(rstr);
	klen = strlen(key);
	p = (char*)rstr + rlen - klen;
	if(strncmp(key, p, klen) == 0){
		return true;
	}else{
		return false;
	}
}

bool phy_isdir(const char* path)
{
	struct stat st;
	if(stat(path, &st) < 0 || !S_ISDIR(st.st_mode)) {
		printf("invalid path: %s\n", path);
	    return false;
	 }else{
		 return true;
	 }
}

void strlist2file(struct strlist* head, const char* file)
{
	FILE *fp=NULL;
	struct strlist* p = NULL;
	p = head->next;
	fp = fopen(file,"a+");
	if(!fp)
	{
		phy_log(LOG_LEVEL_ERR, "strlist2file: File %s cannot open.", file);
		return;
	}
	while(p){
		fprintf(fp, "%s\n", p->data);
		p = p->next;
	}
	fclose(fp);
}

void remove_file(const char* fpath)
{
	char strcmd[BUFLEN]={0};
	phy_snprintf(strcmd, BUFLEN, "rm -rf %s", fpath);
	system(strcmd);
}

int sharememory(int ipc_size,int flag)
{
	int id;
	key_t key=ftok("/tmp",66);
	if(key < 0)
	{
		printf("get key error\n");
		return -1;
	}
	id = shmget(key,ipc_size,flag);
	if(id < 0)
	{
		printf("get id error\n");
		return -1;
	}
	return id;
}

int create_ipc(int ipc_size)
{
	return sharememory(ipc_size,IPC_CREAT|IPC_EXCL|0666);
}
int get_ipc(int ipc_size)
{
	return sharememory(ipc_size,IPC_CREAT|0666);
}
int destroy_sharememory(int id)
{
	return shmctl(id,IPC_RMID,NULL);
}

void sig_handler(int sig)
{
	exit(0);
}

void phy_timer(pfun pf, void* args, int dur)
{
	pid_t	pid;
	struct sigaction action;
	memset(&action, 0, sizeof(struct sigaction));
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_NOCLDWAIT;
	if(sigaction(SIGCHLD, &action, NULL) == -1){
		printf("sigaction error\n");
		exit(1);
	}

	if((pid = fork()) == -1){
		printf("fork error\n");
		exit(1);
	}else if(pid == 0){
		struct sigaction act, oldact;
		memset(&act, 0, sizeof(struct sigaction));
		memset(&oldact, 0, sizeof(struct sigaction));
		act.sa_handler = sig_handler;
		sigaddset(&act.sa_mask, SIGQUIT);
		act.sa_flags = SA_RESETHAND | SA_NODEFER;
		sigaction(SIGINT, &act, &oldact);
		pf(args);
		exit(0);
	}else{
		sleep(dur);
		kill(pid, SIGINT);
	}
}

bool is_exist(const char* file_name)
{
    const char      *__function_name = "is_exist";
    if (access(file_name, 0) != 0)
    {
//        printf("%s: File %s does not exist!\n", __function_name, file_name);
	phy_log(LOG_LEVEL_WARNING, "%s: File %s does not exist!", __function_name, file_name);
        return false;
    }else{
        return true;
    }
}

bool fil_isexist(const char* filnm)
{
	struct stat buf;
	int exist = 0;
	exist = stat(filnm, &buf);
	if(exist == 0){
		return true;
	}else{
		return false;
	}
}

bool fil_remove(const char* filnm)
{
	if(unlink(filnm) == 0){
		return true;
	}else{
		phy_log(LOG_LEVEL_WARNING, "fil_remove: File %s does not exist!", filnm);
	}
	return false;
}

void* mythread(void* arg)                                         /* 定义新线程运行的函数 */
{
  int i,ret;
  ret = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);     /* 设置线程的取消状态 */
  if(ret != 0)
  {
    printf("Thread pthread_setcancelsate failed.");                /* 如果取消状态未设置成功，打印错误信息 */
    exit(1);
  }
//  ret = pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);    /* 设置线程的取消类型 */
  ret = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  if(ret != 0)
  {
    printf("Thread pthread_setcanceltype failed.");                 /* 如果取消类型未设置成功，打印错误信息 */
    exit(1);
  }

  for(i=0; i<100; i++)                                                                /* 连续输出字符串，同时显示运行位置 */
  {
    printf("Thread is running (%d) ...\n",i);
    sleep(1);
  }
  pthread_exit((void *)"Thank you for the CPU time.\n");                /* 终止当前线程 */
}


int	phy_strcmp_natural(const char *s1, const char *s2)
{
	int	ret, value1, value2;

	for (;'\0' != *s1 && '\0' != *s2; s1++, s2++)
	{
		if (0 == isdigit(*s1) || 0 == isdigit(*s2))
		{
			if (0 != (ret = *s1 - *s2))
				return ret;

			continue;
		}

		value1 = 0;
		while (0 != isdigit(*s1))
			value1 = value1 * 10 + *s1++ - '0';

		value2 = 0;
		while (0 != isdigit(*s2))
			value2 = value2 * 10 + *s2++ - '0';

		if (0 != (ret = value1 - value2))
			return ret;

		if ('\0' == *s1 || '\0' == *s2)
			break;
	}

	return *s1 - *s2;
}

bool keyword_at_the_end_of_the_string(const char* str, const char* key)
{
	size_t len = 0;
	size_t klen = 0;
	char* p = NULL;
	if(str == NULL || key == NULL){
		return false;
	}

	klen = strlen(key);
	len = strlen(str);
	if(len == 0 || klen == 0 || len <= klen){
		return false;
	}

	p = strstr(str, key);
	if(NULL == p || ((p - str) + klen) != len ){
		return false;
	}
	return true;
}

bool keyword_at_the_middle_of_the_string(const char* str, const char* key)
{
	size_t len = 0;
	size_t klen = 0;
	char* p = NULL;
	if(str == NULL || key == NULL){
		return false;
	}

	klen = strlen(key);
	len = strlen(str);
	p = strstr(str, key);
	if(len == 0 || klen == 0 || len <= klen || p == NULL){
		return false;
	}

	if((p - str) + klen < len ){
		return true;
	}
	return false;
}

char* string_add(char* str, const char* key)
{
	char* p = NULL;
	size_t len = 0;
	size_t klen = 0;
	klen = strlen(key);
	len = strlen(str);
	p = (char*)phy_malloc(p, len + klen + 1);
	memset(p, 0, len+klen+1);
	phy_snprintf(p, len + klen + 1, "%s%s", str, key);
	phy_free(str);
	return p;
}

void strlist_reverse(struct strlist** head)
{
	struct strlist* p;
	struct strlist* r;
	struct strlist* t;

	p = (*head);
	r = p->next;

	if(r != NULL){
		t = r->next;
		if(t == NULL){
			r->next = (*head);
			(*head) = r;
			p->next = t;
			return;
		}
	}else{
		return;
	}

	while(r){
//
		r->next = (*head);
		(*head) = r;
		p->next = t;
//
		r = t;
		t = r->next;
		if(t==NULL){
			r->next = (*head);
			(*head) = r;
			p->next = t;
			break;
		}
	}
}

unsigned long get_file_size(const char *path)
{

    unsigned long filesize = -1;
    struct stat statbuff;
    if(stat(path, &statbuff) < 0)
        return filesize;
    else
        filesize = statbuff.st_size;

    return filesize;
}

//tar.gz
void uncompress(const char* tagfile, const char* dstdir)
{
	char strcmd[BUFLEN]={0};
	memset(strcmd, 0, BUFLEN);
	struct stat st;
	if(stat(dstdir, &st) < 0 || !S_ISDIR(st.st_mode)) {
		memset(strcmd, 0, BUFLEN);
		phy_snprintf(strcmd, BUFLEN, "mkdir -p %s", dstdir);
		system(strcmd);
//		printf("invalid path: %s\n", dstdir);
	}else{
		clean_dir(dstdir);
	}
	memset(strcmd, 0, BUFLEN);
	phy_snprintf(strcmd, BUFLEN, "tar zxf %s --strip-components 1 -C %s", tagfile, dstdir);
	system(strcmd);
}

void jsonfile2mem(const char* file, char** content)
{
	int i = 0;
	char* mem = NULL;
	FILE *stream = NULL;
	unsigned long filesize = 0;
	filesize = get_file_size(file);
	if(filesize == -1){
		*content = NULL;
		return;
	}
	mem = (char*)phy_malloc(mem, filesize);
	memset(mem, 0, filesize);
	stream = fopen(file, "r+");
	if(stream == NULL){
		*content = NULL;
		return;
	}
	fread(mem, 1, filesize, stream);
//correcting
	i = filesize - 1;
	while(mem[i] != '}'){
		mem[i] = '\0';
		i--;
	}

	fclose(stream);
	*content = mem;
}

char* __get_nearest_key(const char *filename, int line, const char* res, const char* prefix)
{
	char* re = NULL;
	char *p = NULL;
	const char      *__function_name = "get_nearest_key";
	if(res == NULL && prefix == NULL){
		printf("[file:%s,line:%d, func: %s ]:%s\n", filename,  line, __function_name, "ARG_INPUT_ERR");
		return re;
    }

	p = strstr(res, prefix);
	if(p == NULL){
		return re;
	}

	re = phy_malloc(re, 2);
	memset(re, 0, 2);
	if(strchr(p, ',')){
		phy_snprintf(re, 2, "%c", ',');
		return re;
	}

	if(strchr(p, ';')){
		phy_snprintf(re, 2, "%c", ';');
		return re;
	}

	if(strchr(p, ' ')){
		phy_snprintf(re, 2, "%c", ' ');
		return re;
	}

	if(strchr(p, '\0')){
		phy_snprintf(re, 2, "%c", '\0');
		return re;
	}
	return re;
}

int	is_uhex(const char *str)
{
	int	res = FAIL;

	while (' ' == *str)	/* trim left spaces */
		str++;

	for (; '\0' != *str; str++)
	{
		if (0 == isxdigit(*str))
			break;

		res = SUCCEED;
	}

	while (' ' == *str)	/* check right spaces */
		str++;

	if ('\0' != *str)
		return FAIL;

	return res;
}

void	phy_strlower(char *str)
{
	for (; '\0' != *str; str++)
		*str = tolower(*str);
}

void	phy_strupper(char *str)
{
	for (; '\0' != *str; str++)
		*str = toupper(*str);
}

char* get_prefix_character(const char* str, size_t len)
{
	char* prefixn = NULL;
	size_t slen = 0;
	if(str == NULL){
		return NULL;
	}

	slen = strlen(str);
	if((slen < len) || (len == 0)){
		return NULL;
	}

	prefixn = (char*)phy_malloc(prefixn, len + 1);
	memset(prefixn, 0, len + 1);
	phy_snprintf(prefixn, len + 1, "%s", str);
	return prefixn;
}

char* get_suffix_character(const char* str, size_t len)
{
	char* suffixn = NULL;
	size_t slen = 0;
	if(str == NULL){
		return NULL;
	}
	slen = strlen(str);

	if((slen < len) || (len == 0)){
		return NULL;
	}
	suffixn = (char*)phy_malloc(suffixn, len + 1);
	memset(suffixn, 0, len + 1);

	phy_snprintf(suffixn, len + 1, "%s", str + slen - len);

	return suffixn;
}

bool move_nbytes_ahead_of_string(char ** str, size_t n)
{
	char* pstr = NULL;
	size_t slen = 0;
	size_t mlen = 0;
	pstr = *str;
	int i = 0;
	if(pstr == NULL){
		return false;
	}
	slen = strlen(pstr);
	if(slen < n){
		return false;
	}
	mlen = slen - n;
	while( i < mlen ){
		(*str)[i] = pstr[n+i];
		i++;
	}
	while( i < slen ){
		(*str)[i] = '\0';
		i++;
	}
	return true;
}

char* is_hex_string(const char *str)
{
	char* hexstr = NULL;
	char* prefix = NULL;
	char* suffix = NULL;
	bool mf = false;
	if(str == NULL){
		return NULL;
	}
	if ('\0' == *str)
		return NULL;
	size_t slen = 0;
	slen = strlen(str);

//prefix: OX ox HEX hex...
//suffix: H h
	 suffix = get_suffix_character(str, 1);
	 phy_strlower(suffix);
	 if( suffix != NULL ){
		 if((0 != phy_strcmp_natural(suffix, "h")) && (0!= is_uhex(suffix))){
			 phy_free(suffix);
			 goto tom;
		 }else if(0 == phy_strcmp_natural(suffix, "h")){
			 hexstr = (char*)phy_malloc(hexstr, slen);
			 memset(hexstr, 0, slen);
//del 'h' or 'H'
			 phy_snprintf(hexstr, slen, "%s", str);
	 	 }
		 phy_free(suffix);
	 }
tom:
	 if(hexstr == NULL){
		 hexstr = (char*)phy_malloc(hexstr, slen + 1);
		 memset(hexstr, 0, slen + 1);
		 phy_snprintf(hexstr, slen + 1, "%s", str);
	 }

	 prefix = get_prefix_character(hexstr, 3);
	 if( prefix != NULL ){
		 phy_strlower(prefix);
		 phy_strlower(prefix);
		 if( prefix != NULL ){
			 if((0 != phy_strcmp_natural(prefix, "hex")) && (0!= is_uhex(prefix))){
//				 phy_free(hexstr);
				 phy_free(prefix);
				 goto tox;
			 }else if(0 == phy_strcmp_natural(prefix, "hex")){
				 mf = true;
				 move_nbytes_ahead_of_string(&hexstr, 3);
				 phy_free(prefix);
			 }
		 }
	 }

	 if(mf == false){
tox:
		 prefix = get_prefix_character(hexstr, 2);
		 if(prefix != NULL){
			 phy_strlower(prefix);
			 if( prefix != NULL ){
				 if((0 != phy_strcmp_natural(prefix, "0x")) && (0!= is_uhex(prefix))){
//					 phy_free(hexstr);
					 phy_free(prefix);
//					 return NULL;
					 goto tos;
				 }else if(0 == phy_strcmp_natural(prefix, "0x")){
					 move_nbytes_ahead_of_string(&hexstr, 2);
					 phy_free(prefix);
				 }
			 }
			 phy_free(prefix);
		 }
	}
tos:
	if(is_uhex(hexstr) == -1){
		phy_free(hexstr);
		return NULL;
	}
	return hexstr;
}


int	is_hex_n_range(const char *str, size_t n, void *value, size_t size, phy_uint64_t min, phy_uint64_t max)
{
	phy_uint64_t		value_uint64 = 0, c;
	const phy_uint64_t	max_uint64 = ~(phy_uint64_t)__UINT64_C(0);
	int			len = 0;

	if ('\0' == *str || 0 == n || sizeof(phy_uint64_t) < size || (0 == size && NULL != value))
		return FAIL;

	while ('\0' != *str && 0 < n--)
	{
		if ('0' <= *str && *str <= '9')
			c = *str - '0';
		else if ('a' <= *str && *str <= 'f')
			c = 10 + (*str - 'a');
		else if ('A' <= *str && *str <= 'F')
			c = 10 + (*str - 'A');
		else
			return FAIL;	/* not a hexadecimal digit */

		if (16 < ++len && (max_uint64 >> 4) < value_uint64)
			return FAIL;	/* maximum value exceeded */

		value_uint64 = (value_uint64 << 4) + c;

		str++;
	}
	if (min > value_uint64 || value_uint64 > max)
		return FAIL;

	if (NULL != value)
	{
		unsigned short	value_offset = (unsigned short)((sizeof(phy_uint64_t) - size) << 8);

		memcpy(value, (unsigned char *)&value_uint64 + *((unsigned char *)&value_offset), size);
	}

	return SUCCEED;
}

void nt_access(const char* path)
{
	if(access(path, F_OK)==0)
	{
		printf("文件存在\n");
	}
	else
		printf("文件不存在\n");
	if(access(path, R_OK)==0)
	{
		printf("文件可读\n");
	}
	else
		printf("文件不可读\n");
	if(access(path, W_OK)==0)
	{
		printf("文件可写\n");
	}
	else
		printf("文件不可写\n");
	FILE *fd = fopen(path,"w+");
	if(fd != NULL){
		printf("%s is created.\n",path);
		fclose(fd);
	}else{
		printf("Error creating the %s file.\n",path);
	}
}

int gets_random_number_between_two_numbers(int a, int b)
{
	int i = 0;          /*定义变量的数据类型为整型*/
	struct timeval	current_time;
	gettimeofday(&current_time, NULL);
	srand(current_time.tv_usec);
	i = rand()%(b-a+1)+a;
    return i;
}

int listen_local_port(int*  pport)
{
	  struct sockaddr_in bind_addr;
	  int fd_wait;
	  if((fd_wait = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
	    perror("socket ");
	    return 0;
	  }

	  bind_addr.sin_family = AF_INET;
	  bind_addr.sin_addr.s_addr = INADDR_ANY;
rerandom:
	  *pport = gets_random_number_between_two_numbers(25000, 65535);
	  bind_addr.sin_port = htons(*pport);

	  if(bind(fd_wait, (struct sockaddr*) &bind_addr, sizeof(struct sockaddr_in))) {
	    phy_log(LOG_LEVEL_ERR, "listen_local_port: bind error!");
	    goto rerandom;
	  }

	  if(listen(fd_wait, 1) == 1) {
		  perror("listen ");
	  	  return 0;
	  }
	  return fd_wait;
}

void move_one_to_right(char** dst, size_t dl, size_t pos)
{
	char *vp = NULL;
	char* p = NULL;
	p = *dst;

	if(pos == dl){
		return ;
	}

	vp = p + dl;

	for(int i = 0; i< dl - pos; i++){
		*(vp - i) = *(vp - i - 1);
	}
	*(p + pos) = ' ';
	*(p + dl + 1) = '\0';
}	

#if 1
//dst space Long enough
void str_insert_opos(char** dst, size_t dl, size_t pos, const char* ks)
{
	size_t kl = 0;
	kl = strlen(ks);
#if 1
	for(int i = 0; i<kl; i++)
	{
		move_one_to_right(dst, dl + i, pos + i);
	}
#endif
	for(int i=0; i<kl; i++){
		*(*dst + pos + i) = *(ks + i);
	}
}
#endif
//192168222222484=>192.168.222.222
char* uint64s2ip4(const char* str)
{
	char* rest = NULL;
	char stc[2] = {0};
	size_t len;
	len = strlen(str);
	size_t ofst1,ofst2,ofst3;
	if(str == NULL){
		return NULL;
	}else{
		rest = (char*)phy_malloc(rest, len + 3 + 1 );
		memset(rest, 0, len + 3 + 1);
		snprintf(rest, len + 3 + 1, "%s", str);
		rest[len] = ' ';
		rest[len + 1] = ' ';
		rest[len + 2] = ' ';
		rest[len + 3] = '\0';

		memset(stc, 0, 2);
		phy_snprintf(stc, 2, "%s", rest + len - 1);
		ofst3 = atoi(stc);
		memset(stc, 0, 2);
		phy_snprintf(stc, 2, "%s", rest + len - 2);
		ofst2 = atoi(stc);
		memset(stc, 0, 2);
		phy_snprintf(stc, 2, "%s", rest + len - 3);
		ofst1 = atoi(stc);

		str_insert_opos(&rest, len, ofst1, ".");
#if 1
		str_insert_opos(&rest, len, ofst2, ".");
		ofst3 = len - 4 - ofst3 + 2;
		str_insert_opos(&rest, len, ofst3 + 1, ".");
		*(rest + len) = '\0';
		*(rest + len + 1) = '0';
		*(rest + len + 2) = '0';
#endif
	}
	return rest;
}

//192.168.333.222=>192168333222373
char* ip42uint64s(const char* ipadd)
{
	int res = 0;
	size_t len = 0;
	char* pos1,*pos2,*pos3;
	int ofst1,ofst2,ofst3;
	char* p = NULL;
	char* rest = NULL;
	res = is_ip4(ipadd);
	if(res == 0){
		len = strlen(ipadd);
		rest = (char*)phy_malloc(rest, len + 1);
		memset(rest, 0, len + 1);
		p = (char*)ipadd;
		pos1 = strchr(p, '.');
		p = pos1 + 1;
		pos2 = strchr(p, '.');
		p = pos2 + 1;
		pos3 = strchr(p, '.');
		ofst1 = pos1 - ipadd;
		ofst2 = pos2 - ipadd;
		ofst3 = len - (pos3 - ipadd) - 1;
		phy_snprintf(rest, len + 1, "%s", ipadd);
		un_remove_str(rest, ".");
		phy_snprintf(rest + len - 3, 4, "%d%d%d", ofst1, ofst2, ofst3);
		return rest;
	}else{
		return NULL;
	}
}

char* buy_some_mem(char* data, const char* msg)
{
    char* rstr = NULL;
    struct mmana *mn = NULL;
    unsigned int len = 0;
    if(data == NULL && msg == NULL){
        int	retry;
        for (retry = 10; 0 < retry && NULL == rstr; rstr = malloc(INCREMENT + sizeof(struct mmana)), retry--)
            ;
        memset(rstr, 0, INCREMENT+ sizeof(struct mmana));
        mn = (struct mmana*)(MMANAPOS(rstr));
        mn->len = INCREMENT + sizeof(struct mmana);
        mn->remain = INCREMENT - strlen(rstr) - 1;
    }

    if(msg == NULL){
        return data;
    }

    if(data == NULL && msg != NULL){
        len = strlen(msg);
        len += INCREMENT + sizeof(struct mmana);
        int	retry;
        for (retry = 10; 0 < retry && NULL == rstr; rstr = malloc(len), retry--)
            ;
        memset(rstr, 0, len);
        strncpy(rstr, msg, strlen(msg));
        mn = (struct mmana*)(MMANAPOS(rstr));
        mn->len = len;
        mn->remain = len - strlen(rstr) - 1 - sizeof(struct mmana);
    }

    if(data != NULL && msg != NULL){
        GETMMANA(data, mn);
        if((int)((mn->remain - strlen(msg))) >= 0){
            len = mn->len;
            strncat(data, msg, strlen(msg));
            GETMMANA(data,mn);
            mn->len = len;
            mn->remain = len - strlen(data) - sizeof(struct mmana) - 1;
            return data;
        }else{
            len = strlen(msg) + mn->len + INCREMENT;
            int	retry;
            for (retry = 10; 0 < retry && NULL == rstr; rstr = malloc(len), retry--)
                ;
            memset(rstr, 0, len);
            strncpy(rstr, data, strlen(data));
            strncat(rstr, msg, strlen(msg));
            GETMMANA(rstr,mn);
            mn->len = len;
            mn->remain = len - strlen(rstr) - sizeof(struct mmana) -1;
            free(data);
        }
    }
    return rstr;
}

char* str_joint(const char* s1, ...)
{
	char* dst = NULL;
	struct strlist* head=NULL;
	create_strlist(&head);
	struct strlist*p=NULL;

	va_list ap;
	va_start(ap, s1);

	char* tmp = NULL;
	int i = 0;
	while ((tmp = va_arg(ap, char*)) != END)
	{
		strlist_add(&head, tmp);
		i++;
	}

	if(i == 0){
		destory_strlist(head);
		va_end(ap);
		return false;
	}

	dst = buy_some_mem(dst, s1);
	p = head->next;
	while(p){
		dst = buy_some_mem(dst, p->data);
		p = p->next;
	}
	destory_strlist(head);
	va_end(ap);
	return dst;
}
/////////////////////
void create_field_chain(struct field_chain** head)
{
	struct field_chain* fchead = malloc(sizeof(struct field_chain));
	memset(fchead, 0, sizeof(struct field_chain));
	snprintf(fchead->descr, PHRASE,  "%s", "This is filed's head");
	fchead->next = NULL;
	fchead->curr = fchead->next;
	fchead->fdnum = 0;
	fchead->field_t = NULL;
	*head = fchead;
}

void field_chain_add(struct field_chain** head, struct vriant_t* data, bool swch)
{
        struct field_chain** fcsp = NULL;
        struct field_chain* curfcp = NULL;

        curfcp = ((struct field_chain*)*head)->curr;
        curfcp = (struct field_chain*) malloc(sizeof(struct field_chain));
        memset(curfcp, 0, sizeof(struct field_chain));
        curfcp->swch = swch;
        curfcp->fdnum = ((struct field_chain*)*head)->fdnum;
        curfcp->field_t = (struct vriant_t *) malloc(sizeof(struct vriant_t));
        memset(curfcp->field_t, 0, sizeof(struct vriant_t));
        memcpy(curfcp->field_t, data, sizeof(struct vriant_t));
//        memcpy(curfcp->descr, data->descr, PHRASE);
        snprintf(curfcp->descr, PHRASE, "%s", data->descr);
        fcsp = head;
        while(*fcsp){
                fcsp = &(((struct field_chain*)(*fcsp))->next);
        }
        *fcsp = curfcp;
        ((struct field_chain*)*head)->curr = curfcp;
        ((struct field_chain*)*head)->fdnum++;
}

void iterator_field_chain(struct field_chain* head)
{
	struct field_chain* p = NULL;
    p = head->next;
    while(p){
    	//struct vriant_t* data;
 //   	printf("***********Filed number: %ld**************\n", p->fdnum);
    	printf("************** %s **************\n", p->descr);
 //   	if( ((struct vriant_t*)(p->field_t))->type == VARIANT_STRC){
    		iterator_datalist(p->field_t->data.stl);
 //   	}
        p = p->next;
    }
}

void destroy_field_chain(struct field_chain* head)
{
	struct field_chain* p=head;
	while(p){
		head=p->next;
		if(p->field_t == NULL){ //head
			phy_free(p);
			p = head;
			continue;
		}

		if( ((struct vriant_t*)(p->field_t))->type == VARIANT_ARRY){
			destory_strlist(p->field_t->data.sl);
		}

		if( ((struct vriant_t*)(p->field_t))->type == VARIANT_STRC){
			destory_datalist(p->field_t->data.stl);
		}

		phy_free(p->field_t);
		phy_free(p);
		p = head;
	}
}

void field_datalist_add(struct datalist** head, void* data, cnfsct dtype, const char* desc, const char* belong)
{
	struct datalist* p = *head;
    struct datalist* r = NULL;
	struct datalist* q = NULL;
	q = (struct datalist*)phy_malloc(q, sizeof(struct datalist));
	memset(q, 0, sizeof(struct datalist));
	q->data = (struct cnfinfo*)phy_malloc(q->data, sizeof(struct cnfinfo));
	phy_snprintf(((struct cnfinfo*)data)->belong, PHRASE, "%s", belong);
//	q->dtype = dtype;
	phy_snprintf(q->descr, PHRASE, "%s", desc);
	memcpy(q->data, data, sizeof(struct cnfinfo));
    q->next=NULL;

    while(p){
        r = p;
        p = p->next;
    }
    r->next = q;
    return;
}

void new_data_node(struct field_chain* fhd, const char* fldt, cnfsct dtp, const char* item)
{
	struct field_chain* pfhd = NULL;
	pfhd = fhd->next;
//find field
	while(pfhd){
		if( strcmp(pfhd->descr, fldt) == 0 ){
			struct cnfinfo *scf = NULL;
			scf = (struct cnfinfo *)phy_malloc(scf, sizeof(struct cnfinfo));
			memset(scf, 0, sizeof(struct cnfinfo));
			phy_snprintf(scf->item, LINELEN, "%s", item);
//add data insert scf(struct cnfinfo) into stl(struct datalist)
//			if(dtp == VARIANT_CNFINFO){
//				datalist_add(&(pfhd->field_t->data.stl), scf, dtp, item);
//			}
			field_datalist_add(&(pfhd->field_t->data.stl), scf, dtp, item, fldt);
			phy_free(scf);
		}
		pfhd = pfhd->next;
	}
}

void insert_unit_of_item(struct field_chain* fhd, const char* fldt, const char* item, const char* unit, void* data)
{
	struct field_chain* pfhd = NULL;
	struct datalist* dal = NULL;
	pfhd = fhd->next;
//find field
	while(pfhd){
		if( strcmp(pfhd->descr, fldt) == 0 ){
//add data
			dal = pfhd->field_t->data.stl;
			while(strcmp(dal->descr, item)){
				dal = dal->next;
			}
			if( strcmp(unit, "item") == 0 ){
				phy_snprintf(((struct cnfinfo*)dal->data)->item, LINELEN, "%s", (char*)data);
			}
			if( strcmp(unit, "Dir") == 0 ){
				phy_snprintf(((struct cnfinfo*)dal->data)->dir, LINELEN, "%s", (char*)data);
			}
			if( strcmp(unit, "Exe") == 0 ){
				phy_snprintf(((struct cnfinfo*)dal->data)->exe, LINELEN, "%s", (char*)data);
			}
			if( strcmp(unit, "Desc") == 0 ){
				phy_snprintf(((struct cnfinfo*)dal->data)->desc, LINELEN, "%s", (char*)data);
			}
			if( strcmp(unit, "Args") == 0 ){
				phy_snprintf(((struct cnfinfo*)dal->data)->args, LINELEN, "%s", (char*)data);
			}
			if( strcmp(unit, "Dist") == 0 ){
				phy_snprintf(((struct cnfinfo*)dal->data)->dist, LINELEN, "%s", (char*)data);
			}
			if( strcmp(unit, "Sudo") == 0 ){
				phy_snprintf(((struct cnfinfo*)dal->data)->sudo, LINELEN, "%s", (char*)data);
//				phy_snprintf(((struct cnfinfo*)dal->data)->sudo, LINELEN, "%s", NULL);
			}
			if( strcmp(unit, "Scanpath") == 0 ){
				phy_snprintf(((struct cnfinfo*)dal->data)->scanpath, LINELEN, "%s", (char*)data);
			}
			if( strcmp(unit, "Numthreads") == 0 ){
//				phy_snprintf(((struct cnfinfo*)dal->data)->pthds, LINELEN, "%s", (char*)data);
//				phy_snprintf(((struct cnfinfo*)dal->data)->pthds, LINELEN, "%s", (char*)data);
				PHY_STR2UINT64(((struct cnfinfo*)dal->data)->pthds, ((char*)data));
			}
			if( strcmp(unit, "Duration") == 0 ){
				//phy_snprintf(((struct cnfinfo*)dal->data)->scanpath, LINELEN, "%s", (char*)data);
				PHY_STR2UINT64(((struct cnfinfo*)dal->data)->duration, (char*)data);
			}
			if( strcmp(unit, "Switch") == 0 ){
				if(strcmp((char*)data, "yes") == 0){
					((struct cnfinfo*)dal->data)->swch = true;
				}else{
					((struct cnfinfo*)dal->data)->swch = false;
				}
			}
			break;
		}
		pfhd = pfhd->next;
	}
}

//new field node
void field_node_grow(struct field_chain* fhd, const char* fldt, bool swchsta)
{
	struct vriant_t* data = NULL;
	data = (struct vriant_t*)phy_malloc(data, sizeof(struct vriant_t));
	memset(data, 0, sizeof(struct vriant_t));
	struct datalist *dhead = NULL;
	create_datalist(&dhead);
	phy_snprintf(dhead->descr,  PHRASE, "%s", "This is head!");
	data->data.stl = dhead;
	data->type = VARIANT_STRC;
	snprintf(data->descr, PHRASE, "%s", fldt);
	field_chain_add(&fhd, data, swchsta);
	phy_free(data);
}

void field_node_delete(struct field_chain* fhd, const char* domain)
{
	struct field_chain* p = NULL;
	struct field_chain* pp = NULL;
	pp = fhd;
	p = fhd->next;
	while(p){
		if(phy_strcmp_natural(p->descr, domain) == 0){
			printf("delete  %s \n", p->descr);
			fhd->fdnum--;
			pp->next = p->next;
			destory_datalist(p->field_t->data.stl);
			phy_free(p->field_t);
			phy_free(p);
			break;
		}
		pp = p;
		p = p->next;
	}
}

char* nt_fl2string(const char* flpt)
{
	char *dst = NULL;
	FILE *file = NULL;
	int		lineno = 0;
	char	line[MAX_STRING_LEN + 3];

	if (NULL != flpt)
	{
		if (NULL == (file = fopen(flpt, "r")))
			return NULL;
	}

//	for (lineno = 1; NULL != fgets(line, sizeof(line), file); lineno++)
//	{
//		dst = buy_some_mem(dst, line);
//	}

	while(fgets(line, sizeof(line), file)){
		dst = buy_some_mem(dst, line);
		memset(line, 0, MAX_STRING_LEN + 3);
		lineno++;
	}

	fclose(file);
	return dst;
}


char* add_left_space(char* res)
{
	char* ret = NULL;
	ret = (char*)malloc(2 + strlen(res));
	phy_snprintf(ret, 2 + strlen(res), " %s", res);
	phy_free(res);
	return ret;
}

char* labeling_repeat_substring(const char* res, const char* sbstr)
{
	int ilb = 1;
	char* labelstr = NULL;
	char flgstr[ISL] = {0};
	char* crtpos = NULL;
	char* crtstr = NULL;

	size_t crpos = 0;
	size_t cursor = 0;
	size_t crlen = 0;
	size_t sblen = 0;
	size_t fllen = 0;

	if(!ISNULL(res) &&  !ISNULL(sbstr)){
		return NULL;
	}

	sblen = strlen(sbstr);
	crtstr = (char*)res;
	for(;;){
		crtpos = strstr(crtstr + cursor, sbstr);
		if(crtpos == NULL){
			break;
		}
		memset(flgstr, 0, ISL);
		phy_snprintf(flgstr, ISL, " %d", ilb);
		fllen = strlen(flgstr);
		crlen = strlen(crtstr) + strlen(flgstr) + 1;
		labelstr = phy_malloc(labelstr, crlen);
		memset(labelstr, 0, crlen);
//		strncpy(labelstr, crtstr, strlen(crtstr));
		phy_snprintf(labelstr, crlen, "%s", crtstr);
		crpos = (crtpos - crtstr) + sblen;
		str_insert_opos(&labelstr, strlen(crtstr), crpos, flgstr);
		if(crtstr != res){
			phy_free(crtstr);
		}
		crtstr = strndup(labelstr, crlen);
		phy_free(labelstr);
		cursor = crpos + fllen;
		ilb++;
	}
	return crtstr;
}

ssize_t readline(int fd, char *vptr, size_t maxlen)
{
	ssize_t	n, rc;
	char	c, *ptr;

	ptr = vptr;
	for (n = 1; n < maxlen; n++) {
		if ( (rc = read(fd, &c,1)) == 1) {
			*ptr++ = c;
			if (c == '\n')
				break;	/* newline is stored, like fgets() */
		} else if (rc == 0) {
			*ptr = 0;
			return(n - 1);	/* EOF, n - 1 bytes were read */
		} else
			return(-1);		/* error, errno set by read() */
	}
	*ptr = 0;	/* null terminate like fgets() */
	return(n);
}

int ping_status(char *ip)
{
    int i, status;
    pid_t pid;
    phy_log(LOG_LEVEL_TRACE, "ping_status: ip %s.", ip);
    // 不同则循环检测多次
    for (i = 0; i < 1; ++i)
    {
        // 新建一个进程来执行ping命令
        if ((pid = vfork()) < 0)
        {
            printf("vfork error");
            phy_log(LOG_LEVEL_ERR, "ping_status: vfork error.");
            continue;
        }

        if (pid == 0)
        {
            // 执行ping命令
            //if (execlp("ping", "ping", "-c 1", ip, (char*)0) < 0)
            //if ( execlp("ping", "ping","-c 1",svrip, (char*)0) < 0)
            if ( execlp("ping", "ping","-c","1",ip, (char*)0) < 0)
            {
                phy_log(LOG_LEVEL_ERR, "ping_status: execlp error.");
                exit(1);
            }
        }
        waitpid(pid, &status, 0);

        // 相等说明正常
        if (status == 0)
            return 0;
    }
    phy_log(LOG_LEVEL_WARNING, "ping_status: %s cannot access.", ip);
    return -1;
}
// "abc 444" true
bool is_alphanum(const char* res)
{
	char *p = NULL;
	const char *sp = NULL;
	size_t len = 0;
	size_t i = 0;
	if(false == ISNULL(res)){
		return false;
	}
	p = strchr(res, ' ');
	if(p == NULL){
		return false;
	}

	len = strlen(res);
	sp = res;

	for(i = 0; i < (p - res - 1); i++){
		if(!((sp[i] >= 'a' && sp[i] <= 'z') || (sp[i] >= 'A' && sp[i] <= 'Z'))){
			return false;
		}
	}

	for(i = (p - res + 1); i < (len - 1); i++){
		if(!(sp[i] >= '0' && sp[i] <= '9')){
			return false;
		}
	}
	return true;
}

//mt true 123456 fals 1 2 3 4 5 6
char* get_numbers(const char* res, bool mt)
{
	char* rts = NULL;
	char* p = NULL;

	size_t len = 0;
	size_t rlen = 1;
	bool spbf = false;
	int i = 0;
	if(false == ISNULL(res)){
		return NULL;
	}

	len = strlen(res);
	for( i = 0; i < (len); i++){
		if((res[i] >= '0' && res[i] <= '9')){
			if( (i+1) <= (len -1)){
//			if( (i+1) != (len -1)){
				if( !(res[i+1] >= '0' && res[i+1] <= '9') ){
					rlen = rlen + 2;
					p = (char*)malloc(rlen);
					memset(p, 0, rlen);
					spbf = true;
				}

				if( (res[i+1] >= '0' && res[i+1] <= '9') ){
					rlen = rlen + 1;
					p = (char*)malloc(rlen);
					memset(p, 0, rlen);
				}

				if(p == NULL){
					phy_free(rts);
					printf("get_numbers: malloc error! \n");
					return NULL;
				}
			}

			if( (i+1) == len ){
				if( !(res[i] >= '0' && res[i] <= '9') ){
					return rts;
				}

				if( (res[i] >= '0' && res[i] <= '9') ){
					rlen = rlen + 1;
					p = (char*)malloc(rlen);
					memset(p, 0, rlen);
				}
			}
//first
			if( rts == NULL ){
				rts = p;
				if(spbf == true){
					snprintf(rts, rlen, "%c ", res[i]);
					spbf = false;
				}else{
					snprintf(rts, rlen, "%c", res[i]);
				}
				continue;
			}

			if(spbf == true){
				snprintf(p, rlen, "%s%c ", rts, res[i]);
				spbf = false;
			}else{
				snprintf(p, rlen, "%s%c", rts, res[i]);
			}
			phy_free(rts);
			rts = p;
		}
	}
	return rts;
}

bool is_number(const char* res)
{
	size_t len = 0;
	int i = 0;
	if(false == ISNULL(res)){
		return false;
	}
	len = strlen(res);

	for( i = 0; i < (len - 1); i++){
		if(!(res[i] >= '0' && res[i] <= '9')){
			return false;
		}
	}
	return true;
}

bool is_placeholder(const char* res)
{
	size_t len = 0;
	int i = 0;
	if(false == ISNULL(res)){
		return false;
	}

	len = strlen(res);

	for( i = 0; i < (len - 1); i++ ){
		if( (res[i] != ' ') && (res[i] != '\0') ){
			return false;
		}
	}
	return true;
}

char** obtain_value_correspond_item(const char* res, const char* key1, const char* key2, ...)
{
//	char*** rta = NULL;

//	return *rta;
	return NULL;
}

int find_free_port()
{
	int sock = 0;
	int port = 0;
	struct sockaddr_in addr;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock == -1){
		perror("socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;

	addr.sin_port = 0;
	if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1)
	{
		perror("bind");
		close(sock);
		return -1;
	}

	socklen_t addr_len = sizeof(addr);
	if(getsockname(sock, (struct sockaddr*)&addr, &addr_len) == -1)
	{
		perror("getsockname");
		close(sock);
		return -1;
	}
	port = ntohs(addr.sin_port);
	close(sock);

	if(port == -1){
		printf("No idle port numbers found./n");
	}

	return port;
}

bool matches_strings(const char* line, bool flg, ...)
{
	struct strlist* head=NULL;
	create_strlist(&head);
	struct strlist*p=NULL;
//	bool reb = false;
	va_list ap;
	va_start(ap, flg);

	char* tmp = NULL;
	int i = 0;
	while ((tmp = va_arg(ap, char*)) != END)
	{
		strlist_add(&head, tmp);
		i++;
	}

	if(i == 0){
		destory_strlist(head);
		va_end(ap);
		return false;
	}

	p = head->next;
	while(p){
		if(strstr(line, p->data)){
			if(flg == false){
				destory_strlist(head);
				return true;
			}
		}else{
			if(flg == true){
				return false;
			}
		}
		p = p->next;
	}

	destory_strlist(head);
	va_end(ap);
	if(flg == false){
		return false;
	}else{
		return true;
	}
}

bool left_search_substring(const char* res, const char* sbs, size_t hmp)
{
	char* ofs = 0;
	size_t lfv = 0;
	if(ISNULL(res) == false || ISNULL(sbs) == false){
		return false;
	}

	ofs = strstr(res, sbs);
	if(ofs == NULL){
		return false;
	}
	lfv = ofs - res;

	if( (lfv + strlen(sbs)) > hmp ){
		return false;
	}
	return true;
}

void remove_ansi_sequences(char *str) {
    char *p1 = str;
    char *p2 = str;
    while (*p1) {
        if (*p1 == '\x1b') {
            // 跳过开始的ESC字符
            ++p1;
            // 如果后面跟随'[', 进入ANSI序列
            if (*p1 == '[') {
                // 跳过直到序列结束（字母字符结束）
                while (*p1 && !isalpha((unsigned char)*p1)) {
                    ++p1;
                }
                // 跳过结束的字母字符
                if (*p1) {
                    ++p1;
                }
                continue;
            }
        }
        // 不是ANSI序列，复制字符
        *p2++ = *p1++;
    }
    *p2 = '\0';
}


// 去除ANSI转义序列的函数
void remove_ansi_escape_sequences(const char *input, char *output)
{
    if (!input || !output) return;

    while (*input) {
        if (*input == '\x1b') {
            // 跳过转义字符开始的字符
            ++input;
            // 如果跟随的是'('或'[', 跳过直到我们达到字母字符（ANSI序列的结束）
            if (*input == '(' || *input == '[') {
                ++input;
                // 跳过所有可能的数字和分号
                while (*input && !isalpha((unsigned char)*input)) {
                    ++input;
                }
                // 跳过结束的字母字符
                if (*input) {
                    ++input;
                }
                continue;
            }
        }
        // 如果不是转义序列，就复制字符
        *output++ = *input++;
    }

    // 字符串末尾添加null终止符
    *output = '\0';
}

void remove_special_chars(char *str)
{
    char *src = str, *dst = str;
    while (*src) {
        if (*src == '\x1b') { // 对应 ESC
            src++; // 跳过 ESC
            // 如果下一个字符是 [ 或者 (，跳过直到遇到字母或者其他特定的字符
            if (*src == '[' || *src == '(') {
                src++; // 跳过 [ 或者 (
                // 跳过直到一个字母或者特定的结束符
                while (*src && !isalpha((unsigned char)*src) && *src != 'm' && *src != 'K') {
                    src++;
                }
                if (*src) {
                    src++; // 跳过最后的字母或者结束符
                }
            }
        } else if (*src == '\r' || *src == '^') { // 对应 ^M 和 ^ 任何字符
            src++; // 跳过 \r 或者 ^
            if (*src == 'M') { // 如果是 ^M 组合
                src++; // 再跳过 M
            }
        } else if (isprint((unsigned char)*src) || *src == '\n' || *src == '\t' || *src == ' ') {
            // 正常字符复制
            *dst++ = *src++;
        } else {
            // 跳过其他非打印字符
            src++;
        }
    }
    *dst = '\0'; // 空终止目标字符串
}

#if 0
void ntlst_create(ntlst** ntl)
{
	*ntl = (ntlst*)phy_malloc(*ntl, sizeof(ntlst));
	((ntlst*)(*ntl))->dsc  = NULL;
	((ntlst*)(*ntl))->next = NULL;
	((ntlst*)(*ntl))->rigt = NULL;
	((ntlst*)(*ntl))->ln   = 0;
	((ntlst*)(*ntl))->data   = NULL;
}


//ssnlp = snlp->rigt;
//			while(ssnlp){
//				if(strncmp(ssnlp->dsc, dsc, strlen(ssnlp->dsc)) == 0 && strncmp(dsc, ssnlp->dsc, strlen(dsc)) == 0){
//					return rntp;
//				}
//				ssnlp = ssnlp->next;
//			}

//ntvdp ntlst_search(ntlst* ntl, const char* dsc)
ntlst* ntlst_search(ntlst* ntl, const char* dsc)
{
//	ntvdp rntp = NULL;
	ntlst* rntp = NULL;
	ntlst* nlp = NULL;
	ntlst* snlp = NULL;
	nlp = ntl;

	while(nlp){
		if(strncmp(nlp->dsc, dsc, strlen(nlp->dsc)) == 0 && strncmp(dsc, nlp->dsc, strlen(dsc)) == 0){
			return nlp;
		}
		snlp = nlp->rigt;
		while(snlp){
			if(strncmp(snlp->dsc, dsc, strlen(snlp->dsc)) == 0 && strncmp(dsc, snlp->dsc, strlen(dsc)) == 0){
				return snlp;
			}
			rntp = ntlst_search(snlp, dsc);
			if(rntp != NULL){
				return rntp;
			}else{
				snlp = snlp->next;
				continue;
			}
			snlp = snlp->next;
		}
		nlp = nlp->next;
	}
	return NULL;
}

ntlst* ntlst_search_yaxis(ntlst* ntl, const char* dsc)
{
//	ntvdp rntp = NULL;
//	ntlst* rntp = NULL;
	ntlst* nlp = NULL;
//	ntlst* snlp = NULL;
	nlp = ntl;

	while(nlp){
		if(strncmp(nlp->dsc, dsc, strlen(nlp->dsc)) == 0 && strncmp(dsc, nlp->dsc, strlen(dsc)) == 0){
			return nlp;
		}
		nlp = nlp->next;
	}
	return NULL;
}

ntlst* ntlst_search_xaxis(ntlst* ntl, const char* ydsc, const char* xdsc)
{
//	ntvdp rntp = NULL;
	ntlst* rntp = NULL;
	ntlst* nlp = NULL;
	ntlst* snlp = NULL;
	nlp = ntl;

	while(nlp){
		if(strncmp(nlp->dsc, ydsc, strlen(nlp->dsc)) == 0 && strncmp(ydsc, nlp->dsc, strlen(ydsc)) == 0){
			rntp = nlp;
		}
		nlp = nlp->next;
	}
	if(rntp != NULL){
		snlp = rntp->rigt;
		rntp = NULL;
		while(snlp){
			if(strncmp(snlp->dsc, xdsc, strlen(snlp->dsc)) == 0 && strncmp(xdsc, snlp->dsc, strlen(xdsc)) == 0){
				rntp = snlp;
			}
			snlp = snlp->next;
		}
	}
	return rntp;
}

ntlst* ntlst_search_zaxis(ntlst* ntl, const char* ydsc, const char* xdsc, const char* zdsc)
{
//	ntvdp rntp = NULL;
	ntlst* rntp = NULL;
	ntlst* nlp = NULL;
	ntlst* snlp = NULL;
	ntlst* ssnlp = NULL;
	nlp = ntl;

	while(nlp){
		if(strncmp(nlp->dsc, ydsc, strlen(nlp->dsc)) == 0 && strncmp(ydsc, nlp->dsc, strlen(ydsc)) == 0){
			rntp = nlp;
		}
		nlp = nlp->next;
	}

	if(rntp != NULL){
		snlp = rntp->rigt;
		rntp = NULL;
		while(snlp){
			if(strncmp(snlp->dsc, xdsc, strlen(snlp->dsc)) == 0 && strncmp(xdsc, snlp->dsc, strlen(xdsc)) == 0){
				rntp = snlp;
			}
			snlp = snlp->next;
		}
	}

	if(rntp != NULL){
		ssnlp = rntp->rigt;
		rntp = NULL;
		while(ssnlp){
			if(strncmp(ssnlp->dsc, zdsc, strlen(ssnlp->dsc)) == 0 && strncmp(zdsc, ssnlp->dsc, strlen(zdsc)) == 0){
				rntp = ssnlp;
			}
			ssnlp = ssnlp->next;
		}
	}
	return rntp;
}

void ntlst_insert(ntlst** ntl, const char* dsc, unsigned char flg)
{
	ntlst* ntp = NULL;
	ntp = ntlst_search(*ntl, dsc);
	if(ntp == NULL){
		ntp = (ntlst*)phy_malloc(ntp, sizeof(ntlst));
		memset(ntp, 0, sizeof(ntlst));
	}else{

	}
	ntp = (ntlst*)phy_malloc(ntp, sizeof(ntlst));
	memset(ntp, 0, sizeof(ntlst));
}

void ntlst_insert_yaxis(ntlst** ntl, ntlst* nd)
{
	ntlst* ntp = NULL;
	ntp = (ntlst*)phy_malloc(ntp, sizeof(ntlst));
	memset(ntp, 0, sizeof(ntlst));
}

void ntlst_insert_xaxis(ntlst** ntl, ntlst* nd)
{
	ntlst* ntp = NULL;
	ntp = (ntlst*)phy_malloc(ntp, sizeof(ntlst));
	memset(ntp, 0, sizeof(ntlst));
}
#endif

char* mystrstr(const char* str, size_t len, const char* spt)
{
	size_t spt_len = strlen(spt);
	if(spt_len == 0) return (char*)str;
	char* result = NULL;
	FOR(i, 0, len - spt_len + 1, 1, {
			if(strncmp(str + i, spt, spt_len) == 0 ){
				result = (char*)(str + i);
				break;
			}
	})
	return result;
}

int str_reverse_search(const char * oristr, size_t len, const char * sstr)
{
//	const char	*__function_name = "str_reverse_search";
	size_t pos = 0;
	size_t rpos = 0;
	size_t sslen =0;
	char*  p = NULL;
	sslen = strlen(oristr);
	sslen = strlen(sstr);


	p = MYSTRSTR(oristr, len, sstr);
	if (p == NULL){
//		printf("[func: %s ]:%s ", __function_name, ARG_INPUT_ERR);
		return -1;
	}

	if( oristr == NULL || len < MINIMIZESSTRLEN || sslen >= len ){
//		printf("[func: %s ]:%s ", __function_name, ARG_INPUT_ERR);
		return -2;
	}

	do{
		rpos = pos;
//		p = (char*)strstr(oristr + pos, sstr);
		p = MYSTRSTR(oristr + pos, len - pos, sstr);
		if( p == NULL ){
			if(rpos != 0){
				if(rpos == (len -1)){
					break;
				}
				rpos -= sslen;
			}
			break;
		}
		pos = p - oristr + sslen;
		if(pos == len){
			rpos =	len - sslen;
			break;
		}
		if(MINIMIZESSTRLEN == sslen && pos == len){
			rpos = pos;
		}
	}while(pos < len);
	return rpos;
}

void row_extractor(const char* str, size_t olen, lnbhd** lbhd)
{
	lnbhd* ld  = NULL;
	size_t pos = 0;
	size_t spos = 0;
	size_t epos = 0;
	int lnpos = 0;
	size_t len = 0;
	size_t sbl = 0;
	char* tmbf = NULL;
	len = olen;
	char* sstr = (char*)str;
	lnbuf* slbf = NULL;
	ld = *lbhd;

	lnpos = str_reverse_search(sstr, olen, "\n");
	if(lnpos == -2){
		return;
	}

	if(ld == NULL){
		ld = phy_malloc(ld, sizeof(lnbhd));
		memset(ld, 0, sizeof(lnbhd));
		*lbhd = ld;
	}

	if(sstr[0] == '\n'){
		sstr = sstr + 1;
		len = len - 1;
		lnpos = lnpos - 1;
		if(ld->curr != NULL){
			if(ld->curr->stflg == true){
				ld->curr->stflg = false;
			}
		}
	}

	if(lnpos == -1){
		tmbf = NULL;
		tmbf = phy_malloc(tmbf, len + 1);
		memset(tmbf, 0, len + 1);
//		phy_snprintf(tmbf, sbl + 1, "%s", sstr + spos);
		memcpy(tmbf, sstr, len);
		slbf = NULL;
		slbf = phy_malloc(slbf, sizeof(lnbuf));
		memset(slbf, 0, sizeof(lnbuf));
		slbf->len = len + 1;
		slbf->data = (void*)tmbf;
		slbf->stflg = true;
		slbf->next = NULL;

		if(ld->lnbl == NULL){
			ld->lnbl = slbf;
			ld->curr = slbf;
		}else{
			if(ld->curr->stflg == true){
//处理字符串时
				sbl = ld->curr->len + slbf->len - 1;
				tmbf = NULL;
				tmbf = phy_malloc(tmbf, sbl);
				memset(tmbf, 0, sbl);
//				phy_snprintf(tmbf, sbl, "%s%s", (char*)(ld->curr->data), (char*)(slbf->data));
				memcpy(tmbf, ld->curr->data, ld->curr->len);
				memcpy(tmbf + ld->curr->len - 1, slbf->data, slbf->len);
				phy_free(ld->curr->data);
				phy_free(slbf->data);
				phy_free(slbf);
				ld->curr->data = (void*)tmbf;
				ld->curr->stflg = true;
				ld->curr->len = sbl;
			}else{
				ld->curr->next = slbf;
				ld->curr = slbf;
			}
		}
		return;
	}

	while(pos <= len){
		if(sstr[pos] == '\n'){
			epos = pos;
			sbl = epos - spos;
//当碰到"\n\n"时
			if(sbl == 0){
				pos++;
				spos = pos;
				continue;
			}
			tmbf = NULL;
			tmbf = phy_malloc(tmbf, sbl + 1);
			memset(tmbf, 0, sbl + 1);
//			phy_snprintf(tmbf, sbl + 1, "%s", sstr + spos);
			memcpy(tmbf, sstr+spos, sbl);
			spos = pos + 1;
			slbf = NULL;
			slbf = phy_malloc(slbf, sizeof(lnbuf));
			memset(slbf, 0, sizeof(lnbuf));
			slbf->len = sbl + 1;
			slbf->data = (void*)tmbf;
			slbf->next = NULL;
			if(ld->lnbl == NULL){
				ld->lnbl = slbf;
				ld->curr = slbf;
			}else{
				if(ld->curr->stflg == true){
//处理字符串时
					sbl = ld->curr->len + slbf->len - 1;
					tmbf = NULL;
					tmbf = phy_malloc(tmbf, sbl);
					memset(tmbf, 0, sbl);
//					phy_snprintf(tmbf, sbl, "%s%s", (char*)(ld->curr->data), (char*)(slbf->data));
					memcpy(tmbf, ld->curr->data, ld->curr->len);
					memcpy(tmbf + ld->curr->len - 1, slbf->data, slbf->len);
					phy_free(ld->curr->data);
					phy_free(slbf->data);
					phy_free(slbf);
					ld->curr->data = (void*)tmbf;
					ld->curr->stflg = false;
					ld->curr->len = sbl;
				}else{
					ld->curr->next = slbf;
					ld->curr = slbf;
				}
			}
		}
		pos++;
	}

	if(lnpos == 0){
		tmbf = NULL;
		sbl = len - lnpos;
		tmbf = phy_malloc(tmbf, sbl + 1);
		memset(tmbf, 0, sbl + 1);
//		phy_snprintf(tmbf, sbl, "%s", sstr +  lnpos + 1);
		memcpy(tmbf, sstr + lnpos, sbl);
		slbf = NULL;
		slbf = phy_malloc(slbf, sizeof(lnbuf));
		memset(slbf, 0, sizeof(lnbuf));
		slbf->data = (void*)tmbf;
		slbf->len = sbl + 1;
		slbf->next = NULL;
		if(ld->lnbl == NULL){
			ld->lnbl = slbf;
			ld->curr = slbf;
		}else{
			ld->curr->next = slbf;
			ld->curr = slbf;
		}
		ld->curr->stflg = true;
	}else if(lnpos < len){
//"xxxxxxxxxxxxx\nxxxx\n"最后一个为"\n"
//		if(lnpos == (len - 1)){
//			return;
//		}
		if((sstr[lnpos] != '\n') && (lnpos == (len - 1))){
			tmbf = NULL;
			sbl = len - lnpos;
			tmbf = phy_malloc(tmbf, sbl + 1);
			memset(tmbf, 0, sbl + 1);
	//		phy_snprintf(tmbf, sbl, "%s", sstr +  lnpos + 1);
			memcpy(tmbf, sstr + lnpos, sbl);
			slbf = NULL;
			slbf = phy_malloc(slbf, sizeof(lnbuf));
			memset(slbf, 0, sizeof(lnbuf));
			slbf->data = (void*)tmbf;
			slbf->len = sbl + 1;
			slbf->next = NULL;
			if(ld->lnbl == NULL){
				ld->lnbl = slbf;
				ld->curr = slbf;
			}else{
				ld->curr->next = slbf;
				ld->curr = slbf;
			}
			ld->curr->stflg = true;
			return;
		}
		if(lnpos == (len - 1)){
			return;
		}else{
			tmbf = NULL;
			sbl = len - lnpos - 1;
			tmbf = phy_malloc(tmbf, sbl + 1);
			memset(tmbf, 0, sbl + 1);
	//		phy_snprintf(tmbf, sbl, "%s", sstr +  lnpos + 1);
			memcpy(tmbf, sstr + lnpos + 1, sbl);
			slbf = NULL;
			slbf = phy_malloc(slbf, sizeof(lnbuf));
			memset(slbf, 0, sizeof(lnbuf));
			slbf->data = (void*)tmbf;
			slbf->len = sbl + 1;
			slbf->next = NULL;
			if(ld->lnbl == NULL){
				ld->lnbl = slbf;
				ld->curr = slbf;
			}else{
				ld->curr->next = slbf;
				ld->curr = slbf;
			}
			ld->curr->stflg = true;
			return;
		}
	}
}

void rows_extractor(const char* str, size_t olen, lnbhd** lbhd)
{
	lnbhd* ld  = NULL;
	size_t pos = 0;
	size_t spos = 0;
	size_t epos = 0;
	int lnpos = 0;
	size_t len = 0;
	size_t sbl = 0;
	char* tmbf = NULL;
	len = olen;
	char* sstr = (char*)str;
	lnbuf* slbf = NULL;
	ld = *lbhd;

	lnpos = str_reverse_search(sstr, olen, "\n");
	if(lnpos == -2){
		return;
	}

	if(ld == NULL){
		ld = phy_malloc(ld, sizeof(lnbhd));
		memset(ld, 0, sizeof(lnbhd));
		*lbhd = ld;
	}

	if(sstr[0] == '\n'){
		sstr = sstr + 1;
		len = len - 1;
		lnpos = lnpos - 1;
		if(ld->curr != NULL){
			if(ld->curr->stflg == true){
				ld->curr->stflg = false;
			}
		}
	}

	if(lnpos == -1){
		tmbf = NULL;
		tmbf = phy_malloc(tmbf, len + 1);
		memset(tmbf, 0, len + 1);
		memcpy(tmbf, sstr, len);
		slbf = NULL;
		slbf = phy_malloc(slbf, sizeof(lnbuf));
		memset(slbf, 0, sizeof(lnbuf));
		slbf->len = len + 1;
		slbf->data = (void*)tmbf;
		slbf->stflg = true;
		slbf->next = NULL;

		if(ld->lnbl == NULL){
			ld->lnbl = slbf;
			ld->curr = slbf;
		}else{
			if(ld->curr->stflg == true){
//处理字符串时
				sbl = ld->curr->len + slbf->len - 1;
				tmbf = NULL;
				tmbf = phy_malloc(tmbf, sbl);
				memset(tmbf, 0, sbl);
				memcpy(tmbf, ld->curr->data, ld->curr->len);
				memcpy(tmbf + ld->curr->len - 1, slbf->data, slbf->len);
				phy_free(ld->curr->data);
				phy_free(slbf->data);
				phy_free(slbf);
				ld->curr->data = (void*)tmbf;
				ld->curr->stflg = true;
				ld->curr->len = sbl;
			}else{
				ld->curr->next = slbf;
				ld->curr = slbf;
			}
		}
		return;
	}

	while(pos <= len){
		if(sstr[pos] == '\n'){
			epos = pos;
			sbl = epos - spos;
//当碰到"\n\n"时
			if(sbl == 0){
				pos++;
				spos = pos;
				continue;
			}
			tmbf = NULL;
			tmbf = phy_malloc(tmbf, sbl + 1);
			memset(tmbf, 0, sbl + 1);
			memcpy(tmbf, sstr+spos, sbl);
			spos = pos + 1;
			slbf = NULL;
			slbf = phy_malloc(slbf, sizeof(lnbuf));
			memset(slbf, 0, sizeof(lnbuf));
			slbf->len = sbl + 1;
			slbf->data = (void*)tmbf;
			slbf->next = NULL;
			if(ld->lnbl == NULL){
				ld->lnbl = slbf;
				ld->curr = slbf;
			}else{
				if(ld->curr->stflg == true){
//处理字符串时
					sbl = ld->curr->len + slbf->len - 1;
					tmbf = NULL;
					tmbf = phy_malloc(tmbf, sbl);
					memset(tmbf, 0, sbl);
					memcpy(tmbf, ld->curr->data, ld->curr->len);
					memcpy(tmbf + ld->curr->len - 1, slbf->data, slbf->len);
					phy_free(ld->curr->data);
					phy_free(slbf->data);
					phy_free(slbf);
					ld->curr->data = (void*)tmbf;
					ld->curr->stflg = false;
					ld->curr->len = sbl;
				}else{
					ld->curr->next = slbf;
					ld->curr = slbf;
				}
			}
		}
		pos++;
	}

	if(lnpos == 0){
		tmbf = NULL;
		sbl = len - lnpos;
		tmbf = phy_malloc(tmbf, sbl + 1);
		memset(tmbf, 0, sbl + 1);
		memcpy(tmbf, sstr + lnpos, sbl);
		slbf = NULL;
		slbf = phy_malloc(slbf, sizeof(lnbuf));
		memset(slbf, 0, sizeof(lnbuf));
		slbf->data = (void*)tmbf;
		slbf->len = sbl + 1;
		slbf->next = NULL;
		if(ld->lnbl == NULL){
			ld->lnbl = slbf;
			ld->curr = slbf;
		}else{
			ld->curr->next = slbf;
			ld->curr = slbf;
		}
		ld->curr->stflg = true;
	}else if(lnpos < len){
		if((sstr[lnpos] != '\n') && (lnpos == (len - 1))){
			tmbf = NULL;
			sbl = len - lnpos;
			tmbf = phy_malloc(tmbf, sbl + 1);
			memset(tmbf, 0, sbl + 1);
			memcpy(tmbf, sstr + lnpos, sbl);
			slbf = NULL;
			slbf = phy_malloc(slbf, sizeof(lnbuf));
			memset(slbf, 0, sizeof(lnbuf));
			slbf->data = (void*)tmbf;
			slbf->len = sbl + 1;
			slbf->next = NULL;
			if(ld->lnbl == NULL){
				ld->lnbl = slbf;
				ld->curr = slbf;
			}else{
				ld->curr->next = slbf;
				ld->curr = slbf;
			}
			ld->curr->stflg = true;
			return;
		}
		if(lnpos == (len - 1)){
			return;
		}else{
			tmbf = NULL;
			sbl = len - lnpos - 1;
			tmbf = phy_malloc(tmbf, sbl + 1);
			memset(tmbf, 0, sbl + 1);
			memcpy(tmbf, sstr + lnpos + 1, sbl);
			slbf = NULL;
			slbf = phy_malloc(slbf, sizeof(lnbuf));
			memset(slbf, 0, sizeof(lnbuf));
			slbf->data = (void*)tmbf;
			slbf->len = sbl + 1;
			slbf->next = NULL;
			if(ld->lnbl == NULL){
				ld->lnbl = slbf;
				ld->curr = slbf;
			}else{
				ld->curr->next = slbf;
				ld->curr = slbf;
			}
			ld->curr->stflg = true;
			return;
		}
	}
}

void remove_blank_lines(const char *filename)
{
    char command[256];
    snprintf(command, sizeof(command), "grep -v '^$' %s > tempfile && mv tempfile %s", filename, filename);
    int result = system(command);
    if (result != 0) {
        perror("Error executing system command");
    }
}

void remove_null_lines(const char *filename)
{
    char command[256];
    snprintf(command, sizeof(command), "sed -i '/^\\x00/d' %s", filename);
    int result = system(command);
    if (result != 0) {
        perror("Error executing system command");
    }
}

static int free_elem(void* elem, void *arg) {
  userelem *el = (userelem *) elem;
  free(el->value);
  free(el);
  return 0;
}

int free_data(void* data, void *arg)
{
  userdata *dat = (userdata *) data;
  /* 删除整个子 map */
  hashmap_destroy(dat->map, free_elem, 0);
  free(dat);
  return 0;
}

extern hmap_t promap;
char* load_filpath(const char* inpath, const char* name)
{
	char tistr[PHRASE]= {0};
	char *resth = NULL;
//Get the performance monitor
	userdata  *dat;
	userelem  *el;
	int ret;
/* 创建 hashmap */
	promap = hashmap_create();

	struct strlist *pstrlist = NULL;
	struct strlist *filelist = NULL;
	create_strlist(&filelist);
	trave_dir(inpath, &filelist);

	pstrlist = filelist->next;
	while(pstrlist)
	{
		el = (userelem *)malloc(sizeof(userelem));
		memset(el, 0, sizeof(userelem));
		phy_snprintf(el->key, 128, "%s", get_file_name(pstrlist->data));
		//	printf("%s\n", el->key);
		if((phy_strcmp_natural(el->key, "run.sh") == 0) || (phy_strcmp_natural(el->key, "resource") == 0) || (phy_strcmp_natural(el->key, "results") == 0) || (phy_strcmp_natural(el->key, "bin") == 0) || (phy_strcmp_natural(el->key, "server") == 0) || (phy_strcmp_natural(el->key, "pt_controller") == 0) || (phy_strcmp_natural(el->key, "conf") == 0)){
			phy_free(el);
			pstrlist = pstrlist->next;
			continue;
		}

		dat = (userdata *)malloc(sizeof(userdata));
		memset(dat, 0, sizeof(userdata));
		/* 创建子 hashmap */
		dat->map = hashmap_create();

		el->value = (char*) phy_malloc(el->value, strlen(pstrlist->data) + 1);
		phy_snprintf(el->value, strlen(pstrlist->data) + 1, "%s", pstrlist->data);
		ret = hashmap_put(dat->map, el->key, el);
		if(ret!=HMAP_S_OK){
			goto mapputkey_err;
		}

		phy_snprintf(dat->name, 128, "%s", el->key);
		ret = hashmap_put(promap, dat->name, dat);
		if(ret!=HMAP_S_OK){
			goto mapputsub_err;
//			continue;
		}
		pstrlist = pstrlist->next;
	}

	ret = hashmap_get(promap, name, (void_ptr *)&dat);
	if(ret==HMAP_S_OK)
	{
		memset(tistr, 0, PHRASE);
		hashmap_iterate(dat->map, iter_elem, tistr);
		resth = phy_malloc(resth, strlen(tistr) + 1);
		memset(resth, 0, strlen(tistr) + 1);
		phy_snprintf(resth, strlen(tistr) + 1, "%s", tistr);
//		printf("hashmap_get: name=%s. size=%d, value=%s\n", dat->name, hashmap_size(promap), tistr);
	}else{
		goto mapget_err;
	}
out:
	hashmap_destroy(promap, free_data, 0);
	destory_strlist(filelist);
	return resth;
mapputkey_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map put key: %s error.", el->key);
	goto out;
mapputsub_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map put sub: %s error.", dat->name);
	goto out;
mapget_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map get: %s error.", name);
	goto out;
}

char* __get_segment_data(const char *filename, int line, const char *src, const char* spliter, int n)
{
	const char *__function_name = "get_segment_data";
	char* rets = NULL;
	char* np = NULL;
	char* pp = NULL;
	size_t retsl = 0;
	if(src == NULL || spliter == NULL || n <= 0)
	{
		goto inputerr;
	}

	pp = (char*)src;
	np = NULL;
	for( int i = 1; i <= n; i++ ){
		np = NTSTRSTR(pp, spliter);
		if(np == NULL){
			if(i == n){
				goto special;
			}else{
				goto inputerr;
			}
		}
		if(i == n){
			goto common;
		}
		pp = np + strlen(spliter);
	}

special:
	retsl = NTCPTEND(src, pp) + 1;
	goto pmac;
common:
	retsl = np - pp + 1;
pmac:
	if(retsl == 1){
		goto retnul;
	}
	rets = (char*) phy_malloc(rets, retsl);
	memset(rets, 0, retsl);
	phy_snprintf(rets, retsl, "%s", pp);
	return rets;

inputerr:
	phy_log(LOG_LEVEL_ERR, "[file:%s,line:%d, func: %s ]:%s ", filename, line, __function_name, ARG_INPUT_ERR);
retnul:
	return NULL;
}

int custom_strstr(const char *haystack, int haystack_len, const char *needle)
{
    int needle_len = strlen(needle);
    for (int i = 0; i <= haystack_len - needle_len; ++i) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}

void print_buffer(const char *buffer, int len)
{
    for (int i = 0; i < len; ++i) {
        if (buffer[i] == '\0') {
            printf("\\0");
        } else {
            putchar(buffer[i]);
        }
    }
    putchar('\n');
}
#if 0
bool check_dependency(const char* add, const char* usr, const char* pwd, const char* prgm)
{
   ssh_session session;
	ssh_channel channel;
	int rc;
	char buffer[256];
	unsigned int nbytes;
	int total_read = 0;
	const char *command = "ldconfig -p | grep -E 'libQt5Network.so.5|libQt5Core.so.5'";
	time_t start_time, current_time;
	const int timeout = 10; // 超时时间（秒）

	// 创建会话
	session = ssh_new();
	if (session == NULL) {
		fprintf(stderr, "Error: Failed to create SSH session.\n");
		return 0;
	}

	// 设置远程主机名和普通用户名
	ssh_options_set(session, SSH_OPTIONS_HOST, add);
	ssh_options_set(session, SSH_OPTIONS_USER, usr);

	// 连接到远程主机
	rc = ssh_connect(session);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error connecting to %s: %s\n", add, ssh_get_error(session));
		ssh_free(session);
		return 0;
	}
	printf("Connected to %s\n", add);

	// 使用普通用户密码进行身份验证
	rc = ssh_userauth_password(session, NULL, pwd);
	if (rc != SSH_AUTH_SUCCESS) {
		fprintf(stderr, "Authentication failed for user %s: %s\n", usr, ssh_get_error(session));
		ssh_disconnect(session);
		ssh_free(session);
		return 0;
	}
	printf("Authenticated as %s\n", usr);

	// 打开一个新的channel
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
	printf("Channel opened.\n");

	// 执行验证库文件是否安装的命令
	rc = ssh_channel_request_exec(channel, command);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error: Failed to execute command: %s\n", ssh_get_error(session));
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		ssh_disconnect(session);
		ssh_free(session);
		return 0;
	}
	printf("Command executed.\n");

	// 清空缓冲区用于读取命令输出
	memset(buffer, 0, sizeof(buffer));
	total_read = 0;

	sleep(1);
	// 读取命令输出
	start_time = time(NULL);
	while (1) {
		nbytes = ssh_channel_read(channel, buffer + total_read, sizeof(buffer) - total_read - 1, 0);
		if (nbytes > 0) {
			total_read += nbytes;
		} else if (nbytes == 0) {
			break; // EOF received
		} else {
			fprintf(stderr, "Error: Failed to read channel: %s\n", ssh_get_error(session));
			ssh_channel_close(channel);
			ssh_channel_free(channel);
			ssh_disconnect(session);
			ssh_free(session);
			return 0;
		}

		current_time = time(NULL);
		if (difftime(current_time, start_time) > timeout) {
			fprintf(stderr, "Error: Reading from channel timed out.\n");
			ssh_channel_close(channel);
			ssh_channel_free(channel);
			ssh_disconnect(session);
			ssh_free(session);
			return 0;
		}
	}
	printf("Command output read.\n");

	// 打印调试信息
	printf("Debug: Buffer content:\n");
	print_buffer(buffer, total_read);

	// 关闭channel
	ssh_channel_send_eof(channel);
	ssh_channel_close(channel);
	ssh_channel_free(channel);
	printf("Channel closed.\n");

	// 断开会话
	ssh_disconnect(session);
	ssh_free(session);
	printf("Session disconnected.\n");

	// 检查命令输出
	if (custom_strstr(buffer, total_read, "libQt5Network.so.5") != NULL && custom_strstr(buffer, total_read, "libQt5Core.so.5") != NULL) {
		return 1; // 库文件已安装
	} else {
		return 0; // 库文件未安装
	}
}

#endif
// 创建新的链表节点
list* create_node(const char* dependency) {
    list* new_node = (list*)malloc(sizeof(list));
    if (new_node == NULL) {
        perror("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }
    new_node->dependency = strdup(dependency);
    new_node->next = NULL;
    return new_node;
}

// 追加节点到链表
void app_node(list** head, const char* dependency) {
    list* new_node = create_node(dependency);
    if (*head == NULL) {
        *head = new_node;
    } else {
        list* temp = *head;
        while (temp->next != NULL) {
            temp = temp->next;
        }
        temp->next = new_node;
    }
}

void free_list(list* head)
{
    while (head != NULL) {
        list* temp = head;
        head = head->next;
        free(temp->dependency);
        free(temp);
    }
}

// 上传文件到远程机器
int upload_file(ssh_session session, sftp_session sftp, const char* local_path, const char* remote_path) {
    sftp_file file;
    FILE *local;
    char buffer[1024];
    size_t nbytes, nwritten;

    local = fopen(local_path, "rb");
    if (local == NULL) {
        perror("Failed to open local file");
        return SSH_ERROR;
    }

    file = sftp_open(sftp, remote_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
    if (file == NULL) {
        fprintf(stderr, "Can't open remote file: %s\n", ssh_get_error(session));
        fclose(local);
        return SSH_ERROR;
    }

    while ((nbytes = fread(buffer, 1, sizeof(buffer), local)) > 0) {
        nwritten = sftp_write(file, buffer, nbytes);
        if (nwritten != nbytes) {
            fprintf(stderr, "Can't write data to remote file: %s\n", ssh_get_error(session));
            sftp_close(file);
            fclose(local);
            return SSH_ERROR;
        }
    }

    sftp_close(file);
    fclose(local);
    return SSH_OK;
}

// 执行命令并获取输出
int execute_command(ssh_session session, const char* command, char* output, size_t max_output)
{
    ssh_channel channel;
    int rc;
    size_t len = 0;

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        return SSH_ERROR;
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        return rc;
    }

    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }
    sleep(1);
    while ((rc = ssh_channel_read(channel, output + len, max_output - len - 1, 0)) > 0) {
    	len += rc;
    }

    output[len] = '\0';

    if (rc < 0) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return SSH_OK;
}

list* check_dependency(const char* add, const char* usr, const char* pwd, const char* prgm)
{
    ssh_session session;
    sftp_session sftp;
    int rc;
    char command[512];
    char output[4096];
    list *head = NULL;

	char **arr = NULL;
	char **stmp = NULL;
	char *token = NULL;
	int i = 0;

// 创建并连接SSH会话
    session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "Error: Failed to create SSH session.\n");
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
        fprintf(stderr, "Authentication failed for user %s: %s\n", usr, ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }

// 创建SFTP会话
    sftp = sftp_new(session);
    if (sftp == NULL) {
        fprintf(stderr, "Error creating SFTP session: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }

    rc = sftp_init(sftp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %d\n", sftp_get_error(sftp));
        sftp_free(sftp);
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }

// 上传程序文件到远程机器的/tmp目录
    char remote_path[256];
    snprintf(remote_path, sizeof(remote_path), "/tmp/%s", strrchr(prgm, '/') + 1);
    rc = upload_file(session, sftp, prgm, remote_path);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error uploading file to remote machine\n");
        sftp_free(sftp);
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }

// 执行ldd命令检查依赖库
    snprintf(command, sizeof(command), "ldd %s", remote_path);
    rc = execute_command(session, command, output, sizeof(output));
    if (rc != SSH_OK) {
        fprintf(stderr, "Error executing command on remote machine\n");
        sftp_free(sftp);
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }

	phy_strarr_init(&arr);
	str_to_arr(output, "\n", &arr);
	for (stmp = arr; NULL != *stmp; stmp++){
		if (strstr(*stmp, "not found") != NULL) {
			token = strtok(*stmp, " \t");
			if (token != NULL) {
				app_node(&head, token);
			}
		}
		i++;
	}
	phy_strarr_free(arr);
//    char *line = strtok(output, "\n");
//    while (line != NULL) {
//        if (strstr(line, "not found") != NULL) {
//            char *token = strtok(line, " \t");
//            if (token != NULL) {
//                app_node(&head, token);
//            }
//        }
//        line = strtok(NULL, "\n");
//    }

//删除拷贝的文件
    snprintf(command, sizeof(command), "rm -f %s", remote_path);
    execute_command(session, command, output, sizeof(output));

    sftp_free(sftp);
    ssh_disconnect(session);
    ssh_free(session);

    return head;
}

int is_executable_file(const char *path) {
    struct stat file_stat;

    if (stat(path, &file_stat) != 0) {
        perror("stat");
        return 0;
    }

    // 检查是否为普通文件
    if (!S_ISREG(file_stat.st_mode)) {
        return 0; // 不是普通文件
    }

    // 检查可执行权限
    if ((file_stat.st_mode & S_IXUSR) || (file_stat.st_mode & S_IXGRP) || (file_stat.st_mode & S_IXOTH)) {
        return 1; // 是可执行文件
    }

    return 0; // 不是可执行文件
}

int is_script_file(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) {
        perror("fopen");
        return 0;
    }

    char buffer[3];
    if (fread(buffer, 1, 2, file) == 2) {
        buffer[2] = '\0';
        // 检查脚本的（#!）
        if (strcmp(buffer, "#!") == 0) {
            fclose(file);
            return 1; // 是脚本文件
        }
    }
    fclose(file);
    return 0; // 不是脚本文件
}

int nt_exec(const char *cmd)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        // 子进程
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        perror("execl");
        _exit(EXIT_FAILURE);
    } else {
        // 父进程
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return -1;
        }
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        } else {
            return -1;
        }
    }
}

//去除字符串首位的\r\n
void trim(char *str)
{
	size_t len = strlen(str);

	// 结尾 "\r\n"
	while (len >= 2 && str[len - 2] == '\r' && str[len - 1] == '\n') {
		str[len - 2] = '\0';
		len -= 2;
	}

	// 开头 "\r\n"
	while (strncmp(str, "\r\n", 2) == 0) {
		memmove(str, str + 2, len - 1);
		len -= 2;
	}
}

int write_pid(pid_t pid)
{
#define chlpidfil "/tmp/chlpid"
	FILE* fp = NULL;
	size_t len = 0;
	fp = fopen(chlpidfil, "a+");
	if(fp == NULL){
		return 1;
	}
	len = fprintf(fp, "%d\n", pid);
	fclose(fp);
	if(len > 0){
		return 0;
	}else{
		return 1;
	}
}
void phy_mkdir(const char* path)
{
	char cmd[CMDLEN]={0};
	phy_snprintf(cmd, CMDLEN, "mkdir -p %s", path);
	system(cmd);
}

bool is_file_empty(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return false; // 这里返回 false，具体逻辑可以根据需求调整
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fclose(file);
    return size == 0;
}

//void prt_lst(lst* p)
//{
//    lst* curr = p;
//    while (curr){
//    	printf("%s\n", curr->dat);
//    	curr = curr->next;
//    }
//}
//
//void free_lst(lst *head)
//{
//    while (head) {
//        lst *tmp = head;
//        head = head->next;
//        free(tmp->dat);
//        free(tmp);
//    }
//}
//
//#if 0
//void lst_ini(lst **head)
//{
//	lst *node = (lst*)malloc(sizeof(lst));
//	memset(node, 0, sizeof(lst));
//	*head = node;
//}
//#endif
//
//lst* lst_app(lst *head, const char *s)
//{
//    if (!s) return head;
//
//    if (!head) {
//    	head = (lst*)malloc(sizeof(lst));
//    	memset(head, 0, sizeof(lst));
//    	head->dat = strdup(s);
//        return head;
//    }
//
//    lst *node = (lst*)malloc(sizeof(lst));
//    node->dat = strdup(s);
//    node->next = NULL;
//
//    lst *cur = head;
//    while (cur->next) cur = cur->next;
//    cur->next = node;
//    return head;
//}

size_t *stroffstr(const char *str, const char *pat, size_t off, size_t *cnt)
{
    size_t str_len, pat_len;
    size_t i, j;
    size_t count = 0;
    size_t *pos = null;

    if (!str || !pat || !cnt) {
        return null;
    }

    str_len = strlen(str);
    pat_len = strlen(pat);
    *cnt = 0;

    if (off >= str_len || pat_len == 0 || pat_len > str_len) {
        return null;
    }

    /* ——— 第一次遍历：统计匹配次数 ——— */
    for (i = off; i + pat_len <= str_len; i++) {
        for (j = 0; j < pat_len; j++) {
            if (str[i + j] != pat[j]) {
                break;
            }
        }
        if (j == pat_len) {
            count++;
        }
    }

    if (count == 0) {
        return null;
    }

    /* 分配数组 */
    pos = malloc(count * sizeof(size_t));
    if (!pos) {
        perror("malloc");
        return null;
    }

    size_t idx = 0;
    for (i = off; i + pat_len <= str_len; i++) {
        for (j = 0; j < pat_len; j++) {
            if (str[i + j] != pat[j]) {
                break;
            }
        }
        if (j == pat_len) {
            pos[idx++] = i;
        }
    }

    *cnt = count;
    return pos;
}

void lst_prt(lst* p)
{
    lst* curr = p;
//    char* sp = null;
    while (curr){
//    	sp = (char*)malloc(curr->len);
//    	memset(sp, 0, curr->len);
//    	memcpy(sp, curr->dat, curr->len);
    	printf("%s\n", (char*)curr->dat);
//    	phy_free(sp);
    	curr = curr->next;
    }
}

void lst_fre(lst *head)
{
    while (head) {
        lst *tmp = head;
        head = head->next;
        free(tmp->dat);
        free(tmp);
    }
}

lst* lst_app(lst *head, const char *s)
{
    if (!s) return head;
    lst *node = (lst*)malloc(sizeof(lst));
    node->dat = strdup(s);
    node->next = NULL;
    if (!head) {
        return node;
    }
    lst *cur = head;
    while (cur->next) cur = cur->next;
    cur->next = node;
    return head;
}

lvh *lvh_app(lvh *hed, void *dat, size_t len)
{
	lvn *nod = null;
	lvh *vhd = null;

	if (!dat) return hed;

    if (!hed) {
    	vhd = malloc(sizeof(lvh));
        if (!vhd) return null;

        vhd->ent = malloc(sizeof(lvn));
        if (!(vhd->ent)) goto hderr;

        vhd->ent->dat = malloc(len);
        if (!(vhd->ent)) goto hdderr;

        memset(vhd->ent->dat, 0, len);

        memcpy(vhd->ent->dat, dat, len);
        vhd->ent->len = len;
        vhd->ent->next = null;
        vhd->cnt = 1;
        vhd->cur = vhd->ent;
        return vhd;
    }

    nod = malloc(sizeof(lvn));
    if (!nod) return hed;

    nod->dat = malloc(len);
    if (!nod->dat) goto nderr;

	memset(nod->dat, 0, len);
	memcpy(nod->dat, dat, len);
	nod->len = len;
	nod->next = null;

	hed->cur->next = nod;
	hed->cur = nod;
    hed->cnt++;

	return hed;

nderr:
	free(nod);
	return hed;
hdderr:
	free(vhd->ent);
hderr:
	free(vhd);
	return null;
}

void lvh_prt(lvh *hed, lvh_pfun pfu)
{
	lvn *p = hed->ent;
	while (p) {
		pfu(p->dat);
		p = p->next;
	}
}

void lvh_fre(lvh *hed)
{
    if (!hed) return;

    lvn *p = hed->ent;
    while (p) {
        lvn *next = p->next;
        free(p->dat);
        free(p);
        p = next;
    }
    free(hed);
}

void ddlx_init(ddlhx **dh)
{
    *dh = (ddlhx*)malloc(sizeof(ddlhx));
    memset(*dh, 0, sizeof(ddlhx));
}

void ddlx_insert_end(ddlhx **dh, ddlx* di)
{
    if ((*dh)->tail == NULL) {
        (*dh)->entr = di;
        (*dh)->curr = di;
        (*dh)->tail = di;
        (*dh)->pos  = di;
        (*dh)->num  = 1;
    } else {
        (*dh)->tail->next = di;
        di->prev = (*dh)->tail;
        (*dh)->tail = di;
        (*dh)->curr = di;
        (*dh)->num++;
    }
}

void ddlx_insert(ddlhx **dh, void* data, size_t len, int flg)
{
    ddlx* di = (ddlx*)malloc(sizeof(ddlx));
    memset(di, 0, sizeof(ddlx));
    di->data = malloc(len);
    memcpy(di->data, data, len);
    di->dln = len;
    ddlx_insert_end(dh, di);
}

void ddlx_insert_brch(ddlhx **dh, void* data, size_t len, int flg)
{
    if ((*dh)->curr == NULL) return;

    ddlx *di = (ddlx*)malloc(sizeof(ddlx));
    memset(di, 0, sizeof(ddlx));
    di->data = malloc(len);
    memcpy(di->data, data, len);
    di->dln = len;

    if ((*dh)->curr->brch == NULL) {
        (*dh)->curr->brch = di;
    } else {
        ddlx *p = (*dh)->curr->brch;
        while (p->next) p = p->next;
        p->next = di;
        di->prev = p;
    }
}

void ddlx_destory_node(ddlx *node)
{
    if (node->brch) ddlx_destory_node(node->brch);
    if (node->next) ddlx_destory_node(node->next);
    free(node->data);
    free(node);
}

void ddlx_destory(ddlhx *dh)
{
    if (dh->entr) ddlx_destory_node(dh->entr);
    free(dh);
}

#define MAX_DIR_LEN (1024)
void load_fils(const char* path, ddlhx **dh)
{
    DIR *d = NULL;
    struct dirent *dp = NULL;
    struct stat st;
    char p[MAX_DIR_LEN] = {0};
    if(stat(path, &st) < 0 || !S_ISDIR(st.st_mode)) {
        printf("invalid path: %s\n", path);
        return;
    }

    if(!(d = opendir(path))) {
        printf("opendir[%s] error: %m\n", path);
        return;
    }

    while((dp = readdir(d)) != NULL) {
        if((!strncmp(dp->d_name, ".", 1)) || (!strncmp(dp->d_name, "..", 2)))
            continue;

        memset(p, 0, MAX_DIR_LEN);
        snprintf(p, sizeof(p) - 1, "%s/%s", path, dp->d_name);
        ddlx_insert(dh, p, strlen(p)+1, 1);
        stat(p, &st);

        if(S_ISDIR(st.st_mode)) {
        	load_fils(p, dh);
        }
    }
    closedir(d);
    return;
}

char **rd_lns(const char *dat)
{
    const char *p = dat;
    size_t lines = 0;

    while (*p) {
        if (*p == '\n') lines++;
        p++;
    }
    if (p > dat && *(p-1) != '\n') lines++;

    char **result = malloc((lines + 1) * sizeof(char *));
    if (!result) return NULL;

    size_t idx = 0;
    const char *start = dat;
    while (*start) {
        const char *end = strchr(start, '\n');
        size_t len = end ? (size_t)(end - start) : strlen(start);

        /* 剔除末尾 '\r'、空格、制表符 */
        while (len > 0 && (start[len-1] == '\r'
                         || start[len-1] == ' '
                         || start[len-1] == '\t')) {
            len--;
        }

        result[idx] = malloc(len + 1);
        memcpy(result[idx], start, len);
        result[idx][len] = '\0';
        idx++;

        if (!end) break;
        start = end + 1;
    }

    result[idx] = NULL;
    return result;
}

void fre_lns(char **lines)
{
    for (size_t i = 0; lines[i]; i++) free(lines[i]);
    free(lines);
}

int strcmpx(const char *s1, const char *s2)
{
	if(s1 == null && s2 == null) return 0;
	if(s1 == null && s2 != null) return -1;
	if(s1 != null && s2 == null) return 1;

    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);

    if (len1 != len2) {
        return (len1 > len2) ? 1 : -1;
    }

    for (size_t i = 0; i < len1; ++i) {
        unsigned char c1 = (unsigned char)s1[i];
        unsigned char c2 = (unsigned char)s2[i];
        if (c1 != c2) {
            return (c1 > c2) ? 1 : -1;
        }
    }
    return 0;
}

char* int2sstr(int num, char* s)
{
	char* res = null;
	char tmp[20] = {0};
	size_t len = 0;
	size_t rln = 0;
	size_t sln = 0;
	sln = strlen(s);
	int i = 0;

	for(; i < num; i++){
		memset(tmp , 0, sizeof(tmp));
		snprintf(tmp, sizeof(tmp), "%d", i);
		len += strlen(tmp);
		len += sln;
	}

	rln = len - sln;
	res = malloc(len + 1);
	memset(res, 0 ,len + 1);

	for(i = 0; i < num; i++){
		memset(tmp, 0, sizeof(tmp));
		snprintf(tmp, sizeof(tmp), "%d", i);
		strncat(res, tmp, strlen(tmp));
		strcat(res, s);
	}
	res[rln] = '\0';
	return res;
}

#define NTCAT_MAX_ARGS 10
char *__ntcat(char *a, char *b, char *c, ...)
{
    int count = 0;
    size_t total = 0;
    char *p = null;
    char *out = null;
    char *args[NTCAT_MAX_ARGS];

    args[count++] = a;
    args[count++] = b;
    args[count++] = c;

    va_list ap;
    va_start(ap, c);
    while (count < NTCAT_MAX_ARGS) {
        char *s = va_arg(ap, char*);
        if (!s) break;
        args[count++] = s;
    }
    va_end(ap);

    total = 0;
    for (int i = 0; i < count; i++) {
        total += strlen(args[i]);
    }

    out = malloc(total + 1);
    if (!out) return NULL;
    p = out;
    for (int i = 0; i < count; i++) {
        size_t len = strlen(args[i]);
        memcpy(p, args[i], len);
        p += len;
    }
    *p = '\0';
    return out;
}

//size_t *stroffstr(const char *str, const char *pat, size_t off, size_t *cnt)
//{
//    size_t str_len, pat_len;
//    size_t i, j;
//    size_t count = 0;
//    size_t *pos = null;
//
//    if (!str || !pat || !cnt) {
//        return null;
//    }
//
//    str_len = strlen(str);
//    pat_len = strlen(pat);
//    *cnt = 0;
//
//    if (off >= str_len || pat_len == 0 || pat_len > str_len) {
//        return null;
//    }
//
//    /* ——— 第一次遍历：统计匹配次数 ——— */
//    for (i = off; i + pat_len <= str_len; i++) {
//        for (j = 0; j < pat_len; j++) {
//            if (str[i + j] != pat[j]) {
//                break;
//            }
//        }
//        if (j == pat_len) {
//            count++;
//        }
//    }
//
//    if (count == 0) {
//        return null;
//    }
//
//    /* 分配数组 */
//    pos = malloc(count * sizeof(size_t));
//    if (!pos) {
//        perror("malloc");
//        return null;
//    }
//
//    size_t idx = 0;
//    for (i = off; i + pat_len <= str_len; i++) {
//        for (j = 0; j < pat_len; j++) {
//            if (str[i + j] != pat[j]) {
//                break;
//            }
//        }
//        if (j == pat_len) {
//            pos[idx++] = i;
//        }
//    }
//
//    *cnt = count;
//    return pos;
//}
//
//char* route(ddlhx *dh, const char* pre, const char* typ, const char* key)
//{
//	size_t len = 0;
//	size_t cnt = 0;
//	size_t *pos = null;
//	char* rte   = null;
//	lst*  pib   = null;
//	lst*  pid   = null;
//	lst*  piq   = null;
//	ddlx *sct   = null;
//
//	 if (pre == null || typ == null || key == 0 ) {
//	        return null;
//	    }
//
//	len = strlen(pre);
//	sct = dh->entr;
//
//	while(sct)
//	{
//		if(strstr((char*)sct->data, pre)){
//			pib = lst_app(pib, (char*)sct->data);
//		}
//		sct = sct->next;
//	}
//
//	pid = pib;
//	while(pid)
//	{
//		pos = stroffstr(pid->dat, typ, len, &cnt);
//		if(null != pos){
//			piq = lst_app(piq, pid->dat);
//			phy_free(pos);
//		}
//		pid = pid->next;
//	}
//	free_lst(pib);
//
//	len = len + strlen(typ);
//	pib = piq;
//	while(pib)
//	{
//		pos = stroffstr(pib->dat, key, len, &cnt);
//		if(null != pos){
//			phy_free(pos);
//			rte = strdup(pib->dat);
//			goto end;
//		}
//		pib = pib->next;
//	}
//
//end:
//	free_lst(piq);
//	return rte;
//}
