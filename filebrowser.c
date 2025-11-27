#include "filebrowser.h"
#include "channel.h"
#include "messtype.h"

bool bol_create_shm(const char* shmnm, size_t shmlen, const char* semnm)
{
    int shm_fd;
    sem_t *sem;

    sem = sem_open(semnm, O_CREAT, 0666, 1);
    if (sem == SEM_FAILED) {
        perror("sem_open");
        return false;
    }

    shm_fd = shm_open(shmnm, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        return false;
    }

    if (ftruncate(shm_fd, shmlen) == -1) {
        perror("ftruncate");
        return false;
    }
    return true;
}

size_t siz_write_shm(const char* shmnm, size_t shmlen, const char* semnm, void* dat, size_t ln)
{
    int shm_fd;
    void *shm_ptr;
    sem_t *sem;

    sem = sem_open(semnm, 0);
    if(sem == SEM_FAILED){
    	perror("sem_open");
    	return 0;
    }

    shm_fd = shm_open(shmnm, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        return 0;
    }

    if (ftruncate(shm_fd, shmlen) == -1) {
        perror("ftruncate");
        return 0;
    }

    shm_ptr = mmap(0, shmlen, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED) {
        perror("mmap");
        return 0;
    }

    sem_wait(sem);
    memcpy(shm_ptr, dat, ln);
    sem_post(sem);

    if (munmap(shm_ptr, shmlen) == -1) {
        perror("munmap");
        return 0;
    }

    if (close(shm_fd) == -1) {
        perror("close");
        return 0;
    }

    if (sem_close(sem) == -1) {
        perror("sem_close");
        return 0;
    }
    return ln;
}

char* chr_readshm(const char* shmnm, size_t shmlen, void* dat, size_t ln)
{
    int shm_fd;
    void *shm_ptr;
    sem_t *sem;

    sem = sem_open(msemnm, 0);
    if (sem == SEM_FAILED) {
        perror("sem_open");
        exit(EXIT_FAILURE);
    }

    shm_fd = shm_open(mshmnm, O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        exit(EXIT_FAILURE);
    }

    shm_ptr = mmap(0, shmlen, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    sem_wait(sem);
    printf("Process B read from shared memory: %s\n", (char *)shm_ptr);
    sem_post(sem);
    if (munmap(shm_ptr, shmlen) == -1) {
        perror("munmap");
        exit(EXIT_FAILURE);
    }

    if (close(shm_fd) == -1) {
        perror("close");
        exit(EXIT_FAILURE);
    }

    if (sem_close(sem) == -1) {
        perror("sem_close");
        exit(EXIT_FAILURE);
    }
    return 0;
}

void lst_add(vphd *head, filst *file_info)
{
    vplst *new_node = NULL;
	new_node = (vplst *)malloc(sizeof(vplst));
    memset(new_node, 0, sizeof(vplst));
    new_node->data = malloc(sizeof(filst));
    memset(new_node->data, 0, sizeof(filst));
    memcpy(new_node->data, file_info, sizeof(filst));
    new_node->next = NULL;
    if (head->dlt == NULL) {
    	head->dlt = new_node;
        head->cur = head->dlt;
    } else {
        vplst *temp = head->cur;
        temp->next = new_node;
        head->cur = new_node;
    }
    head->len++;
}

void lst_del(vphd **head, vplst** nd)
{
	vplst* q = NULL;
	vplst* r = NULL;
	vplst* s = NULL;
	bool flag = false;
	if((*nd) == NULL){
		return;
	}

	if((vplst*)(*nd) == (vplst*)(*head)->cur){
		flag = true;
	}

	q = (vplst*)((*head)->dlt);
	s = (vplst*)((*head)->dlt);
	while(q){
		if(q == ((vplst*)*nd)){
			r = q->next;
			free(q->data);
			free(q);
			*nd = r;
#if 0
			s->next = r;
#else
			if(s != q){
				s->next = r;
			}else{
				(*head)->dlt = r;
			}
#endif
			(*head)->len --;
			break;
		}
		s = q;
		q = q->next;
	}

	if(flag == true){
		(*head)->cur = s;
		(*nd) = (vplst*)NULL;
	}
}

void lst_print(vphd *head)
{
    vplst *temp = head->dlt;
    printf("%ld\n", head->len);
//    FILE *fp = NULL;
//    fp = fopen("/home/nt/111xxx.txt", "a+");
    while (temp != NULL) {
        filst *file_info = (filst *)temp->data;
//        printf("Path: %s\n", file_info->flpt);
        printf("Name: %s\n", file_info->flpt);
//        fprintf(fp, "%s\n", file_info->flnm);
//        printf("Links: %d\n", file_info->lknu);
//        printf("User: %s\n", file_info->usr);
//        printf("Group: %s\n", file_info->grp);
//        printf("Size: %zu\n", file_info->siz);
//        printf("Date: %s\n\n", file_info->date);
        temp = temp->next;
    }
//    fclose(fp);
}

void mdf_dirnm(vphd *head)
{
    vplst *temp = head->dlt;
    printf("%ld\n", head->len);
    while (temp != NULL) {
        filst *file_info = (filst *)temp->data;
        if(0 == strncmp(file_info->fpms, "d", 1)){
        	file_info->flpt[strlen(file_info->flpt)] = '/';
        	file_info->flpt[strlen(file_info->flpt) + 1] = '\0';
        }
        temp = temp->next;
    }
}

void fil_filter(vphd** head, const char* usr, const char* pms)
{
    vplst *temp = (*head)->dlt;
	printf("%ld\n", (*head)->len);
loop:
	while (temp != NULL) {
		filst *file_info = (filst *)temp->data;
		if(0 != strncmp(file_info->fpms, "d", 1)){
			if(0 == phy_strcmp_natural(file_info->usr, usr)){
				if( file_info->fpms[3] != 'x'){
//delete
					lst_del(head, &temp);
					if(temp == NULL){
						break;
					}
					goto loop;
				}
			}else{
//delete
				lst_del(head, &temp);
				if(temp == NULL){
					break;
				}
				goto loop;
			}
		}
		temp = temp->next;
	}
}

void lst_free(vphd *head)
{
    vplst *temp = head->dlt;
    while (temp != NULL) {
        vplst *next = temp->next;
        free(temp->data);
        free(temp);
        temp = next;
    }
    head->cur = NULL;
    head->dlt = NULL;
    head->len = 0;
    free(head);
}

static struct fltp ftpmp[] =
{
	{'-',	"普通文件"},
	{'d',	"目录"},
	{'l',	"链接文件"},
	{'c',	"字符设备"},
	{'b',	"块设备"},
	{'p',	"管道文件"},
	{'s',	"套接字"},
	{'x', "null"}
};

enum uflg{
	OWN,
	GRP,
	OTR
};

void list_remote_files(const char *hostname, const char *username, const char *password, const char *path, vphd **vhd)
{
    ssh_session session = ssh_new();
    if (session == NULL) return;

    ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
    ssh_options_set(session, SSH_OPTIONS_USER, username);

    if (ssh_connect(session) != SSH_OK) {
    	send_message(MESS, ERROR, FILBRSER, "ssh 连接错误.");
//      fprintf(stderr, "Error connecting to %s: %s\n", hostname, ssh_get_error(session));
        ssh_free(session);
        return;
    }

    if (ssh_userauth_password(session, NULL, password) != SSH_AUTH_SUCCESS) {
    	send_message(MESS, ERROR, FILBRSER, "ssh 验证错误.");
//        fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL) return;

    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    char command[256];
    snprintf(command, sizeof(command), "ls -l %s %s | tail -n +2 | awk '{print $1\"|\"$2\"|\"$3\"|\"$4\"|\"$5\"|\"$6\"|\"$7\"|\"$8}' 2>&1", "--time-style='+%Y%m%d-%H:%M:%S'", path);
//    snprintf(command, sizeof(command), "cat %s", path);
    if (ssh_channel_request_exec(channel, command) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    char buffer[4096];
//    char buferr[256];
    int nbytes;
    filst file_info;
    char *line, *saveptr;
    char partial_line[4096] = {0};
    int lin = 0;

    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[nbytes] = '\0';
        memset(&file_info, 0, sizeof(filst));
        if (partial_line[0] != '\0') {
            strncat(partial_line, buffer, sizeof(partial_line) - strlen(partial_line) - 1);
            line = strtok_r(partial_line, "\n", &saveptr);
        } else {
            line = strtok_r(buffer, "\n", &saveptr);
        }

        while (line != NULL) {
            if (saveptr && *saveptr == '\0') {
//                strncpy(partial_line, line, sizeof(partial_line) - 1);
//                partial_line[sizeof(partial_line) - 1] = '\0';
            	memmove(partial_line, line, strlen(line) + 1);
                break;
            } else {
                partial_line[0] = '\0';
            }

            char *token = strtok(line, "|");
            if (token != NULL) {
            	strncpy(file_info.fpms, token, pmln);
			    for (lin = 0; 'x' != ftpmp[lin].flg; lin++){
			    	if(0 == strncmp(token, &(ftpmp[lin].flg), 1)){
			    		break;
			    	}
				}
			    memset(file_info.fltp, 0, pmln);
			    snprintf(file_info.fltp, pmln, "%s", ftpmp[lin].des);
            }

            token = strtok(NULL, "|");
            if (token != NULL) file_info.lknu = atoi(token);

            token = strtok(NULL, "|");
            if (token != NULL) strncpy(file_info.usr, token, dtln);

            token = strtok(NULL, "|");
            if (token != NULL) strncpy(file_info.grp, token, dtln);

            token = strtok(NULL, "|");
            if (token != NULL) file_info.siz = strtoul(token, NULL, 10);

            token = strtok(NULL, "|");
            if (token != NULL) snprintf(file_info.date, dtln, "%s", token);//strncpy(file_info.date, token, dtln);

            token = strtok(NULL, "|");
            if (token != NULL) strncpy(file_info.flnm, token, urln);

            memset(file_info.flpt, 0, flptln);
            if(strlen(path) == 1){
            	snprintf(file_info.flpt, flptln, "/%s", file_info.flnm);
            }else{
            	snprintf(file_info.flpt, flptln, "%s/%s", path, file_info.flnm);
            }

            if((lin == 0) || (lin == 1)){
            	if(((file_info.fpms[3] == 'x') && (0 == phy_strcmp_natural(username, file_info.usr))) || (file_info.fpms[9] == 'x') || (file_info.fpms[9] == 't')){
            		file_info.enbl = true;
            	}else{
            		file_info.enbl = false;
            	}
            	if(lin == 0){
            		file_info.cope = false;
            	}else{
            		file_info.cope = true;
            	}
            }else{
    			file_info.enbl = false;
    			file_info.cope = false;
    		}

            lst_add(*vhd, &file_info);

            line = strtok_r(NULL, "\n", &saveptr);
        }
    }

    if (partial_line[0] != '\0') {
        line = partial_line;
        char *token = strtok(line, "|");
        if (token != NULL) {
			strncpy(file_info.fpms, token, pmln);
			for (lin = 0; 'x' != ftpmp[lin].flg; lin++){
				if(0 == strncmp(token, &(ftpmp[lin].flg), 1)){
					break;
				}
			}
			memset(file_info.fltp, 0, pmln);
			snprintf(file_info.fltp, pmln, "%s", ftpmp[lin].des);
		}

        token = strtok(NULL, "|");
        if (token != NULL) file_info.lknu = atoi(token);

        token = strtok(NULL, "|");
        if (token != NULL) strncpy(file_info.usr, token, dtln);

        token = strtok(NULL, "|");
        if (token != NULL) strncpy(file_info.grp, token, dtln);

        token = strtok(NULL, "|");
        if (token != NULL) file_info.siz = strtoul(token, NULL, 10);

        token = strtok(NULL, "|");
        if (token != NULL) strncpy(file_info.date, token, dtln);

        token = strtok(NULL, "|");
        if (token != NULL) strncpy(file_info.flnm, token, urln);

        memset(file_info.flpt, 0, flptln);
        if(strlen(path) == 1){
			snprintf(file_info.flpt, flptln, "/%s", file_info.flnm);
		}else{
			snprintf(file_info.flpt, flptln, "%s/%s", path, file_info.flnm);
		}

        if((lin == 0) || (lin == 1)){
        	if(((file_info.fpms[3] == 'x') && (0 == phy_strcmp_natural(username, file_info.usr))) || (file_info.fpms[9] == 'x') || (file_info.fpms[9] == 't')){
        		file_info.enbl = true;
        	}else{
        		file_info.enbl = false;
        	}
        	if(lin == 0){
        		file_info.cope = false;
        	}else{
        		file_info.cope = true;
        	}
        }else{
			file_info.enbl = false;
			file_info.cope = false;
		}

        lst_add(*vhd, &file_info);
    }    
//out:
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
}

void init_vplst(vphd** vhd)
{
	vphd* head = (vphd*)malloc(sizeof(vphd));
	head->cur = NULL;
	head->dlt = NULL;
	head->len = 0;
	*vhd = head;
}

char* filnm2str(vphd *head)
{
	char* res = NULL;
    vplst *temp = head->dlt;
	while (temp != NULL) {
		filst *file_info = (filst *)temp->data;
//		printf("Name: %s\n", file_info->flpt);
		res = buy_some_mem(res, file_info->flpt);
		res = buy_some_mem(res, "|");
		temp = temp->next;
	}
	return res;
}

void filst2mem(vphd *head, void** ret, size_t* len)
{
	filst* res = NULL;
	filst *fif = NULL;
	vplst *temp = head->dlt;
    size_t cnt = head->len;
    size_t dln = sizeof(filst)*cnt;
    int i = 0;
    res = (filst*)phy_calloc(res, cnt, sizeof(filst));
	while (temp != NULL) {
		fif = (filst *)temp->data;
		memcpy(&(res[i]), fif, sizeof(filst));
		i++;
		temp = temp->next;
	}
	*ret = res;
	*len = dln;
}

void list_remote_files_local(const char* usr, const char *password, const char *path, vphd **vhd)
{
    char command[256];
    snprintf(command, sizeof(command), "ls -l %s %s | tail -n +2 | awk '{print $1\"|\"$2\"|\"$3\"|\"$4\"|\"$5\"|\"$6\"|\"$7\"|\"$8}' 2>&1", "--time-style='+%Y%m%d-%H:%M:%S'", path);
    filst file_info;
    char *line;
    int lin = 0;
    struct strlist* head = NULL;
    struct strlist* p = NULL;
    create_strlist(&head);
    get_result_strlist(command, head, false);
    p = head->next;
    while(p){
    	line = p->data;
		char *token = strtok(line, "|");
		if (token != NULL) {
			strncpy(file_info.fpms, token, pmln);
			for (lin = 0; 'x' != ftpmp[lin].flg; lin++){
				if(0 == strncmp(token, &(ftpmp[lin].flg), 1)){
					break;
				}
			}
			memset(file_info.fltp, 0, pmln);
			snprintf(file_info.fltp, pmln, "%s", ftpmp[lin].des);
		}

		token = strtok(NULL, "|");
		if (token != NULL) file_info.lknu = atoi(token);

		token = strtok(NULL, "|");
		if (token != NULL) strncpy(file_info.usr, token, dtln);

		token = strtok(NULL, "|");
		if (token != NULL) strncpy(file_info.grp, token, dtln);

		token = strtok(NULL, "|");
		if (token != NULL) file_info.siz = strtoul(token, NULL, 10);

		token = strtok(NULL, "|");
		if (token != NULL) snprintf(file_info.date, dtln, "%s", token);

		token = strtok(NULL, "|");
		if (token != NULL) strncpy(file_info.flnm, token, urln);

		memset(file_info.flpt, 0, flptln);
		if(strlen(path) == 1){
			snprintf(file_info.flpt, flptln, "/%s", file_info.flnm);
		}else{
			snprintf(file_info.flpt, flptln, "%s/%s", path, file_info.flnm);
		}

		if((lin == 0) || (lin == 1)){
			if(((file_info.fpms[3] == 'x') && (0 == phy_strcmp_natural(usr, file_info.usr))) || (file_info.fpms[9] == 'x') || (file_info.fpms[9] == 't')){
				file_info.enbl = true;
			}else{
				file_info.enbl = false;
			}
			if(lin == 0){
				file_info.cope = false;
			}else{
				file_info.cope = true;
			}
		}else{
			file_info.enbl = false;
			file_info.cope = false;
		}
		lst_add(*vhd, &file_info);
		p = p->next;
    }
    destory_strlist(head);
}

vphd* lst_filebrowser_local(const char* usr, const char* pwd, const char* dftpt)
{
	vphd* vhd = NULL;
	init_vplst(&vhd);
	list_remote_files_local(usr, pwd, dftpt, &vhd);
	return vhd;
}

vphd* lst_filebrowser(const char* add, const char* usr, const char* pwd, const char* dftpt)
{
	vphd* vhd = NULL;
	init_vplst(&vhd);
	list_remote_files(add, usr, pwd, dftpt, &vhd);
	return vhd;
}

