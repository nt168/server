#include <stdio.h>
#include "poller.h"
#include "tpool.h"
#include "common.h"
#include "log.h"
#include "messtype.h"
#include "phy_sql/phy_sql.h"
#include "phy_sql/sqlite3.h"
#include "phy_ssh.h"
#include "base64.h"
#include "channel.h"

extern sqlite3* phydb;

void poller_handle(const char* a, const char* b, const char *c, void **arg)
{
	char cmd[128] = {0};
//	char* pob = NULL;
	void** record = NULL;
	record = arg;
//	pob = (char*)(*arg);
	snprintf(cmd, 128, "ls /home/%s/agent", b);
	run_phy_ssh_record(a, b, c, (const char*)cmd, (char**)record);
}

void poller_walker(const char* a, const char* b, const char *c, void **arg)
{
	void** record = NULL;
	record = arg;
	int rc = 0;
	rc = create_sshsession(a, b, c);
	if(rc != 0){
		phy_log(LOG_LEVEL_ERR, "Error connecting to localhost: %s", a);
	}else{
		*record = (void*)malloc(1);
	}
}

void pohandle(const char* a, const char* b, const char *c, void **arg)
{
	char cmd[128] = {0};
//	char* pob = NULL;
	void** record = NULL;
	record = arg;
//	pob = (char*)(*arg);
	snprintf(cmd, 128, "ls /home/%s/agent", b);
//	run_phy_ssh_record(a, b, c, (const char*)cmd, (char**)record);
	phy_ssh_poller(a, b, c, (const char*)cmd, (char**)record);
}

void poller_resuts_handle(char* record)
{
	char* result = NULL;
	char* sta = NULL;
	char **arr = NULL;
	char **stmp = NULL;
	char *trecd = NULL;
	struct transfer tran = {0};
	tran.mma.matp = STATUS;
	tran.mma.mst = ALLSTAT;
	if(record == NULL){
		return;
	}

	int i = 0;

	phy_strarr_init(&arr);
	str_to_arr(record, "PhyDelimiter", &arr);

	for (stmp = arr; NULL != *stmp; stmp++){
		printf("result : %s\n", *stmp);
		result = get_str_between_two_words(*stmp, "]", NULL);
		sta = get_str_between_two_words(*stmp, "[", "]");
		if(sta == NULL || strlen(sta) < 2){
			phy_log(LOG_LEVEL_ERR, "poller_resuts_handle: Encounter an error.");
		}
		trecd = buy_some_mem(trecd, sta);
		phy_free(sta);
		trecd = buy_some_mem(trecd, ":");
		if(result == NULL || strlen(result) < 2 || strstr(result, "No such file or directory")){
			trecd = buy_some_mem(trecd, "unagented");
		}else{
			phy_free(result);
			trecd = buy_some_mem(trecd, "installed");
		}
		trecd = buy_some_mem(trecd, ";");
		i++;
	}
	snprintf(tran.td.mes, 1280, "%s", trecd);
	write_message_to_controller((char*)(&tran), sizeof(struct transfer));
	phy_strarr_free(arr);
	arr = NULL;
	phy_free(trecd);
}

void* poller_pthread(void* arg)
{
	struct transfer tran = {0};
	tran.mma.matp = STATUS;
	tran.mma.mst = ALLSTAT;
	agtrow* head = NULL;
	agtrow* curr = NULL;
	agtrow* temp = NULL;
	char* mes = NULL;
	int rc = 0;
	const char* sql = "SELECT * FROM agent;";
	while(1){

		head = NULL;
		rc = phy_sql_reqagts(m_phydb, sql, &head, 5, 1);
		if(rc != SQLITE_OK){
			continue;
		}
		curr = head;
		while(curr != NULL){
//			printf("Id = %d, Add = %s, Usr = %s, Pwd = %s, Sta = %s\n", curr->id, curr->add, curr->usr, curr->pwd, curr->sta);
			mes = buy_some_mem((char*)(mes), (const char*)curr->add);
			mes = buy_some_mem((char*)(mes), ":");
			mes = buy_some_mem((char*)(mes), (const char*)curr->usr);
			mes = buy_some_mem((char*)(mes), ":");
			mes = buy_some_mem((char*)(mes), (const char*)curr->sta);
			mes = buy_some_mem((char*)(mes), ";");
			temp = curr;
			curr = curr->next;
			phy_free(temp);
		}

		if(mes != NULL){
			memset(tran.td.mes, 0, 1280);
			snprintf(tran.td.mes, strlen(mes) + 1, "%s", mes);
			phy_free(mes);
			write_message_to_controller((char*)(&tran), sizeof(struct transfer));
		}else{
			memset(tran.td.mes, 0, 1280);
			write_message_to_controller((char*)(&tran), sizeof(struct transfer));
		}
		sleep(5);
	}
	return NULL;
}

unsigned int phy_poller()
{
//	tpool_t *tpool = tpool_create(1);
	phy_setproctitle("Poller, Pid:%d", (int)getpid());
	phy_log(LOG_LEVEL_TRACE, "phy_server: Poller, Pid:%d.", (int)getpid());
	pthread_t popt;
	pthread_create(&popt, NULL, poller_pthread, NULL);
	char* poller_buf = NULL;
#if 1
	while(1){
//		phy_log(LOG_LEVEL_TRACE, "Start phy_poller-----------------------------");
//		physql_agent_execute(pohandle, (const char*)NULL, (const char*)NULL, (const char*)NULL, (void**)(&poller_buf));
		phyagents_walker(poller_walker, (const char*)NULL, (const char*)NULL, (const char*)NULL, (void**)(&poller_buf));
		phy_free(poller_buf);
		sleep(1);
	}
#endif
	pthread_join(popt, NULL);
	return 0;
}
