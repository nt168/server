#ifndef PHYSQL_H
#define PHYSQL_H
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "../phy_sql/sqlite3.h"
#include "../phy_def.h"

typedef struct {
    sqlite3 *db;
    int  lock_fd;
} safedb;

#define MAX_RETRIES 5
#define RETRY_DELAY 1000 //milliseconds

typedef struct agtrow{
	int id;
	char add[20];
	char usr[20];
	char pwd[20];
	char sta[20];
	struct agtrow *next;
}agtrow;

typedef struct hisrow{
	int id;
	char add[20];
	char typ[20];
	char dte[20];
	char cmd[256];
	char res[256];
	struct hisrow *next;
}hisrow;

void close_db(safedb *h);
safedb* open_db(const char *dbpath);
int execute_sql(sqlite3 *db, const char* sql);
int physql_add_agent(sqlite3 *db, const char* add, const char* usr, const char* pwd, const char* sta);
int physql_del_agent(sqlite3 *db, const char* add, const char* usr, const char* pwd, const char* sta);
int physql_udt_agent(sqlite3 *db, const char* add, const char* usr, const char* pwd, const char* sta);
int physql_query_agent(sqlite3 *db);
int physql_add_history(sqlite3 *db, const char* timestamp, const char* command, const char* result);
int physql_del_history(sqlite3 *db, const char* timestamp, const char* command, const char* result);
int physql_udt_history(sqlite3 *db, int id,  const char* timestamp, const char* command, const char* result);
int physql_query_history(sqlite3 *db);
//int physql_query_agent_execute(sqlite3 *db, void *hdfun, void** ags);
//int physql_query_agent_execute(sqlite3 *db, void *hdfun, char* a, char* b, char* c, void** ags);
typedef void (*hdfun)(const char* a, const char* b, const char *c, void** ags);
int physql_query_agent_execute(sqlite3 *db, hdfun hdf, const char* a, const char* b, const char *c, void** ags);
int physql_agent_execute(hdfun hdf, const char* a, const char* b, const char* c, void** ags);
int phyagents_walker(hdfun hdf, const char* a, const char* b, const char* c, void** ags);
//void poller_handle(const char* a, const char* b, const char *c, void **arg);
int physql_init();
int phy_sql_exe(const char* dbpath, const char* sql, int attempts, int interval);
int physql_select(const char* add, char** usr, char** pwd, char** sta);
int phy_sql_reqagts(const char* dbpath, const char* sql, agtrow** head, int attempts, int interval);
bool physql_field_exist(sqlite3 *db, const char* tab, const char* fie, const char* des);
#endif
