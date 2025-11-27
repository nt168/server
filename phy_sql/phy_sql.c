#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/queue.h>
#include <pthread.h>
#include "../base64.h"
#include "phy_sql.h"

#include "../common.h"
#include "../log.h"
#include "sqlite3.h"
sqlite3 *phydb;
const char* odbpth="/opt/phytune/server/conf/phyconf.db";

/**
 * 返回 safedb*，失败返回 NULL。
 */
safedb* open_db(const char *dbpath)
{
    safedb    *h;
    char       lockpath[PATH_MAX];
    struct flock fl = {0};
    int        fd;
    sqlite3   *db = NULL;

    snprintf(lockpath, sizeof(lockpath), "%s.lock", dbpath);
    fd = open(lockpath, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        perror("open(lockfile)");
        return NULL;
    }

    fl.l_type   = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;
    if (fcntl(fd, F_SETLKW, &fl) < 0) {
        perror("fcntl(lock)");
        close(fd);
        return NULL;
    }

    if (sqlite3_open_v2(dbpath, &db,
         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
         NULL) != SQLITE_OK)
    {
        fprintf(stderr, "sqlite3_open: %s\n", sqlite3_errmsg(db));
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
        close(fd);
        return NULL;
    }

    /* 可选：设置忙超时和 WAL 模式提升并发性能 */
    sqlite3_busy_timeout(db, 1000);
    sqlite3_exec(db, "PRAGMA journal_mode = WAL;", NULL, NULL, NULL);

    h = malloc(sizeof(*h));
    h->db      = db;
    h->lock_fd = fd;
    return h;
}

void close_db(safedb *h)
{
    struct flock fl = {0};
    if (!h) return;

    /* 先关闭 SQLite 连接 */
    sqlite3_close(h->db);

    /* 再释放文件锁 */
    fl.l_type   = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;
    if (fcntl(h->lock_fd, F_SETLK, &fl) < 0) {
        perror("fcntl(unlock)");
    }
    close(h->lock_fd);

    free(h);
}

int execute_sql(sqlite3 *db, const char* sql)
{
	char *err_msg = 0;
	int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);

	if(rc != SQLITE_OK){
		fprintf(stderr, "SQL error: %s\n", err_msg);
		sqlite3_free(err_msg);
		return rc;
	}
	return SQLITE_OK;
}

static int phy_sql_callback(void* data, int argc, char **argv, char **cloname)
{
	agtrow **head = (agtrow **)data;
	agtrow *nrow = malloc(sizeof(agtrow));
	memset(nrow, 0 , sizeof(agtrow));
	if(nrow == NULL){
		fprintf(stderr, "out of memmory\n");
		exit(1);
	}

	nrow->id = atoi(argv[0]);
	strncpy(nrow->add, argv[1], sizeof(nrow->add) - 1);
	strncpy(nrow->usr, argv[2], sizeof(nrow->usr) - 1);
	strncpy(nrow->pwd, argv[3], sizeof(nrow->pwd) - 1);
	strncpy(nrow->sta, argv[4], sizeof(nrow->sta) - 1);
	nrow->next = *head;
	*head = nrow;
	return 0;
}

int phy_sql_exe(const char* dbpath, const char* sql, int attempts, int interval)
{
	int rc;
	sqlite3 *db = NULL;
	char* errmsg = NULL;
	for(int i=0; i< attempts; i++){
		if(db == NULL){
			rc = sqlite3_open(dbpath, &db);
			if(rc != SQLITE_OK){
				sleep(interval);
				i++;
				db = NULL;
				continue;
			}
		}
		rc = sqlite3_exec(db, sql, 0, 0, &errmsg);
		if(rc != SQLITE_OK){
			sleep(interval);
			i++;
			sqlite3_free(errmsg);
			continue;
		}
		break;
	}
	if(db != NULL){
		sqlite3_close(db);
	}
	return rc;
}

int phy_sql_reqagts(const char* dbpath, const char* sql, agtrow** head, int attempts, int interval)
{
	int rc;
	sqlite3 *db = NULL;
	char* errmsg = NULL;
	for(int i=0; i< attempts; i++){
		if(db == NULL){
			rc = sqlite3_open(dbpath, &db);
			if(rc != SQLITE_OK){
				sleep(interval);
				i++;
				db = NULL;
				continue;
			}
		}
		rc = sqlite3_exec(db, sql, phy_sql_callback, head, &errmsg);
		if(rc != SQLITE_OK){
			sleep(interval);
			i++;
			sqlite3_free(errmsg);
			continue;
		}
		break;
	}
	if(db != NULL){
		sqlite3_close(db);
	}
	return rc;
}

sqlite3* physql_open(const char* dbpath, const char* sql, agtrow** head, int attempts, int interval)
{
	int rc;
	sqlite3 *db = NULL;
	char* errmsg = NULL;
	for(int i=0; i< attempts; i++){
		if(db == NULL){
			rc = sqlite3_open(dbpath, &db);
			if(rc != SQLITE_OK){
				sleep(interval);
				i++;
				db = NULL;
				continue;
			}
		}
		rc = sqlite3_exec(db, sql, phy_sql_callback, head, &errmsg);
		if(rc != SQLITE_OK){
			sleep(interval);
			i++;
			sqlite3_free(errmsg);
			continue;
		}
		break;
	}
	if(db != NULL){
		sqlite3_close(db);
	}
	return db;
}

#if 0
int physql_agent_udt(sqlite3 *db, const char* add, const char* usr, const char* pwd, const char* sta)
{
	char sql[256] = {0};
	snprintf(sql, sizeof(sql), "UPDATE agent SET user = '%s', password = '%s', status = '%s', WHERE address = %s;", usr, pwd, sta, add);
	return execute_sql(db, sql);
}
#endif

int prepare_statement_with_retry(sqlite3 *db, sqlite3_stmt **stmt, const char* sql)
{
	int rc;
	int retries = MAX_RETRIES;
	while(retries-- > 0){
//		rc = sqlite3_prepare_v2(db, sql, -1, stmt, 0);
		rc = execute_sql(db, sql);
		if(rc == SQLITE_BUSY){
			return rc;
		}
		sqlite3_sleep(RETRY_DELAY);
	}
	return 0;
}

int physql_add_agent(sqlite3 *db, const char* add, const char* usr, const char* pwd, const char* sta)
{
	sqlite3_stmt *stmt;
	int rc;
	char sql[256] = {0};
	snprintf(sql, sizeof(sql), "INSERT INTO agent (address, user, password, status) VALUES ('%s', '%s', '%s', '%s');", add, usr, pwd, sta);
	rc = prepare_statement_with_retry(db, &stmt, sql);
	if(rc != SQLITE_OK){
		fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return rc;
	}
	sqlite3_finalize(stmt);
	return 0;
//	return execute_sql(db, sql);
}

#if 0
int physql_del_agent(sqlite3 *db, const char* add, const char* usr, const char* pwd, const char* sta)
{
	char sql[128] = {0};
//	snprintf(sql, sizeof(sql), "DELETE FROM agent (address, user, password, status) VALUES ('%s', '%s', '%s', '%s');", add, usr, pwd, sta);
	snprintf(sql, sizeof(sql), "DELETE FROM agent WHERE address = %s;", add);
	return execute_sql(db, sql);
}

int physql_udt_agent(sqlite3 *db, const char* add, const char* usr, const char* pwd, const char* sta)
{
	char sql[256] = {0};
	snprintf(sql, sizeof(sql), "UPDATE agent SET user = '%s', password = '%s', status = '%s', WHERE address = %s;", usr, pwd, sta, add);
	return execute_sql(db, sql);
}
#endif

int physql_query_agent(sqlite3 *db)
{
	const char* sql = "SELECT * FROM agent;";
	sqlite3_stmt *stmt;
	int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

	if(rc != SQLITE_OK){
		fprintf(stderr, "Failed to fetch agents: %s\n", sqlite3_errmsg(db));
		return rc;
	}

	while((rc = sqlite3_step(stmt)) == SQLITE_ROW){

		int id = sqlite3_column_int(stmt, 0);
		const unsigned char *address = sqlite3_column_text(stmt, 1);
		const unsigned char *user = sqlite3_column_text(stmt, 2);
		const unsigned char *password = sqlite3_column_text(stmt, 3);
		const unsigned char *status = sqlite3_column_text(stmt, 4);
		printf("ID: %d, Address: %s, User: %s, Password: %s, Status: %s\n", id, address, user, password, status);
	}
	sqlite3_finalize(stmt);
	return SQLITE_OK;
}

int physql_select(const char* add, char** usr, char** pwd, char** sta)
{
	int rc = 0;
	char sql[256] = {0};
	snprintf(sql, 256, "SELECT * FROM agent WHERE address = '%s';", add);
	agtrow* head = NULL;
	agtrow* curr = NULL;
	agtrow* temp = NULL;

	rc = phy_sql_reqagts(m_phydb, sql, &head, 5, 1);
	curr = head;
	while(curr != NULL){
		*usr = strdup(curr->usr);
		*pwd = strdup(curr->pwd);
		*sta = strdup(curr->sta);
		temp = curr;
		curr = curr->next;
		free(temp);
	}
	return rc;
}

int physql_agent_execute(hdfun hdf, const char* a, const char* b, const char* c, void** ags)
{
	int rc = 0;
	char sql[256] = {0};
	agtrow* head = NULL;
	agtrow* curr = NULL;
	agtrow* temp = NULL;
	char* rest = NULL;
	snprintf(sql, sizeof(sql), "%s", "SELECT * FROM agent;");
	rc = phy_sql_reqagts(m_phydb, sql, &head, 5, 1);
	if(rc != SQLITE_OK){
		return rc;
	}
	memset(sql, 0, 256);
	curr = head;
	while(curr != NULL){
//		printf("Id = %d, Add = %s, Usr = %s, Pwd = %s, Sta = %s\n", curr->id, curr->add, curr->usr, curr->pwd, curr->sta);
		hdf((const char*)curr->add, (const char*)curr->usr, (const char*)curr->pwd, (void**)(&rest));
		if(rest == NULL || strlen(rest) < 2 || strstr(rest, "No such file or directory") || strstr(rest, "没有那个文件或目录")){
			snprintf(sql, sizeof(sql), "UPDATE agent SET status = 'unagented' WHERE address = '%s';", curr->add);
		}else{
			snprintf(sql, sizeof(sql), "UPDATE agent SET status = 'installed' WHERE address = '%s';", curr->add);
		}
		printf("[%s] %s \n", (const char*)curr->add, (rest == NULL)?"null":rest);
		phy_free(rest);
		temp = curr;
		curr = curr->next;
		free(temp);

		rc = phy_sql_exe(m_phydb, sql, 5, 1);
		if(rc != SQLITE_OK){
			continue;
		}
	}
	return rc;
}

void nt_encryption(char* opt, const char* ipt)
{
	base64_encode((const unsigned char *)ipt, strlen(ipt), opt);
}

char* convert_data(const char* add, const char* usr, const char* pwd)
{
	char tstr[128]={0};
	char *tdta = NULL;
	char* num = NULL;
	char bs64opt[64] = {0};
	num = ip42uint64s(add);
	phy_snprintf(tstr, 128, "9002;%s;%s;2024061913;standby;", usr, pwd);
	nt_encryption(bs64opt, tstr);
	tdta = (char*)phy_malloc(tdta, 256);
	phy_snprintf(tdta, 256, "[%s|%s]", num, bs64opt);
	phy_free(num);
	return tdta;
}
typedef struct Node {
    char *data;
    size_t length;
    TAILQ_ENTRY(Node) nodes;
} Node;
TAILQ_HEAD(tailhead, Node);
void append_node(struct tailhead *head, const char *data, size_t length)
{
    Node *new_node = (Node*)malloc(sizeof(Node));
    new_node->data = (char*)malloc(length + 1);
    memcpy(new_node->data, data, length);
    new_node->length = length;
    new_node->data[length] = '\0';
    TAILQ_INSERT_TAIL(head, new_node, nodes);
}
void read_file_to_list(struct tailhead *head, const char* strcont, size_t size)
{
	const char* start = strcont;
	const char* end = start;
	while(( end = memchr(start, '\n', size - (start - strcont))) != NULL){
		append_node(head, start, end-start);
		start = end + 1;
	}
	if(start < strcont + size){
		append_node(head, start, strcont + size - start);
	}
}
void clear_list(struct tailhead *head) {
    while (!TAILQ_EMPTY(head)) {
        Node *temp = TAILQ_FIRST(head);
        TAILQ_REMOVE(head, temp, nodes);
        free(temp->data);
        free(temp);
    }
}
int mmap_tplst(const char* filth, struct tailhead lst)
{
    int fd;
    struct stat st;
    size_t size;
    char *content;
	fd = open(filth, O_RDWR);
	if (fd == -1) {
		perror("open");
		return 1;
	}
	if (fstat(fd, &st) == -1) {
		perror("fstat");
		close(fd);
		pthread_exit(NULL);
	}
	size = st.st_size;
	if (size == 0) {
		close(fd);
		return 1;
	}

	content = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (content == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return 1;
	}
	clear_list(&lst); // 清空临时链表
	read_file_to_list(&lst, content, size);
	if (munmap(content, size) == -1) {
		perror("munmap");
		return 1;
	}
	close(fd);
	return 0;
}
int sync_data(const char* odbfil, struct tailhead lst)
{
    struct tailhead tplst;
    TAILQ_INIT(&tplst);
    int fd;
    struct stat st;
    size_t size;
    Node *tp_node = NULL;
    Node *dt_node = NULL;

    fd = open(odbfil, O_RDWR);
	if (fd == -1) {
		perror("open");
		return 1;
	}

	if (fstat(fd, &st) == -1) {
		perror("fstat");
		close(fd);
		pthread_exit(NULL);
	}

	size = st.st_size;
//size为0表示目标配置以及清空此时如果lst有数据应该将 lst中数据插入到此同步文件中
	if (size == 0) {
		dt_node = TAILQ_FIRST(&lst);
		while (dt_node != NULL) {
			write(fd, dt_node->data, strlen(dt_node->data));
			write(fd, "\n", 1);
			dt_node = TAILQ_NEXT(dt_node, nodes);
		}
	}
	close(fd);

    if (mmap_tplst(odbfil, tplst) != 0) {
        perror("create tplst");
        return 1;
    }
	int need_sync = 0;
	tp_node = TAILQ_FIRST(&tplst);
	dt_node = TAILQ_FIRST(&lst);
	while (tp_node != NULL && dt_node != NULL) {
		if (strcmp(tp_node->data, dt_node->data) != 0) {
			need_sync = 1;
			break;
		}
		tp_node = TAILQ_NEXT(tp_node, nodes);
		dt_node = TAILQ_NEXT(dt_node, nodes);
	}
	if (tp_node != NULL || dt_node != NULL) {
		need_sync = 1;
	}
	clear_list(&tplst);
	if (need_sync) {
		int fd = open(odbfil, O_RDWR | O_TRUNC | O_CREAT, 0666);
		if (fd == -1) {
			perror("open");
			return 1;
		}
		dt_node = TAILQ_FIRST(&lst);
		while (dt_node != NULL) {
			write(fd, dt_node->data, strlen(dt_node->data));
			write(fd, "\n", 1);
			dt_node = TAILQ_NEXT(dt_node, nodes);
		}
		close(fd);
	}
    return 0;
}
int phyagents_walker(hdfun hdf, const char* a, const char* b, const char* c, void** ags)
{
	int rc = 0;
	char sql[256] = {0};
	agtrow* head = NULL;
	agtrow* curr = NULL;
	agtrow* temp = NULL;
	char* tstr = NULL;
	struct tailhead lst;
	char* rest = NULL;
	snprintf(sql, sizeof(sql), "%s", "SELECT * FROM agent;");
	rc = phy_sql_reqagts(m_phydb, sql, &head, 5, 1);
	if(rc != SQLITE_OK){
		return rc;
	}
	memset(sql, 0, 256);
	TAILQ_INIT(&lst);
	curr = head;
	while(curr != NULL){
//		printf("Id = %d, Add = %s, Usr = %s, Pwd = %s, Sta = %s\n", curr->id, curr->add, curr->usr, curr->pwd, curr->sta);
		hdf((const char*)curr->add, (const char*)curr->usr, (const char*)curr->pwd, (void**)(&rest));
		if(rest == NULL){
			snprintf(sql, sizeof(sql), "UPDATE agent SET status = 'unavailable' WHERE address = '%s';", curr->add);
		}else{
			snprintf(sql, sizeof(sql), "UPDATE agent SET status = 'available' WHERE address = '%s';", curr->add);
			phy_free(rest);
		}
//		printf("[%s] %s \n", (const char*)curr->add, (rest == NULL)?"null":rest);
		phy_log(LOG_LEVEL_TRACE, "phyagents_walker: [%s] %s.", (const char*)curr->add, (rest == NULL)?"null":rest);

		tstr = convert_data(curr->add, (const char*)curr->usr, (const char*)curr->pwd);
		append_node(&lst, tstr, strlen(tstr));
		phy_free(tstr);
		temp = curr;
		curr = curr->next;
		free(temp);

		rc = phy_sql_exe(m_phydb, sql, 5, 1);
		if(rc != SQLITE_OK){
			continue;
		}
	}
	sync_data(odbpth, lst);
	clear_list(&lst);
	return rc;
}

int physql_query_agent_execute(sqlite3 *db, hdfun hdf, const char* a, const char* b, const char* c, void** ags)
{
	int rc = 0;
	const char* sql = "SELECT * FROM agent;";
	agtrow* head = NULL;
	agtrow* curr = NULL;
	agtrow* temp = NULL;
	rc = phy_sql_reqagts(m_phydb, sql, &head, 5, 1);

	curr = head;
	while(curr != NULL){
		printf("Id = %d, Add = %s, Usr = %s, Pwd = %s, Sta = %s\n", curr->id, curr->add, curr->usr, curr->pwd, curr->sta);

		*ags = buy_some_mem((char*)(*ags), "PhyDelimiter");
		*ags = buy_some_mem((char*)(*ags), "[");
		*ags = buy_some_mem((char*)(*ags), (const char*)curr->add);
		*ags = buy_some_mem((char*)(*ags), ":");
		*ags = buy_some_mem((char*)(*ags), (const char*)curr->usr);
		*ags = buy_some_mem((char*)(*ags), "]");
		hdf((const char*)curr->add, (const char*)curr->usr, (const char*)curr->pwd, ags);

		temp = curr;
		curr = curr->next;
		free(temp);
	}
	return rc;

#if 0
	//	int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
	int rc = prepare_statement_with_retry(db, &stmt, sql);
	if(rc != SQLITE_OK){
		fprintf(stderr, "Failed to fetch agents: %s\n", sqlite3_errmsg(db));
		return rc;
	}

	while((rc = sqlite3_step(stmt)) == SQLITE_ROW){
//		int id = sqlite3_column_int(stmt, 0);
		const unsigned char *address = sqlite3_column_text(stmt, 1);
		const unsigned char *user = sqlite3_column_text(stmt, 2);
		const unsigned char *password = sqlite3_column_text(stmt, 3);
//		poller_handle();
		*ags = buy_some_mem((char*)(*ags), "PhyDelimiter");
		*ags = buy_some_mem((char*)(*ags), "[");
		*ags = buy_some_mem((char*)(*ags), (const char*)address);
		*ags = buy_some_mem((char*)(*ags), ":");
		*ags = buy_some_mem((char*)(*ags), (const char*)user);
		*ags = buy_some_mem((char*)(*ags), "]");
		hdf((const char*)address, (const char*)user, (const char*)password, ags);
//		*ags = buy_some_mem((char*)(*ags), "PhyDelimiter");
//		printf("ID: %d, Address: %s, User: %s, Password: %s\n", id, address, user, password);
	}

	sqlite3_finalize(stmt);
	return SQLITE_OK;
#endif
}

int physql_requests(const char* dbp, const char* sql, hisrow** head, int att, int itv)
{
	int rc;
	sqlite3 *db = NULL;
	char* errmsg = NULL;
	for(int i=0; i< att; i++){
		if(db == NULL){
			rc = sqlite3_open(dbp, &db);
			if(rc != SQLITE_OK){
				sleep(itv);
				i++;
				db = NULL;
				continue;
			}
		}
		rc = sqlite3_exec(db, sql, phy_sql_callback, head, &errmsg);
		if(rc != SQLITE_OK){
			sleep(itv);
			i++;
			sqlite3_free(errmsg);
			continue;
		}
		break;
	}
	if(db != NULL){
		sqlite3_close(db);
	}
	return rc;
}

bool physql_field_exist(sqlite3 *db, const char* tab, const char* fie, const char* des)
{
	int exi = 0;
	char sql[256] = {0};
	sqlite3_stmt *stmt;
	snprintf(sql, 256, "SELECT EXISTS(SELECT 1 FROM %s WHERE %s = ?);", tab, fie);
	sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, des, -1, SQLITE_STATIC);
	if(sqlite3_step(stmt) == SQLITE_ROW){
		exi = sqlite3_column_int(stmt, 0);
		if(exi){
			return true;
		}else{
			return false;
		}
	}
	return false;
}

#if 0
int physql_add_history(sqlite3 *db, const char* timestamp, const char* command, const char* result)
{
	char sql[256] = {0};
	snprintf(sql, sizeof(sql), "INSERT INTO history (timestamp, command, result) VALUES ('%s', '%s', '%s');", timestamp, command, result);
	return execute_sql(db, sql);
}

int physql_del_history(sqlite3 *db, const char* timestamp, const char* command, const char* result)
{
	char sql[128] = {0};
	snprintf(sql, sizeof(sql), "DELETE FROM history (timestamp, command, result) VALUES ('%s', '%s', '%s');", timestamp, command, result);
	return execute_sql(db, sql);
}

int physql_udt_history(sqlite3 *db, int id,  const char* timestamp, const char* command, const char* result)
{
	char sql[256] = {0};
	snprintf(sql, sizeof(sql), "UPDATE history SET timestamp= '%s', command = '%s', result = '%s' WHERE id = %d;", timestamp, command, result, id);
	return execute_sql(db, sql);
}
#endif

int physql_query_history(sqlite3 *db)
{
	const char* sql = "SELECT * FROM history;";
	sqlite3_stmt *stmt;
	int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

	if(rc != SQLITE_OK){
		fprintf(stderr, "Failed to fetch history records: %s\n", sqlite3_errmsg(db));
		return rc;
	}

	while((rc = sqlite3_step(stmt)) == SQLITE_ROW){

		int id = sqlite3_column_int(stmt, 0);
		const unsigned char *timestamp = sqlite3_column_text(stmt, 1);
		const unsigned char *command = sqlite3_column_text(stmt, 2);
		const unsigned char *result = sqlite3_column_text(stmt, 3);
		printf("ID: %d, Timestamp: %s, Command: %s, Result: %s\n", id, timestamp, command, result);
	}

	sqlite3_finalize(stmt);
	return SQLITE_OK;

}

int physql_init()
{
	sqlite3 *db = NULL;
	char sql[256] = {0};

	int rc;
	rc = sqlite3_initialize();
	if(rc != SQLITE_OK){
		fprintf(stderr, "Cannot initalize SQLite: %d\n", rc);
		return rc;
	}

	int thread_mode = sqlite3_threadsafe();
	printf("Sqlite thread mode : %d\n", thread_mode);

	rc = sqlite3_open(m_phydb, &db);
	if(rc){
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		return rc;
	}else{
		fprintf(stdout, "Opened database sucessfully\n");
	}

	phydb = db;
	sqlite3_busy_timeout(db, 5000);

#if 0
	const char *sql_drop_agent_table = "DROP TABLE IF EXISTS agent;";
	rc = execute_sql(db, sql_drop_agent_table);
	if(rc != SQLITE_OK){
		fprintf(stderr, "Failed to create agent table\n");
		sqlite3_close(db);
		return rc;
	}

	const char *sql_create_agent_table = "CREATE TABLE agent("
	                                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
	                                    "address TEXT NOT NULL, "
	                                    "user TEXT NOT NULL, "
	                                    "password TEXT NOT NULL, "
	                                    "status TEXT NOT NULL);";

	rc = execute_sql(db, sql_create_agent_table);
	if(rc != SQLITE_OK){
		fprintf(stderr, "Failed to create agent table\n");
		sqlite3_close(db);
		return rc;
	}

#endif

#if 0
	const char *sql_drop_history_table = "DROP TABLE IF EXISTS history;";
	rc = execute_sql(db, sql_drop_history_table);
	if(rc != SQLITE_OK){
		fprintf(stderr, "Failed to create agent table\n");
		sqlite3_close(db);
		return rc;
	}

	const char *sql_create_history_table = "CREATE TABLE history("
										"id INTEGER PRIMARY KEY AUTOINCREMENT, "
										"address TEXT NOT NULL, "
										"type TEXT NOT NULL, "
										"timestamp TEXT NOT NULL, "
										"command TEXT NOT NULL, "
										"result TEXT NOT NULL);";

	rc = execute_sql(db, sql_create_history_table);
	if(rc != SQLITE_OK){
		fprintf(stderr, "Failed to create history table\n");
		sqlite3_close(db);
		return rc;
	}
#endif

//	physql_add_agent(db, "10.31.94.247", "ft", "ft123123");
//	physql_add_history(db, "1478555222", "perf stat sleep 1", "/opt/phytune/server/results/10.31.94.247/topdowm.txt");
//	physql_query_agent(db);
//	physql_query_history(db);

//	execute_sql(db, "DELETE FROM agent");
//	execute_sql(db, "DELETE FROM history");
//
//	physql_add_agent(db, "10.31.94.247", "ft", "ft123123", "not installed");
//	physql_add_agent(db, "10.31.94.248", "ft", "ft123123", "not installed");
//	physql_add_agent(db, "10.31.94.249", "ft", "ft123123", "not installed");
//	physql_add_history(db, "1478555222", "perf stat sleep 1", "/opt/phytune/server/results/10.31.94.247/topdowm.txt");
//	insert_history("localhost", "TMA", "202505231134", "-u top l2d_cache_workload", "/opt/phytune/server/results/10.31.94.247/topdowm.txt");
//	physql_query_agent(db);
//	physql_query_history(db);

	return rc;
}

#if 0
extern sqlite3 *phydb;
bool physql_init()
{
	int rc = 0;
	const char *agt_tab = "CREATE TABLE IF NOT EXISTS agent("
							"id INTEGER PRIMARY KEY AUTOINCREMENT, "
							"address TEXT NOT NULL, "
							"user TEXT NOT NULL, "
							"password TEXT NOT NULL, "
							"status TEXT NOT NULL);";

	const char *his_tab = "CREATE TABLE IF NOT EXISTS history("
							"id INTEGER PRIMARY KEY AUTOINCREMENT, "
							"address TEXT NOT NULL, "
							"type TEXT NOT NULL, "
							"timestamp TEXT NOT NULL, "
							"command TEXT NOT NULL, "
							"result TEXT NOT NULL);";

/* 1. 启用序列化线程模式 */
	sqlite3_config(SQLITE_CONFIG_SERIALIZED);
	sqlite3_initialize();

/* 2. 打开主连接 */
	rc = sqlite3_open_v2(m_phydb, phydb,
						 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
						 NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(phydb));
		return false;
	}

/* 3. 公共配置：超时 + WAL + 表结构 */
	sqlite3_busy_timeout(phydb, 1000);
	sqlite3_exec(phydb, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

/* 4. 创建agent与history表 */
	 sqlite3_exec(phydb, agt_tab, NULL, NULL, NULL);
	 sqlite3_exec(phydb, his_tab, NULL, NULL, NULL);

	return true;
}
#endif
