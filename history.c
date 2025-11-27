#include "history.h"

static int physql_his_cb(void* data, int argc, char **argv, char **cloname)
{
	hisrow **head = (hisrow **)data;
	hisrow *nrow = malloc(sizeof(hisrow));
	memset(nrow, 0 , sizeof(hisrow));
	if(nrow == NULL){
		fprintf(stderr, "out of memmory\n");
		exit(1);
	}

	nrow->id = atoi(argv[0]);
	strncpy(nrow->add, argv[1], sizeof(nrow->add) - 1);
	strncpy(nrow->typ, argv[2], sizeof(nrow->typ) - 1);
	strncpy(nrow->dte, argv[3], sizeof(nrow->dte) - 1);
	strncpy(nrow->cmd, argv[4], sizeof(nrow->cmd) - 1);
	strncpy(nrow->res, argv[5], sizeof(nrow->res) - 1);
	nrow->next = *head;
	*head = nrow;
	return 0;
}

void init_history()
{
//	char str[256] = {0};
	ddlhx *dh = NULL;
    ddlx *sct = NULL;

    ddlx_init(&dh);

	load_fils(m_rstdir, &dh);

	sct = dh->entr;

	while(sct)
	{
//		phy_snprintf(str, strlen(((char*)(sct->data))) + 1, "%s", ((char*)(sct->data)));
		printf("%s\n", (char*)sct->data);
		sct = sct->next;
	}

	goto out;
out:
	ddlx_destory(dh);
	return;
}

bool insert_history(const char* add, const char* typ, const char* dat, const char* cmd, const char* pth)
{
	int rc = 0;

	safedb* sdb = NULL;
	sqlite3_stmt *stmt;
//	char sql[256] = {0};

	sdb = open_db(m_phydb);
	if(sdb == NULL){
		return false;
	}
#if 0
	sqlite3_stmt *stmt;
	snprintf(sql, 256, "SELECT EXISTS(SELECT 1 FROM %s WHERE %s = ?);", "history", "timestamp");
	sqlite3_prepare_v2(sdb->db, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, dat, -1, SQLITE_STATIC);
	if(sqlite3_step(stmt) == SQLITE_ROW){
		rc = sqlite3_column_int(stmt, 0);
		if(rc){
			phy_log(LOG_LEVEL_WARNING, "insert_history: [history]-(timestamp)_%s already exists!", dat);
			return true;
		}
	}
#endif

	const char *sql = "INSERT INTO history(address, type, timestamp, command, result) VALUES(?,?,?,?,?)";
	sqlite3_prepare_v2(sdb->db, sql, -1, &stmt, NULL);

	// 绑定参数时自动处理转义
	sqlite3_bind_text(stmt, 1, add, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 2, typ, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 3, dat, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 4, cmd, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 5, pth, -1, SQLITE_TRANSIENT);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		phy_log(LOG_LEVEL_ERR, "insert_history:  err!");
		close_db(sdb);
		return false;
	}
	sqlite3_finalize(stmt);

//	rc = sqlite3_exec(sdb->db, sql, 0, 0, &errmsg);
//	if(rc != SQLITE_OK){
//		sqlite3_free(errmsg);
//		phy_log(LOG_LEVEL_ERR, "insert_history:  err!");
//		close_db(sdb);
//		return false;
//	}

	close_db(sdb);
	return true;
}

bool delete_history(const char* add, const char* typ, const char* dat)
{

	int rc = 0;
	char* errmsg = NULL;
	safedb* sdb = NULL;
	char sql[256] = {0};

	sdb = open_db(m_phydb);
	if(sdb == NULL){
		return false;
	}

//	snprintf(sql, sizeof(sql), "DELETE FROM history "
//								"WHERE address = '%s' "
//								"AND type = '%s' "
//								"AND timestamp = '%s';"
//								, add, typ, dat);

	snprintf(sql, sizeof(sql), "DELETE FROM history "
								"WHERE timestamp = '%s' ;"
								, dat);

	rc = sqlite3_exec(sdb->db, sql, 0, 0, &errmsg);
	if(rc != SQLITE_OK){
		sqlite3_free(errmsg);
		phy_log(LOG_LEVEL_ERR, "insert_history:  err!");
		return false;
	}

	close_db(sdb);
	return true;
}

bool get_history(const char* add, const char* typ, hisrow** head)
{
	int rc = 0;
	char* errmsg = NULL;
	safedb* sdb = NULL;
	char sql[256] = {0};

	sdb = open_db(m_phydb);
	if(sdb == NULL){
		return false;
	}

	snprintf(sql, sizeof(sql), "SELECT * FROM history "
									"WHERE address = '%s' "
									"AND type = '%s' "
									, add, typ);

	rc = sqlite3_exec(sdb->db, sql, physql_his_cb, head, &errmsg);
	if(rc != SQLITE_OK){
		sqlite3_free(errmsg);
		close_db(sdb);
		return false;
	}

	close_db(sdb);
	return true;
}

void handle_his(meshis mhi, trandst td)
{
	char* mes = NULL;
	hisrow* head = NULL;
	hisrow* curr = NULL;
	hisrow* temp = NULL;

	struct transfer tran = {0};

	switch(mhi){

		case HISDEL:
			delete_history(td.receiver, HIS2STR(td.affi), td.date);
		break;

		case HISSEL:
			tran.mma.matp = HISTORY;
			tran.mma.mhi = HISSEL;

			if(true == get_history(td.receiver, HIS2STR(td.affi), &head))
			{
				curr = head;
				while(curr != NULL){

					mes = buy_some_mem((char*)(mes), (const char*)curr->add);
					mes = buy_some_mem((char*)(mes), ":");
					mes = buy_some_mem((char*)(mes), (const char*)curr->typ);
					mes = buy_some_mem((char*)(mes), ":");
					mes = buy_some_mem((char*)(mes), (const char*)curr->dte);
					mes = buy_some_mem((char*)(mes), ";");
					mes = buy_some_mem((char*)(mes), (const char*)curr->cmd);
					mes = buy_some_mem((char*)(mes), ";");
					mes = buy_some_mem((char*)(mes), (const char*)curr->res);
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

			}else{

				phy_log(LOG_LEVEL_ERR, "handle_his:  No historical data obtained!");

			}

		break;

		default:
		break;
	}
}
