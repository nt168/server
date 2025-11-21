#ifndef HISTORY_H
#define HISTORY_H
#include "messtype.h"
#include "channel.h"
#include "common.h"
#include "phy_def.h"
#include "log.h"
#include "phy_sql/phy_sql.h"
void init_history();
void handle_his(meshis mhi, trandst td);
bool delete_history(const char* add, const char* typ, const char* dat);
bool insert_history(const char* add, const char* typ, const char* dat, const char* cmd, const char* pth);
bool get_history(const char* add, const char* typ, hisrow** head);
#endif
