#include "phy_mix.h"
#include "common.h"
#include "ntmp.h"

void handle_mix(mesmix mmi, trandst td)
{
	fil_remove("/tmp/kilflg");

	char* mes = NULL;
	char* res = NULL;
	hisrow* head = NULL;
	hisrow* curr = NULL;
	hisrow* temp = NULL;

	struct transfer tran = {0};

	if(strstr(td.receiver, "localhost")){
		return;
	}

	switch(mmi){

		case MIXALL:
			tran.mma.matp = MIX;
			tran.mma.mmi = MIXALL;
			tran.td.affi = td.affi;
			phy_log(LOG_LEVEL_TRACE, "handle_mix get_history");
			if(true == get_history(td.receiver, MDE2STR(td.affi), &head))
			{
				curr = head;
				while(curr != NULL){
//					mes = buy_some_mem((char*)(mes), (const char*)curr->add);
//					mes = buy_some_mem((char*)(mes), ":");
//					mes = buy_some_mem((char*)(mes), (const char*)curr->typ);
//					mes = buy_some_mem((char*)(mes), ":");
					mes = buy_some_mem((char*)(mes), "[");
					mes = buy_some_mem((char*)(mes), (const char*)curr->dte);
					mes = buy_some_mem((char*)(mes), "|");
					mes = buy_some_mem((char*)(mes), (const char*)curr->cmd);
					mes = buy_some_mem((char*)(mes), "|");
					mes = buy_some_mem((char*)(mes), (const char*)curr->res);
					mes = buy_some_mem((char*)(mes), "]");
					temp = curr;
					curr = curr->next;
					phy_free(temp);
				}
				if(mes == null){
					mes = buy_some_mem((char*)(mes), "[");
					mes = buy_some_mem((char*)(mes), "202506201601");
					mes = buy_some_mem((char*)(mes), "|");
					mes = buy_some_mem((char*)(mes), "无历史-测试数据!");
					mes = buy_some_mem((char*)(mes), "|");
					mes = buy_some_mem((char*)(mes), "xxxxxxxx");
					mes = buy_some_mem((char*)(mes), "]");
				}

				mes = buy_some_mem((char*)(mes), "[");
				mes = buy_some_mem((char*)(mes), "true");
				mes = buy_some_mem((char*)(mes), "]");

//				从缓存池中获取 该机器 与 检测类型是否有 对应的检测能力
				res = get_mempool_devs(td.receiver, MDE2STR(td.affi));

				if(mes != NULL){
					memset(tran.td.mes, 0, 1280);
					snprintf(tran.td.mes, 1280, "%s", mes);
					if(res != null) {
						strcat(tran.td.mes, res);
					}
					phy_free(mes);
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

void handle_mixs(spmd mdt, size dln, const char* dat)
{
	fil_remove("/tmp/kilflg");

	char* mes = NULL;
	char* res = NULL;
	hisrow* head = NULL;
	hisrow* curr = NULL;
	hisrow* temp = NULL;

	ntsp* pd = null;
	size len = 0;
	char* sdat = null;

	if(strstr(mdt.rcr, "localhost")){
		return;
	}

	switch(mdt.mde.sty){

		case MIXALL:
			phy_log(LOG_LEVEL_TRACE, "handle_mix get_history");
			if(true == get_history(mdt.rcr, MDE2STR(mdt.mde.gty), &head))
			{
				curr = head;
				while(curr != NULL){
					mes = buy_some_mem((char*)(mes), "[");
					mes = buy_some_mem((char*)(mes), (const char*)curr->dte);
					mes = buy_some_mem((char*)(mes), "|");
					mes = buy_some_mem((char*)(mes), (const char*)curr->cmd);
					mes = buy_some_mem((char*)(mes), "|");
					mes = buy_some_mem((char*)(mes), (const char*)curr->res);
					mes = buy_some_mem((char*)(mes), "]");
					temp = curr;
					curr = curr->next;
					phy_free(temp);
				}
				if(mes == null){
					mes = buy_some_mem((char*)(mes), "[");
					mes = buy_some_mem((char*)(mes), "202506201601");
					mes = buy_some_mem((char*)(mes), "|");
					mes = buy_some_mem((char*)(mes), "无历史-测试数据!");
					mes = buy_some_mem((char*)(mes), "|");
					mes = buy_some_mem((char*)(mes), "xxxxxxxx");
					mes = buy_some_mem((char*)(mes), "]");
				}

//				从缓存池中获取 该机器 与 检测类型是否有 对应的检测能力
				mes = buy_some_mem((char*)(mes), "[");
				if( true == get_mempool_isenabled(mdt.rcr, MDE2STR(mdt.mde.gty))){
					mes = buy_some_mem((char*)(mes), "true");
				}else{
					mes = buy_some_mem((char*)(mes), "false");
				}
				mes = buy_some_mem((char*)(mes), "]");

				res = get_mempool_devs(mdt.rcr, MDE2STR(mdt.mde.gty));
				if(res != null) {
					mes = buy_some_mem((char*)(mes), res);
					phy_free(res);
				}

				if(mes != NULL){
					len = sizeof(ntsp) + strlen(mes);
					sdat = (char*)malloc(len);
					memset(sdat, 0, len);
					pd = (ntsp*)sdat;
					pd->dln = strlen(mes);

					snprintf(pd->des, m_nspl, "%s",  m_nspdes);
					pd->mdt.mde.mty = MIX;
					pd->mdt.mde.sty = MIXALL;
					pd->mdt.mde.gty = mdt.mde.gty;

					snprintf(pd->mdt.rcr, sizeof(pd->mdt.rcr), "%s", mdt.rcr);
					memcpy(sdat + OFFSETOF(ntsp, dat), mes, pd->dln);
					phy_free(mes);
					sendmsgx(sdat, len);
				}
			}else{
				phy_log(LOG_LEVEL_ERR, "handle_his:  No historical data obtained!");
			}
		break;

		default:
		break;
	}
}
