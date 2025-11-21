#include "ddr.h"
extern char	*CONFIG_PAWD;
extern ntmp *hwmp;
extern char* chns[];
extern volatile bool slgflg;

void run_ddr(const char* add, const char* usr, const char* pwd, trandst td)
{
	bool  lob = false;
	char* str = null;
	char* cpu = null;
	char* tpo = null;
	char* tpp = null;
	char* pmu = null;
	char* tjs = null;
	char* nam = null;
	char* bri = null;
	char* nod = null;
	char* ctr = null;
	char* nct = null;
	char* pth = null;
	char* chn = null;

	char* nra = null;
	char* res = null;
	char* des = null;
	char* drt = null;
	char* dim = null;
	tbh hds;
	lst* slx = null;
	lst* scu;

	char cmd[256] = {0};
	char scm[218] = {0};
	char jso[128] = {0};
//获取node
	nod = get_str_between_two_words(td.mes, "node_id=", ";");

//获取ddr类型
	chn = get_str_between_two_words(td.mes, "hm_id=", ";");
	//获取首个通道数(如果一个为DDR5 一个为DDR4怎么弄？)
	if( strstr(chn, ",") ){
		str = get_str_between_two_words(chn, null, ",");
		dim = ntcat(m_dimm, " ", str);
		phy_free(str);
	}else{
		dim = ntcat(m_dimm, " ", chn);
	}
	//根据DIMM值去查缓存池
//	if(	HMAP_S_OK == get_hash_ext( hwmp, add, m_ddrnam, &slx ) ) {
	if(	HMAP_S_OK == get_hash_ext( hwmp, add, m_ddrnam, dim, "Type", &slx ) ) {
		scu = slx;
		while(scu){
			drt = strdup(scu->dat);
			scu = scu->next;
		}
		lst_fre(slx);
	}
	phy_free(dim);

//获取cpu型号
	if(	HMAP_S_OK == get_hash_ext( hwmp, add, "cpu", "type", &slx ) ) {
		scu = slx;
		while (scu) {
			cpu = strdup(scu->dat);
			scu = scu->next;
		}
		lst_fre(slx);
	}

#if 0
//获取最大的Locator
	if(	HMAP_S_OK == get_hash_ext( hwmp, add, "ddr", &slx ) ) {
		lst* scu = slx;
		while (scu) {
			if( strcmpx(scu->dat, str) == 1 ){
				if(str != null){
					phy_free(str);
				}
				str = strdup(scu->dat);
			}else{
				if(str == null){
					 str = strdup(scu->dat);
				}
			}
			scu = scu->next;
		}
		lst_fre(slx);
	}
//获取最大DIMM数
	dnb = get_numbers(str, true);
#endif

#if 0
//获取通道
	hds = tab_ldrx(pth);
	rat = tab_search(&hds, "ddr", "ddr5", "通道数");
	rat = tab_search(&hds, "node", "nodes", "DIMM 31");
	rat = tab_search(&hds, "node", "nodes", "DIMM 20");
	nra = get_numbers(rat, true);
#endif

//pmu路径
	str = string_replace(m_pmupth, "$CPU", cpu);
	pmu = string_replace(str, "$TYP", m_ddrnam);
	phy_free(str);

//推送pmu
	memset(cmd, 0, 256);
	phy_snprintf(cmd, 256, "scp -rp %s %s@%s:%s/", pmu, usr, add, m_tmpdir);
	forkpty_cutlines(add, usr, pwd, null, cmd, 4, &res, -1);
	phy_free(res);

//推送样例程序
	tpo = get_str_between_two_words(td.mes, "tarpro=", ";");

	if(tpo != NULL){
		if(	HMAP_S_OK == get_hash_ext( hwmp, m_empdir, &slx ) ) {
			lst* scu = slx;
			while(scu){
				if(strstr(scu->dat, tpo)){
					lob = false;
					tpp = strdup(scu->dat);
					break;
				}
				scu = scu->next;
			}
			lst_fre(slx);
		}else{
			lob = true;
		}
	}

#if 0
	if(lob == false){
		memset(cmd, 0, 256);
		phy_snprintf(cmd, 256, "scp -rp %s %s@%s:%s/", tpp, usr, add, m_tmpdir);
		forkpty_cutlines(add, usr, pwd, null, cmd, 4, &res, -1);
		phy_free(tpp);
		phy_free(res);

		memset(cmd, 0, 256);
		phy_snprintf(cmd, 256, "%s/pmu.sh -n %s -h %s -d %s %s/%s" ,
											m_tmpdir,
											nod,
											chn,
											drt,
											m_tmpdir,
											tpo);
	}else{
		memset(cmd, 0, 256);
		phy_snprintf(cmd, 256, "%s/pmu.sh -n %s -h %s -d %s" ,
											m_tmpdir,
											nod,
											chn,
											drt,
											tpo);
	}
#endif

	if(lob == false){
		memset(cmd, 0, 256);
		phy_snprintf(cmd, 256, "scp -rp %s %s@%s:%s/", tpp, usr, add, m_tmpdir);
		forkpty_cutlines(add, usr, pwd, null, cmd, 4, &res, -1);
		phy_free(tpp);
		phy_free(res);

		memset(scm, 0, sizeof(scm));
		phy_snprintf(scm, sizeof(scm), "-n %s -h %s -d %s %s/%s" ,
											nod,
											chn,
											drt,
											m_tmpdir,
											tpo);
	}else{
		memset(scm, 0, sizeof(scm));
		phy_snprintf(scm, sizeof(scm), "-n %s -h %s -d %s" ,
											nod,
											chn,
											drt,
											tpo);
	}

	phy_free(chn);
	phy_free(tpo);

	memset(cmd, 0, sizeof(cmd));
	phy_snprintf(cmd, sizeof(cmd), "%s/pmu.sh %s", m_tmpdir, scm);

	forkpty_cutlines(add, usr, pwd, null, cmd, 1, &res, -1);
	des = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(des == NULL || (fil_isexist("/tmp/kilflg") == true)){
		send_message(MESS, ERROR, DDR, "发生执行错误！");
	}

	memset(cmd, 0, 256);
	phy_snprintf(cmd, 256, "mkdir %s/%s", m_resdir, add);
	system(cmd);

	memset(cmd, 0, 256);
	phy_snprintf(cmd, 256, "%s/%s/%s_%s.res", m_resdir, add, m_ddrnam, td.date);

	FILE* fp = null;
	fp = fopen(cmd, "w+");
		fprintf(fp, "%s", des);
	fclose(fp);

	phy_free(res);
	phy_free(des);

	memset(jso, 0, 128);
	phy_snprintf(jso, 128, "%s/%s/%s_%s.json", m_resdir, add, m_ddrnam, td.date);

//2json路径
	str = string_replace(m_2jspth, "$CPU", cpu);
	tjs = string_replace(str, "$TYP", m_ddrnam);
	phy_free(str);
	phy_free(cpu);

	memset(cmd, 0, 256);
	phy_snprintf(cmd, 256, "python %s %s/%s/%s_%s.res %s", tjs, m_resdir, add, m_ddrnam, td.date, jso);
	system(cmd);

	slgflg = true;

	if( !is_json(jso) ){
		send_message(MESS, ERROR, DDR, "json file error.");
	}else{
		send_message(DETECT, FINISH, DDR, jso);
	}
	insert_history(td.receiver, "DDR", td.date, scm, jso);

	phy_free(tjs);
	phy_free(tpo);
	phy_free(pmu);
	phy_free(nra);
	phy_free(nct);
	phy_free(nam);
	phy_free(pth);
	phy_free(cpu);
	phy_free(bri);
	phy_free(nod);
	phy_free(chn);
	phy_free(ctr);

//	free_tbh(&hds);
	return;
}

void run_ddr_old(const char* add, const char* usr, const char* pwd, trandst td)
{
	char* ecrt = NULL;
	char* res = NULL;
	int ret = 0;

	dynamic_tips("执行环境检查 ");
	if(strstr(td.receiver, "localhost")){
		ret = env_check_rtcputp_local(CONFIG_PAWD, td.skey, DDR, &ecrt);
		if(1 == ret)
		{
			slgflg = true;
			phy_log(LOG_LEVEL_ERR, "%s", "handle_det: DDR envcheck err!");
			return;
		}

		slgflg = true;
		sleep(1);

		if(0 != strncmp("0x700f8620", ecrt, 10)){
			slgflg = true;
			send_message(MESS, ERROR, DDR, "该CPU型号不支持DDR性能分析！");
			return;
		}
		if(fil_isexist(kilflg) == true){
			return;
		}

		dynamic_tips("性能检测执行中 ");
		run_detect_local(CONFIG_PAWD, DDR, td, "pmu_ddr.sh");
	} else {
		ret = env_check_rtcputp(td.receiver, usr, pwd, td.skey, DDR, &ecrt);
		if(1 == ret)
		{
			slgflg = true;
			phy_log(LOG_LEVEL_ERR, "%s", "handle_det: DDR envcheck err!");
			return;
		}

		slgflg = true;
		sleep(1);

		if(0 != strncmp("0x700f8620", ecrt, 10)){
			slgflg = true;
			phy_free(ecrt);
			send_message(MESS, ERROR, DDR, "该CPU型号不支持DDR性能分析！");
			return;
		}
		phy_free(ecrt);
		if(fil_isexist(kilflg) == true){
			return;
		}
		dynamic_tips("性能检测执行中 ");
		run_detect(usr, pwd, DDR, td, "pmu_ddr.sh");
	}
}



