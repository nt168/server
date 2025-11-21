#include "pcie.h"

extern ntmp *hwmp;
extern char* chns[];
extern volatile bool slgflg;
extern char	*CONFIG_PAWD;

void run_pcie(const char* add, const char* usr, const char* pwd, trandst td)
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
	char* rat = null;
	char* nra = null;
	char* res = null;
	char* des = null;

	tbh hds;

	lst* slx = null;

	char cmd[256] = {0};
	char scm[218] = {0};
	char jso[128] = {0};
//获取pcie设备名称
	nam = get_str_between_two_words(td.mes, "pmu_id=", ";");
//获取对应的桥设备
	bri = get_str_between_two_words(td.mes, "ctrler_id=", ";");

//获取node节点
	if(	HMAP_S_OK == get_hash_ext(hwmp, add, "pcie", nam, "节点号", &slx) ) {
		lst* scu = slx;
		while (scu) {
			nod = strdup(scu->dat);
			scu = scu->next;
		}
	}
	lst_fre(slx);

//获取控制器
	if(	HMAP_S_OK == get_hash_ext(hwmp, add, "pcie", nam, "控制器", &slx) ) {
		lst* scu = slx;
		while (scu) {
			ctr = strdup(scu->dat);
			scu = scu->next;
		}
		lst_fre(slx);
	}


//获取通道数
	if(	HMAP_S_OK == get_hash_ext(hwmp, add, "pcie", nam, "通道数", &slx) ) {
		lst* scu = slx;
		while (scu) {
			chn = strdup(scu->dat);
			scu = scu->next;
		}
		lst_fre(slx);
	}


//获取cpu型号
	if(	HMAP_S_OK == get_hash_ext( hwmp, add, "cpu", "type", &slx ) ) {
		lst* scu = slx;
		while (scu) {
			cpu = strdup(scu->dat);
			scu = scu->next;
		}
		lst_fre(slx);
	}

	str = string_replace(m_hwcpth, "$CPU", cpu);
	pth = string_replace(str, "$TYP", "pcie");
	phy_free(str);

//获取带宽
	hds = tab_ldr(pth);
	rat = tab_search(&hds, "pcie版本", "5.0", chns[atoi(chn)]);
	nra = get_numbers(rat, true);
//	phy_free(rat);

//pmu路径
	str = string_replace(m_pmupth, "$CPU", cpu);
	pmu = string_replace(str, "$TYP", "pcie");
	phy_free(str);

//推送pmu
	memset(cmd, 0, 256);
	phy_snprintf(cmd, 256, "scp -rp %s %s@%s:%s/", pmu, usr, add, m_tmpdir);
	forkpty_cutlines(add, usr, pwd, null, cmd, 4, &res, -1);
	phy_free(res);

//
	nct = get_numbers(ctr, true);
	phy_free(ctr);

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

	if(lob == false){
		memset(cmd, 0, 256);
		phy_snprintf(cmd, 256, "scp -rp %s %s@%s:%s/", tpp, usr, add, m_tmpdir);
		forkpty_cutlines(add, usr, pwd, null, cmd, 4, &res, -1);
		phy_free(tpp);
		phy_free(res);

		memset(scm, 0, sizeof(scm));
		phy_snprintf(scm, sizeof(scm), "-n %d -b %s -C %s -d \"%s\" -v %s %s/%s" ,
											atoi(nod),
											bri,
											nct,
											nam,
											nra,
											m_tmpdir,
											tpo);
	}else{
		memset(scm, 0, sizeof(scm));
		phy_snprintf(scm, 256, "-n %d -b %s -C %s -d \"%s\" -v %s %s" ,
											atoi(nod),
											bri,
											nct,
											nam,
											nra,
											tpo);
	}

	memset(cmd, 0, sizeof(cmd));
	phy_snprintf(cmd, sizeof(cmd), "%s/pmu.sh %s", m_tmpdir, scm);

#if 0
	if(lob == false){
		memset(cmd, 0, 256);
		phy_snprintf(cmd, 256, "scp -rp %s %s@%s:%s/", tpp, usr, add, m_tmpdir);
		forkpty_cutlines(add, usr, pwd, null, cmd, 4, &res, -1);
		phy_free(tpp);
		phy_free(res);

		memset(cmd, 0, 256);
		phy_snprintf(cmd, 256, "%s/pmu.sh -n %d -b %s -C %s -d \"%s\" -v %s %s/%s" ,
											m_tmpdir,
											atoi(nod),
											bri,
											nct,
											nam,
											nra,
											m_tmpdir,
											tpo);
	}else{
		memset(cmd, 0, 256);
		phy_snprintf(cmd, 256, "%s/pmu.sh -n %d -b %s -C %s -d \"%s\" -v %s %s" ,
											m_tmpdir,
											atoi(nod),
											bri,
											nct,
											nam,
											nra,
											tpo);
	}
#endif

	forkpty_cutlines(add, usr, pwd, null, cmd, 1, &res, -1);
	des = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(des == NULL || (fil_isexist("/tmp/kilflg") == true)){
		send_message(MESS, ERROR, TOPDOWN, "发生执行错误！");
	}

	memset(cmd, 0, 256);
	phy_snprintf(cmd, 256, "mkdir %s/%s", m_resdir, add);
	system(cmd);

	memset(cmd, 0, 256);
	phy_snprintf(cmd, 256, "%s/%s/pcie_%s.res", m_resdir, add, td.date);

	FILE* fp = null;
	fp = fopen(cmd, "w+");
		fprintf(fp, "%s", des);
	fclose(fp);

	phy_free(res);
	phy_free(des);

	memset(jso, 0, 128);
	phy_snprintf(jso, 128, "%s/%s/pcie_%s.json", m_resdir, add, td.date);

//2json路径
	str = string_replace(m_2jspth, "$CPU", cpu);
	tjs = string_replace(str, "$TYP", "pcie");
	phy_free(str);

	memset(cmd, 0, 256);
	phy_snprintf(cmd, 256, "python %s %s/%s/pcie_%s.res %s", tjs, m_resdir, add, td.date, jso);
	system(cmd);

	slgflg = true;

	if( !is_json(jso) ){
		send_message(MESS, ERROR, PCIE, "json file error.");
	}else{
		send_message(DETECT, FINISH, PCIE, jso);
	}

	insert_history(td.receiver, "PCIE", td.date, scm, jso);

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

	free_tbh(&hds);
	return;
}

void run_pcie_old(const char* add, const char* usr, const char* pwd, trandst td)
{
	char* ecrt = NULL;
	char* res = NULL;
	int ret = 0;

	dynamic_tips("执行环境检查 ");
	if(strstr(td.receiver, "localhost")){
		ret = env_check_rtcputp_local(CONFIG_PAWD, td.skey, PCIE, &ecrt);
		if(1 == ret)
		{
			slgflg = true;
			phy_log(LOG_LEVEL_ERR, "%s", "handle_det: PCIE envcheck err!");
			return;
		}

		slgflg = true;
		sleep(1);

		if(0 != strncmp("0x700f8620", ecrt, 10)){
			phy_free(ecrt);
			send_message(MESS, ERROR, PCIE, "该CPU型号不支持PCIE性能分析！");
			return;
		}
		phy_free(ecrt);

		if(fil_isexist(kilflg) == true){
			return;
		}

		dynamic_tips("性能检测执行中 ");
		run_detect_local(CONFIG_PAWD, PCIE, td, "pmu_pcie.sh");
	}else{
		ret = env_check_rtcputp(td.receiver, usr, pwd, td.skey, PCIE, &ecrt);
		if(1 == ret)
		{
			slgflg = true;
			phy_log(LOG_LEVEL_ERR, "%s", "handle_det: PCIE envcheck err!");
			return;
		}

		slgflg = true;
		sleep(1);

		if(0 != strncmp("0x700f8620", ecrt, 10)){
			phy_free(ecrt);
			send_message(MESS, ERROR, PCIE, "该CPU型号不支持PCIE性能分析！");
			return;
		}
		phy_free(ecrt);
		if(fil_isexist(kilflg) == true){
			return;
		}
		dynamic_tips("性能检测执行中 ");
		run_detect(usr, pwd, PCIE, td, "pmu_pcie.sh");
	}

}
