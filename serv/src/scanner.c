#include "scanner.h"

ddlhx *scdh = null;
ntmp *hwmp = null;
tbh	hctb;
//char* cputp = null;

void scan_init()
{
	ddlx_init(&scdh);
	hwmp = create_ntmp();

	load_fils(m_thwdir, &scdh);
	load_fils(m_pmucnf, &scdh);

#if 0
	ddlx *sct = NULL;
	sct = scdh->entr;
	while(sct)
	{
		printf("%s\n", (char*)sct->data);
		sct = sct->next;
	}
#endif
//	ddlx_destory(scdh);
}

void hwst_prt(void* dat)
{
	hwst* hst = null;
	hst = (hwst*)dat;
	if(hst->ish == true){
		printf("item:  %s\n", "head");
		printf("value: %s\n", hst->itm);
	}else{
		printf("item:  %s\n", hst->itm);
		printf("value: %s\n", hst->dat);
	}
}

lvh* par_res_simp(const char* dat)
{
	lvh* res = null;
	char** lns = null;
	hwst* hst = null;
	char* prf = null;
	char* suf = null;

	lns = rd_lns(dat);
	for (size_t i = 0; lns[i]; i++) {
		if( 0 == strlen(lns[i]) ){
			phy_strarr_del(&lns, lns[i]);
			i--;
		}
	}

	for (size_t i = 0; lns[i]; i++) {
		hst = (hwst*)malloc(sizeof(hwst));
		memset(hst, 0, sizeof(hwst));

		if(i == 0){
			snprintf(hst->itm, sizeof(hst->itm), "%s", lns[i]);
			hst->ish = true;
			goto add;
		}else{
			hst->ish = false;
			prf = get_str_between_two_words(lns[i], null, ":");
			suf = get_str_between_two_words(lns[i], ":", null);
			if(prf == null || suf == null){
				phy_log(LOG_LEVEL_ERR, "par_res_simp: data in wrong format.");
				return res;
			}
			phy_ltrim(prf, " ");
			phy_ltrim(suf, " ");
			snprintf(hst->itm, sizeof(hst->itm), "%s", prf);
			snprintf(hst->dat, sizeof(hst->dat), "%s", suf);
			phy_free(prf);
			phy_free(suf);
		}
add:
		res = lvh_app(res, (void*)hst, sizeof(hwst));
		phy_free(hst);
	}
	fre_lns(lns);
	return res;
}

char* get_cpu_typ(lvh* hed)
{
	lvn *p = hed->ent;
	hwst* hst = null;
	char* res = null;
	while (p) {
		hst = (hwst*)p->dat;
		if(true != hst->ish){
			res = strdup(hst->dat);
			return res;
		}
		p = p->next;
	}
	return null;
}

char* route(ddlhx *dh, const char* pre, const char* typ, const char* key)
{
	size_t len = 0;
	size_t cnt = 0;
	size_t *pos = null;
	char* rte   = null;
	lst*  pib   = null;
	lst*  pid   = null;
	lst*  piq   = null;
	ddlx *sct   = null;

	 if (pre == null || typ == null || key == 0 ) {
	        return null;
	    }

	len = strlen(pre);
	sct = dh->entr;

	while(sct)
	{
		if(strstr((char*)sct->data, pre)){
			pib = lst_app(pib, sct->data);
		}
		sct = sct->next;
	}

	pid = pib;
	while(pid)
	{
		pos = stroffstr(pid->dat, typ, len, &cnt);
		if(null != pos){
			piq = lst_app(piq, pid->dat);
			phy_free(pos);
		}
		pid = pid->next;
	}
	lst_fre(pib);

	len = len + strlen(typ);
	pib = piq;
	while(pib)
	{
		pos = stroffstr(pib->dat, key, len, &cnt);
		if(null != pos){
			phy_free(pos);
			rte = strdup((char*)(pib->dat));
			goto end;
		}
		pib = pib->next;
	}

end:
	lst_fre(piq);
	return rte;
}

char* routex(ddlhx *dh, const char* pre, const char* typ, const char* key, const char* skey)
{
	size_t len = 0;
	size_t cnt = 0;
	size_t *pos = null;
	char* rte   = null;
	lst*  pib   = null;
	lst*  pid   = null;
	lst*  piq   = null;
	ddlx *sct   = null;

	 if (pre == null || typ == null || key == 0 ) {
	        return null;
	    }

	len = strlen(pre);
	sct = dh->entr;

	while(sct)
	{
		if(strstr((char*)sct->data, pre)){
			pib = lst_app(pib, sct->data);
		}
		sct = sct->next;
	}

	pid = pib;
	while(pid)
	{
		pos = stroffstr(pid->dat, typ, len, &cnt);
		if(null != pos){
			piq = lst_app(piq, pid->dat);
			phy_free(pos);
		}
		pid = pid->next;
	}
	lst_fre(pib);

	len = len + strlen(typ);
	pib = piq;
	while(pib)
	{
		pos = stroffstr(pib->dat, key, len, &cnt);
		if(null != pos){
			pid = lst_app(pid, pib->dat);
			phy_free(pos);
		}
		pib = pib->next;
	}
	lst_fre(piq);

	len = len + strlen(key);
	piq = pid;
	while(piq)
	{
		pos = stroffstr(piq->dat, skey, len, &cnt);
		if(null != pos){
			phy_free(pos);
			rte = strdup((char*)(piq->dat));
			goto end;
		}
		piq = piq->next;
	}

end:
	lst_fre(pid);
	return rte;
}

void ins_ntmp(lvh* dat, const char* add, const char* typ)
{
	char* tmn = null;
	lvn* p = null;
	hwst* hw = null;
	char tnm[20] = {0};

	if( 0 == strcmp(typ, m_ddrnam ) ){
		snprintf(tnm, sizeof(tnm), "%s", m_ddrten);
	}else if( 0 == strcmp(typ, m_pcinam ) ) {
		snprintf(tnm, sizeof(tnm), "%s", m_pciten);
	}

	p = dat->ent;
	while ( p ) {
		hw = ((hwst*)p->dat);

		if( true ==  hw->ish){
			p = p->next;
			continue;
		}

		if( strstr(hw->itm, tnm) ){
			phy_free(tmn);
			tmn = strdup(hw->dat);
			ins_hash_ext(hwmp, add, typ, tmn);
		} else {
			ins_hash_ext(hwmp, add, typ, tmn, hw->itm, hw->dat);
		}

		p = p->next;
	}

	phy_free(tmn);
}

char* res_judg(const char* res)
{
	char* dst = null;
	lvh * lre = null;
	lre = par_res_simp(res);

	lvn* p = null;
	p = lre->ent;
	hwst *hw = null;
	while ( p ) {
		hw = ((hwst*)p->dat);
		if( true ==  hw->ish){
			dst = buy_some_mem(dst, hw->itm);
			p = p->next;
			continue;
		}
		if( 0 == strncmp(hw->dat, "0", 1) ){
			dst = buy_some_mem(dst, hw->itm);
			dst = buy_some_mem(dst, " NOK");
			lvh_fre(lre);
			return dst;
		}
		p = p->next;
	}
	lvh_fre(lre);
	phy_free(dst);
	return null;
}

void scan_start(const char* add)
{
	int rc = 0;
	char* ept = null;
	char* usr = null;
	char* pwd = null;
	char* sta = null;
	char* res = null;
	char* dst = null;
	char* cpu = null;
	char* jud = null;
//	char* pcie = null;
	lvh * lre = null;
	char cmd[256] = {0};
	rc = physql_select(add, &usr, &pwd, &sta);//sql查询
	if(rc != SQLITE_OK){
		phy_log(LOG_LEVEL_ERR, "handle_exe: Cannot find info of %s.", add);
		return;
	}
	if(0 == strcmp(m_unvalb, sta)){
		phy_free(sta);
		phy_free(usr);
		phy_free(pwd);
		return;
	}

//sys
	//依赖
	if( false == rmt_exe(add, usr, pwd, null, m_deppth, m_tmpdir, &res, 1, -1, true) ) {
		phy_log(LOG_LEVEL_ERR, "scan_start:  %s.", m_deppth);
		return;
	}
	jud = res_judg(res);
	if(null != jud){
		ins_hash_ext(hwmp, add, "system", "依赖", jud);
		phy_free(jud);
	}else{
		ins_hash_ext(hwmp, add, "system", "依赖", "ok");
	}
	phy_free(res);

	//切换为root
	if( false == rmt_exe(add, usr, pwd, null, m_torpth, m_tmpdir, &res, 0, -1, true) ) {
		phy_log(LOG_LEVEL_ERR, "scan_start:  %s.", m_deppth);
		return;
	}
	jud = res_judg(res);
	if(null != jud){
		ins_hash_ext(hwmp, add, "system", "权限", jud);
		phy_free(jud);
	}else{
		ins_hash_ext(hwmp, add, "system", "权限", "ok");
	}
	phy_free(res);


	//perf提权
	if( false == rmt_exe(add, usr, pwd, null, m_perpth, m_tmpdir, &res, 1, -1, true) ) {
		phy_log(LOG_LEVEL_ERR, "scan_start:  %s.", m_perpth);
		return;
	}
	jud = res_judg(res);
	if(null != jud){
		ins_hash_ext(hwmp, add, "system", "perf", jud);
		phy_free(jud);
	}else{
		ins_hash_ext(hwmp, add, "system", "perf", "ok");
	}
	phy_free(res);
	phy_free(jud);

//driver
	//pcie
	if( false == rmt_exe(add, usr, pwd, null, m_pcipth, m_tmpdir, &res, 1, -1, true) ) {
		phy_log(LOG_LEVEL_ERR, "scan_start:  %s.", m_pcipth);
		return;
	}
	jud = res_judg(res);
	if(null != jud){
		ins_hash_ext(hwmp, add, "driver", "pcie", jud);
		phy_free(jud);
	}else{
		ins_hash_ext(hwmp, add, "driver", "pcie", "ok");
	}
	phy_free(res);

	//ddr
	if( false == rmt_exe(add, usr, pwd, null, m_ddrpth, m_tmpdir, &res, 1, -1, true) ) {
		phy_log(LOG_LEVEL_ERR, "scan_start:  %s.", m_ddrpth);
		return;
	}
	jud = res_judg(res);
	if(null != jud){
		ins_hash_ext(hwmp, add, "driver", "ddr", jud);
		phy_free(jud);
	}else{
		ins_hash_ext(hwmp, add, "driver", "ddr", "ok");
	}
	phy_free(res);

//cpu
	ept = route(scdh, m_thwdir, "cpu", "get.sh");
	memset(cmd, 0, 256);
	phy_snprintf(cmd, 256, "scp -rp %s %s@%s:%s/", ept, usr, add, m_tmpdir);
	forkpty_cutlines(add, usr, pwd, null, cmd, 4, &res, -1);
	dst = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if (dst == NULL) {
		goto err;
	}

	memset(cmd, 0, 256);
	phy_snprintf(cmd, 256, "%s/%s", m_tmpdir, get_file_name(ept));
	phy_free(ept);
	phy_free(dst);
	phy_free(res);

	forkpty_cutlines(add, usr, pwd, null, cmd, 1, &res, -1);
	dst = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if (dst == NULL) {
		goto err;
	}
	phy_free(res);

	lre = par_res_simp(dst);
	lvh_prt(lre, hwst_prt);

	phy_free(ept);
	phy_free(dst);
	cpu = get_cpu_typ(lre);
	ins_hash_ext(hwmp, add, "cpu", "type", cpu);
	lvh_fre(lre);

#if 1
//获取ddr设备
	ept = routex(scdh, m_pmucnf, cpu, "ddr", "infos.sh");
	if(ept == null){
		struct transfer tran = {0};
		tran.mma.matp = MIX;
		tran.mma.mst = MIXLOD;
		tran.mma.mst = MIXERR;
		memset(tran.td.mes, 0, 1280);
		snprintf(tran.td.mes, 1280, "%s", "远程加载数据失败!");
		write_message_to_controller((char*)(&tran), sizeof(struct transfer));
		return;
	}
	memset(cmd, 0, 256);
	phy_snprintf(cmd, 256, "scp -rp %s %s@%s:%s/", ept, usr, add, m_tmpdir);
	forkpty_cutlines(add, usr, pwd, null, cmd, 4, &res, -1);
	dst = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if (dst == NULL) {
		goto err;
	}

	memset(cmd, 0, 256);
	phy_snprintf(cmd, 256, "%s/%s", m_tmpdir, get_file_name(ept));
	phy_free(ept);
	phy_free(dst);
	phy_free(res);

	forkpty_cutlines(add, usr, pwd, null, cmd, 1, &res, -1);
	dst = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if (dst == NULL) {
		goto err;
	}
	phy_free(res);

	lre = par_res_simp(dst);
	phy_free(dst);
//插入缓存池
	ins_ntmp(lre, add, "ddr");
	lvh_fre(lre);
#endif

#if 1
//获取pcie设备
	ept = routex(scdh, m_pmucnf, cpu, "pcie", "infos.sh");
	if(ept == null){
		struct transfer tran = {0};
		tran.mma.matp = MIX;
		tran.mma.mst = MIXLOD;
		tran.mma.mst = MIXERR;
		memset(tran.td.mes, 0, 1280);
		snprintf(tran.td.mes, 1280, "%s", "远程加载数据失败!");
		write_message_to_controller((char*)(&tran), sizeof(struct transfer));
		return;
	}
	memset(cmd, 0, 256);
	phy_snprintf(cmd, 256, "scp -rp %s %s@%s:%s/", ept, usr, add, m_tmpdir);
	forkpty_cutlines(add, usr, pwd, null, cmd, 4, &res, -1);
	dst = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if (dst == NULL) {
		goto err;
	}

	memset(cmd, 0, 256);
	phy_snprintf(cmd, 256, "%s/%s", m_tmpdir, get_file_name(ept));
	phy_free(ept);
	phy_free(dst);
	phy_free(res);

	forkpty_cutlines(add, usr, pwd, null, cmd, 1, &res, -1);
	dst = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if (dst == NULL) {
		goto err;
	}
	phy_free(res);

	lre = par_res_simp(dst);
//	lvh_prt(lre, hwst_prt);
//插入缓存池
	ins_ntmp(lre, add, "pcie");
#endif

#if 0
//pcie
	lst* lx = null;
	if(	HMAP_S_OK == get_hash_ext(hwmp, add, "pcie", "Marvell Technology Group Ltd. 88SE9230 PCIe 2.0 x2 4-port SATA 6 Gb/s RAID Controller", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, add, "pcie", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}
	destroy_ntmp(hwmp);

#endif

#if 0
// ddr
	lst* lx = null;
	if(	HMAP_S_OK == get_hash_ext(hwmp, add, "ddr", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, add, "ddr", "DIMM 0",  &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext(hwmp, add, "ddr", "DIMM 0", "Type", &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}

//	destroy_ntmp(hwmp);
#endif

	phy_free(cpu);
	phy_free(dst);
	lvh_fre(lre);

err:
	phy_free(sta);
	phy_free(usr);
	phy_free(pwd);
	phy_free(res);
	phy_free(ept);
	return;
}

void scan_samp()
{
	ddlhx* fils = null;
	ddlx_init(&fils);
	load_fils(m_empdir, &fils);
	ddlx *sct = NULL;

	sct = fils->entr;
	while(sct)
	{
		ins_hash_ext(hwmp, m_empdir, (char*)sct->data);
		sct = sct->next;
	}
//	lst* lx = null;
//	if(	HMAP_S_OK == get_hash_ext(hwmp, m_empdir, &lx) )
//	{
//		lst_prt(lx);
//		lst_fre(lx);
//	}
	ddlx_destory(fils);
}

void scan_pmus()
{
	ddlhx* fils = null;
	ddlx_init(&fils);
	load_fils(m_pmucnf, &fils);
	ddlx *sct = NULL;

	sct = fils->entr;
	while(sct)
	{
		ntmp_ins_ext(hwmp, (char*)sct->data);
		sct = sct->next;
	}
#if 0
	lst* scu;
	lst* lx;
	if(	HMAP_S_OK == get_hash_ext( hwmp, "opt", "phytune", "agent", "arm", "pmucnf", "ddr_pcie_sh", &lx ) ) {
		scu = lx;
		while(scu){
			printf("%s\n", scu->dat);
			scu = scu->next;
		}
	}
	lst_fre(lx);

	if(	HMAP_S_OK == get_hash_ext( hwmp, "opt", "phytune", "agent", "arm", "pmucnf", &lx ) ) {
		scu = lx;
		while(scu){
			printf("%s\n", scu->dat);
			scu = scu->next;
		}
	}
	lst_fre(lx);

	if(	HMAP_S_OK == get_hash_ext( hwmp, "opt", "phytune", "agent", "arm", "pmucnf", "S5000C", "pcie", &lx ) ) {
		scu = lx;
		while(scu){
			printf("%s\n", scu->dat);
			scu = scu->next;
		}
	}
	lst_fre(lx);

	if(	HMAP_S_OK == get_hash_ext(hwmp, m_pmucnf, &lx) )
	{
		lst_prt(lx);
		lst_fre(lx);
	}
#endif
	ddlx_destory(fils);
}

void init_ntmp()
{
	struct transfer tran = {0};
	tran.mma.matp = MIX;
	tran.mma.mst = MIXLOD;
	agtrow* head = NULL;
	agtrow* curr = NULL;
	agtrow* temp = NULL;
	int rc = 0;

	const char* sql = "SELECT * FROM agent;";

	head = NULL;

	rc = phy_sql_reqagts(m_phydb, sql, &head, 5, 1);
	if(rc != SQLITE_OK){
		goto err;
	}
	curr = head;

	while(curr != NULL){
		scan_start((const char*)curr->add);
		temp = curr;
		curr = curr->next;
		phy_free(temp);
	}

	scan_samp();
	scan_pmus();

	sleep(5);
	memset(tran.td.mes, 0, 1280);
	write_message_to_controller((char*)(&tran), sizeof(struct transfer));
	return;
err:
	sleep(5);
	tran.mma.mst = MIXERR;
	memset(tran.td.mes, 0, 1280);
	snprintf(tran.td.mes, 1280, "%s", "远程加载数据失败!");
	write_message_to_controller((char*)(&tran), sizeof(struct transfer));
	exit(1);
	return;
}
