#include "env_check.h"
#include "phy_ssh.h"

//extern char phy_env_check_template[BUFLEN];
extern char phy_env_check_sh[BUFLEN];
static struct st_line cpu_mod_cmds[] =
{
	{"cat /proc/cpuinfo | grep 'model name'  -m 1"},
	{"cat /sys/devices/system/cpu/cpu0/regs/identification/midr_el1"},
	{NULL},
	{"cat /sys/devices/virtual/dmi/id/bios_vendor"},
	{"cat /proc/cpuinfo"},
	{"sudo dmidecode -t processor"},
	{NULL}
};
static struct det_items cpu_det_tab1[] =
{
		{"0x413fd0c1", "Ampere Q80", "pmu_ftc6.sh", NULL, NULL, NULL},
		{"0x701f6622", "2000+/64", "pmu_ftc6.sh", NULL, NULL, NULL},
		{"0x701f6633 ", "2500", "pmu_ftc6.sh", NULL, NULL, NULL},
		{"0x701f6633", "D2000", "pmu_ftc6.sh", NULL, NULL, NULL},
		{"0x701f6633", "FT-2000/4", "pmu_ftc6.sh", NULL, NULL, NULL},
		{"0x700f8620", "S5000C", "pmu_ftc8.sh", "pmu_ddr.sh", "pmu_pcie.sh", "topdown"},
		{"0x481fd010", "Kunpeng920", "pmu_ftc6.sh", NULL, NULL, NULL},
		{NULL, NULL, NULL, NULL, NULL, NULL},
};
static struct det_items cpu_det_tab[] =
{
		{"0x00000000413fd0c1", "Ampere Q80", "pmu_ftc6.sh", NULL, NULL, NULL},
		{"0x00000000701f6622", "2000+/64", "pmu_ftc6.sh", NULL, NULL, NULL},
		{"0x00000000701f6633 ", "2500", "pmu_ftc6.sh", NULL, NULL, NULL},
		{"0x00000000701f6633", "D2000", "pmu_ftc6.sh", NULL, NULL, NULL},
		{"0x00000000701f6633", "FT-2000/4", "pmu_ftc6.sh", NULL, NULL, NULL},
		{"0x00000000700f8620", "S5000C", "pmu_ftc8.sh", "pmu_ddr.sh", "pmu_pcie.sh", "topdown"},
		{"0x00000000481fd010", "Kunpeng920", "pmu_ftc6.sh", NULL, NULL, NULL},
		{NULL, NULL, NULL, NULL, NULL, NULL},
};
static struct st_table cpu_mod_tab[] =
{
		{"0x00000000413fd0c1", "Ampere Q80"},
		{"0x00000000701f6622", "2000+/64"},
		{"0x00000000701f6633 ", "2500"},
		{"0x00000000701f6633", "D2000"},
		{"0x00000000701f6633", "FT-2000/4"},
		{"0x00000000700f8620", "S5000C"},
		{"0x00000000481fd010", "Kunpeng920"},
		{NULL, NULL},
};
#if 0
static struct st_table cpu_mod_tab1[] =
{
		{"0x413fd0c1", "Ampere Q80"},
		{"0x701f6622", "2000+/64"},
		{"0x701f6633 ", "2500"},
		{"0x701f6633", "D2000"},
		{"0x701f6633", "FT-2000/4"},
		{"0x700f8620", "S5000C"},
		{"0x481fd010", "Kunpeng920"},
		{NULL, NULL},
};
#endif

void __env_check(const char *filnm, int line, envcheck type, const char* tplt, const char* rsts, const char* field, const char* user, const char* pass)
{
	if(phy_strcmp_natural(field, NATIVEDOMAIN) == 0){

	}else{

	}
}

struct det_items* cpu_pmu_tp(const char* add, const char* usr, const char* pwd, const char* skey)
{
	char* record = NULL;
	int i = 0;
	int j = 0;
	for (i = 0; NULL != cpu_mod_cmds[i].cmd; i++)
	{
		record = ssh_run_cmd(add, usr, pwd, skey, cpu_mod_cmds[i].cmd, 0);
		if(record != NULL){
			for (j = 0; NULL != cpu_det_tab[j].key; j++)
			{
				if(strstr(record, cpu_det_tab[j].key))
				{
					phy_free(record);
					return &(cpu_det_tab[j]);
				}
			}
//			phy_free(record);
			continue;
		}
	}
	return NULL;
}

void cpu_model()
{
#define PHY_CFG_LTRIM_CHARS	"\t "
	int i = 0;
	char* getcpudes = NULL;
	char* cpumodel= NULL;
	char cpumodcnf[PHRASELEN] = {0};
	char* shex = NULL;

	char cmd[CMDLEN] = {0};
	struct strlist* filecontent = NULL;
	struct strlist* p = NULL;

	char config_file[BUFLEN] = {0};

	for (i = 0; NULL != cpu_mod_cmds[i].cmd; i++)
	{
		get_result_str(cpu_mod_cmds[i].cmd, &getcpudes);
//		printf("cmd : %s, getcpudes : %s\n", cpu_mdl_cmds[i].cmdln, getcpudes);
		if(getcpudes != NULL){
			if(strstr(getcpudes, "error") || strstr(getcpudes, "Unknown") || strstr(getcpudes, "TaiShan")){
				phy_free(getcpudes);
				continue;
			}
			break;
		}
	}

//Intel
	if(strstr(getcpudes, "Intel")){
		cpumodel = get_str_between_two_words(getcpudes, ":", NULL);
		phy_ltrim(cpumodel, PHY_CFG_LTRIM_CHARS);
		goto out;
	}

//Ampere
	shex = is_hex_string(getcpudes);
	if(shex){
		for (i = 0; NULL != cpu_mod_tab[i].key; i++)
		{
			if(0 == phy_strcmp_natural(getcpudes, cpu_mod_tab[i].key)){
				cpumodel = phy_strdup(cpumodel, cpu_mod_tab[i].value);
				phy_free(shex);
				goto out;
			}
		}
		phy_free(shex);
	}
//Phytium
	cpumodel = get_str_between_two_words(getcpudes, ",", NULL);
	if(cpumodel == NULL){
//FT1500a
		cpumodel = get_str_between_two_words(getcpudes, "phytium ", NULL);
	}
out:
//modify server.cnf
	phy_snprintf(config_file, BUFLEN, "%s/conf/server.cnf", "/opt/phytune/server/");//protop);
	phy_snprintf(cpumodcnf, PHRASELEN, "%s=%s", "CpuModel", cpumodel);

	create_strlist(&filecontent);
	phy_snprintf(cmd, CMDLEN, "cat %s", config_file);
	get_result_strlist(cmd, filecontent, false);
	strlist_replace(&filecontent, "CpuModel", cpumodcnf);
	clean_file(config_file);
	p = filecontent->next;
	while(p){
		write_file(config_file, p->data);
		p = p->next;
	}
	destory_strlist(filecontent);
	phy_free(cpumodel);
	phy_free(getcpudes);

#undef PHY_CFG_LTRIM_CHARS
}

void expanding_template(struct field_chain* fhd, const char* domain, bool isntv)
{
	struct field_chain* p = NULL;
	struct field_chain* sp = NULL;
	struct datalist* spd = NULL;
	bool expf = true;
	sp = fhd->curr;
	p = fhd->next;
	while(p){
		if(phy_strcmp_natural(p->descr, native_section) == 0){
			memset(p->descr, 0, PHRASE);
			phy_snprintf(p->descr, PHRASE, "%s", NATIVEDOMAIN);
			expf = false;
			p = p->next;
			continue;
		}

		if(phy_strcmp_natural(p->descr, remote_section) == 0){
			if(phy_strcmp_natural(domain, NATIVEDOMAIN) != 0){
				memset(p->descr, 0, PHRASE);
				phy_snprintf(p->descr, PHRASE, "%s", domain);
			}
			expf = false;
			p = p->next;
			continue;
		}

		if(phy_strcmp_natural(p->descr, domain) == 0){
			expf = false;
			break;
		}
		p = p->next;
	}

	if(expf == true){
		spd = sp->field_t->data.stl->next;
		field_node_grow(fhd, domain, true);
		while(spd){
			datalist_add(&(fhd->curr->field_t->data.stl), spd->data, sizeof(struct cnfinfo));
			spd = spd->next;
		}
	}
}

void load_template(const char* confpath, struct field_chain* fhd)
{
//get conf content
	struct strlist* head = NULL;
	create_strlist(&head);
	char* tmp = NULL;
	char cmd[CMDLEN]={0};
	struct strlist *p=NULL;
	snprintf(cmd, CMDLEN, "cat %s", confpath);
	get_result_strlist(cmd, head, false);
	phy_free(tmp);
	int cur_section = 0;
	char* sp = NULL;
	char* cur_item = NULL;
	char* unit = NULL;
	char* value = NULL;

//get section
	p = head->next;
	while(p){
		if(strncmp(p->data, "#", 1) == 0){
			p = p->next;
			continue;
		}

		if(strstr(p->data, "[") && strstr(p->data, "]")){
			phy_free(cur_item);
			cur_item = NULL;
		}

		sp = strstr(p->data, native_section);
		if(sp != NULL){
			sp = get_str_between_two_words(p->data, "=", ";");
			cur_section = NATIVESECTION;
			if(!strcmp(sp, "yes")){
				field_node_grow(fhd, native_section, true);
			}else{
				field_node_grow(fhd, native_section, false);
			}
			phy_free(sp);
			p = p->next;
			continue;
		}

		sp = strstr(p->data, remote_section);
		if(sp != NULL){
			sp = get_str_between_two_words(p->data, "=", ";");
			cur_section = REMOTESECTION;
			if(!strcmp(sp, "yes")){
				field_node_grow(fhd, remote_section, true);
			}else{
				field_node_grow(fhd, remote_section, false);
			}
			phy_free(sp);
			p = p->next;
			continue;
		}

///////////////////////////////////////////////////////////////////////////////////////////////////
		if(cur_section == NATIVESECTION)
		{
			if(cur_item == NULL){
				cur_item = get_str_between_two_words(p->data, "[", "]");
				if(cur_item != NULL){
					new_data_node(fhd, native_section, NATIVESECTION, cur_item);
				}
			}else{
				unit = get_str_between_two_words(p->data, NULL, "=");
				value = get_str_between_two_words(p->data, "=", ";");
				insert_unit_of_item(fhd, native_section, cur_item, unit, (void*)value);
				phy_free(unit);
				phy_free(value);
			}
		}

		if(cur_section == REMOTESECTION)
		{
			if(cur_item == NULL){
				cur_item = get_str_between_two_words(p->data, "[", "]");
				if(cur_item != NULL){
					new_data_node(fhd, remote_section, REMOTESECTION, cur_item);
				}
			}else{
				unit = get_str_between_two_words(p->data, NULL, "=");
				value = get_str_between_two_words(p->data, "=", ";");
				insert_unit_of_item(fhd, remote_section, cur_item, unit, (void*)value);
				phy_free(unit);
				phy_free(value);
			}
		}
		p = p->next;
	}
	phy_free(cur_item);
	destory_strlist(head);
}

void local_env_check(char* cur_ckfil)
{
	char cmd[LPHRASE]={0};
//	phy_snprintf(cmd, LPHRASE, "%s %s", "/home/nt/eclipse-workspace/phytune/server/tools/env_check/env_check_all.sh", cur_ckfil);
	phy_snprintf(cmd, LPHRASE, "%s %s", phy_env_check_sh, cur_ckfil);
	system(cmd);
	sleep(1);
}

bool env_analyzer(const char* filpt, const char* addr)
{
	struct strlist *stdshs = NULL;
	struct strlist *p = NULL;
	char strcmd[PHRASE] = {0};
	char* alzrst = NULL;
	char talzrst[LPHRASE] = {0};
	phy_snprintf(strcmd, PHRASE, "cat %s", filpt);
	create_strlist(&stdshs);
	get_result_strlist(strcmd, stdshs, false);
	p = stdshs->next;
	while(p){
		if(strstr(p->data, "|no")){
			alzrst = string_replace(p->data, "|no", " nonsupport");
			phy_snprintf(talzrst, LPHRASE, "10;[%s] %s", addr, alzrst);
			write_message_to_controller(talzrst, strlen(talzrst));
			phy_free(alzrst);
			goto err;
		}
		p = p->next;
	}

	destory_strlist(stdshs);
	return true;
err:
	destory_strlist(stdshs);
	return false;
}

char* env_analyzer_plus(const char* filpt, const char* addr, const char* des)
{
	struct strlist *stdshs = NULL;
	struct strlist *p = NULL;
	char* res = NULL;
	char strcmd[PHRASE] = {0};
	phy_snprintf(strcmd, PHRASE, "cat %s", filpt);
	create_strlist(&stdshs);
	get_result_strlist(strcmd, stdshs, false);
	p = stdshs->next;
	while(p){
		if(strstr(p->data, des)){
			res = get_str_between_two_words(p->data, "|", NULL);
		}
		p = p->next;
	}

	destory_strlist(stdshs);
	return res;
}

char* get_ftc8or6(const char* cputp)
{
	char* ftcstr = NULL;
	int j;
	for (j = 0; NULL != cpu_det_tab1[j].key; j++)
	{
		if(strstr(cputp, cpu_det_tab1[j].key))
		{
			ftcstr = strdup(cpu_det_tab1[j].tma);
			return ftcstr;
		}
	}
	return ftcstr;
}


