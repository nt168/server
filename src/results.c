#include "results.h"

extern char FTC6_NS_TEMPLATE_JSON[BUFLEN];
extern char FTC8_NS_TEMPLATE_JSON[BUFLEN];
extern char ANAL_NS_TEMPLATE_JSON[BUFLEN];
extern char NOC_NS_TEMPLATE_JSON[BUFLEN];
extern char DDR_NS_TEMPLATE_JSON[BUFLEN];
extern char C2C_NS_TEMPLATE_JSON[BUFLEN];
extern char PCIE_NS_TEMPLATE_JSON[BUFLEN];
extern char DDR_NS_TEMPLATE_TXT[BUFLEN];

extern char tpdcsvtran[BUFLEN];
extern char tpdrestran[BUFLEN];
extern char fs_sourcerestran[BUFLEN];
extern char fs_cachelinerestran[BUFLEN];
extern char fs_objrestran[BUFLEN];
extern char fs_callsiterestran[BUFLEN];
extern char numa_cachelinerestran[BUFLEN];
extern char numa_objrestran[BUFLEN];
extern char numa_callsiterestran[BUFLEN];
extern char masrestran[BUFLEN];
extern char msevtrestran[BUFLEN];

void add_metric(struct phy_pmu_analysis **ppa, const char* metric_name)
{
	struct phy_pmu_metrics* ppm = NULL;
	struct phy_pmu_metrics* tppm = NULL;
	ppm = (struct phy_pmu_metrics*)phy_malloc(ppm, sizeof(struct phy_pmu_metrics));
	memset(ppm, 0, sizeof(struct phy_pmu_metrics));
	phy_snprintf(ppm->metric_name, mtcnmlen, "%s", metric_name);
	if((*ppa)->current == NULL){
		(*ppa)->current = ppm;
		(*ppa)->metrics = ppm;
	}else{
		tppm = (*ppa)->current;
		tppm->next = ppm;
		(*ppa)->current = ppm;
	}
	return;
}

bool retrieve_event(struct phy_pmu_event* ppe, const char* key)
{
	struct phy_pmu_event* p;
	p = ppe;
	while(p){
		if( (strcmp(p->event_name, key)==0) && (strcmp(key, p->event_name)==0))
		{
			return true;
		}
		p = p->next;
	}
	return false;
}

void add_event(struct phy_pmu_analysis **ppa, const char* event_line, const char* cur_metric)
{
#define PHY_CFG_LTRIM_CHARS	"\t "
#define PHY_CFG_RTRIM_CHARS	PHY_CFG_LTRIM_CHARS "\r\n"

	char *evname = NULL;
	char *evvalue  = NULL;
	char *tevvalue  = NULL;
	struct phy_pmu_event* ppe=NULL;
	struct phy_pmu_event* tppe=NULL;
//stat
	if(strstr(event_line, "["))
	{
		evname = get_str_between_two_words(event_line, "[", "]");
		if( true == retrieve_event((*ppa)->current->stat_data, evname) ){
			phy_free(evname);
			return;
		}
		evvalue = get_str_between_two_words(event_line, ":", NULL);
		phy_rtrim(evvalue, PHY_CFG_RTRIM_CHARS);
		phy_ltrim(evvalue, PHY_CFG_LTRIM_CHARS);
		if(evvalue[0] == '.'){
			tevvalue = string_replace(evvalue, ".", "0.");
			phy_free(evvalue);
			evvalue = phy_strdup(evvalue, tevvalue);
			phy_free(tevvalue);
		}

		if(((*ppa)->current->stat_data->len) == 0){
			phy_snprintf((*ppa)->current->stat_data->event_name, evtnmlen, "%s", evname);
			phy_snprintf((*ppa)->current->stat_data->event_value, evtvllen, "%s", evvalue);
			phy_snprintf((*ppa)->current->stat_data->metric_name, mtcnmlen, "%s", cur_metric);
			(*ppa)->current->stat_data->len +=1;
		}else{
			ppe = (struct phy_pmu_event*)phy_malloc(ppe, sizeof(struct phy_pmu_event));
			memset(ppe, 0, sizeof(struct phy_pmu_event));
			phy_snprintf(ppe->event_name, evtnmlen, "%s", evname);
			phy_snprintf(ppe->event_value, evtvllen, "%s", evvalue);
			phy_snprintf(ppe->metric_name, mtcnmlen, "%s", cur_metric);
			tppe = (*ppa)->current->curr_stat;
			tppe->next = ppe;
			(*ppa)->current->curr_stat = ppe;
			(*ppa)->current->stat_data->len +=1;
		}
		phy_free(evname);
		phy_free(evvalue);
		return;
	}else{ //orig
		evname = get_str_between_two_words(event_line, NULL, ":");
		if( true == retrieve_event((*ppa)->current->orig_data, evname) ){
			phy_free(evname);
			return;
		}
	    evvalue = get_str_between_two_words(event_line, ":", NULL);
		phy_rtrim(evvalue, PHY_CFG_RTRIM_CHARS);
		phy_ltrim(evvalue, PHY_CFG_LTRIM_CHARS);
		if(evvalue[0] == '.'){
			tevvalue = string_replace(evvalue, ".", "0.");
			phy_free(evvalue);
			evvalue = phy_strdup(evvalue, tevvalue);
			phy_free(tevvalue);
		}
		if(((*ppa)->current->orig_data->len) == 0){
			phy_snprintf((*ppa)->current->orig_data->event_name, evtnmlen, "%s", evname);
			phy_snprintf((*ppa)->current->orig_data->event_value, evtvllen, "%s", evvalue);
			phy_snprintf((*ppa)->current->orig_data->metric_name, mtcnmlen, "%s", cur_metric);
			(*ppa)->current->orig_data->len +=1;
		}else{
			ppe = (struct phy_pmu_event*)phy_malloc(ppe, sizeof(struct phy_pmu_event));
			memset(ppe, 0, sizeof(struct phy_pmu_event));
			phy_snprintf(ppe->event_name, evtnmlen, "%s", evname);
			phy_snprintf(ppe->event_value, evtvllen, "%s", evvalue);
			phy_snprintf(ppe->metric_name, mtcnmlen, "%s", cur_metric);
			tppe = (*ppa)->current->curr_orig;
			tppe->next = ppe;
			(*ppa)->current->curr_orig = ppe;
			(*ppa)->current->orig_data->len +=1;
		}
		phy_free(evname);
		phy_free(evvalue);
		return;
	}
	return;
}

#if 1
void pmu_orig_struct(const char* origfile, struct phy_pmu_analysis **ppa)
{
	FILE *file;
	int	lineno;
	char line[MAX_STRING_LEN + 3];
	bool new_metric_flag = false;
	bool new_event_flag = false;
	char* tstr = NULL;
	char* cur_metric=NULL;
	if(*ppa == NULL)
	{
//init
		*ppa = (struct phy_pmu_analysis*)phy_malloc(*ppa, sizeof(struct phy_pmu_analysis));
		memset(*ppa, 0, sizeof(struct phy_pmu_analysis));
		(*ppa)->current = NULL;
		(*ppa)->metrics = (*ppa)->current;
	}

	if (NULL != origfile)
	{
		if (NULL == (file = fopen(origfile, "r")))
			return;

		for (lineno = 1; NULL != fgets(line, sizeof(line), file); lineno++)
		{
//			printf("%s", line);
			if(strstr(line, ":") && !new_metric_flag)
			{
				tstr = get_str_between_two_words(line, NULL, ":");
				phy_snprintf((*ppa)->anal_name, mtcnmlen, "%s", tstr);
				phy_free(tstr);
				continue;
			}

			if(new_event_flag == true)
			{
				if(strstr(line, "=======")){
					new_metric_flag = false;
					new_event_flag = false;
					continue;
				}

				if(strstr(line, "-------") || strstr(line, "........"))
				{
					continue;
				}
				if(((*ppa)->current->orig_data == NULL) || ((*ppa)->current->orig_data == NULL)){
					(*ppa)->current->orig_data = (struct phy_pmu_event*)phy_malloc((*ppa)->current->orig_data, sizeof(struct phy_pmu_event));
					(*ppa)->current->stat_data = (struct phy_pmu_event*)phy_malloc((*ppa)->current->stat_data, sizeof(struct phy_pmu_event));
					memset((*ppa)->current->orig_data, 0, sizeof(struct phy_pmu_event));
					memset((*ppa)->current->stat_data, 0, sizeof(struct phy_pmu_event));
					(*ppa)->current->curr_orig = (*ppa)->current->orig_data;
					(*ppa)->current->curr_stat = (*ppa)->current->stat_data;
				}
				add_event(ppa, line, cur_metric);
			}

			if(strstr(line, "=======") && !new_metric_flag)
			{
				new_metric_flag = true;
				continue;
			}

			if(new_metric_flag == true && !new_event_flag)
			{
				if(strstr(line, "=======")){
					new_event_flag = true;
					continue;
				}
				tstr = get_str_between_two_words(line, NULL, ":");
				cur_metric = phy_strdup(cur_metric, tstr);
				add_metric(ppa, tstr);
				phy_free(tstr);
				continue;
			}
		}
		fclose(file);
	}
	phy_free(cur_metric);
}
#endif

void pmu_orig_struct_to_json(const char* origfile, const char* jsonfile)
{
#define PHY_CFG_LTRIM_CHARS	"\t "
#define PHY_CFG_RTRIM_CHARS	PHY_CFG_LTRIM_CHARS "\r\n"

	struct strlist* filecontent = NULL;
	struct strlist* p = NULL;

#define js_heta "{\n	\"title\":\"banner\",\n}"
#define js_rarry_body ": {\n	},"


	char cmd[CMDLEN] = {0};

	char* event_name = NULL;
	char* event_value = NULL;
	char tstr[mjslnlen]={0};
	char* pinjson = NULL;
	char* binjson = NULL;
	char* qinjson = NULL;

	char evstr[BUFLEN] = {0};
	char evline[MAX_STRING_LEN] = {0};

	create_strlist(&filecontent);
	phy_snprintf(cmd, CMDLEN, "cat %s", origfile);
	get_result_strlist(cmd, filecontent, false);
	strlist_delete_relkey(&filecontent, "........");
	strlist_delete_relkey(&filecontent, "--------");
	strlist_delete_relkey(&filecontent, "========");
	if(strlist_delete_relkey(&filecontent, "Analysis")){
		strlist_insert_str(&filecontent, "PMUs Analysis", true);
	}
//	strlist_insert_str(&filecontent, "PMUs Analysis", true);
//	iterator_strlistah(filecontent);
	strlist_reverse(&filecontent);
//	iterator_strlistah(filecontent);
	destory_strlist(filecontent);
	return;
//	p = filecontent->next;
//	tstrp = p->data;
//	while(p){
//		strncmp(tstrp);
//		p = p->next;
//	}

	p = filecontent->next;
	while(p)
	{
		phy_rtrim(p->data, PHY_CFG_RTRIM_CHARS);
		phy_ltrim(p->data, PHY_CFG_LTRIM_CHARS);
//title
		if(!strchr(p->data, ':')){
			pinjson = string_replace(js_heta, "banner", p->data);
			p = p->next;
			continue;
		}
//evets
		if(keyword_at_the_middle_of_the_string(p->data, ":")){
			event_name = get_str_between_two_words(p->data, NULL, ":");
			event_value = get_str_between_two_words(p->data, ":", NULL);
			memset(evstr, 0, BUFLEN);
			phy_snprintf(evstr, BUFLEN, "		\"%s\":\"%s\",\n", event_name, event_value);
			phy_free(event_name);
			phy_free(event_value);
			strncat(evline, evstr, strlen(evstr));
	//last one event
			if(p->next == NULL){
				phy_rtrim(evline, ",\n");
				phy_strlcat(evline, "\n", 1);
				qinjson = insert_string(tstr, "	},", evline, true);
				phy_rtrim(qinjson, ",");
				binjson = insert_string(pinjson, "\n}", qinjson, true);
				phy_free(qinjson);
				phy_free(pinjson);
				pinjson = binjson;
			}
			p = p->next;
//			nmtcf = true;
			continue;
		}
//metrics
		if(keyword_at_the_end_of_the_string(p->data, ":")){
			if(strlen(tstr) != 0){
				phy_rtrim(evline, ",\n");
				phy_strlcat(evline, "\n", 1);
				qinjson = insert_string(tstr, "	},", evline, true);
				binjson = insert_string(pinjson, "\n}", qinjson, true);
				phy_free(qinjson);
				phy_free(pinjson);
				memset(evline, 0, MAX_STRING_LEN);
				pinjson = binjson;
			}
			phy_rtrim(p->data, ":");
			memset(tstr, 0, mjslnlen);
			phy_snprintf(tstr, mjslnlen, "\n	\"%s\"%s", p->data, js_rarry_body);
//			p->data = phy_strdup(p->data, tstr);
			p = p->next;
			continue;
		}
		p = p->next;
	}
	write_file(jsonfile, pinjson);
	phy_free(pinjson);
	destory_strlist(filecontent);
	return;
}

struct strlist* get_pmuevent(struct strlist* stlst,  const char* metircname)
{
	struct strlist* p = NULL;
	struct strlist* shtcontent = NULL;
	create_strlist(&shtcontent);
	bool schf = false;
	p = stlst->next;
	while(p){
		if(keyword_at_the_end_of_the_string(p->data, ":") && strstr(p->data, metircname)){
			schf = true;
		}
		p = p->next;
		if(schf == true){
			if(p->next == NULL){
				if(keyword_at_the_middle_of_the_string(p->data, ":")){
					strlist_add(&shtcontent, p->data);
				}
			}
			if(keyword_at_the_end_of_the_string(p->data, ":") || (p->next == NULL)){
				break;
			}
			strlist_add(&shtcontent, p->data);
		}
	}
	return shtcontent;
}

void set_templatejson_value(struct strlist** tempcontent, struct strlist* shtcontent)
{
	struct strlist* shtcp = NULL;
	struct strlist* tempp = NULL;
	char* event_name = NULL;
	char* event_value = NULL;
	char* revent_value = NULL;
	char* revent_name = NULL;
	char* tevent_str = NULL;
	char event_str[mjslnlen]={0};
	shtcp = shtcontent->next;
	tempp = *tempcontent;
	while(tempp){

		memset(event_str, 0, mjslnlen);
		event_name = get_str_between_two_words(tempp->data, "\"", "\"");
		event_value = get_str_between_two_words(tempp->data, ": \"", "\"");
//		phy_snprintf(event_value_str, evtnmlen, "\"%s\"", event_value);
		shtcp = shtcontent->next;
		while(shtcp){
			revent_name = get_str_between_two_words(shtcp->data, NULL, ":");
			if(strlen(revent_name) == strlen(event_name) && strstr(revent_name, event_name)){
				revent_value = get_str_between_two_words(shtcp->data, ":", NULL);
//				printf("%s, %s\n", shtcp->data, tempp->data);
				tevent_str = string_replace(tempp->data, event_value, revent_value);
				phy_free(tempp->data);
				tempp->data = phy_strdup(tempp->data, tevent_str);
				phy_free(tevent_str);
				phy_free(revent_value);
				phy_free(revent_name);
				break;
			}
			phy_free(revent_name);
			shtcp = shtcp->next;
		}
		phy_free(event_name);
		phy_free(event_value);
		tempp = tempp->next;
		*tempcontent = tempp;
		if(strstr(tempp->data, ": {") || strstr(tempp->data, "		}")){
			break;
		}
	}
}

void strlist_to_chartjson(struct strlist* stlst, const char*  templatejson, char* chartjsonfile)
{
	struct strlist* tempcontent = NULL;
	struct strlist* tempp = NULL;
	struct strlist* shtcontent = NULL;
	char* metricnm = NULL;
	bool schf = false;
	char cmd[CMDLEN] = {0};
	create_strlist(&tempcontent);
	if(strlen(templatejson) == 0){
		return;
	}
	phy_snprintf(cmd, CMDLEN, "cat %s", templatejson);
	get_result_strlist(cmd, tempcontent, false);
//search "keys" :[
	tempp = tempcontent->next;
	while(tempp){
		if(strstr(tempp->data, "histogram\":") || strstr(tempp->data, "PieDiagram\":")){
			tempp = tempp->next;
			continue;
		}
		if(strstr(tempp->data, ": {") && (schf == false)){
			schf = true;
			metricnm = get_str_between_two_words(tempp->data, "\"", "\"");
			shtcontent = get_pmuevent(stlst,  metricnm);
			phy_free(metricnm);
//			printf("--------%s\n", metricnm);
//			iterator_strlist(shtcontent);
		}
		tempp = tempp->next;
		if(schf == true){
//set templatejson's value
			set_templatejson_value(&tempp, shtcontent);
			destory_strlist(shtcontent);
			schf = false;
		}
	}
//special treat
	if(strstr(chartjsonfile, "ftc8")){
// Top PieDiagram->Cycle Effectiveness
		double sfrtvalue;
		double sbrtvalue;
		double recyvalue;

		struct strlist* lpstall_find_rt = NULL;
		struct strlist* lpstall_bknd_rt = NULL;
		struct strlist* lpretired_cycles = NULL;
		char *evvl = NULL;

		tempp = tempcontent->next;
		bool toppie = false;
		bool cycefc = false;
		while(tempp){
			if(cycefc == true){
				if(strstr(tempp->data, "[STALL_FTND_RT]")){
					lpstall_find_rt = tempp;
				}
				if(strstr(tempp->data, "[STALL_BKND_RT]")){
					lpstall_bknd_rt = tempp;
				}
				if(strstr(tempp->data, "[RETIRED_CYCLES]")){
					lpretired_cycles = tempp;
				}
				tempp = tempp->next;
				continue;
			}
			if( strstr(tempp->data, "Top PieDiagram") && toppie == false){
				toppie = true;
				tempp = tempp->next;
				continue;
			}
			if( toppie == true ){
				if(strstr(tempp->data, "Cycle Effectiveness")){
					cycefc = true;
				}
			}
			tempp = tempp->next;
		}

		evvl =  get_str_between_two_words(lpstall_find_rt->data, ": \"", "\%");
		sfrtvalue = str2double(evvl);
		phy_free(evvl);
		evvl =  get_str_between_two_words(lpstall_bknd_rt->data, ": \"", "\%");
		sbrtvalue = str2double(evvl);
		phy_free(evvl);
		recyvalue = 100 - (sfrtvalue + sbrtvalue);
		if(recyvalue > 0){
			memset(cmd, 0, CMDLEN);
			phy_snprintf(cmd, CMDLEN, "			\"[RETIRED_CYCLES]\": \"%.2lf%\"", recyvalue);
			phy_free(lpretired_cycles->data);
			lpretired_cycles->data = phy_strdup(lpretired_cycles->data, cmd);
		}else{
			strlist_delete_p(&tempcontent, &lpretired_cycles);
		}
	}
	strlist2file(tempcontent, chartjsonfile);
	destory_strlist(tempcontent);
}

void strlist_to_chartjson_newftc8(struct strlist* stlst, const char*  templatejson, char* chartjsonfile)
{
	struct strlist* tempcontent = NULL;
	struct strlist* tempp = NULL;
	struct strlist* shtcontent = NULL;
	char* bktstr = NULL;
	char bktstrs[20] = {0};
	char* metricnm = NULL;
	bool schf = false;
	char cmd[CMDLEN] = {0};
	create_strlist(&tempcontent);
	if(strlen(templatejson) == 0){
		return;
	}
	phy_snprintf(cmd, CMDLEN, "cat %s", templatejson);
	get_result_strlist(cmd, tempcontent, false);
//search "keys" :[
	tempp = tempcontent->next;
	while(tempp){
		if(strstr(tempp->data, "histogram\":") || strstr(tempp->data, "PieDiagram\":")){
			tempp = tempp->next;
			continue;
		}
		if(strstr(tempp->data, ": {") && (schf == false)){
			schf = true;
			if(strstr(tempp->data, "(") && strstr(tempp->data, ")")){
				memset(bktstrs, 0, 20);
				bktstr = get_str_between_two_words(tempp->data, "(", ")");
				phy_snprintf(bktstrs, 20, "(%s) ", bktstr);
				phy_free(bktstr);
				bktstr = get_str_between_two_words(tempp->data, "\"", "\"");
				if(strstr(bktstr, "CACHE")){
					metricnm = string_replace(bktstr, bktstrs, " & MEM ");
				}else{
					metricnm = string_replace(bktstr, bktstrs, " ");
				}
				phy_free(bktstr);
			}else{
				metricnm = get_str_between_two_words(tempp->data, "\"", "\"");
			}
			shtcontent = get_pmuevent(stlst,  metricnm);
			phy_free(metricnm);
//			printf("--------%s\n", metricnm);
//			iterator_strlist(shtcontent);
		}
		tempp = tempp->next;
		if(schf == true){
//set templatejson's value
			set_templatejson_value(&tempp, shtcontent);
			destory_strlist(shtcontent);
			schf = false;
		}
	}
//special treat
	if(strstr(chartjsonfile, "ftc8")){
// Top PieDiagram->Cycle Effectiveness
		double sfrtvalue;
		double sbrtvalue;
		double recyvalue;

		struct strlist* lpstall_find_rt = NULL;
		struct strlist* lpstall_bknd_rt = NULL;
		struct strlist* lpretired_cycles = NULL;
		char *evvl = NULL;

		tempp = tempcontent->next;
		bool toppie = false;
		bool cycefc = false;
		while(tempp){
			if(cycefc == true){
				if(strstr(tempp->data, "[STALL_FTND_RT]")){
					lpstall_find_rt = tempp;
				}
				if(strstr(tempp->data, "[STALL_BKND_RT]")){
					lpstall_bknd_rt = tempp;
				}
				if(strstr(tempp->data, "[RETIRED_CYCLES]")){
					lpretired_cycles = tempp;
				}
				tempp = tempp->next;
				continue;
			}
			if( strstr(tempp->data, "Top PieDiagram") && toppie == false){
				toppie = true;
				tempp = tempp->next;
				continue;
			}
			if( toppie == true ){
				if(strstr(tempp->data, "Cycle Effectiveness")){
					cycefc = true;
				}
			}
			tempp = tempp->next;
		}

		evvl =  get_str_between_two_words(lpstall_find_rt->data, ": \"", "\%");
		sfrtvalue = str2double(evvl);
		phy_free(evvl);
		evvl =  get_str_between_two_words(lpstall_bknd_rt->data, ": \"", "\%");
		sbrtvalue = str2double(evvl);
		phy_free(evvl);
		recyvalue = 100 - (sfrtvalue + sbrtvalue);
		if(recyvalue > 0){
			memset(cmd, 0, CMDLEN);
			phy_snprintf(cmd, CMDLEN, "			\"[RETIRED_CYCLES]\": \"%.2lf%\"", recyvalue);
			phy_free(lpretired_cycles->data);
			lpretired_cycles->data = phy_strdup(lpretired_cycles->data, cmd);
		}else{
			strlist_delete_p(&tempcontent, &lpretired_cycles);
		}
	}
	strlist2file(tempcontent, chartjsonfile);
	destory_strlist(tempcontent);
}

bool fs_orig_to_json(const char* origfile, const char* source_jsonfile, const char* callsite_jsonfile, const char* obj_jsonfile, const char* cacheline_jsonfile)
{
	char cmd[BUFLEN] = {0};
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s %s %s", fs_sourcerestran, origfile, source_jsonfile);
	system(cmd);
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s %s %s", fs_callsiterestran, origfile, callsite_jsonfile);
	system(cmd);
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s %s %s", fs_objrestran, origfile, obj_jsonfile);
	system(cmd);
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s %s %s", fs_cachelinerestran, origfile, cacheline_jsonfile);
	system(cmd);
	return true;
}
bool numa_orig_to_json(const char* origfile, const char* source_jsonfile, const char* callsite_jsonfile, const char* obj_jsonfile, const char* cacheline_jsonfile)
{
	char cmd[BUFLEN] = {0};
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s %s %s", fs_sourcerestran, origfile, source_jsonfile);
	system(cmd);
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s %s %s", numa_callsiterestran, origfile, callsite_jsonfile);
	system(cmd);
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s %s %s", numa_objrestran, origfile, obj_jsonfile);
	system(cmd);
	memset(cmd, 0, BUFLEN);
	phy_snprintf(cmd, BUFLEN, "%s %s %s", numa_cachelinerestran, origfile, cacheline_jsonfile);
	system(cmd);
	return true;
}
bool topdown_orig_to_json(const char* origfile, const char* jsonfile, char** chartjsonfile)
{
	char cmd[BUFLEN] = {0};
	phy_snprintf(cmd, BUFLEN, "cat %s", origfile);
	struct strlist* orfl=NULL;
	create_strlist(&orfl);
	bool typef = false;

// get result
	get_result_strlist(cmd, orfl, false);
	if(orfl->next == NULL){
		destory_strlist(orfl);
		return false;
	}

	remove_file(origfile);
	strlist_delete_tooshort(&orfl, 2);
	strlist2file(orfl, origfile);

	typef = matches_strings((const char*)(orfl->next->data), true, "time", "level", "stage", "group", "metric", "value", "units", END);
	destory_strlist(orfl);

	memset(tpdcsvtran, 0, BUFLEN);
	memset(tpdrestran, 0, BUFLEN);
	phy_snprintf(tpdcsvtran, BUFLEN, "%s", "/opt/phytune/server/resource/topdown_csv2json.sh");
	phy_snprintf(tpdrestran, BUFLEN, "%s", "/opt/phytune/server/resource/topdown_res2json.sh");

	*chartjsonfile = string_replace(jsonfile, "_table.json", "_chart.json");

	if(typef == true){//type 1
		memset(cmd, 0, BUFLEN);
		phy_snprintf(cmd, BUFLEN, "%s %s %s %s", tpdcsvtran, origfile, jsonfile, *chartjsonfile);
		system(cmd);
	}else{//type 2
		memset(cmd, 0, BUFLEN);
		phy_snprintf(cmd, BUFLEN, "%s %s %s %s", tpdrestran, origfile, jsonfile, *chartjsonfile);
		system(cmd);
	}
	return true;
}

bool memaccess_to_json(const char* origfile, const char* jsonfile, char** chartjsonfile)
{
	char cmd[1024] = {0};
	if(!is_exist(origfile)){
		return false;
	}

	memset(masrestran, 0, BUFLEN);
	memset(msevtrestran, 0, BUFLEN);
	*chartjsonfile = string_replace(jsonfile, ".json", "_chart.json");
	if (strstr(origfile, "stats") != NULL){
		phy_snprintf(masrestran, BUFLEN, "%s", "/opt/phytune/server/resource/memaccess_res2json");
		phy_snprintf(cmd, 1024, "%s %s %s %s", masrestran, origfile, jsonfile, *chartjsonfile);
	}else if (strstr(origfile, "missevt") != NULL){
		phy_snprintf(msevtrestran, BUFLEN, "%s", "/opt/phytune/server/resource/miss_event_res2json");
		phy_snprintf(cmd, 1024, "%s %s %s %s", msevtrestran, origfile, jsonfile, *chartjsonfile);
	}

	system(cmd);
	return true;
}

#if 0
bool topdown_orig_to_json(const char* origfile, const char* jsonfile, char** chartjsonfile)
{
	char cmd[BUFLEN] = {0};
	phy_snprintf(cmd, BUFLEN, "cat %s", origfile);
	struct strlist* orfl=NULL;
	struct strlist* orp=NULL;
	char **arr = NULL;
	char** stmp = NULL;
	ntlst* ntl = NULL;
	char* time=NULL, *level=NULL, *stage=NULL, *group=NULL, *metric=NULL, *value=NULL, *units=NULL;
	int i = 0;
//	ntlst_create(&ntl);
	create_strlist(&orfl);
	bool typef = false;
// get result
	get_result_strlist(cmd, orfl, false);
	typef = matches_strings((const char*)(orfl->next->data), true, "time", "level", "stage", "group", "metric", "value", "units", END);
	orp = orfl->next->next;

	phy_snprintf(tpdcsvtran, BUFLEN, "%s", "/home/nt/phyTune_version/phyTune-v1.6.0/server/resource/topdown_csv2json.sh");
	phy_snprintf(tpdrestran, BUFLEN, "%s", "/home/nt/phyTune_version/phyTune-v1.6.0/server/resource/topdown_res2json.sh");

	if(typef == true){//type 1
		memset(cmd, 0, BUFLEN);
		phy_snprintf(cmd, BUFLEN, "%s %s %s", tpdcsvtran, origfile, jsonfile);
		system(cmd);
#if 0
		while(orp){
			phy_strarr_init(&arr);
			str_to_arr(orp->data, ",", &arr);
			time=NULL, level=NULL, stage=NULL, group=NULL, metric=NULL, value=NULL, units=NULL;
			i = 0;
			for (stmp = arr; NULL != *stmp; stmp++){
				if(i==0){
					time = *stmp;
					printf("time = %s\n", *stmp);
				}else if(i == 1){
					level = *stmp;
					printf("level = %s\n", *stmp);
				}else if(i == 2){
					stage = *stmp;
					printf("stage = %s\n", *stmp);
				}else if(i == 3){
					group = *stmp;
					printf("group = %s\n", *stmp);
				}else if(i == 4){
					metric = *stmp;
					printf("metric = %s\n", *stmp);
				}else if(i == 5){
					value = *stmp;
					printf("value = %s\n", *stmp);
				}else if(i == 6){
					units = *stmp;
					printf("units = %s\n", *stmp);
				}
				i++;
			}

			orp = orp->next;
			phy_strarr_free(arr);
			arr = NULL;
//			break;
		}
#endif
	}else{//type 2
		memset(cmd, 0, BUFLEN);
		phy_snprintf(cmd, BUFLEN, "%s %s %s", tpdrestran, origfile, jsonfile);
		system(cmd);
	}
	destory_strlist(orfl);
	return true;
}
#endif

bool pmu_orig_struct_to_json_p(const char* origfile, const char* jsonfile, char** chartjsonfile)
{
#define PHY_CFG_LTRIM_CHARS	"\t "
#define PHY_CFG_RTRIM_CHARS	PHY_CFG_LTRIM_CHARS "\r\n"

	struct strlist* filecontent = NULL;
	struct strlist* p = NULL;
#define myjson_head "{\n\
	\"title\":\"banner\","
#define myjson_tail "}"

	char cmd[CMDLEN] = {0};

	char* event_name = NULL;
	char* event_value = NULL;
	char tstr[mjslnlen]={0};
	char* pinjson = NULL;
	char evstr[BUFLEN] = {0};

	if(!is_exist(origfile)){
		return false;
	}

	create_strlist(&filecontent);
	phy_snprintf(cmd, CMDLEN, "cat %s", origfile);
	get_result_strlist(cmd, filecontent, false);
	strlist_delete_tooshort(&filecontent, 2);
	strlist_delete_relkey(&filecontent, "........");
	strlist_delete_relkey(&filecontent, "--------");
	strlist_delete_relkey(&filecontent, "========");

	p = filecontent->next;
	if(strstr(p->data, "FTC6")){
//		*chartjsonfile = string_replace(jsonfile, ".json", "_ftc6-chart.json");
		*chartjsonfile = string_replace(jsonfile, ".json", "_chart.json");
		strlist_to_chartjson(filecontent, FTC6_NS_TEMPLATE_JSON, *chartjsonfile);
	}else if(strstr(p->data, "FTC8")){
//replace keys
		memset(cmd, 0, CMDLEN);
		phy_snprintf(cmd, CMDLEN, "sed -i 's/r31/remote_access/g;s/r34/dtlb_walk/g;s/r35/itlb_walk/g;s/r36/ll_cache_rd/g;s/r37/ll_cache_miss_rd/g;s/r70/ld_spec/g;s/r71/st_spec/g;s/r72/ldst_spec/g;s/r73/dp_spec/g;s/r74/ase_spec/g;s/r75/vfp_spec/g;s/r76/pc_write_spec/g;s/r77/crypto_spec/g;s/r78/br_immed_spec/g;s/r79/br_return_spec/g;s/r7a/br_indirect_spec/g' %s", origfile);
		system(cmd);
//reload
		destory_strlist(filecontent);
		memset(cmd, 0, CMDLEN);
		filecontent = NULL;
		create_strlist(&filecontent);
		phy_snprintf(cmd, CMDLEN, "cat %s", origfile);
		get_result_strlist(cmd, filecontent, false);
		strlist_delete_tooshort(&filecontent, 2);
		strlist_delete_relkey(&filecontent, "........");
		strlist_delete_relkey(&filecontent, "--------");
		strlist_delete_relkey(&filecontent, "========");
		p = filecontent->next;

//		*chartjsonfile = string_replace(jsonfile, ".json", "_ftc8-chart.json");
		*chartjsonfile = string_replace(jsonfile, ".json", "_chart.json");

		strlist_to_chartjson_newftc8(filecontent, FTC8_NS_TEMPLATE_JSON, *chartjsonfile);
	}else if(strstr(p->data, "NOC")){
		*chartjsonfile = string_replace(jsonfile, ".json", "_chart.json");
		strlist_to_chartjson(filecontent, NOC_NS_TEMPLATE_JSON, *chartjsonfile);
	}else if(strstr(p->data, "DDR")){
		destory_strlist(filecontent);
		return pmu_ddr_to_json(origfile, jsonfile, chartjsonfile);
	}else if(strstr(p->data, "C2C")){
		destory_strlist(filecontent);
		return pmu_c2c_to_json(origfile, jsonfile, chartjsonfile);
	}else if(strstr(p->data, "PCIe")){
		destory_strlist(filecontent);
		return pmu_pcie_to_json(origfile, jsonfile, chartjsonfile);
	}else if(strstr(p->data, "PMUs Analysis")){
		*chartjsonfile = string_replace(jsonfile, ".json", "_anal-chart.json");
		strlist_to_chartjson(filecontent, ANAL_NS_TEMPLATE_JSON, *chartjsonfile);
	}else{
		return false;
	}

	while(p)
	{
		phy_rtrim(p->data, PHY_CFG_RTRIM_CHARS);
		phy_ltrim(p->data, PHY_CFG_LTRIM_CHARS);
//event
		if(keyword_at_the_middle_of_the_string(p->data, ":")){
			event_name = get_str_between_two_words(p->data, NULL, ":");
			event_value = get_str_between_two_words(p->data, ":", NULL);
			memset(evstr, 0, BUFLEN);
			if(p->next == NULL){
				phy_snprintf(evstr, BUFLEN, "		\"%s\":\"%s\"\n	}", event_name, event_value);
			}
			else if(keyword_at_the_end_of_the_string(p->next->data, ":")){
				phy_snprintf(evstr, BUFLEN, "		\"%s\":\"%s\"\n	},", event_name, event_value);
			}else{
				phy_snprintf(evstr, BUFLEN, "		\"%s\":\"%s\",", event_name, event_value);
			}
			phy_free(event_name);
			phy_free(event_value);
			phy_free(p->data);
			p->data = phy_strdup(p->data, evstr);
			p = p->next;
//			evetf = true;
			continue;
		}
//metrics
		if(keyword_at_the_end_of_the_string(p->data, ":")){
			memset(tstr, 0, mjslnlen);
			phy_snprintf(tstr, mjslnlen, "	\"%s\": {", p->data);
			phy_free(p->data);
			p->data = phy_strdup(p->data, tstr);
			p = p->next;
//			metcf = true;
			continue;
		}

//set title
		if(!strchr(p->data, ':')){
			pinjson = string_replace(myjson_head, "banner", p->data);
			phy_free(p->data);
			p->data = phy_strdup(p->data, pinjson);
			phy_free(pinjson);
			p = p->next;
			continue;
		}
	}
	strlist_insert_str(&filecontent, myjson_tail, false);
	strlist2file(filecontent, jsonfile);
	destory_strlist(filecontent);
	if(!is_exist(jsonfile) || !is_exist(*chartjsonfile)){
		return false;
	}
	return true;
}

void iterator_pmu_orig_struct(struct phy_pmu_analysis *ppa)
{
	struct phy_pmu_metrics* current = NULL;
	struct phy_pmu_event* origevt = NULL;
	struct phy_pmu_event* statevt = NULL;

	printf("pmu analysis: %s\n", ppa->anal_name);
	current = ppa->metrics;
	while(current){
		printf("<--metric name: %s\n", current->metric_name);
		origevt = current->orig_data;
		statevt = current->stat_data;
		while(origevt){
			printf("<----metric name:%s, event_name: %s, event_value: %s\n", origevt->metric_name, origevt->event_name, origevt->event_value);
			origevt = origevt->next;
		}
		while(statevt){
			printf("<----metric name:%s, event_name: [%s], event_value: %s\n", statevt->metric_name, statevt->event_name, statevt->event_value);
			statevt = statevt->next;
		}
		current = current->next;
	}
}

void destroy_pmu_event_struct(struct phy_pmu_event* evt)
{
	struct phy_pmu_event* tevt = NULL;
	tevt= evt;
	while(tevt){
		evt = tevt->next;
		phy_free(tevt);
		tevt = evt;
	}
}

void destroy_pmu_orig_struct(struct phy_pmu_analysis *ppa)
{
	struct phy_pmu_metrics* current = NULL;
	struct phy_pmu_event* origevt = NULL;
	struct phy_pmu_event* statevt = NULL;

//	printf("pmu analysis: %s\n", ppa->anal_name);
	current = ppa->metrics;
	while(current){
		ppa->metrics = current->next;
		origevt = current->orig_data;
		statevt = current->stat_data;
		destroy_pmu_event_struct(origevt);
		destroy_pmu_event_struct(statevt);
		phy_free(current);
		current = ppa->metrics;
	}
	phy_free(ppa);
}

void pmu_orig_struct_to_jason(const char* jsonfile, struct phy_pmu_analysis *ppa)
{
#define myjson_head "{\n\
	\"title\":\"banner\","
#define myjson_tail "}"
#define myjson_rarry_head ": {"
#define myjson_rarry_tail "\n			}"

	char jrarryh[mjslnlen];
	char tstring[mjslnlen];
	char *jsonhead=NULL;
	struct phy_pmu_metrics* current = NULL;
	struct phy_pmu_event* origevt = NULL;
	struct phy_pmu_event* statevt = NULL;
	jsonhead = string_replace(myjson_head, "banner", ppa->anal_name);
	write_file(jsonfile, jsonhead);
	phy_free(jsonhead);

	current = ppa->metrics;
	while(current){
//		printf("<--metric name: %s\n", current->metric_name);
		memset(jrarryh, 0, mjslnlen);
		phy_snprintf(jrarryh, mjslnlen, "	\"%s\": {", current->metric_name);
		write_file(jsonfile, jrarryh);

		origevt = current->orig_data;
		statevt = current->stat_data;

		while(origevt){
			memset(tstring, 0, mjslnlen);
			phy_snprintf(tstring, mjslnlen, "		\"%s\": \"%s\",", origevt->event_name, origevt->event_value);
			origevt = origevt->next;
			write_file(jsonfile, tstring);
		}
		while(statevt){
			memset(tstring, 0, mjslnlen);
			if(statevt->next != NULL){
				phy_snprintf(tstring, mjslnlen, "		\"%s\": \"%s\",", statevt->event_name, statevt->event_value);
			}else{
				phy_snprintf(tstring, mjslnlen, "		\"%s\": \"%s\"", statevt->event_name, statevt->event_value);
			}
			statevt = statevt->next;
			write_file(jsonfile, tstring);
		}
		if(current->next != NULL){
			write_file(jsonfile, "	},");
		}else{
			write_file(jsonfile, "	}");
		}
		current = current->next;
	}
	write_file(jsonfile, myjson_tail);
}

#define PCIETTKS "PCIe Analysis"
bool pmu_pcie_to_json(const char* origfile, const char* jsonfile, char** chartjsonfile)
{
	char* junction = "	}\n\
}\n\
{\n\
	";
	char* junctionnn = "	}\n\
}\n\
{";
	char* linker = "	},";

	char* ptstr = NULL;
	bool subitem = false;
	struct strlist *p = NULL;
	struct strlist *filecontent = NULL;

	char title[LPHRASE] = {0};
	char pjunction[LPHRASE] = {0};

	char atstrs[PHRASE] = {0};
	char atstr[PHRASE] = {0};
	char* strpin = NULL;
	char* strpon = NULL;

	char* node_id = NULL;
	char* pmu_id = NULL;
	char* ctrler_id = NULL;
	char* pcie_freq_in_ghz = NULL;
	char* pcie_data_width = NULL;

	char* cycles_ctrler = NULL;        //0x0/: 1
	char* ar_ctrler=NULL;        //0x0/: 2
	char* r_last_ctrler=NULL;        //0x0/: 3
	char* r_err_ctrler=NULL;        //0x0/: 4
	char* r_full_ctrler=NULL;        //0x0/: 5
	char* aw_ctrler=NULL;        //0x0/: 6
	char* w_last_ctrler=NULL;        //0x0/: 7
	char* w_err_ctrler=NULL;        //0x0/: 8
	char* b_ctrler=NULL;        //0x0/: 9
	char* w_data_ctrler=NULL;        //0x0/: 10
	char* delay_rd_ctrler=NULL;        //0x0/: 11
	char* rd_max_ctrler=NULL;        //0x0/: 12
	char* rd_min_ctrler=NULL;        //0x0/: 13
	char* rdelay_time_ctrler=NULL;        //0x0/: 14
	char* delay_wr_ctrler=NULL;        //0x0/: 15
	char* wr_max_ctrler=NULL;        //0x0/: 16
	char* wr_min_ctrler=NULL;        //0x0/: 17
	char* wdelay_time_ctrler=NULL;        //0x0/: 18
	char* WR_FLOW_RT=NULL;        //: 19 GBps
	char* RD_FLOW_RT=NULL;        //: 20 GBps
	char* WR_DELAY=NULL;        //: 21
	char* RD_DELAY=NULL;        //: 22
	char* TRANS_ar_RT=NULL;        //: 23 GTps
	char* TRANS_r_last_RT=NULL;        //: 24 GTps
	char* TRANS_r_err_RT=NULL;        //: 25 GTps
	char* TRANS_r_full_RT=NULL;        //: 26 GTps
	char* TRANS_aw_RT=NULL;        //: 27 GTps
	char* TRANS_w_last_RT=NULL;        //: 28 GTps
	char* TRANS_w_err_RT=NULL;        //: 29 GTps
	char* TRANS_b_RT=NULL;        //: 30 GTps
	char* TRANS_delay_rd_RT=NULL;        //: 31 GTps
	char* TRANS_delay_wr_RT=NULL;        //: 32 GTps

	char* ojsflcontent = NULL;
	char cmd[CMDLEN] = {0};

	create_strlist(&filecontent);

	phy_snprintf(cmd, CMDLEN, "cat %s", origfile);
	get_result_strlist(cmd, filecontent, false);
	strlist_delete_tooshort(&filecontent, 2);
	strlist_delete_relkey(&filecontent, "........");
	strlist_delete_relkey(&filecontent, "--------");
	strlist_delete_relkey(&filecontent, "========");

	p = filecontent->next;

	ptstr = string_replace(jsonfile, ".json", "_chart.json");
	*chartjsonfile = phy_strdup(*chartjsonfile, ptstr);
	phy_free(ptstr);

	clean_file(jsonfile);
	clean_file(*chartjsonfile);

	while(p){
		if(strstr(p->data, PCIETTKS)){
			phy_snprintf(title, LPHRASE, "\"title\": \"%s\",", p->data);
			phy_snprintf(pjunction, LPHRASE, "%s%s", junction, title);
			p = p->next;
			continue;
		}
		if( strstr(p->data, "Node") && strstr(p->data, "PCIe") && strstr(p->data, "Ctrler") ){
			subitem = false;
		}

//get node_id
		if(node_id == NULL){
			node_id = get_str_between_two_words(p->data, "Node(", ")PCIe");
		}
//get pmu_id
		if(pmu_id == NULL){
			pmu_id = get_str_between_two_words(p->data, "PCIe(", ")Ctrler");
		}
//get ctrler_id
		if(ctrler_id == NULL){
			ctrler_id = get_str_between_two_words(p->data, "Ctrler(", ")");
		}
//get pcie_freq_in_ghz
		if(pcie_freq_in_ghz == NULL){
			pcie_freq_in_ghz = get_str_between_two_words(p->data, "PCIe_Freq:", "GHz");
		}
//get pcie_data_width
		if(pcie_data_width == NULL){
			pcie_data_width = get_str_between_two_words(p->data, "PCIe_DATA_WIDTH:", NULL);
		}

//get cycles_ctrler
		if(cycles_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "cycles,ctrler=%s/: ", ctrler_id);
			cycles_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get ar_ctrler
		if(ar_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "ar,ctrler=%s/: ", ctrler_id);
			ar_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get r_last_ctrler
		if(r_last_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "r_last,ctrler=%s/: ", ctrler_id);
			r_last_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get r_err_ctrler
		if(r_err_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "r_err,ctrler=%s/: ", ctrler_id);
			r_err_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get r_full_ctrler
		if(r_full_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "r_full,ctrler=%s/: ", ctrler_id);
			r_full_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get aw_ctrler
		if(aw_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "aw,ctrler=%s/: ", ctrler_id);
			aw_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get w_last_ctrler
		if(w_last_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "w_last,ctrler=%s/: ", ctrler_id);
			w_last_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get w_err_ctrler
		if(w_err_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "w_err,ctrler=%s/: ", ctrler_id);
			w_err_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get b_ctrler
		if(b_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "b,ctrler=%s/: ", ctrler_id);
			b_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get w_data_ctrler
		if(w_data_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "w_data,ctrler=%s/: ", ctrler_id);
			w_data_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get delay_rd_ctrler
		if(delay_rd_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "delay_rd,ctrler=%s/: ", ctrler_id);
			delay_rd_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get rd_max_ctrler
		if(rd_max_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rd_max,ctrler=%s/: ", ctrler_id);
			rd_max_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get rd_min_ctrler
		if(rd_min_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rd_min,ctrler=%s/: ", ctrler_id);
			rd_min_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get rdelay_time_ctrler
		if(rdelay_time_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rdelay_time,ctrler=%s/: ", ctrler_id);
			rdelay_time_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get delay_wr_ctrler
		if(delay_wr_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "delay_wr,ctrler=%s/: ", ctrler_id);
			delay_wr_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get wr_max_ctrler
		if(wr_max_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "wr_max,ctrler=%s/: ", ctrler_id);
			wr_max_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get wr_min_ctrler
		if(wr_min_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "wr_min,ctrler=%s/: ", ctrler_id);
			wr_min_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get wdelay_time_ctrler
		if(wdelay_time_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "wdelay_time,ctrler=%s/: ", ctrler_id);
			wdelay_time_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get DDR_WR_FLOW_RT
		if(WR_FLOW_RT == NULL){
			WR_FLOW_RT = get_str_between_two_words(p->data, "WR_FLOW_RT:", NULL);
		}
//get DDR_RD_FLOW_RT
		if(RD_FLOW_RT == NULL){
			RD_FLOW_RT = get_str_between_two_words(p->data, "RD_FLOW_RT:", NULL);
		}
//get TRANS_rxreq_RT
		if(WR_DELAY == NULL){
			WR_DELAY = get_str_between_two_words(p->data, "WR_DELAY:", NULL);
		}
//get RD_DELAY
		if(RD_DELAY == NULL){
			RD_DELAY = get_str_between_two_words(p->data, "RD_DELAY:", NULL);
		}
//get TRANS_ar_RT
		if(TRANS_ar_RT == NULL){
			TRANS_ar_RT = get_str_between_two_words(p->data, "TRANS_ar_RT]:", NULL);
		}
//get TRANS_r_last_RT
		if(TRANS_r_last_RT == NULL){
			TRANS_r_last_RT = get_str_between_two_words(p->data, "TRANS_r_last_RT]:", NULL);
		}
//get TRANS_r_err_RT
		if(TRANS_r_err_RT == NULL){
			TRANS_r_err_RT = get_str_between_two_words(p->data, "TRANS_r_err_RT]:", NULL);
		}
//get TRANS_r_full_RT
		if(TRANS_r_full_RT == NULL){
			TRANS_r_full_RT = get_str_between_two_words(p->data, "TRANS_r_full_RT]:", NULL);
		}
//get TRANS_aw_RT
		if(TRANS_aw_RT == NULL){
			TRANS_aw_RT = get_str_between_two_words(p->data, "TRANS_aw_RT]:", NULL);
		}
//get TRANS_w_last_RT
		if(TRANS_w_last_RT == NULL){
			TRANS_w_last_RT = get_str_between_two_words(p->data, "TRANS_w_last_RT]:", NULL);
		}
//get TRANS_w_err_RT
		if(TRANS_w_err_RT == NULL){
			TRANS_w_err_RT = get_str_between_two_words(p->data, "TRANS_w_err_RT]:", NULL);
		}
//get TRANS_b_RT
		if(TRANS_b_RT == NULL){
			TRANS_b_RT = get_str_between_two_words(p->data, "TRANS_b_RT]:", NULL);
		}
//get TRANS_delay_rd_RT
		if(TRANS_delay_rd_RT == NULL){
			TRANS_delay_rd_RT = get_str_between_two_words(p->data, "TRANS_delay_rd_RT]:", NULL);
		}
//get TRANS_delay_wr_RT
		if(TRANS_delay_wr_RT == NULL){
			TRANS_delay_wr_RT = get_str_between_two_words(p->data, "TRANS_delay_wr_RT]:", NULL);
			if(TRANS_delay_wr_RT != NULL){
				subitem = true;
			}
		}
//json file
		if(subitem == true){
			strpin = string_replace(phy_pcie_json, "${node_id}", node_id);
			strpon = string_replace(strpin, "\"title\": \"testing items\",", title);
			phy_free(strpin);

			strpin = string_replace(strpon, "${pmu_id}", pmu_id);
			phy_free(strpon);
			strpon = string_replace(strpin, "${ctrler_id}", ctrler_id);
			phy_free(strpin);
			strpin = string_replace(strpon, "${pcie_freq_in_GHz}", pcie_freq_in_ghz);
			phy_free(strpon);
			strpon = string_replace(strpin, "${PCIe_DATA_WIDTH}", pcie_data_width);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "cycles,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(cycles_ctrler));
			phy_snprintf(atstrs, PHRASE, "cycles,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "ar,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(ar_ctrler));
			phy_snprintf(atstrs, PHRASE, "ar,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "r_last,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(r_last_ctrler));
			phy_snprintf(atstrs, PHRASE, "r_last,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "r_err,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(r_err_ctrler));
			phy_snprintf(atstrs, PHRASE, "r_err,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "r_full,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(r_full_ctrler));
			phy_snprintf(atstrs, PHRASE, "r_full,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "aw,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(aw_ctrler));
			phy_snprintf(atstrs, PHRASE, "aw,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "w_last,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(w_last_ctrler));
			phy_snprintf(atstrs, PHRASE, "w_last,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "w_err,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(w_err_ctrler));
			phy_snprintf(atstrs, PHRASE, "w_err,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "b,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(b_ctrler));
			phy_snprintf(atstrs, PHRASE, "b,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "w_data,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(w_data_ctrler));
			phy_snprintf(atstrs, PHRASE, "w_data,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "delay_rd,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(delay_rd_ctrler));
			phy_snprintf(atstrs, PHRASE, "delay_rd,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rd_max,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(rd_max_ctrler));
			phy_snprintf(atstrs, PHRASE, "rd_max,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rd_min,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(rd_min_ctrler));
			phy_snprintf(atstrs, PHRASE, "rd_min,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rdelay_time,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(rdelay_time_ctrler));
			phy_snprintf(atstrs, PHRASE, "rdelay_time,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "delay_wr,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(delay_wr_ctrler));
			phy_snprintf(atstrs, PHRASE, "delay_wr,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "wr_max,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(wr_max_ctrler));
			phy_snprintf(atstrs, PHRASE, "wr_max,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "wr_min,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(wr_min_ctrler));
			phy_snprintf(atstrs, PHRASE, "wr_min,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "wdelay_time,ctrler=%s/\": \"%s\"", ctrler_id, NULL2ZERO(wdelay_time_ctrler));
			phy_snprintf(atstrs, PHRASE, "wdelay_time,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

/////////////////////////////////////////////////////////////////////////////////
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "WR_FLOW_RT\": \"%s", WR_FLOW_RT);
			strpin = string_replace(strpon, "WR_FLOW_RT\": \"0 GBps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "RD_FLOW_RT\": \"%s", RD_FLOW_RT);
			strpon = string_replace(strpin, "RD_FLOW_RT\": \"0 GBps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "WR_DELAY\": \"%s", NULL2ZERO(WR_DELAY));
			strpin = string_replace(strpon, "WR_DELAY\": \"0", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "RD_DELAY\": \"%s", NULL2ZERO(RD_DELAY));
			strpon = string_replace(strpin, "RD_DELAY\": \"0", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_ar_RT]\": \"%s", TRANS_ar_RT);
			strpin = string_replace(strpon, "TRANS_ar_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_r_last_RT]\": \"%s", TRANS_r_last_RT);
			strpon = string_replace(strpin, "TRANS_r_last_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_r_err_RT]\": \"%s", TRANS_r_err_RT);
			strpin = string_replace(strpon, "TRANS_r_err_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_r_full_RT]\": \"%s", TRANS_r_full_RT);
			strpon = string_replace(strpin, "TRANS_r_full_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_aw_RT]\": \"%s", TRANS_aw_RT);
			strpin = string_replace(strpon, "TRANS_aw_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_w_last_RT]\": \"%s", TRANS_w_last_RT);
			strpon = string_replace(strpin, "TRANS_w_last_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_w_err_RT]\": \"%s", TRANS_w_err_RT);
			strpin = string_replace(strpon, "TRANS_w_err_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_b_RT]\": \"%s", TRANS_b_RT);
			strpon = string_replace(strpin, "TRANS_b_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_delay_rd_RT]\": \"%s", TRANS_delay_rd_RT);
			strpin = string_replace(strpon, "TRANS_delay_rd_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_delay_wr_RT]\": \"%s", TRANS_delay_wr_RT);
			strpon = string_replace(strpin, "TRANS_delay_wr_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			write_file(jsonfile, strpon);
			phy_free(strpon);
//chart json
			strpin = string_replace(phy_pcie_chart_json, "\"title\": \"testing items\",", title);
			strpon = string_replace(strpin, "${node_id}", node_id);
			phy_free(strpin);

			strpin = string_replace(strpon, "${pmu_id}", pmu_id);
			phy_free(strpon);
			strpon = string_replace(strpin, "${ctrler_id}", ctrler_id);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "WR_FLOW_RT\": \"%s", WR_FLOW_RT);
			strpin = string_replace(strpon, "WR_FLOW_RT\": \"0 GBps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "RD_FLOW_RT\": \"%s", RD_FLOW_RT);
			strpon = string_replace(strpin, "RD_FLOW_RT\": \"0 GBps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "WR_DELAY\": \"%s", WR_DELAY);
			strpin = string_replace(strpon, "WR_DELAY\": \"0", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "RD_DELAY\": \"%s", RD_DELAY);
			strpon = string_replace(strpin, "RD_DELAY\": \"0", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_ar_RT]\": \"%s", TRANS_ar_RT);
			strpin = string_replace(strpon, "TRANS_ar_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_r_last_RT]\": \"%s", TRANS_r_last_RT);
			strpon = string_replace(strpin, "TRANS_r_last_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_r_err_RT]\": \"%s", TRANS_r_err_RT);
			strpin = string_replace(strpon, "TRANS_r_err_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_r_full_RT]\": \"%s", TRANS_r_full_RT);
			strpon = string_replace(strpin, "TRANS_r_full_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_aw_RT]\": \"%s", TRANS_aw_RT);
			strpin = string_replace(strpon, "TRANS_aw_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_w_last_RT]\": \"%s", TRANS_w_last_RT);
			strpon = string_replace(strpin, "TRANS_w_last_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_w_err_RT]\": \"%s", TRANS_w_err_RT);
			strpin = string_replace(strpon, "TRANS_w_err_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_b_RT]\": \"%s", TRANS_b_RT);
			strpon = string_replace(strpin, "TRANS_b_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_delay_rd_RT]\": \"%s", TRANS_delay_rd_RT);
			strpin = string_replace(strpon, "TRANS_delay_rd_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_delay_wr_RT]\": \"%s", TRANS_delay_wr_RT);
			strpon = string_replace(strpin, "TRANS_delay_wr_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			write_file(*chartjsonfile, strpon);
			phy_free(strpon);

			phy_free(node_id);
			phy_free(pmu_id);
			phy_free(ctrler_id);
			phy_free(pcie_freq_in_ghz);
			phy_free(pcie_data_width);

			phy_free(cycles_ctrler);        //0x0/: 1
			phy_free(ar_ctrler);        //0x0/: 2
			phy_free(r_last_ctrler);        //0x0/: 3
			phy_free(r_err_ctrler);        //0x0/: 4
			phy_free(r_full_ctrler);        //0x0/: 5
			phy_free(aw_ctrler);        //0x0/: 6
			phy_free(w_last_ctrler);        //0x0/: 7
			phy_free(w_err_ctrler);        //0x0/: 8
			phy_free(b_ctrler);        //0x0/: 9
			phy_free(w_data_ctrler);        //0x0/: 10
			phy_free(delay_rd_ctrler);        //0x0/: 11
			phy_free(rd_max_ctrler);        //0x0/: 12
			phy_free(rd_min_ctrler);        //0x0/: 13
			phy_free(rdelay_time_ctrler);        //0x0/: 14
			phy_free(delay_wr_ctrler);        //0x0/: 15
			phy_free(wr_max_ctrler);        //0x0/: 16
			phy_free(wr_min_ctrler);        //0x0/: 17
			phy_free(wdelay_time_ctrler);        //0x0/: 18
			phy_free(WR_FLOW_RT);        //: 19 GBps
			phy_free(RD_FLOW_RT);        //: 20 GBps
			phy_free(WR_DELAY);        //: 21
			phy_free(RD_DELAY);        //: 22
			phy_free(TRANS_ar_RT);        //: 23 GTps
			phy_free(TRANS_r_last_RT);        //: 24 GTps
			phy_free(TRANS_r_err_RT);        //: 25 GTps
			phy_free(TRANS_r_full_RT);        //: 26 GTps
			phy_free(TRANS_aw_RT);        //: 27 GTps
			phy_free(TRANS_w_last_RT);        //: 28 GTps
			phy_free(TRANS_w_err_RT);        //: 29 GTps
			phy_free(TRANS_b_RT);        //: 30 GTps
			phy_free(TRANS_delay_rd_RT);        //: 31 GTps
			phy_free(TRANS_delay_wr_RT);
		}
		p = p->next;
	}
	destory_strlist(filecontent);
#if 1
//Correction file
//tab js
	ojsflcontent = nt_fl2string(jsonfile);
	if(ojsflcontent == NULL){
		return false;
	}
	strpin = string_replace(ojsflcontent, pjunction, linker);
	clean_file(jsonfile);
	write_file(jsonfile, strpin);
	phy_free(strpin);
	phy_free(ojsflcontent);
//cha js
	ojsflcontent = nt_fl2string(*chartjsonfile);
	if(ojsflcontent == NULL){
		return false;
	}
	strpin = string_replace(ojsflcontent, junctionnn, linker);
//Labeling
	strpon = labeling_repeat_substring(strpin, "数据流量 histogram");
	phy_free(strpin);
	strpin = labeling_repeat_substring(strpon, "事务流量 histogram");
	phy_free(strpon);
	strpon = labeling_repeat_substring(strpin, "读写延迟 histogram");
	phy_free(strpin);
	clean_file(*chartjsonfile);
	write_file(*chartjsonfile, strpon);
	phy_free(strpon);
	phy_free(ojsflcontent);
#endif
	return true;
}

#define C2CTTKS "C2C analysis"
bool pmu_c2c_to_json(const char* origfile, const char* jsonfile, char** chartjsonfile)
{
	char* junction = "	}\n\
}\n\
{\n\
	";
	char* junctionnn = "	}\n\
}\n\
{";
	char* linker = "	},";

	char* ptstr = NULL;
	bool subitem = false;
	struct strlist *p = NULL;
	struct strlist *filecontent = NULL;

	char title[LPHRASE] = {0};
	char pjunction[LPHRASE] = {0};

	char atstrs[PHRASE] = {0};
	char atstr[PHRASE] = {0};
	char* strpin = NULL;
	char* strpon = NULL;

	char* node_id = NULL;
	char* c2c_id = NULL;
	char* ctrler_id = NULL;
	char* c2c_freq_in_ghz = NULL;
	char* c2c_data_width = NULL;
//		char* cycles_ctrler = NULL;
//		char* ar_ctrler = NULL;
//		char* r_last_ctrler = NULL;
	char* cycles_ctrler = NULL;        //0x0/: 1
	char* ar_ctrler=NULL;        //0x0/: 2
	char* r_last_ctrler=NULL;        //0x0/: 3
	char* r_err_ctrler=NULL;        //0x0/: 4
	char* r_full_ctrler=NULL;        //0x0/: 5
	char* aw_ctrler=NULL;        //0x0/: 6
	char* w_last_ctrler=NULL;        //0x0/: 7
	char* w_err_ctrler=NULL;        //0x0/: 8
	char* b_ctrler=NULL;        //0x0/: 9
	char* w_data_ctrler=NULL;        //0x0/: 10
	char* delay_rd_ctrler=NULL;        //0x0/: 11
	char* rd_max_ctrler=NULL;        //0x0/: 12
	char* rd_min_ctrler=NULL;        //0x0/: 13
	char* rdelay_time_ctrler=NULL;        //0x0/: 14
	char* delay_wr_ctrler=NULL;        //0x0/: 15
	char* wr_max_ctrler=NULL;        //0x0/: 16
	char* wr_min_ctrler=NULL;        //0x0/: 17
	char* wdelay_time_ctrler=NULL;        //0x0/: 18
	char* WR_FLOW_RT=NULL;        //: 19 GBps
	char* RD_FLOW_RT=NULL;        //: 20 GBps
	char* WR_DELAY=NULL;        //: 21
	char* RD_DELAY=NULL;        //: 22
	char* TRANS_ar_RT=NULL;        //: 23 GTps
	char* TRANS_r_last_RT=NULL;        //: 24 GTps
	char* TRANS_r_err_RT=NULL;        //: 25 GTps
	char* TRANS_r_full_RT=NULL;        //: 26 GTps
	char* TRANS_aw_RT=NULL;        //: 27 GTps
	char* TRANS_w_last_RT=NULL;        //: 28 GTps
	char* TRANS_w_err_RT=NULL;        //: 29 GTps
	char* TRANS_b_RT=NULL;        //: 30 GTps
	char* TRANS_delay_rd_RT=NULL;        //: 31 GTps
	char* TRANS_delay_wr_RT=NULL;        //: 32 GTps

	char* ojsflcontent = NULL;
	char cmd[CMDLEN] = {0};

	create_strlist(&filecontent);

	phy_snprintf(cmd, CMDLEN, "cat %s", origfile);
	get_result_strlist(cmd, filecontent, false);
	strlist_delete_tooshort(&filecontent, 2);
	strlist_delete_relkey(&filecontent, "........");
	strlist_delete_relkey(&filecontent, "--------");
	strlist_delete_relkey(&filecontent, "========");
	p = filecontent->next;

	ptstr = string_replace(jsonfile, ".json", "_chart.json");
	*chartjsonfile = phy_strdup(*chartjsonfile, ptstr);
	phy_free(ptstr);

	clean_file(jsonfile);
	clean_file(*chartjsonfile);

	while(p){

		if(strstr(p->data, C2CTTKS)){
			phy_snprintf(title, LPHRASE, "\"title\": \"%s\",", p->data);
			phy_snprintf(pjunction, LPHRASE, "%s%s", junction, title);
			p = p->next;
			continue;
		}
		if( strstr(p->data, "Node") && strstr(p->data, "C2C") && strstr(p->data, "Ctrler") ){
			subitem = false;
		}

//get node_id
		if(node_id == NULL){
			node_id = get_str_between_two_words(p->data, "Node(", ")C2C");
		}
//get c2c_id
		if(c2c_id == NULL){
			c2c_id = get_str_between_two_words(p->data, "C2C(", ")Ctrler");
		}
//get ctrler_id
		if(ctrler_id == NULL){
			ctrler_id = get_str_between_two_words(p->data, "Ctrler(", ")");
		}
//get c2c_freq_in_ghz
		if(c2c_freq_in_ghz == NULL){
			c2c_freq_in_ghz = get_str_between_two_words(p->data, "C2C_Freq:", "GHz");
		}
//get c2c_data_width
		if(c2c_data_width == NULL){
			c2c_data_width = get_str_between_two_words(p->data, "C2C_DATA_WIDTH:", NULL);
		}

//get cycles_ctrler
		if(cycles_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "cycles,ctrler=%s/: ", ctrler_id);
			cycles_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get ar_ctrler
		if(ar_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "ar,ctrler=%s/: ", ctrler_id);
			ar_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get r_last_ctrler
		if(r_last_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "r_last,ctrler=%s/: ", ctrler_id);
			r_last_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get r_err_ctrler
		if(r_err_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "r_err,ctrler=%s/: ", ctrler_id);
			r_err_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get r_full_ctrler
		if(r_full_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "r_full,ctrler=%s/: ", ctrler_id);
			r_full_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get aw_ctrler
		if(aw_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "aw,ctrler=%s/: ", ctrler_id);
			aw_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get w_last_ctrler
		if(w_last_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "w_last,ctrler=%s/: ", ctrler_id);
			w_last_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get w_err_ctrler
		if(w_err_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "w_err,ctrler=%s/: ", ctrler_id);
			w_err_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get b_ctrler
		if(b_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "b,ctrler=%s/: ", ctrler_id);
			b_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get w_data_ctrler
		if(w_data_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "w_data,ctrler=%s/: ", ctrler_id);
			w_data_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get delay_rd_ctrler
		if(delay_rd_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "delay_rd,ctrler=%s/: ", ctrler_id);
			delay_rd_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get rd_max_ctrler
		if(rd_max_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rd_max,ctrler=%s/: ", ctrler_id);
			rd_max_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get rd_min_ctrler
		if(rd_min_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rd_min,ctrler=%s/: ", ctrler_id);
			rd_min_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get rdelay_time_ctrler
		if(rdelay_time_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rdelay_time,ctrler=%s/: ", ctrler_id);
			rdelay_time_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get delay_wr_ctrler
		if(delay_wr_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "delay_wr,ctrler=%s/: ", ctrler_id);
			delay_wr_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get wr_max_ctrler
		if(wr_max_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "wr_max,ctrler=%s/: ", ctrler_id);
			wr_max_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get wr_min_ctrler
		if(wr_min_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "wr_min,ctrler=%s/: ", ctrler_id);
			wr_min_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get wdelay_time_ctrler
		if(wdelay_time_ctrler == NULL){
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "wdelay_time,ctrler=%s/: ", ctrler_id);
			wdelay_time_ctrler = get_str_between_two_words(p->data, atstr, NULL);
		}
//get DDR_WR_FLOW_RT
		if(WR_FLOW_RT == NULL){
			WR_FLOW_RT = get_str_between_two_words(p->data, "WR_FLOW_RT:", NULL);
		}
//get DDR_RD_FLOW_RT
		if(RD_FLOW_RT == NULL){
			RD_FLOW_RT = get_str_between_two_words(p->data, "RD_FLOW_RT:", NULL);
		}
//get TRANS_rxreq_RT
		if(WR_DELAY == NULL){
			WR_DELAY = get_str_between_two_words(p->data, "WR_DELAY:", NULL);
		}
//get RD_DELAY
		if(RD_DELAY == NULL){
			RD_DELAY = get_str_between_two_words(p->data, "RD_DELAY:", NULL);
		}
//get TRANS_ar_RT
		if(TRANS_ar_RT == NULL){
			TRANS_ar_RT = get_str_between_two_words(p->data, "TRANS_ar_RT]:", NULL);
		}
//get TRANS_r_last_RT
		if(TRANS_r_last_RT == NULL){
			TRANS_r_last_RT = get_str_between_two_words(p->data, "TRANS_r_last_RT]:", NULL);
		}
//get TRANS_r_err_RT
		if(TRANS_r_err_RT == NULL){
			TRANS_r_err_RT = get_str_between_two_words(p->data, "TRANS_r_err_RT]:", NULL);
		}
//get TRANS_r_full_RT
		if(TRANS_r_full_RT == NULL){
			TRANS_r_full_RT = get_str_between_two_words(p->data, "TRANS_r_full_RT]:", NULL);
		}
//get TRANS_aw_RT
		if(TRANS_aw_RT == NULL){
			TRANS_aw_RT = get_str_between_two_words(p->data, "TRANS_aw_RT]:", NULL);
		}
//get TRANS_w_last_RT
		if(TRANS_w_last_RT == NULL){
			TRANS_w_last_RT = get_str_between_two_words(p->data, "TRANS_w_last_RT]:", NULL);
		}
//get TRANS_w_err_RT
		if(TRANS_w_err_RT == NULL){
			TRANS_w_err_RT = get_str_between_two_words(p->data, "TRANS_w_err_RT]:", NULL);
		}
//get TRANS_b_RT
		if(TRANS_b_RT == NULL){
			TRANS_b_RT = get_str_between_two_words(p->data, "TRANS_b_RT]:", NULL);
		}
//get TRANS_delay_rd_RT
		if(TRANS_delay_rd_RT == NULL){
			TRANS_delay_rd_RT = get_str_between_two_words(p->data, "TRANS_delay_rd_RT]:", NULL);
		}
//get TRANS_delay_wr_RT
		if(TRANS_delay_wr_RT == NULL){
			TRANS_delay_wr_RT = get_str_between_two_words(p->data, "TRANS_delay_wr_RT]:", NULL);
			if(TRANS_delay_wr_RT != NULL){
				subitem = true;
			}
		}
//json file
		if(subitem == true){
			strpin = string_replace(phy_c2c_json, "${node_id}", node_id);
			strpon = string_replace(strpin, "\"title\": \"testing items\",", title);
			phy_free(strpin);

			strpin = string_replace(strpon, "${c2c_id}", c2c_id);
			phy_free(strpon);
			strpon = string_replace(strpin, "${ctrler_id}", ctrler_id);
			phy_free(strpin);
			strpin = string_replace(strpon, "${c2c_freq_in_GHz}", c2c_freq_in_ghz);
			phy_free(strpon);
			strpon = string_replace(strpin, "${C2C_DATA_WIDTH}", c2c_data_width);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "cycles,ctrler=%s/\": \"%s\"", ctrler_id, cycles_ctrler);
			phy_snprintf(atstrs, PHRASE, "cycles,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "ar,ctrler=%s/\": \"%s\"", ctrler_id, ar_ctrler);
			phy_snprintf(atstrs, PHRASE, "ar,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "r_last,ctrler=%s/\": \"%s\"", ctrler_id, r_last_ctrler);
			phy_snprintf(atstrs, PHRASE, "r_last,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "r_err,ctrler=%s/\": \"%s\"", ctrler_id, r_err_ctrler);
			phy_snprintf(atstrs, PHRASE, "r_err,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "r_full,ctrler=%s/\": \"%s\"", ctrler_id, r_full_ctrler);
			phy_snprintf(atstrs, PHRASE, "r_full,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "aw,ctrler=%s/\": \"%s\"", ctrler_id, aw_ctrler);
			phy_snprintf(atstrs, PHRASE, "aw,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "w_last,ctrler=%s/\": \"%s\"", ctrler_id, w_last_ctrler);
			phy_snprintf(atstrs, PHRASE, "w_last,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "w_err,ctrler=%s/\": \"%s\"", ctrler_id, w_err_ctrler);
			phy_snprintf(atstrs, PHRASE, "w_err,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "b,ctrler=%s/\": \"%s\"", ctrler_id, b_ctrler);
			phy_snprintf(atstrs, PHRASE, "b,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "w_data,ctrler=%s/\": \"%s\"", ctrler_id, w_data_ctrler);
			phy_snprintf(atstrs, PHRASE, "w_data,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "delay_rd,ctrler=%s/\": \"%s\"", ctrler_id, delay_rd_ctrler);
			phy_snprintf(atstrs, PHRASE, "delay_rd,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rd_max,ctrler=%s/\": \"%s\"", ctrler_id, rd_max_ctrler);
			phy_snprintf(atstrs, PHRASE, "rd_max,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rd_min,ctrler=%s/\": \"%s\"", ctrler_id, rd_min_ctrler);
			phy_snprintf(atstrs, PHRASE, "rd_min,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rdelay_time,ctrler=%s/\": \"%s\"", ctrler_id, rdelay_time_ctrler);
			phy_snprintf(atstrs, PHRASE, "rdelay_time,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "delay_wr,ctrler=%s/\": \"%s\"", ctrler_id, delay_wr_ctrler);
			phy_snprintf(atstrs, PHRASE, "delay_wr,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "wr_max,ctrler=%s/\": \"%s\"", ctrler_id, wr_max_ctrler);
			phy_snprintf(atstrs, PHRASE, "wr_max,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "wr_min,ctrler=%s/\": \"%s\"", ctrler_id, wr_min_ctrler);
			phy_snprintf(atstrs, PHRASE, "wr_min,ctrler=%s/\": \"0\"", ctrler_id);
			strpin = string_replace(strpon, atstrs, atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			memset(atstrs, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "wdelay_time,ctrler=%s/\": \"%s\"", ctrler_id, wdelay_time_ctrler);
			phy_snprintf(atstrs, PHRASE, "wdelay_time,ctrler=%s/\": \"0\"", ctrler_id);
			strpon = string_replace(strpin, atstrs, atstr);
			phy_free(strpin);

/////////////////////////////////////////////////////////////////////////////////
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "WR_FLOW_RT\": \"%s", WR_FLOW_RT);
			strpin = string_replace(strpon, "WR_FLOW_RT\": \"0 GBps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "RD_FLOW_RT\": \"%s", RD_FLOW_RT);
			strpon = string_replace(strpin, "RD_FLOW_RT\": \"0 GBps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "WR_DELAY\": \"%s", WR_DELAY);
			strpin = string_replace(strpon, "WR_DELAY\": \"0", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "RD_DELAY\": \"%s", RD_DELAY);
			strpon = string_replace(strpin, "RD_DELAY\": \"0", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_ar_RT]\": \"%s", TRANS_ar_RT);
			strpin = string_replace(strpon, "TRANS_ar_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_r_last_RT]\": \"%s", TRANS_r_last_RT);
			strpon = string_replace(strpin, "TRANS_r_last_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_r_err_RT]\": \"%s", TRANS_r_err_RT);
			strpin = string_replace(strpon, "TRANS_r_err_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_r_full_RT]\": \"%s", TRANS_r_full_RT);
			strpon = string_replace(strpin, "TRANS_r_full_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_aw_RT]\": \"%s", TRANS_aw_RT);
			strpin = string_replace(strpon, "TRANS_aw_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_w_last_RT]\": \"%s", TRANS_w_last_RT);
			strpon = string_replace(strpin, "TRANS_w_last_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_w_err_RT]\": \"%s", TRANS_w_err_RT);
			strpin = string_replace(strpon, "TRANS_w_err_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_b_RT]\": \"%s", TRANS_b_RT);
			strpon = string_replace(strpin, "TRANS_b_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_delay_rd_RT]\": \"%s", TRANS_delay_rd_RT);
			strpin = string_replace(strpon, "TRANS_delay_rd_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_delay_wr_RT]\": \"%s", TRANS_delay_wr_RT);
			strpon = string_replace(strpin, "TRANS_delay_wr_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			write_file(jsonfile, strpon);
			phy_free(strpon);
//chart json
			strpin = string_replace(phy_c2c_chart_json, "\"title\": \"testing items\",", title);
			strpon = string_replace(strpin, "${node_id}", node_id);
			phy_free(strpin);

			strpin = string_replace(strpon, "${c2c_id}", c2c_id);
			phy_free(strpon);
			strpon = string_replace(strpin, "${ctrler_id}", ctrler_id);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "WR_FLOW_RT\": \"%s", WR_FLOW_RT);
			strpin = string_replace(strpon, "WR_FLOW_RT\": \"0 GBps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "RD_FLOW_RT\": \"%s", RD_FLOW_RT);
			strpon = string_replace(strpin, "RD_FLOW_RT\": \"0 GBps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "WR_DELAY\": \"%s", WR_DELAY);
			strpin = string_replace(strpon, "WR_DELAY\": \"0", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "RD_DELAY\": \"%s", RD_DELAY);
			strpon = string_replace(strpin, "RD_DELAY\": \"0", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_ar_RT]\": \"%s", TRANS_ar_RT);
			strpin = string_replace(strpon, "TRANS_ar_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_r_last_RT]\": \"%s", TRANS_r_last_RT);
			strpon = string_replace(strpin, "TRANS_r_last_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_r_err_RT]\": \"%s", TRANS_r_err_RT);
			strpin = string_replace(strpon, "TRANS_r_err_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_r_full_RT]\": \"%s", TRANS_r_full_RT);
			strpon = string_replace(strpin, "TRANS_r_full_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_aw_RT]\": \"%s", TRANS_aw_RT);
			strpin = string_replace(strpon, "TRANS_aw_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_w_last_RT]\": \"%s", TRANS_w_last_RT);
			strpon = string_replace(strpin, "TRANS_w_last_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_w_err_RT]\": \"%s", TRANS_w_err_RT);
			strpin = string_replace(strpon, "TRANS_w_err_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_b_RT]\": \"%s", TRANS_b_RT);
			strpon = string_replace(strpin, "TRANS_b_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_delay_rd_RT]\": \"%s", TRANS_delay_rd_RT);
			strpin = string_replace(strpon, "TRANS_delay_rd_RT]\": \"0 GTps", atstr);
			phy_free(strpon);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_delay_wr_RT]\": \"%s", TRANS_delay_wr_RT);
			strpon = string_replace(strpin, "TRANS_delay_wr_RT]\": \"0 GTps", atstr);
			phy_free(strpin);

			write_file(*chartjsonfile, strpon);
			phy_free(strpon);

			phy_free(node_id);
			phy_free(c2c_id);
			phy_free(ctrler_id);
			phy_free(c2c_freq_in_ghz);
			phy_free(c2c_data_width);

			phy_free(cycles_ctrler);        //0x0/: 1
			phy_free(ar_ctrler);        //0x0/: 2
			phy_free(r_last_ctrler);        //0x0/: 3
			phy_free(r_err_ctrler);        //0x0/: 4
			phy_free(r_full_ctrler);        //0x0/: 5
			phy_free(aw_ctrler);        //0x0/: 6
			phy_free(w_last_ctrler);        //0x0/: 7
			phy_free(w_err_ctrler);        //0x0/: 8
			phy_free(b_ctrler);        //0x0/: 9
			phy_free(w_data_ctrler);        //0x0/: 10
			phy_free(delay_rd_ctrler);        //0x0/: 11
			phy_free(rd_max_ctrler);        //0x0/: 12
			phy_free(rd_min_ctrler);        //0x0/: 13
			phy_free(rdelay_time_ctrler);        //0x0/: 14
			phy_free(delay_wr_ctrler);        //0x0/: 15
			phy_free(wr_max_ctrler);        //0x0/: 16
			phy_free(wr_min_ctrler);        //0x0/: 17
			phy_free(wdelay_time_ctrler);        //0x0/: 18
			phy_free(WR_FLOW_RT);        //: 19 GBps
			phy_free(RD_FLOW_RT);        //: 20 GBps
			phy_free(WR_DELAY);        //: 21
			phy_free(RD_DELAY);        //: 22
			phy_free(TRANS_ar_RT);        //: 23 GTps
			phy_free(TRANS_r_last_RT);        //: 24 GTps
			phy_free(TRANS_r_err_RT);        //: 25 GTps
			phy_free(TRANS_r_full_RT);        //: 26 GTps
			phy_free(TRANS_aw_RT);        //: 27 GTps
			phy_free(TRANS_w_last_RT);        //: 28 GTps
			phy_free(TRANS_w_err_RT);        //: 29 GTps
			phy_free(TRANS_b_RT);        //: 30 GTps
			phy_free(TRANS_delay_rd_RT);        //: 31 GTps
			phy_free(TRANS_delay_wr_RT);
		}
		p = p->next;
	}
	destory_strlist(filecontent);
#if 1
//Correction file
//tab js
	ojsflcontent = nt_fl2string(jsonfile);
	if(ojsflcontent == NULL){
		return false;
	}
	strpin = string_replace(ojsflcontent, pjunction, linker);
	clean_file(jsonfile);
	write_file(jsonfile, strpin);
	phy_free(strpin);
	phy_free(ojsflcontent);
//cha js
	ojsflcontent = nt_fl2string(*chartjsonfile);
	if(ojsflcontent == NULL){
		return false;
	}
	strpin = string_replace(ojsflcontent, junctionnn, linker);
//Labeling
	strpon = labeling_repeat_substring(strpin, "数据流量 histogram");
	phy_free(strpin);
	strpin = labeling_repeat_substring(strpon, "事务流量 histogram");
	phy_free(strpon);
	strpon = labeling_repeat_substring(strpin, "读写延迟 histogram");
	phy_free(strpin);
	clean_file(*chartjsonfile);
	write_file(*chartjsonfile, strpon);
	phy_free(strpon);
	phy_free(ojsflcontent);
#endif
	return true;
}

#define DDRTTKS "DDR Analysis"
bool pmu_ddr_to_json(const char* origfile, const char* jsonfile, char** chartjsonfile)
{
	char* junction = "	}\n\
}\n\
{\n\
	";
	char* junctionnn = "	}\n\
}\n\
{";
	char* linker = "	},";
	char* ptstr = NULL;

	char* ojsflcontent = NULL;
	struct strlist* p = NULL;
	struct strlist* filecontent = NULL;
	bool subitem = false;
	char* strpin = NULL;
	char* strpon = NULL;
	char title[LPHRASE] = {0};
	char pjunction[LPHRASE] = {0};

	char* node_id = NULL;
	char* hm_id = NULL;
	char* pmu_id = NULL;
	char* ddr_freq_in_ghz = NULL;
	char* ddr_data_width = NULL;

	char* cycles = NULL;
	char* rxreq = NULL;
	char* rxreq_RNS = NULL;
	char* rxreq_WNSF = NULL;
	char* rxreq_WNSP = NULL;
	char* rxdat = NULL;

	char* txdat = NULL;
	char* bandwidth = NULL;
	char* DDR_WR_FLOW_RT = NULL;
	char* DDR_RD_FLOW_RT = NULL;
	char* TRANS_rxreq_RT = NULL;
	char* TRANS_rxreq_RNS_RT = NULL;
	char* TRANS_rxreq_WNSP_RT = NULL;
	char* TRANS_rxreq_WNSF_RT = NULL;
	char* TRANS_rxdat_RT = NULL;
	char* TRANS_txdat_RT = NULL;


	char atstr[PHRASE] = {0};
	char* jsflpo = NULL;
	char* jsflpi = NULL;

	char cmd[CMDLEN] = {0};
	create_strlist(&filecontent);

	phy_snprintf(cmd, CMDLEN, "cat %s", origfile);
	get_result_strlist(cmd, filecontent, false);
	strlist_delete_tooshort(&filecontent, 2);
	strlist_delete_relkey(&filecontent, "........");
	strlist_delete_relkey(&filecontent, "--------");
	strlist_delete_relkey(&filecontent, "========");

	p = filecontent->next;
//	if(strstr(p->data, "DDR")){
//		msflg = DDR;
	ptstr = string_replace(jsonfile, ".json", "_chart.json");
	*chartjsonfile = phy_strdup(*chartjsonfile, ptstr);
	phy_free(ptstr);
//	}
	clean_file(jsonfile);
	clean_file(*chartjsonfile);

	while(p){
//title
		if(strstr(p->data, DDRTTKS)){
//			title = p->data;
			phy_snprintf(title, LPHRASE, "\"title\": \"%s\",", p->data);
			phy_snprintf(pjunction, LPHRASE, "%s%s", junction, title);
			p = p->next;
			continue;
		}
//
		if( strstr(p->data, "Node") && strstr(p->data, "DDR") && strstr(p->data, "CHANNEL") ){
//			ostitle_eff = p->data;
			subitem = false;
		}
//get node_id
		if(node_id == NULL){
			node_id = get_str_between_two_words(p->data, "Node(", ")DDR");
		}
//get hm_id
		if(hm_id == NULL){
			hm_id = get_str_between_two_words(p->data, "DDR(", ")CHANNEL");
		}
//get pmu_id
		if(pmu_id == NULL){
			pmu_id = get_str_between_two_words(p->data, ")CHANNEL(", ")");
		}
//get ddr_freq_in_GHz
		if(ddr_freq_in_ghz == NULL){
			ddr_freq_in_ghz = get_str_between_two_words(p->data, "DDR_Freq:", "GHz");
//			ostitle_freq = p->data;
		}
//get DDR_DATA_WIDTH
		if(ddr_data_width == NULL){
			ddr_data_width = get_str_between_two_words(p->data, "DDR_DATA_WIDTH:", NULL);
//			ostitle_width = p->data;
		}
//get cycles
		if(cycles == NULL){
			cycles = get_str_between_two_words(p->data, "cycles/:", NULL);
		}
//get rxreq
		if(rxreq == NULL){
			rxreq = get_str_between_two_words(p->data, "rxreq/:", NULL);
		}
//get rxreq_RNS
		if(rxreq_RNS == NULL){
			rxreq_RNS = get_str_between_two_words(p->data, "rxreq_RNS/:", NULL);
		}
//get rxreq_WNSP
		if(rxreq_WNSP == NULL){
			rxreq_WNSP = get_str_between_two_words(p->data, "rxreq_WNSP/:", NULL);
		}
//get rxreq_WNSF
		if(rxreq_WNSF == NULL){
			rxreq_WNSF = get_str_between_two_words(p->data, "rxreq_WNSF/:", NULL);
		}
//get rxdat
		if(rxdat == NULL){
			rxdat = get_str_between_two_words(p->data, "rxdat/:", NULL);
		}
//get txdat
		if(txdat == NULL){
			txdat = get_str_between_two_words(p->data, "txdat/:", NULL);
		}
//get bandwidth
		if(bandwidth == NULL){
			bandwidth = get_str_between_two_words(p->data, "bandwidth/:", NULL);
		}
//get DDR_WR_FLOW_RT
		if(DDR_WR_FLOW_RT == NULL){
			DDR_WR_FLOW_RT = get_str_between_two_words(p->data, "DDR_WR_FLOW_RT:", NULL);
		}
//get DDR_RD_FLOW_RT
		if(DDR_RD_FLOW_RT == NULL){
			DDR_RD_FLOW_RT = get_str_between_two_words(p->data, "DDR_RD_FLOW_RT:", NULL);
		}
//get TRANS_rxreq_RT
		if(TRANS_rxreq_RT == NULL){
			TRANS_rxreq_RT = get_str_between_two_words(p->data, "TRANS_rxreq_RT]:", NULL);
		}
//get TRANS_rxreq_RNS_RT
		if(TRANS_rxreq_RNS_RT == NULL){
			TRANS_rxreq_RNS_RT = get_str_between_two_words(p->data, "TRANS_rxreq_RNS_RT]:", NULL);
		}
//get TRANS_rxreq_WNSP_RT
		if(TRANS_rxreq_WNSP_RT == NULL){
			TRANS_rxreq_WNSP_RT = get_str_between_two_words(p->data, "TRANS_rxreq_WNSP_RT]:", NULL);
		}
//get TRANS_rxreq_WNSF_RT
		if(TRANS_rxreq_WNSF_RT == NULL){
			TRANS_rxreq_WNSF_RT = get_str_between_two_words(p->data, "TRANS_rxreq_WNSF_RT]:", NULL);
		}
//get TRANS_rxdat_RT
		if(TRANS_rxdat_RT == NULL){
			TRANS_rxdat_RT = get_str_between_two_words(p->data, "TRANS_rxdat_RT]:", NULL);
		}
//get TRANS_txdat_RT
		if(TRANS_txdat_RT == NULL){
			TRANS_txdat_RT = get_str_between_two_words(p->data, "TRANS_txdat_RT]:", NULL);
			if(TRANS_txdat_RT != NULL){
				subitem = true;
			}
		}

		if(subitem == true){
//table json
			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "cycles/\": \"%s\"", cycles);
			jsflpi = string_replace(phy_ddr_json, "cycles/\": \"0\"", atstr);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rxreq/\": \"%s\"", rxreq);
			jsflpo = string_replace(jsflpi, "rxreq/\": \"0\"", atstr);
			phy_free(jsflpi);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rxreq_RNS/\": \"%s\"", rxreq_RNS);
			jsflpi = string_replace(jsflpo, "rxreq_RNS/\": \"0\"", atstr);
			phy_free(jsflpo);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rxreq_WNSP/\": \"%s\"", rxreq_WNSP);
			jsflpo = string_replace(jsflpi, "rxreq_WNSP/\": \"0\"", atstr);
			phy_free(jsflpi);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rxreq_WNSF/\": \"%s\"", rxreq_WNSF);
			jsflpi = string_replace(jsflpo, "rxreq_WNSF/\": \"0\"", atstr);
			phy_free(jsflpo);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "rxdat/\": \"%s\"", rxdat);
			jsflpo = string_replace(jsflpi, "rxdat/\": \"0\"", atstr);
			phy_free(jsflpi);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "txdat/\": \"%s\"", txdat);
			jsflpi = string_replace(jsflpo, "txdat/\": \"0\"", atstr);
			phy_free(jsflpo);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "bandwidth/\": \"%s\"", bandwidth);
			jsflpo = string_replace(jsflpi, "bandwidth/\": \"0\"", atstr);
			phy_free(jsflpi);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "DDR_WR_FLOW_RT\": \"%s\"", DDR_WR_FLOW_RT);
			jsflpi = string_replace(jsflpo, "DDR_WR_FLOW_RT\": \"0 GBps\"", atstr);
			phy_free(jsflpo);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "DDR_RD_FLOW_RT\": \"%s\"", DDR_RD_FLOW_RT);
			jsflpo = string_replace(jsflpi, "DDR_RD_FLOW_RT\": \"0 GBps\"", atstr);
			phy_free(jsflpi);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_rxreq_RT\": \"%s\"", TRANS_rxreq_RT);
			jsflpi = string_replace(jsflpo, "TRANS_rxreq_RT\": \"0 GTps\"", atstr);
			phy_free(jsflpo);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_rxreq_RNS_RT\": \"%s\"", TRANS_rxreq_RNS_RT);
			jsflpo = string_replace(jsflpi, "TRANS_rxreq_RNS_RT\": \"0 GTps\"", atstr);
			phy_free(jsflpi);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_rxreq_WNSP_RT\": \"%s\"", TRANS_rxreq_WNSP_RT);
			jsflpi = string_replace(jsflpo, "TRANS_rxreq_WNSP_RT\": \"0 GTps\"", atstr);
			phy_free(jsflpo);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_rxreq_WNSF_RT\": \"%s\"", TRANS_rxreq_WNSF_RT);
			jsflpo = string_replace(jsflpi, "TRANS_rxreq_WNSF_RT\": \"0 GTps\"", atstr);
			phy_free(jsflpi);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_rxdat_RT\": \"%s\"", TRANS_rxdat_RT);
			jsflpi = string_replace(jsflpo, "TRANS_rxdat_RT\": \"0 GTps\"", atstr);
			phy_free(jsflpo);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_txdat_RT\": \"%s\"", TRANS_txdat_RT);
			jsflpo = string_replace(jsflpi, "TRANS_txdat_RT\": \"0 GTps\"", atstr);
			phy_free(jsflpi);


			jsflpi = string_replace(jsflpo, "${node_id}", node_id);
			phy_free(jsflpo);

			jsflpo = string_replace(jsflpi, "${hm_id}", hm_id);
			phy_free(jsflpi);

			jsflpi = string_replace(jsflpo, "${pmu_id}", pmu_id);
			phy_free(jsflpo);

			jsflpo = string_replace(jsflpi, "${ddr_freq_in_GHz}", ddr_freq_in_ghz);
			phy_free(jsflpi);

			jsflpi = string_replace(jsflpo, "${DDR_DATA_WIDTH}", ddr_data_width);
			phy_free(jsflpo);

			jsflpo = string_replace(jsflpi, "\"title\": \"testing items\",", title);
			phy_free(jsflpi);

			write_file(jsonfile, jsflpo);
			phy_free(jsflpo);

//chart json
			jsflpo = string_replace(phy_ddr_chart_json, "${ddr_freq_in_GHz}", ddr_freq_in_ghz);

			jsflpi = string_replace(jsflpo, "${DDR_DATA_WIDTH}", ddr_data_width);
			phy_free(jsflpo);

			jsflpo = string_replace(jsflpi, "${node_id}", node_id);
			phy_free(jsflpi);

			jsflpi = string_replace(jsflpo, "${hm_id}", hm_id);
			phy_free(jsflpo);

			jsflpo = string_replace(jsflpi, "${pmu_id}", pmu_id);
			phy_free(jsflpi);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "_DDR_WR_FLOW_RT\": \"%s", DDR_WR_FLOW_RT);
			jsflpi = string_replace(jsflpo, "_DDR_WR_FLOW_RT\": \"0 GBps", atstr);
			phy_free(jsflpo);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "DDR_RD_FLOW_RT\": \"%s", DDR_RD_FLOW_RT);
			jsflpo = string_replace(jsflpi, "DDR_RD_FLOW_RT\": \"0 GBps", atstr);
			phy_free(jsflpi);

			memset(atstr, 0, PHRASE);//	 TRANS_rxreq_RT\": \"0 GTps\"
			phy_snprintf(atstr, PHRASE, "TRANS_rxreq_RT\": \"%s", TRANS_rxreq_RT);
			jsflpi = string_replace(jsflpo, "TRANS_rxreq_RT\": \"0 GTps", atstr);
			phy_free(jsflpo);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_rxreq_RNS_RT\": \"%s", TRANS_rxreq_RNS_RT);
			jsflpo = string_replace(jsflpi, "TRANS_rxreq_RNS_RT\": \"0 GTps", atstr);
			phy_free(jsflpi);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_rxreq_WNSP_RT\": \"%s", TRANS_rxreq_WNSP_RT);
			jsflpi = string_replace(jsflpo, "TRANS_rxreq_WNSP_RT\": \"0 GTps", atstr);
			phy_free(jsflpo);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_rxreq_WNSF_RT\": \"%s", TRANS_rxreq_WNSF_RT);
			jsflpo = string_replace(jsflpi, "TRANS_rxreq_WNSF_RT\": \"0 GTps", atstr);
			phy_free(jsflpi);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_rxdat_RT\": \"%s", TRANS_rxdat_RT);
			jsflpi = string_replace(jsflpo, "TRANS_rxdat_RT\": \"0 GTps", atstr);
			phy_free(jsflpo);

			memset(atstr, 0, PHRASE);
			phy_snprintf(atstr, PHRASE, "TRANS_txdat_RT\": \"%s", TRANS_txdat_RT);
			jsflpo = string_replace(jsflpi, "TRANS_txdat_RT\": \"0 GTps", atstr);
			phy_free(jsflpi);

			write_file(*chartjsonfile, jsflpo);
			phy_free(jsflpo);

			phy_free(strpin);
			phy_free(strpon);
			phy_free(node_id);
			phy_free(hm_id);
			phy_free(pmu_id);
			phy_free(ddr_freq_in_ghz);
			phy_free(ddr_data_width);
			phy_free(cycles);
			phy_free(rxreq);
			phy_free(rxreq_RNS);
			phy_free(rxreq_WNSF);
			phy_free(rxreq_WNSP);
			phy_free(rxdat);
			phy_free(txdat);
			phy_free(bandwidth);
			phy_free(DDR_WR_FLOW_RT);
			phy_free(DDR_RD_FLOW_RT);
			phy_free(TRANS_rxreq_RT);
			phy_free(TRANS_rxreq_RNS_RT);
			phy_free(TRANS_rxreq_WNSP_RT);
			phy_free(TRANS_rxreq_WNSF_RT);
			phy_free(TRANS_rxdat_RT);
			phy_free(TRANS_txdat_RT);
		}

#if 0
//merge sub title
		if(subitem == true){
			char* dstitle = NULL;
			char* dsstitle = NULL;
			dsstitle =  insert_string(ostitle_eff, " DDR Effectiveness", "; ", true);
			phy_rtrim(dsstitle, ":");
			dstitle =   insert_string(dsstitle, " DDR Effectiveness", ostitle_freq, true);
			phy_free(dsstitle);
			dsstitle =  insert_string(dstitle, " DDR Effectiveness", "; ", true);
			dstitle =  insert_string(dsstitle, " DDR Effectiveness", ostitle_width, true);
			phy_free(dsstitle);
			dsstitle =  insert_string(dstitle, " DDR Effectiveness", ";", true);

			phy_free(dsstitle);
			phy_free(dstitle);
		}
#endif
		p = p->next;
	}
	destory_strlist(filecontent);
//Correction file
//tab js
	ojsflcontent = nt_fl2string(jsonfile);
	if(ojsflcontent == NULL){
		return false;
	}
	jsflpi = string_replace(ojsflcontent, pjunction, linker);
	clean_file(jsonfile);
	write_file(jsonfile, jsflpi);
	phy_free(jsflpi);
	phy_free(ojsflcontent);
//cha js
	ojsflcontent = nt_fl2string(*chartjsonfile);
	if(ojsflcontent == NULL){
		return false;
	}
	jsflpi = string_replace(ojsflcontent, junctionnn, linker);
//Labeling
	jsflpo = labeling_repeat_substring(jsflpi, "数据流量 histogram");
	phy_free(jsflpi);
	jsflpi = labeling_repeat_substring(jsflpo, "事务流量 histogram");
	phy_free(jsflpo);
	clean_file(*chartjsonfile);
	write_file(*chartjsonfile, jsflpi);
	phy_free(jsflpi);
	phy_free(ojsflcontent);
	return true;
}

#define MAX_LINE_LEN 1024
#define MAX_FILE_SIZE (10 * 1024 * 1024) // 最大文件大小10MB
#define RED "\033[31m"
#define RESET "\033[0m"
const char *ptarr[] = { "error", "err", NULL };
// 不区分大小写匹配
char* strcasestr_custom(const char *haystack, const char *needle) {
    if (!*needle) return (char*)haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack, *n = needle;
        while (*h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
            h++; n++;
        }
        if (!*n) return (char*)haystack;
    }
    return NULL;
}

// NULL-terminated array 关键词查找
char* find_keyword(const char *text, const char **ptarr) {
    for (int i = 0; ptarr[i] != NULL; i++) {
        char *p = strcasestr_custom(text, ptarr[i]);
        if (p) return p;
    }
    return NULL;
}

// 把整个文件读进内存
char* load_file(const char *filename, long *size) {
    FILE *f = fopen(filename, "r");
    if (!f) { perror("fopen"); return NULL; }
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    if (*size > MAX_FILE_SIZE) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc(*size + 1);
    fread(buf, 1, *size, f);
    buf[*size] = '\0';
    fclose(f);
    return buf;
}

char* extract_sentence(char *filebuf, char *match_pos) {
    char *start = match_pos, *end = match_pos;

    while (start > filebuf &&
           *(start-1) != '.' &&
           *(start-1) != '\n' &&
           !(start - filebuf >= 3 && strncmp(start-3, "。", 3) == 0)) {
        start--;
    }

    while (*end &&
           *end != '.' &&
           !(strncmp(end, "。", 3) == 0)) {
        end++;
    }
    if (*end == '.' || *end == '\n') {
        end++;
    } else if (strncmp(end, "。", 3) == 0) {
        end += 3;
    }

    size_t len = end - start;
    char *sent = malloc(len + 1);
    memcpy(sent, start, len);
    sent[len] = '\0';
    return sent;
}

void search_and_extlin(const char *cnt, const char **ptarr, char **res)
{
    long   fsize;
    char  *fbuf = (char*)cnt;
    if (!cnt) return;

    fsize = strlen(cnt);
    *res = NULL;
    size_t total_len = 0;

    char *p = (char*)cnt;
    while (*p) {
        // 1) 取出一行
        char *line_end = strchr(p, '\n');
        if (!line_end) line_end = fbuf + fsize;
        size_t linelen = line_end - p;
        char   line[MAX_LINE_LEN];
        if (linelen >= MAX_LINE_LEN) linelen = MAX_LINE_LEN - 1;
        memcpy(line, p, linelen);
        line[linelen] = '\0';

        // 2) 在这一行里找关键词
        char *match = find_keyword(line, ptarr);
        if (match) {
            // 3) 计算 filebuf 中的绝对位置
            char *abs_pos = p + (match - line);

            // 4) 提取句子
            char *sent = extract_sentence(fbuf, abs_pos);
            size_t slen = strlen(sent);

            // 5) 把它追加到 *res：如果已有内容，先加 ';'
            size_t need = total_len + slen + (total_len ? 1 : 0) + 1;
            char *tmp = realloc(*res, need);
            if (!tmp) {
                perror("realloc");
                free(sent);
                break;
            }
            *res = tmp;
            if (total_len) {
                (*res)[total_len++] = ';';
            }
            memcpy(*res + total_len, sent, slen);
            total_len += slen;
            (*res)[total_len] = '\0';

            free(sent);
        }

        // 6) 继续下一行
        if (*line_end == '\0') break;
        p = line_end + 1;
    }
//    free(fbuf);
}

void search_and_extlinx(const char *filename, const char **ptarr, char **res)
{
    long   filesize;
    char  *filebuf = load_file(filename, &filesize);
    if (!filebuf) return;

    *res = NULL;
    size_t total_len = 0;

    char *p = filebuf;
    while (*p) {
        // 1) 取出一行
        char *line_end = strchr(p, '\n');
        if (!line_end) line_end = filebuf + filesize;
        size_t linelen = line_end - p;
        char   line[MAX_LINE_LEN];
        if (linelen >= MAX_LINE_LEN) linelen = MAX_LINE_LEN - 1;
        memcpy(line, p, linelen);
        line[linelen] = '\0';

        // 2) 在这一行里找关键词
        char *match = find_keyword(line, ptarr);
        if (match) {
            // 3) 计算 filebuf 中的绝对位置
            char *abs_pos = p + (match - line);

            // 4) 提取句子
            char *sent = extract_sentence(filebuf, abs_pos);
            size_t slen = strlen(sent);

            // 5) 把它追加到 *res：如果已有内容，先加 ';'
            size_t need = total_len + slen + (total_len ? 1 : 0) + 1;
            char *tmp = realloc(*res, need);
            if (!tmp) {
                perror("realloc");
                free(sent);
                break;
            }
            *res = tmp;
            if (total_len) {
                (*res)[total_len++] = ';';
            }
            memcpy(*res + total_len, sent, slen);
            total_len += slen;
            (*res)[total_len] = '\0';

            free(sent);
        }

        // 6) 继续下一行
        if (*line_end == '\0') break;
        p = line_end + 1;
    }
    free(filebuf);
}
