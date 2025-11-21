#include <stdbool.h>
extern bool slgflg;
#include "arg_parser.h"
#include "channel.h"
#include "log.h"
extern char *cpuNUM;
int get_last_number(const char *str) {
    const char *last_comma = strrchr(str, ',');
    const char *last_dash = strrchr(last_comma ? last_comma : str, '-');

    const char *last_number_start = last_dash ? last_dash + 1 : (last_comma ? last_comma + 1 : str);

    return atoi(last_number_start);
}

int countNum(const char *cpuidt) {
    int count = 0;
    char *token;
    char *str = strdup(cpuidt); // 复制字符串以便进行修改
    char *rest = str;

    while ((token = strtok_r(rest, ",", &rest))) {
        char *dash = strchr(token, '-');
        if (dash) {
            *dash = '\0';// 将 '-' 替换为 '\0'，分割成两个部分
            int start = atoi(token);
            int end = atoi(dash + 1);
            count += (end - start + 1);
        } else {
            // 处理单个数字
            count += 1;
        }
    }

    free(str);
    return count;
}

void reorder_string(char *str) {
    char *tlb_position = strstr(str, "TLB");

    // 检查是否找到 "TLB" 且不在第一个
    if (tlb_position != NULL && tlb_position != str) {
        char result[100]; // 假设结果字符串不会超过 100 个字符
        strcpy(result, "TLB,"); // 先将 "TLB," 复制到结果中

        // 复制 TLB 之前的部分
        strncat(result, str, tlb_position - str);
//        strcat(result, ",");

        // 复制 TLB 之后的部分
        strcat(result, tlb_position + 4); // 跳过 "TLB,"

        // 去除可能重复的逗号
        if (result[strlen(result) - 1] == ',') {
            result[strlen(result) - 1] = '\0';
        }

        strcpy(str, result); // 将结果复制回原字符串
    }
}

char* __arg_parser(const char *cfile, int line, const char* msg, const char* intarpro, mesdet mstp)//enum MESSAGETYPE mstp)
{
	const char      *__function_name = "arg_parser";
	struct transfer *trans = NULL;
	char* cmd = NULL;
	char* tarpro=NULL;
	char* tarcom=NULL;
//	char* tarprop=NULL;
	char* anaopt=NULL;
	char* sleepp=NULL;
	char* timeout=NULL;
//	char* timeoutt=NULL;
	char* nodeid=NULL;
	char* meshid=NULL;
	char* hm_id=NULL;
	char* pmu_id=NULL;
	char* c2c_id=NULL;
	char* ctrler_id=NULL;
	char* tra_switch=NULL;
	char* tpid=NULL; // target program
	char* apid=NULL;    // analys argus
//	char* pid=NULL;
//	pid_t pidt=0;
//	phy_uint64_t sleept=0;
//	char* sleept=NULL;
	char* tarcomt = NULL;
	char* tarprot = NULL;
	char* anaoptt = NULL;

	char* nodeidt= NULL;
	char* meshidt= NULL;

	char* pmu_idt=NULL;
	char* hm_idt =NULL;

	char* c2c_idt=NULL;
	char* ctrler_idt=NULL;
	char* tra_switcht=NULL;

	char* coreid = NULL;
	char* repet = NULL;

	char* node = NULL;
	char* nodet = NULL;
	char* duration = NULL;
	char* durationt = NULL;
	char* interval = NULL;
	char* intervalt = NULL;
	char* cpuid = NULL;
	char* cpuidt = NULL;
	char* stages = NULL;
	char* stagest = NULL;
	char* metricg = NULL;
	char* metricgt = NULL;
	bool acpus = false;

	char promptInfo[256]={0};
	char **arr = NULL;
	phy_strarr_init(&arr);
	str_to_arr(msg, ";", &arr);
	char** stmp = NULL;
//	char mesg[128] = {0};
//	char * sline = NULL;
//	sline = phy_malloc(sline, STRING_LEN);
	int i = 0;
	cmd = (char*)phy_malloc(cmd, BUFLEN);
	memset(cmd, 0, BUFLEN);

	for (stmp = arr; NULL != *stmp; stmp++){
//		printf("%s\n", *stmp);
//		if(tarprop == NULL){
//			tarprop = strstr(*stmp, "tarprop=");
//		}
		if(tarpro == NULL){
			tarpro = strstr(*stmp, "tarpro=");
		}
		if(tarcom == NULL){
			tarcom = strstr(*stmp, "tarcom=");
		}
		if(anaopt == NULL){
			anaopt = strstr(*stmp, "anaopt=");
		}
		if(nodeid == NULL){
			nodeid = strstr(*stmp, "node_id=");
		}

//topdown
		if(node == NULL){
			node = strstr(*stmp, "node=");
		}
		if(stages == NULL){
			stages = strstr(*stmp, "stages=");
		}
		if(metricg == NULL){
			metricg = strstr(*stmp, "metric-group=");
		}
		if(duration == NULL){
			duration = strstr(*stmp, "duration=");
		}
		if(interval == NULL){
			interval = strstr(*stmp, "interval=");
		}
		if(cpuid == NULL){
			cpuid = strstr(*stmp, "cpuid=");
		}
		if(acpus == false){
			if(strstr(*stmp, "ALL-CPUS")){
				acpus = true;
			}
		}

		if(meshid == NULL){
			meshid = strstr(*stmp, "mesh_id=");
		}
		if(hm_id == NULL){
			hm_id  = strstr(*stmp, "hm_id=");
		}
		if(pmu_id == NULL){
			pmu_id = strstr(*stmp, "pmu_id=");
		}
		if(c2c_id == NULL){
			c2c_id = strstr(*stmp, "c2c_id=");
		}
		if(ctrler_id == NULL){
			ctrler_id = strstr(*stmp, "ctrler_id=");
		}
		if(tra_switch == NULL){
			tra_switch = strstr(*stmp, "tra_switch=");
		}
		i++;
	}

//	phy_strarr_free(arr);
//	return cmd;
	if( anaopt != NULL ){
		coreid = get_str_between_two_words(anaopt, "-C ", " ");
		if(coreid == NULL)
			coreid = get_str_between_two_words(anaopt, "-C ", NULL);

		apid = get_str_between_two_words(anaopt, "-p ", " ");
		if(apid == NULL)
			apid = get_str_between_two_words(anaopt, "-p ", NULL);

		repet = get_str_between_two_words(anaopt, "-r ", " ");
		if(repet == NULL)
			repet = get_str_between_two_words(anaopt, "-r ", NULL);

		timeout = get_str_between_two_words(anaopt, "--timeout ", " ");
		if(timeout == NULL)
			timeout = get_str_between_two_words(anaopt, "--timeout ", NULL);
	}

	//访存分析采样时长
	if(duration){
		durationt = get_str_between_two_words(duration, "duration=", ";");
		if(durationt == NULL){
			durationt = get_str_between_two_words(duration, "duration=", NULL);
		}
		if(durationt == NULL){
			goto arg_err;
		}
	}

		//Miss分析CPU id
	if(cpuid){
		cpuidt = get_str_between_two_words(cpuid, "cpuid=", ";");
		if(cpuidt == NULL){
			cpuidt = get_str_between_two_words(cpuid, "cpuid=", NULL);
		}
		if (strcmp(cpuidt, "") == 0 && (strstr(msg, "Miss") != NULL || strstr(msg, "Hit") != NULL)) {
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入CPU ID！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}
		if(get_last_number(cpuidt)>atoi(cpuNUM)-1){
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s%d。", "cpu id超出限制！cpu范围请限制在0-",atoi(cpuNUM)-1);
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}
//		if(countNum(cpuidt)>20 && strstr(msg,"实时")){
//			slgflg = true;
//			phy_snprintf(promptInfo, 1280, "%s", "cpu数量过多可能会占用较多的系统资源，请限制在20个CPU内！");
//			send_message(MESS, ERROR, mstp,promptInfo);
//			goto err_out;
//		}
	}



//判断参数输入 进程号与等待时间
//tarprot
	if(tarpro){
		tarprot = get_str_between_two_words(tarpro, "tarpro=", ",");
		if(tarprot == NULL){
			tarprot = get_str_between_two_words(tarpro, "tarpro=", NULL);
		}
		if(tarprot == NULL || *tarprot == '\0'){
//			goto arg_err;
			phy_free(tarprot);
		}
	}

#if 1
//如果tarpro没有设置 为空，那么-p 不应该为空 --timeout 也不能为空
	if(tarprot == NULL){
		if((apid == NULL || timeout == NULL) && (durationt == NULL)){
			if(mstp == ACCMEMSYS || mstp == ACCMEMAPI || mstp == IOSYS || mstp == (mesdet)IORTEXEC || mstp== (mesdet)SYSHITRTEXEC || mstp== (mesdet)SYSMISSRTEXEC || mstp== (mesdet)APIHITRTEXEC || mstp== (mesdet)APIMISSRTEXEC ){
			}else{
				goto arg_err;
			}
		}
	}

//如果tarpro不为空，那么-p应该为空 --timeout可为空
	if(tarprot != NULL){
		if(apid != NULL){
			goto arg_err;
		}
	}
#endif

#if 0
//tarprot
//目标程序为纯数字 错误
	if(is_number(tarprot)){
		goto arg_err;
	}else if(is_alphanum(tarprot)){ //如果为字母和数字组合则为 sleep xxx 或是 -p xxx
		if(strstr(tarprot, "sleep")){
//			sleept = get_numbers(tarprot, true);
//			if((sleept != NULL) && (timeout != NULL)){ //如果tarpro 为 sleep xxx 且 anaopt中有 --timeout设定
//				goto arg_err;
//			}
//			if(apid != NULL){    //如果tarpro 为 sleep xxx 且 anaopt中有 -p 设定，则待检测程序 设置重复
//				goto arg_err;
//			}
		}else if(strstr(tarprot, "-p")){
				goto arg_err;
			tpid = get_numbers(tarprot, true);
			if((tpid != NULL) && (apid != NULL)){
				goto arg_err;
			}
		}else{//如果tarpro 为字母数字组合 且没有"sleep" "-p"字符, 则设置错误
			goto arg_err;
		}
	}else{ //如果tarpro为纯字符串

	}
#endif

//tarcomt
	if(tarcom){
		tarcomt = get_str_between_two_words(tarcom, "tarcom=", ";");
		if(tarcomt == NULL){
			tarcomt = get_str_between_two_words(tarcom, "tarcom=", NULL);
		}
		if(tarcomt == NULL){
			goto arg_err;
		}
		if(0 == phy_strcmp_natural(tarcomt, "ALL")){
			phy_free(tarcomt);
			tarcomt = NULL;
		}
	}

//anaoptt
	if(anaopt){
		anaoptt = get_str_between_two_words(anaopt, "anaopt=", ";");
		if(anaoptt == NULL){
			anaoptt = get_str_between_two_words(anaopt, "anaopt=", NULL);
		}
		if(anaoptt == NULL){
			goto arg_err;
		}
	}

	if((tarprot != NULL && tpid != NULL) || (intarpro != NULL && tpid != NULL)){
		goto arg_err;
	}
	if(mstp == TOPDOWN){
//construct cmd
#if 1
		if(acpus == true){
			strncat(cmd, " --all-cpus ", 13);
		}

		if(node != NULL){
			nodet = get_str_between_two_words(node, "node=", ",");
			if(nodet == NULL){
				nodet = get_str_between_two_words(node, "node=", NULL);
			}
			strncat(cmd, " -n ", 5);
			strncat(cmd, nodet, strlen(nodet)+1);
		}

		if(stages != NULL){
			stagest = get_str_between_two_words(stages, "stages=", ",");
			if(stagest == NULL){
				stagest = get_str_between_two_words(stages, "stages=", NULL);
			}
			strncat(cmd, " -s ", 5);
			strncat(cmd, stagest, strlen(stagest)+1);
		}
		if(metricg != NULL){
			metricgt = get_str_between_two_words(metricg, "metric-group=", NULL);
			if(metricgt == NULL){
				metricgt = get_str_between_two_words(metricg, "metric-group=", NULL);
			}
			//strncat(cmd, " --metric-group ", 16);
			strncat(cmd, " -m ", 5);
			strncat(cmd, metricgt, strlen(metricgt)+1);
		}
		if(interval != NULL){
			intervalt = get_str_between_two_words(interval, "interval=", ",");
			if(intervalt == NULL){
				intervalt = get_str_between_two_words(interval, "interval=", NULL);
			}
			strncat(cmd, " -i ", 5);
			strncat(cmd, intervalt, strlen(intervalt)+1);

			strncat(cmd, " --csv ", 8);
		}

		if(intarpro != NULL){
			strncat(cmd, " ", 2);
			strncat(cmd, intarpro, strlen(intarpro)+1);
		}

		if(anaoptt != NULL){
			strncat(cmd, " ", 2);
			strncat(cmd, anaoptt, strlen(anaoptt)+1);
		}
#endif
		phy_free(nodet);
		phy_free(stagest);
		phy_free(metricgt);
		phy_free(intervalt);
		goto out;
	}else if(mstp == TMA){
//construct cmd
		if(tarcomt && strstr(tarcomt,"anaopt")){
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "目标部件未勾选！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}else if(tarcomt != NULL){
			strncat(cmd, " -u ", 5);
			phy_strlower(tarcomt);
			strncat(cmd, tarcomt, strlen(tarcomt)+1);
		}

		if(anaoptt != NULL){
			strncat(cmd, " -o \"", 6);
			strncat(cmd, anaoptt, strlen(anaoptt)+1);
			if(tpid != NULL){
				strncat(cmd, " -p ", 5);
				strncat(cmd, tpid, strlen(tpid)+1);
			}
			if(sleepp != NULL){
				strncat(cmd, " sleep ", 8);
				strncat(cmd, sleepp, strlen(sleepp)+1);
			}
			strncat(cmd, "\"", 2);
		}

		if(intarpro != NULL){
			strncat(cmd, " ", 2);
			strncat(cmd, intarpro, strlen(intarpro)+1);

		}

		if( (intarpro == NULL) && (tarprot != NULL)){
			strncat(cmd, " ", 2);
			strncat(cmd, tarprot, strlen(tarprot)+1);
		}
		goto out;
	}else if(mstp == NOC){
		if(nodeid){
			nodeidt = get_str_between_two_words(nodeid, "node_id=", ",");
			if(nodeidt == NULL){
				nodeidt = get_str_between_two_words(nodeid, "node_id=", NULL);
			}
			if(ISNULL(nodeidt)){
				if(!is_number(nodeidt)){
					goto arg_err;
				}
			}
		}

		if(meshid){
			meshidt = get_str_between_two_words(meshid, "mesh_id=", ",");
			if(meshidt == NULL){
				meshidt = get_str_between_two_words(meshid, "mesh_id=", NULL);
			}
			if(ISNULL(meshidt)){
				if(!is_number(meshidt)){
					goto arg_err;
				}
			}
		}

		if((tarprot != NULL && tpid != NULL) || (intarpro != NULL && tpid != NULL)){
			goto nocarg_err;
		}

//construct cmd
		if(ISNULL(tarcomt)){
			strncat(cmd, " -u ", 5);
			phy_strlower(tarcomt);
			strncat(cmd, tarcomt, strlen(tarcomt)+1);
		}
		if(ISNULL(anaoptt)){
			strncat(cmd, " -o \"", 6);
			strncat(cmd, anaoptt, strlen(anaoptt)+1);

			if(apid != NULL){
				strncat(cmd, " -p ", 5);
				strncat(cmd, apid, strlen(apid)+1);
			}
			if(sleepp != NULL){
				strncat(cmd, " sleep ", 8);
				strncat(cmd, sleepp, strlen(sleepp)+1);
			}
			strncat(cmd, "\"", 2);
		}

		if(ISNULL(nodeidt)){
			strncat(cmd, " -n ", 5);
			strncat(cmd, nodeidt, strlen(nodeidt)+1);
		}

		if(ISNULL(meshidt)){
//(X:01-Y:10-Port:0-DeviceID:01)
			strncat(cmd, " -x (X:", 8);
			strncat(cmd, meshidt, 2);
			strncat(cmd, "-Y:", 4);
			strncat(cmd, meshidt+2, 2);
			strncat(cmd, "-Port:", 7);
			strncat(cmd, meshidt+4, 1);
			strncat(cmd, "-DeviceID:", 11);
			strncat(cmd, meshidt+5, 2);
			strncat(cmd, ")", 2);
		}

		if(intarpro != NULL){
			strncat(cmd, " ", 2);
			strncat(cmd, intarpro, strlen(intarpro)+1);

		}
		if( (intarpro == NULL) && (tarprot != NULL)){
			strncat(cmd, " ", 2);
			strncat(cmd, tarprot, strlen(tarprot)+1);
		}

		phy_free(nodeidt);
		phy_free(meshidt);
		goto out;
	}else if(mstp == DDR){

		if(nodeid){
			nodeidt = get_str_between_two_words(nodeid, "node_id=", ",");
			if(nodeidt == NULL){
				nodeidt = get_str_between_two_words(nodeid, "node_id=", NULL);
			}
			if(ISNULL(nodeidt)){
				if(!is_number(nodeidt)){
					goto arg_err;
				}
			}
		}

		if(hm_id){
			hm_idt = get_str_between_two_words(hm_id, "hm_id=", ",");
			if(hm_idt == NULL){
				hm_idt = get_str_between_two_words(hm_id, "hm_id=", NULL);
			}
			if(ISNULL(hm_idt)){
				if(!is_number(hm_idt)){
					goto arg_err;
				}
			}
		}

		if(pmu_id){
			pmu_idt = get_str_between_two_words(pmu_id, "pmu_id=", ",");
			if(pmu_idt == NULL){
				pmu_idt = get_str_between_two_words(pmu_id, "pmu_id=", NULL);
			}
			if(ISNULL(pmu_idt)){
				if(!is_number(pmu_idt)){
					goto arg_err;
				}
			}
		}

		if((tarprot != NULL && tpid != NULL) || (intarpro != NULL && tpid != NULL)){
			goto ddrarg_err;
		}

//construct cmd
		if(ISNULL(anaoptt)){
			strncat(cmd, " -o \"", 6);
			strncat(cmd, anaoptt, strlen(anaoptt)+1);

			if(tpid != NULL){
				strncat(cmd, " -p ", 5);
				strncat(cmd, tpid, strlen(tpid)+1);
			}
			if(sleepp != NULL){
				strncat(cmd, " sleep ", 8);
				strncat(cmd, sleepp, strlen(sleepp)+1);
			}
			strncat(cmd, "\"", 2);
		}

		if(ISNULL(nodeidt)){
			strncat(cmd, " -n ", 5);
			strncat(cmd, nodeidt, strlen(nodeidt)+1);
		}
		if(ISNULL(hm_idt)){
			strncat(cmd, " -h ", 5);
			strncat(cmd, hm_idt, strlen(hm_idt)+1);
		}
		if(ISNULL(pmu_idt)){
			strncat(cmd, " -u ", 5);
			strncat(cmd, pmu_idt, strlen(pmu_idt)+1);
		}

		if(intarpro != NULL){
			strncat(cmd, " ", 2);
			strncat(cmd, intarpro, strlen(intarpro)+1);

		}
		if( (intarpro == NULL) && (tarprot != NULL)){
			strncat(cmd, " ", 2);
			strncat(cmd, tarprot, strlen(tarprot)+1);
		}

		phy_free(nodeidt);
		phy_free(pmu_idt);
		phy_free(hm_idt);
		goto out;
	}else if(mstp == C2C){

		if(nodeid){
			nodeidt = get_str_between_two_words(nodeid, "node_id=", ",");
			if(nodeidt == NULL){
				nodeidt = get_str_between_two_words(nodeid, "node_id=", NULL);
			}
			if(ISNULL(nodeidt)){
				if(!is_number(nodeidt)){
					goto arg_err;
				}
			}
		}

		if(c2c_id){
			c2c_idt = get_str_between_two_words(c2c_id, "c2c_id=", ",");
			if(c2c_idt == NULL){
				c2c_idt = get_str_between_two_words(c2c_id, "c2c_id=", NULL);
			}
			if(ISNULL(c2c_idt)){
				if(!is_number(c2c_idt)){
					goto arg_err;
				}
			}
		}

		if(ctrler_id){
			ctrler_idt = get_str_between_two_words(ctrler_id, "ctrler_id=", ",");
			if(ctrler_idt == NULL){
				ctrler_idt = get_str_between_two_words(ctrler_id, "ctrler_id=", NULL);
			}
			if(ISNULL(ctrler_idt)){
				if(!is_number(ctrler_idt)){
					goto arg_err;
				}
			}
		}

		if(tra_switch){
			tra_switcht = get_str_between_two_words(tra_switch, "tra_switch=", ",");
			if(tra_switcht == NULL){
				tra_switcht = get_str_between_two_words(tra_switch, "tra_switch=", NULL);
			}
			if(ISNULL(tra_switcht)){
				if(!is_number(tra_switcht)){
					goto arg_err;
				}
			}
		}

		if((tarprot != NULL && tpid != NULL) || (intarpro != NULL && tpid != NULL)){
			goto c2carg_err;
		}

//construct cmd
		if(ISNULL(anaoptt)){
			strncat(cmd, " -o \"", 6);
			strncat(cmd, anaoptt, strlen(anaoptt)+1);

			if(ISNULL(tpid)){
				strncat(cmd, " -p ", 5);
				strncat(cmd, tpid, strlen(tpid)+1);
			}
			if(ISNULL(sleepp)){
				strncat(cmd, " sleep ", 8);
				strncat(cmd, sleepp, strlen(sleepp)+1);
			}
			strncat(cmd, "\"", 2);
		}

		if(ISNULL(nodeidt)){
			strncat(cmd, " -n ", 5);
			strncat(cmd, nodeidt, strlen(nodeidt)+1);
		}
		if(ISNULL(c2c_idt)){
			strncat(cmd, " -u ", 5);
			strncat(cmd, c2c_idt, strlen(c2c_idt)+1);
		}
		if(ISNULL(ctrler_idt)){
			strncat(cmd, " -c ", 5);
			strncat(cmd, ctrler_idt, strlen(ctrler_idt)+1);
		}
		if(*tra_switcht == '1'){
			strncat(cmd, " -b ", 5);
		}

		if(intarpro != NULL){
			strncat(cmd, " ", 2);
			strncat(cmd, intarpro, strlen(intarpro)+1);
		}
		if((intarpro == NULL) && (tarprot != NULL)){
			strncat(cmd, " ", 2);
			strncat(cmd, tarprot, strlen(tarprot)+1);
		}

		phy_free(nodeidt);
		phy_free(ctrler_idt);
		phy_free(c2c_idt);
		phy_free(tra_switcht);
		goto out;
	}else if(mstp == ACCMEMSYS){
		if(tarcomt && (strcmp(tarcomt, "") == 0 || strstr(tarcomt,"="))){
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "目标部件未勾选！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}
		else if(tarcomt != NULL){
			strncat(cmd, " -u ", 5);
//			if(strstr(msg,"Hit")){
//				reorder_string(tarcomt);
//			}
			phy_strlower(tarcomt);
			strncat(cmd, tarcomt, strlen(tarcomt)+1);
		}else{
			strncat(cmd, " -u ", 5);
			strncat(cmd, "all", 4);
		}

		if(interval != NULL){
			intervalt = get_str_between_two_words(interval, "interval=", NULL);
			if(intervalt != NULL && intervalt[0] == '\0'){
//				intervalt = get_str_between_two_words(interval, "interval=", NULL);
				goto arg_err;
			}else{
				strncat(cmd, " -i ", 5);
				// 将intervalt转换为整数，乘以1000后再转换回字符串
				int intervalt_int = atoi(intervalt); // 将字符串转换为整数
				intervalt_int *= 1000; // 乘以1000
				char intervalt_str[20]; // 用于存储转换后的字符串
				snprintf(intervalt_str, 20, "%d", intervalt_int); // 将整数转换为字符串
				strncat(cmd, intervalt_str, strlen(intervalt_str));
			}
		}else{
			if(strstr(msg,"Miss")==NULL){
				slgflg = true;
				phy_snprintf(promptInfo, 1280, "%s", "未输入采样间隔！");
				send_message(MESS, ERROR, mstp,promptInfo);
				goto err_out;
			}
		}

		if(durationt != NULL && strcmp(durationt, "") != 0){
			strncat(cmd, " -t ", 5);
			strncat(cmd, durationt, strlen(durationt)+1);
		}else{
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入采样时长！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}

		if(cpuidt != NULL && strcmp(cpuidt, "") != 0){
			strncat(cmd, " -c ", 5);
			strncat(cmd, cpuidt, strlen(cpuidt)+1);

		}

		if(intarpro != NULL){
			strncat(cmd, " ", 2);
			strncat(cmd, intarpro, strlen(intarpro)+1);
		}

		if( (intarpro == NULL) && (tarprot != NULL)){
			strncat(cmd, " ", 2);
			strncat(cmd, tarprot, strlen(tarprot)+1);
		}

		phy_free(intervalt);
		goto out;
	}else if(mstp == ACCMEMAPI){
		if(tarcomt && (strcmp(tarcomt, "") == 0 || strstr(tarcomt,"="))){
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "目标部件未勾选！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}
		else if(tarcomt != NULL){
			strncat(cmd, " -u ", 5);
//			if(strstr(msg,"Hit")){
//				reorder_string(tarcomt);
//			}
			phy_strlower(tarcomt);
			strncat(cmd, tarcomt, strlen(tarcomt)+1);
		}else{
			strncat(cmd, " -u ", 5);
			strncat(cmd, "all", 4);
		}

		if(interval != NULL){
			intervalt = get_str_between_two_words(interval, "interval=", NULL);
			if(intervalt != NULL && intervalt[0] == '\0'){
//				intervalt = get_str_between_two_words(interval, "interval=", NULL);
				goto arg_err;
			}else{
				strncat(cmd, " -i ", 5);
				// 将intervalt转换为整数，乘以1000后再转换回字符串
				int intervalt_int = atoi(intervalt); // 将字符串转换为整数
				intervalt_int *= 1000; // 乘以1000
				char intervalt_str[20]; // 用于存储转换后的字符串
				snprintf(intervalt_str, 20, "%d", intervalt_int); // 将整数转换为字符串
				strncat(cmd, intervalt_str, strlen(intervalt_str));
			}
		}else{
			if(strstr(msg,"Miss")==NULL){
				slgflg = true;
				phy_snprintf(promptInfo, 1280, "%s", "未输入采样间隔！");
				send_message(MESS, ERROR, mstp,promptInfo);
				goto err_out;
			}
		}

		if(durationt != NULL && strcmp(durationt, "") != 0){
			strncat(cmd, " -t ", 5);
			strncat(cmd, durationt, strlen(durationt)+1);
		}else{
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入采样时长！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}

		if(cpuidt != NULL && strcmp(cpuidt, "") != 0){
			strncat(cmd, " -c ", 5);
			strncat(cmd, cpuidt, strlen(cpuidt)+1);
		}

		if(intarpro != NULL){
			strncat(cmd, " ", 2);
			strncat(cmd, intarpro, strlen(intarpro)+1);
		}else{
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入程序路径/进程号！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}

		phy_free(intervalt);
		goto out;
	}else if(mstp == (mesdet)SYSHITRTEXEC){
		if(tarcomt && (strcmp(tarcomt, "") == 0 || strstr(tarcomt,"="))){
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "目标部件未勾选！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}
		else if(tarcomt != NULL){
			strncat(cmd, " -u ", 5);
//			reorder_string(tarcomt);
			phy_strlower(tarcomt);
			strncat(cmd, tarcomt, strlen(tarcomt)+1);
		}else{
			strncat(cmd, " -u ", 5);
			strncat(cmd, "all", 4);
		}

		if(interval != NULL){
			intervalt = get_str_between_two_words(interval, "interval=", NULL);
			if(intervalt != NULL && intervalt[0] == '\0'){
//				intervalt = get_str_between_two_words(interval, "interval=", NULL);
				goto arg_err;
			}else{
				strncat(cmd, " -i ", 5);
				// 将intervalt转换为整数，乘以1000后再转换回字符串
				int intervalt_int = atoi(intervalt); // 将字符串转换为整数
				intervalt_int *= 1000; // 乘以1000
				char intervalt_str[20]; // 用于存储转换后的字符串
				snprintf(intervalt_str, 20, "%d", intervalt_int); // 将整数转换为字符串
				strncat(cmd, intervalt_str, strlen(intervalt_str));
			}
		}else{
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入采样间隔！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}
		if(cpuidt != NULL && strcmp(cpuidt, "") != 0){
			strncat(cmd, " -c ", 5);
			strncat(cmd, cpuidt, strlen(cpuidt)+1);
		}
		phy_free(intervalt);
		goto out;
	}else if(mstp == (mesdet)APIHITRTEXEC){
		if(tarcomt && (strcmp(tarcomt, "") == 0 || strstr(tarcomt,"="))){
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "目标部件未勾选！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}
		else if(tarcomt != NULL){
			strncat(cmd, " -u ", 5);
//			reorder_string(tarcomt);
			phy_strlower(tarcomt);
			strncat(cmd, tarcomt, strlen(tarcomt)+1);
		}else{
			strncat(cmd, " -u ", 5);
			strncat(cmd, "all", 4);
		}

		if(interval != NULL){
			intervalt = get_str_between_two_words(interval, "interval=", NULL);
			if(intervalt != NULL && intervalt[0] == '\0'){
//				intervalt = get_str_between_two_words(interval, "interval=", NULL);
				goto arg_err;
			}else{
				strncat(cmd, " -i ", 5);
				// 将intervalt转换为整数，乘以1000后再转换回字符串
				int intervalt_int = atoi(intervalt); // 将字符串转换为整数
				intervalt_int *= 1000; // 乘以1000
				char intervalt_str[20]; // 用于存储转换后的字符串
				snprintf(intervalt_str, 20, "%d", intervalt_int); // 将整数转换为字符串
				strncat(cmd, intervalt_str, strlen(intervalt_str));
			}
		}else{
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入采样间隔！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}

		if(cpuidt != NULL && strcmp(cpuidt, "") != 0){
			strncat(cmd, " -c ", 5);
			strncat(cmd, cpuidt, strlen(cpuidt)+1);
		}

		if(intarpro != NULL){
			strncat(cmd, " ", 2);
			strncat(cmd, intarpro, strlen(intarpro)+1);
		}else{
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入程序路径/进程号！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}

		phy_free(intervalt);
		goto out;
	}else if(mstp == (mesdet)SYSMISSRTEXEC){
		if(tarcomt && (strcmp(tarcomt, "") == 0 || strstr(tarcomt,"="))){
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "目标部件未勾选！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}
		else if(tarcomt != NULL){
			strncat(cmd, " -u ", 5);
			phy_strlower(tarcomt);
			strncat(cmd, tarcomt, strlen(tarcomt)+1);
		}else{
			strncat(cmd, " -u ", 5);
			strncat(cmd, "all", 4);
		}

		if(interval != NULL){
			intervalt = get_str_between_two_words(interval, "interval=", NULL);
			if(intervalt != NULL && intervalt[0] == '\0'){
//				intervalt = get_str_between_two_words(interval, "interval=", NULL);
				goto arg_err;
			}else{
				strncat(cmd, " -i ", 5);
				// 将intervalt转换为整数，乘以1000后再转换回字符串
				int intervalt_int = atoi(intervalt); // 将字符串转换为整数
				intervalt_int *= 1000; // 乘以1000
				char intervalt_str[20]; // 用于存储转换后的字符串
				snprintf(intervalt_str, 20, "%d", intervalt_int); // 将整数转换为字符串
				strncat(cmd, intervalt_str, strlen(intervalt_str));
			}
		}else{
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入采样间隔！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}

		if(cpuidt != NULL && strcmp(cpuidt, "") != 0){
			strncat(cmd, " -c ", 5);
			strncat(cmd, cpuidt, strlen(cpuidt)+1);
		}

		if(intarpro != NULL){
			strncat(cmd, " ", 2);
			strncat(cmd, intarpro, strlen(intarpro)+1);
		}

		if( (intarpro == NULL) && (tarprot != NULL)){
			strncat(cmd, " ", 2);
			strncat(cmd, tarprot, strlen(tarprot)+1);
		}

		phy_free(intervalt);
		goto out;
	}else if(mstp == (mesdet)APIMISSRTEXEC){
		if(tarcomt && (strcmp(tarcomt, "") == 0 || strstr(tarcomt,"="))){
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "目标部件未勾选！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}
		else if(tarcomt != NULL){
			strncat(cmd, " -u ", 5);
			phy_strlower(tarcomt);
			strncat(cmd, tarcomt, strlen(tarcomt)+1);
		}else{
			strncat(cmd, " -u ", 5);
			strncat(cmd, "all", 4);
		}

		if(interval != NULL){
			intervalt = get_str_between_two_words(interval, "interval=", NULL);
			if(intervalt != NULL && intervalt[0] == '\0'){
//				intervalt = get_str_between_two_words(interval, "interval=", NULL);
				goto arg_err;
			}else{
				strncat(cmd, " -i ", 5);
				// 将intervalt转换为整数，乘以1000后再转换回字符串
				int intervalt_int = atoi(intervalt); // 将字符串转换为整数
				intervalt_int *= 1000; // 乘以1000
				char intervalt_str[20]; // 用于存储转换后的字符串
				snprintf(intervalt_str, 20, "%d", intervalt_int); // 将整数转换为字符串
				strncat(cmd, intervalt_str, strlen(intervalt_str));
			}
		}else{
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入采样间隔！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}

		if(cpuidt != NULL && strcmp(cpuidt, "") != 0){
			strncat(cmd, " -c ", 5);
			strncat(cmd, cpuidt, strlen(cpuidt)+1);
		}

		if(intarpro != NULL){
			strncat(cmd, " ", 2);
			strncat(cmd, intarpro, strlen(intarpro)+1);
		}else{
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入程序路径/进程号！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}

		phy_free(intervalt);
		goto out;
	}else if(mstp == IOSYS){
		if(tarcomt != NULL){
			strncat(cmd, " -d /dev/", 10);
			phy_strlower(tarcomt);
			strncat(cmd, tarcomt, strlen(tarcomt)+1);
		}else{
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入待测设备！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}

		if(durationt != NULL && strcmp(durationt, "") != 0){
			strncat(cmd, " -w ", 5);
			strncat(cmd, durationt, strlen(durationt)+1);
		}else{
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入采样时长！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}
		goto out;
	}else if(mstp == IOAPI){
		if(durationt != NULL && strcmp(durationt, "") != 0){
			strncat(cmd, " -w ", 5);
			strncat(cmd, durationt, strlen(durationt)+1);
		}else{
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入采样时长！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}

		if(intarpro != NULL){
			strncat(cmd, " ", 2);
			strncat(cmd, intarpro, strlen(intarpro)+1);
		}else{
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入程序路径/进程号！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}

		if( (intarpro == NULL) && (tarprot != NULL)){
			strncat(cmd, " ", 2);
			strncat(cmd, tarprot, strlen(tarprot)+1);
		}

		goto out;
	}else if(mstp == (mesdet)IORTEXEC){
		if(tarcomt != NULL){
			strncat(cmd, " -d /dev/", 10);
			phy_strlower(tarcomt);
			strncat(cmd, tarcomt, strlen(tarcomt)+1);
		}

		if(interval != NULL){
			intervalt = get_str_between_two_words(interval, "interval=", NULL);
			if(intervalt != NULL){
				strncat(cmd, " -i ", 5);
				strncat(cmd, intervalt, strlen(intervalt)+1);
			}
		}else{
			slgflg = true;
			phy_snprintf(promptInfo, 1280, "%s", "未输入采样间隔！");
			send_message(MESS, ERROR, mstp,promptInfo);
			goto err_out;
		}

		phy_free(intervalt);
		goto out;
	} else if(mstp == PCIE){
		if(nodeid){
			nodeidt = get_str_between_two_words(nodeid, "node_id=", ",");
			if(nodeidt == NULL){
				nodeidt = get_str_between_two_words(nodeid, "node_id=", NULL);
			}
			if(ISNULL(nodeidt)){
				if(!is_number(nodeidt)){
					goto arg_err;
				}
			}
		}

		if(pmu_id){
			pmu_idt = get_str_between_two_words(pmu_id, "pmu_id=", ",");
			if(pmu_idt == NULL){
				pmu_idt = get_str_between_two_words(pmu_id, "pmu_id=", NULL);
			}

			if(ISNULL(pmu_idt)){
				if(!is_number(pmu_idt)){
					goto arg_err;
				}
			}
		}

		if(ctrler_id){
			ctrler_idt = get_str_between_two_words(ctrler_id, "ctrler_id=", ",");
			if(ctrler_idt == NULL){
				ctrler_idt = get_str_between_two_words(ctrler_id, "ctrler_id=", NULL);
			}

			if(ISNULL(ctrler_idt)){
				if(!is_number(ctrler_idt)){
					goto arg_err;
				}
			}
		}

		if(tra_switch){
			tra_switcht = get_str_between_two_words(tra_switch, "tra_switch=", ",");
			if(tra_switcht == NULL){
				tra_switcht = get_str_between_two_words(tra_switch, "tra_switch=", NULL);
			}

			if(ISNULL(tra_switcht)){
				if(!is_number(tra_switcht)){
					goto arg_err;
				}
			}else{
				tra_switcht = NULL;
			}
		}

//construct cmd
		if(ISNULL(anaoptt)){
			strncat(cmd, " -o \"", 6);
			strncat(cmd, anaoptt, strlen(anaoptt)+1);

			if(tpid != NULL){
				strncat(cmd, " -p ", 5);
				strncat(cmd, tpid, strlen(tpid)+1);
			}
			if(sleepp != NULL){
				strncat(cmd, " sleep ", 8);
				strncat(cmd, sleepp, strlen(sleepp)+1);
			}
			strncat(cmd, "\"", 2);
		}

		if(ISNULL(nodeidt)){
			strncat(cmd, " -n ", 5);
			strncat(cmd, nodeidt, strlen(nodeidt)+1);
		}
		if(ISNULL(pmu_idt)){
			strncat(cmd, " -u ", 5);
			strncat(cmd, pmu_idt, strlen(pmu_idt)+1);
		}
		if(ISNULL(ctrler_idt)){
			strncat(cmd, " -c ", 5);
			strncat(cmd, ctrler_idt, strlen(ctrler_idt)+1);
		}
		if(*tra_switcht == '1'){
			strncat(cmd, " -b ", 5);
		}

		if(intarpro != NULL){
			strncat(cmd, " ", 2);
			strncat(cmd, intarpro, strlen(intarpro)+1);

		}
		if( (intarpro == NULL) && (tarprot != NULL)){
			strncat(cmd, " ", 2);
			strncat(cmd, tarprot, strlen(tarprot)+1);
		}
		phy_free(nodeidt);
		phy_free(ctrler_idt);
		phy_free(pmu_idt);
		phy_free(tra_switcht);
		goto out;
	}

out:
//###
	phy_free(timeout);
	phy_free(coreid);
	phy_free(apid);
	phy_free(repet);
//	phy_free(anaopt);
//###

//	phy_free(tpid);
	phy_free(sleepp);
	phy_free(anaoptt);
	phy_free(tarprot);
	phy_free(tarcomt);
	phy_strarr_free(arr);
	return cmd;

err_out:
	phy_strarr_free(arr);
	phy_free(cmd);
	return NULL;
arg_err:
	slgflg = true;
	sleep(1);
	phy_log(LOG_LEVEL_ERR, "[file:%s,line:%d] %s: arg error(%s)", cfile, line, __function_name, msg);
	trans = (struct transfer*)malloc(sizeof(struct transfer));
	memset(trans, 0, sizeof(struct transfer));
	trans->mma.mme = ERROR;
	trans->mma.matp = MESS;
	trans->td.affi = mstp;
	phy_snprintf(trans->td.mes, 1280, "%s", "参数错误");
	write_message_to_controller((char*)(trans), sizeof(struct transfer));
	phy_free(trans);
	goto err_out;

//tmaarg_err:
//	phy_log(LOG_LEVEL_ERR, "[file:%s,line:%d] %s: TMA parameter error(%s)", cfile, line, __function_name, msg);
//	goto err_out;
nocarg_err:
	phy_log(LOG_LEVEL_ERR, "[file:%s,line:%d] %s: NOC parameter error(%s)", cfile, line, __function_name, msg);
	goto err_out;
ddrarg_err:
	phy_log(LOG_LEVEL_ERR, "[file:%s,line:%d] %s: DDR parameter error(%s)", cfile, line, __function_name, msg);
	goto err_out;
c2carg_err:
	phy_log(LOG_LEVEL_ERR, "[file:%s,line:%d] %s: C2C parameter error(%s)", cfile, line, __function_name, msg);
	goto err_out;
//pciearg_err:
//	phy_log(LOG_LEVEL_ERR, "[file:%s,line:%d] %s: PCIE parameter error(%s)", cfile, line, __function_name, msg);
	goto err_out;
}
