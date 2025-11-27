#if 0
#include "../common.h"
#include "../log.h"
#include "../net/net_inc.h"

//"tarpro=sleep 100;tarcom=ALL;anaopt=-C 1 -r 1 -p 2280 --timeout 5"
char* __arg_validity_check(const char *cfile, int line, const char* msg, const char* intarpro, enum MESSAGETYPE mstp)
{
	const char      *__function_name = "arg_validity_check";
	char mss[128] = {0};
	char* rstr = NULL;
//	bool rtb = false;
//	bool sleepflg = false;
//	bool tmotflg = false;
//	pid_t pidnm = 0;
//	int coreid = 0;
	char* repet=NULL;
	char* coreid=NULL;
	char* cmd = NULL;
	char* tarpro=NULL;
	char* tarcom=NULL;
	char* anaopt=NULL;
	char* sleep=NULL;
	char* timeout=NULL;
	char* nodeid=NULL;
	char* meshid=NULL;
	char* hm_id=NULL;
	char* pmu_id=NULL;
	char* c2c_id=NULL;
	char* ctrler_id=NULL;
	char* tra_switch=NULL;
	char* tpid=NULL; // target program
	char* apid=NULL;    // analys argus
//	phy_uint64_t sleept=0;
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

	char* sleept = NULL;
	int it=0;

	char **arr = NULL;
	phy_strarr_init(&arr);
	str_to_arr(msg, ";", &arr);

	char** stmp = NULL;
//	char * sline = NULL;
//	sline = phy_malloc(sline, STRING_LEN);
	int i = 0;
	cmd = (char*)phy_malloc(cmd, BUFLEN);
	memset(cmd, 0, BUFLEN);
	for (stmp = arr; NULL != *stmp; stmp++){
//		printf("%s\n", *stmp);
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

	if((tarprot != NULL && tpid != NULL) || (intarpro != NULL && tpid != NULL)){
		goto arg_err;
	}

//判断参数输入 进程号与等待时间
//tarpro，anaopt 都包含待测进程号
	if(is_number(tarpro)){
		if( (apid != NULL) ){
			goto arg_err;
		}
	}else if(is_alphanum(tarpro)){ //如果tarpro为字母和数字组合则为 sleep xxx
		if(strstr(tarpro, "sleep")){
			sleept = get_numbers(tarpro, true);
			if((sleept != NULL) && (timeout != NULL)){ //如果tarpro 为 sleep xxx 且 anaopt中有 --timeout设定
				goto arg_err;
			}
		}else{
			goto arg_err;
		}
	}
//判断性能指标组合
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


	return rstr;

err_out:
	phy_strarr_free(arr);
	phy_free(cmd);
	return NULL;

arg_err:
	phy_log(LOG_LEVEL_ERR, "[file:%s,line:%d] %s: parameter error(%s)", cfile, line, __function_name, msg);
	goto err_out;

}
#endif
