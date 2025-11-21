#include "loader.h"

extern hmap_t ldr;

char* trims(char* s) {
    char *end;
    while(isspace((unsigned char)*s)) s++;
    if(*s == 0) return s;
    end = s + strlen(s) - 1;
    while(end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return s;
}

void insertx_attributes(ddlhx *dh, ddlx *item, char *attrs) {
    char *copy_attrs = strdup(attrs);
    char *p = strtok(copy_attrs, ";");
    while(p) {
        char *attr = trims(p);
        if(strlen(attr) > 0) {
            dh->curr = item;
            ddlx_insert_brch(&dh, attr, strlen(attr)+1, 1);
        }
        p = strtok(NULL, ";");
    }
    free(copy_attrs);
}

int load_conf(const char* conf)
{
    ddlhx *dh = NULL;
    ddlx_init(&dh);

    FILE *fp = fopen(conf, "r");
    if (!fp) { perror("fopen"); return 1; }

    char line[1024];
    ddlx *section = NULL, *item = NULL;

    while (fgets(line, sizeof(line), fp)) {
        char *pline = trims(line);
        if (pline[0] == '#' || pline[0] == '\0') continue;

        if (pline[0] == '[') {
            char *p = strchr(pline, ']'); if (!p) continue;
            *p = '\0'; p = trims(pline + 1);
            ddlx_insert(&dh, p, strlen(p)+1, 1);
            section = dh->curr;
            item = NULL;
        } else if (pline[0] == '+') {
            char *p = pline + 1;//, *c = strchr(p, ':'); if (c) *c = '\0';
            p = trims(p);
            dh->curr = section;
            ddlx_insert_brch(&dh, p, strlen(p)+1, 1);
            item = section->brch;
            while (item->next) item = item->next;
        } else if (pline[0] == '-') {
            char *p = trims(pline + 1);
            if (item) insertx_attributes(dh, item, p);
        }
    }
    fclose(fp);
    ddlx *sec = dh->entr;
    while (sec) {
        printf("[%s]\n", (char*)sec->data);
        ddlx *it = sec->brch;
        while (it) {
            printf("+%s\n", (char*)it->data);
            ddlx *attr = it->brch;
            while (attr) {
                printf(" -%s\n", (char*)attr->data);
                attr = attr->next;
            }
            it = it->next;
        }
        sec = sec->next;
    }

    ddlx_destory(dh);
    return 0;
}

void load_conf_ext(const char* conf, ddlhx** dh)
{
    FILE *fp = fopen(conf, "r");
    if (!fp) { perror("fopen"); return; }

    char line[1024];
    ddlx *section = NULL, *item = NULL;

    while (fgets(line, sizeof(line), fp)) {
        char *pline = trims(line);
        if (pline[0] == '#' || pline[0] == '\0') continue;

        if (pline[0] == '[') {
            char *p = strchr(pline, ']'); if (!p) continue;
            *p = '\0'; p = trims(pline + 1);
            ddlx_insert(dh, p, strlen(p)+1, 1);
            section = (*dh)->curr;
            item = NULL;
        } else if (pline[0] == '+') {
            char *p = pline + 1;//, *c = strchr(p, ':'); if (c) *c = '\0';
            p = trims(p);
            (*dh)->curr = section;
            ddlx_insert_brch(dh, p, strlen(p)+1, 1);
            item = section->brch;
            while (item->next) item = item->next;
        } else if (pline[0] == '-') {
            char *p = trims(pline + 1);
            if (item) insertx_attributes(*dh, item, p);
        }
    }
    fclose(fp);
}

void load_tradir(const char *dirpath, ddlhx **dh)
{
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;

    if (!(dir = opendir(dirpath))) {
        perror("opendir");
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        char path[1024];
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", dirpath, entry->d_name);

        if (stat(path, &statbuf) == -1) {
            perror("stat");
            continue;
        }
        ddlx_insert(dh, path, strlen(path)+1, 1);
        if (S_ISDIR(statbuf.st_mode)) {
        	load_tradir(path, dh); // 递归遍历子目录
        }
    }
    closedir(dir);
}

void load_run_prepro(const char* add, const char* exn, const char* ver)
{
#define optpa "/opt/phytune/optim"
	char str[256] = {0};
	ddlhx* dh = NULL;
	char* enm = NULL;
	ddlx *sec = NULL;

	int rc = 0;
	char* usr = NULL;
	char* pwd = NULL;
	char* res = NULL;
	char* fre = NULL;

	ddlx_init(&dh);
	enm = (char*)get_program_name(exn);
	phy_snprintf(str, sizeof(str), "%s/%s/%s/script", optpa, enm, "pre-process");
	load_tradir(str, &dh);

	rc = physql_select(add, &usr, &pwd, &res);
	if(rc != SQLITE_OK){
		phy_log(LOG_LEVEL_ERR, "load_get_version_rmt: Cannot find info of %s.", add);
		return;
	}
	phy_free(res);

	memset(str, 0, sizeof(str));
	phy_snprintf(str, sizeof(str), "scp -rp %s/%s/%s/script %s@%s:/tmp/", optpa, enm, "pre-process", usr, add);
	forkpty_cutlines(add, usr, pwd, NULL, str, 4, &res, -1);
	phy_free(res);

	sec = ((ddlhx*)dh)->entr;
	while (sec) {
		printf("[%s]\n", (char*)sec->data);
		enm = (char*)get_program_name((char*)sec->data);
		memset(str, 0, sizeof(str));
		phy_snprintf(str, sizeof(str), "/tmp/%s/%s", "script", enm);
		forkpty_cutlines(add, usr, pwd, NULL, str, 0, &res, -1);
		fre = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
		phy_free(res);
		clean_file("/tmp/res.txt");
		writes_file("/tmp/res.txt", fre, strlen(fre));
		phy_free(fre);
		load_set_cnf(exn, "pre-process", "/tmp/res.txt");
		sec = sec->next;
	}

	phy_free(usr);
	phy_free(pwd);
	ddlx_destory(dh);
	if(ver != NULL){
		printf("%s\n", ver);
	}
#undef optpa
}


// 从 start 位置开始，查找与第一个 '(' 匹配的右括号的位置（处理嵌套的括号）
// 返回匹配的 ')' 的下标，如果找不到返回 -1
int find_matching_paren(const char *str, int start) {
    int count = 0;
    for (int i = start; str[i] != '\0'; i++) {
        if (str[i] == '(') {
            count++;
        } else if (str[i] == ')') {
            count--;
            if (count == 0)
                return i;
        }
    }
    return -1;
}

// 将字符串 str 按逗号切分，但忽略在小括号和中括号内的逗号
// 返回一个字符串数组，*count 返回分得的子串个数
char** split_fields(const char* str, int* count) {
    int capacity = 10;
    char** tokens = malloc(sizeof(char*) * capacity);
    int token_count = 0;

    const char* start = str;
    int paren_depth = 0, bracket_depth = 0;
    for (const char *p = str; ; p++) {
        char c = *p;
        if ( (c == ',' && paren_depth == 0 && bracket_depth == 0) || c == '\0') {
            int len = p - start;
            // 去掉前后空白字符
            while(len > 0 && isspace((unsigned char)*start)) {
                start++;
                len--;
            }
            while(len > 0 && isspace((unsigned char)start[len-1]))
                len--;
            char *token = malloc(len + 1);
            strncpy(token, start, len);
            token[len] = '\0';
            tokens[token_count++] = token;
            if (token_count >= capacity) {
                capacity *= 2;
                tokens = realloc(tokens, sizeof(char*) * capacity);
            }
            if (c == '\0')
                break;
            start = p + 1;
        } else {
            if (c == '(') {
                paren_depth++;
            } else if (c == ')') {
                if (paren_depth > 0)
                    paren_depth--;
            } else if (c == '[') {
                bracket_depth++;
            } else if (c == ']') {
                if (bracket_depth > 0)
                    bracket_depth--;
            }
        }
    }
    *count = token_count;
    return tokens;
}

void app_mnod(ddlhx *dh, ddlx *node) {
    if (!dh->tail) {
        dh->entr = node;
        dh->tail = node;
        dh->curr = node;
        dh->pos = node;
        dh->num = 1;
    } else {
        dh->tail->next = node;
        node->prev = dh->tail;
        dh->tail = node;
        dh->curr = node;
        dh->num++;
    }
}

void app_chld(ddlx *parent, ddlx *node) {
    if (!parent) return;
    if (parent->brch == NULL) {
        parent->brch = node;
    } else {
        ddlx *p = parent->brch;
        while (p->next)
            p = p->next;
        p->next = node;
        node->prev = p;
    }
}

ddlx* crte_node(const char* data) {
    ddlx* node = (ddlx*)malloc(sizeof(ddlx));
    if (!node) return NULL;
    memset(node, 0, sizeof(ddlx));
    size_t len = strlen(data) + 1;
    node->data = malloc(len);
    if (!node->data) {
        free(node);
        return NULL;
    }
    memcpy(node->data, data, len);
    node->dln = len;
    return node;
}

void parse_message_into_ddlhx(const char *msg, ddlhx *dh)
{
    // 按 ';' 分割主链部分
    char *msg_copy = strdup(msg);
    char *segment = strtok(msg_copy, ";");
    while (segment) {
        // 忽略空白串
        while(isspace((unsigned char)*segment)) segment++;

        char *colon = strchr(segment, ':');
        if (!colon) {
            // 格式错误，跳过
            segment = strtok(NULL, ";");
            continue;
        }
        *colon = '\0';
        char *main_key = segment;
        char *sidelist = colon + 1;  // 后面是侧链部分

        while(isspace((unsigned char)*main_key)) main_key++;
        char *end = main_key + strlen(main_key) - 1;
        while(end > main_key && isspace((unsigned char)*end)) { *end = '\0'; end--; }

        ddlx *main_node = crte_node(main_key);
        app_mnod(dh, main_node);

        const char *p = sidelist;
        while (*p) {
            if (*p != '(') {
                p++;
                continue;
            }
            int start_idx = p - sidelist;  // 当前 '(' 的下标
            int end_idx = find_matching_paren(sidelist, start_idx);
            if (end_idx == -1) break;  // 匹配错误则退出

            int token_len = end_idx - start_idx - 1;
            char *side_token = malloc(token_len + 1);
            strncpy(side_token, p + 1, token_len);
            side_token[token_len] = '\0';

            int field_count = 0;
            char **fields = split_fields(side_token, &field_count);
            free(side_token);

            if (field_count < 1) {
                for (int i = 0; i < field_count; i++) free(fields[i]);
                free(fields);
                p = sidelist + end_idx + 1;
                continue;
            }

            ddlx *side_node = crte_node(fields[0]);
            app_chld(main_node, side_node);

            for (int i = 1; i < field_count; i++) {
                ddlx *branch_node = crte_node(fields[i]);
                app_chld(side_node, branch_node);
            }
            // 释放 fields 数组
            for (int i = 0; i < field_count; i++) {
                free(fields[i]);
            }
            free(fields);
            p = sidelist + end_idx + 1;
        }
        segment = strtok(NULL, ";");
    }
    free(msg_copy);
}

void print_ddlx_tree(ddlx *node, int level) {
    if (!node) return;
    for (int i = 0; i < level; i++) printf("  ");
    printf("-> %s\n", (char*)node->data);
    if (node->brch) {
        print_ddlx_tree(node->brch, level + 1);
    }
    print_ddlx_tree(node->next, level);
}

void print_ddlx_tree_pls(ddlx *node, int level)
{
    (void)level;
    if (node == NULL)
        return;

    for (ddlx *main_node = node; main_node != NULL; main_node = main_node->next) {
        char *main_str = (char *)main_node->data;
        for (ddlx *side_node = main_node->brch; side_node != NULL; side_node = side_node->next) {
            char *side_str = (char *)side_node->data;
            for (ddlx *leaf = side_node->brch; leaf != NULL; leaf = leaf->next) {
                char *leaf_str = (char *)leaf->data;
                printf("%s->%s->%s\n", main_str, side_str, leaf_str);
            }
        }
    }
}

void extract_str(ddlhx* dh, const char* m, const char* b, int i, char** val)
{
    // 初步校验
    if (!dh || !m || !b || !val || i < 1) {
        if (val)
            *val = NULL;
        return;
    }
    *val = NULL;

    // 1. 遍历主链节点，查找 data 与 m 相等的主链节点
    ddlx* mnod = dh->entr;
    while (mnod) {
        if (strcmp((char*)mnod->data, m) == 0)
            break;
        mnod = mnod->next;
    }
    if (!mnod) {
    	*val = NULL;
        // 未找到主链节点
        return;
    }

    // 2. 在主链节点中，遍历其侧链节点，查找 data 与 b 相等的侧链节点
    ddlx* bnod = mnod->brch;
    while (bnod) {
        if (strcmp((char*)bnod->data, b) == 0)
            break;
        bnod = bnod->next;
    }
    if (!bnod) {
    	*val = NULL;
        // 未找到侧链节点
        return;
    }

    // 3. 在侧链节点的子链中找第 i 个节点（支链节点）
    ddlx* chl = bnod->brch;
    int count = 1;
    while(chl && count < i) {
        chl = chl->next;
        count++;
    }
    if (chl && count == i) {
        *val = (char*)chl->data;
    }
}

void extract_ddlxi(ddlx* dl, int i, char** val)
{
    ddlx* chl = dl->brch;
    int count = 1;

    while(chl && count < i) {
//    	printf("%s\n", (char*)chl->data);
        chl = chl->next;
        count++;
    }

//    while(chl) {
//    	printf("%s\n", (char*)chl->data);
//        chl = chl->next;
//    }

    if (chl && count == i) {
        *val = (char*)chl->data;
    }
}

void extract_ddlxb(ddlhx* dh, const char* m, const char* b, ddlx** dl)
{
 // 1. 遍历主链节点，查找 data 与 m 相等的主链节点
    ddlx* mnod = dh->entr;
    while (mnod) {
        if (strcmp((char*)mnod->data, m) == 0)
            break;
        mnod = mnod->next;
    }
    if (!mnod) {
    	*dl = NULL;
        // 未找到主链节点
        return;
    }

    // 2. 在主链节点中，遍历其侧链节点，查找 data 与 b 相等的侧链节点
    ddlx* bnod = mnod->brch;
    while (bnod) {
        if (strcmp((char*)bnod->data, b) == 0)
            break;
        bnod = bnod->next;
    }
    if (!bnod) {
    	*dl = NULL;
        // 未找到侧链节点
        return;
    }
    *dl = bnod;
}

void extract_ddlxm(ddlhx* dh, const char* m, ddlx** dl)
{
//遍历主链节点，查找 data 与 m 相等的主链节点
    ddlx* mnod = dh->entr;
    while (mnod) {
        if (strcmp((char*)mnod->data, m) == 0)
            break;
        mnod = mnod->next;
    }
    if (!mnod) {
    	dl = NULL;
        // 未找到主链节点
        return;
    }
    *dl = mnod;
}

char* cstru_res_cont(const char* arg, const char* env, const char* cnf, const char* sot)
{
#define res_arch "\n\n		入 参：	\n\t\t\t\t\t\targ\n\n		环 境：	\n\t\t\t\t\t\tenv\n\n		配 置：	\n\t\t\t\t\t\tcnf\n\n		输 出：	\nout\n\n"
	char* rep = NULL;
	char* reb = NULL;
	char* fso = NULL;
	fso = string_replace(sot, "\n", "\t\t\t\t\t\t");
	rep = string_replace(res_arch, "arg", arg);
	reb = string_replace(rep, "env", env);
	phy_free(rep);
	rep = string_replace(reb, "cnf", cnf);
	phy_free(reb);
	reb = string_replace(rep, "out", fso);
	phy_free(rep);
	phy_free(fso);
#undef res_arch
	return reb;
}

void gen_res(const char* cnt, const char* add, const char* emn, const char* ver, const char* dte, bool flg, char** rsp)
{
#define optpa "/opt/phytune/optim"
#define tuned "run/tuned/tuned_results"
#define untun "run/untuned/results"

	char str[256] = {0};
	char rnm[256] = {0};
	char rpt[512] = {0};
	if(flg == true){
		phy_snprintf(str, sizeof(str), "%s/%s/%s", optpa, emn, tuned);
		phy_snprintf(rnm, sizeof(rnm), "%s_%s-%s:tuned_%s.res", add, emn, ver, dte);
	}else{
		phy_snprintf(str, sizeof(str), "%s/%s/%s", optpa, emn, untun);
		phy_snprintf(rnm, sizeof(rnm), "%s_%s-%s-untuned_%s.res", add, emn, ver, dte);
	}

	phy_snprintf(rpt, sizeof(rpt), "%s/%s", str, rnm);
	*rsp = strdup(rpt);
	write_file(rpt, cnt);
#undef optpa
#undef tuned
#undef untun
}
const char* uns[7] = {"h", "m", "s", "GB", "MB", "KB", "0"};
int dat[3] = {1, 2, 3}; //数字、字符串、带单位
void  load_run(const char* add, const char* dte, const char* msg, bool flg)
{
	ddlhx *dh = NULL;
	ddlx *dl = NULL;
	int rc = 0;
	int iut = 0;
	char* val = NULL;
	char* unt = NULL;
	char* usr = NULL;
	char* pwd = NULL;
	char* res = NULL;
	char* fre = NULL;
	char* ver = NULL;
	char* exm = NULL;
	char* fln = NULL;

	char cmd[256] = {0};
	char str[256] = {0};
	char env[256] = {0};
	char cnf[256] = {0};

	ddlx_init(&dh);
	parse_message_into_ddlhx(msg, dh);
	printf("解析后的链表结构：\n");
	extract_str(dh, "软件信息", "路径", 1, &val);
	phy_snprintf(str, sizeof(str), "%s ", val);
	exm = strdup(val);
	extract_str(dh, "软件信息", "版本", 1, &val);
	ver = strdup(val);
//	extract_ddlxb(dh, "参数列表", "路径", &dl);
	extract_ddlxm(dh, "参数列表",  &dl);

	phy_log(LOG_LEVEL_TRACE, "[[[load_run: msg %s.", msg);
	rc = physql_select(add, &usr, &pwd, &res);
	if(rc != SQLITE_OK){
		phy_log(LOG_LEVEL_ERR, "load_run: Cannot find info of %s.", add);
		return;
	}
	phy_free(res);

	ddlx *sec = dl->brch;
	while (sec) {
		strcat(str, "--");
		printf("[%s]\n", (char*)sec->data);
		extract_ddlxi(sec, 2, &val);
		iut = atoi(val);
		if(iut == 3){
			extract_ddlxi(sec, 4, &val);
			iut = atoi(val);
			extract_ddlxi(sec, 1, &val);
			printf("[%s]\n", val);
			strcat(str, (char*)sec->data);
			strcat(str, "=");
			strcat(str, val);
			strcat(str, uns[iut-1]);
			strcat(str, " ");
		}else{
			extract_ddlxi(sec, 1, &val);
			printf("[%s]\n", val);
			strcat(str, (char*)sec->data);
			strcat(str, "=");
			strcat(str, val);
			strcat(str, " ");
		}
		sec = sec->next;
	}

	extract_ddlxm(dh, "环境检查",  &dl);

	sec = dl->brch;
	while (sec) {
		printf("[%s]\n", (char*)sec->data);
		extract_ddlxi(sec, 2, &val);
		extract_ddlxi(sec, 4, &unt);
		extract_ddlxi(sec, 1, &val);
		printf("[%s]\n", val);
		strcat(env, (char*)sec->data);
		strcat(env, ":");
		strcat(env, val);
		strcat(env, " ");
		sec = sec->next;
	}

	ddlx_destory(dh);
	ddlx_init(&dh);
	load_conf_extp(exm, ver, "pre-process", &dh);
	extract_ddlxm(dh, "系统资源",  &dl);

	sec = dl->brch;
	while (sec) {
		printf("[%s]\n", (char*)sec->data);

		extract_ddlxi(sec, 2, &val);
		res = get_str_between_two_words(val, "=", NULL);
		printf("[%s]\n", res);
		if(res == NULL){
			goto out;
		}
		strcat(cnf, (char*)sec->data);
		strcat(cnf, ":");
		strcat(cnf, res);
		strcat(cnf, " ");
		sec = sec->next;
		phy_free(res);
	}

	memset(cmd, 0, sizeof(cmd));
	phy_snprintf(cmd, sizeof(cmd), "ls -l %s", exm);
	forkpty_cutlines(add, usr, pwd, NULL, cmd, 0, &res, -1);
	fre = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(NULL != strstr(fre, "No such file or directory") || NULL != strstr(fre, "没有那个文件或目录")){
		send_message(MESS, ERROR, RUN, "输入的fio文件不存在！");
		goto out;
	}
	phy_free(res);
	phy_free(fre);

	fln = get_str_between_two_words(str, "filename=", " ");
	if(fln == NULL){
		send_message(MESS, ERROR, RUN, "参数文件未设置！");
		goto out;
	}else{
		memset(cmd, 0, sizeof(cmd));
		phy_snprintf(cmd, sizeof(cmd), "ls -l %s", fln);
		forkpty_cutlines(add, usr, pwd, NULL, cmd, 0, &res, -1);
		fre = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
		if(NULL != strstr(fre, "No such file or directory") || NULL != strstr(fre, "没有那个文件或目录")){
			send_message(MESS, ERROR, RUN, "参数文件不存在！");
			goto out;
		}
	}
	phy_free(res);
	phy_free(fre);
	phy_free(fln);

	forkpty_cutlines(add, usr, pwd, NULL, str, 0, &res, -1);
	fre = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	phy_free(res);

	res = cstru_res_cont(str, env, cnf, fre);
	phy_free(fre);
	gen_res(res, add, get_program_name(exm), ver, dte, flg, &fre);
	send_message(OPTIM, RESULT, OPTIM, fre);
out:
	phy_free(exm);
	phy_free(res);
	phy_free(usr);
	phy_free(pwd);
	phy_free(ver);
	phy_free(fre);
	// 释放内存
	ddlx_destory(dh);
}

static int free_elem(void* elem, void *arg) {
  userelem *el = (userelem *) elem;
  free(el->value);
  free(el);
  return 0;
}

//int free_data(void* data, void *arg)
//{
//  userdata *dat = (userdata *) data;
//  /* 删除整个子 map */
//  hashmap_destroy(dat->map, free_elem, 0);
//  free(dat);
//  return 0;
//}

void  load_runt(const char* add, const char* dte, const char* msg, bool flg)
{
#define optpa "/opt/phytune/optim"

	ddlhx *dh = NULL;
	ddlx *dl = NULL;
	int rc = 0;
	int iut = 0;
	char* val = NULL;
	char* unt = NULL;
	char* usr = NULL;
	char* pwd = NULL;
	char* res = NULL;
	char* fre = NULL;
	char* ver = NULL;
	char* exm = NULL;

	char* fln = NULL;
	char* tsh = NULL;
	char cmd[256] = {0};
	char str[512] = {0};
	char env[256] = {0};
	char cnf[256] = {0};

	ddlx_init(&dh);
	parse_message_into_ddlhx(msg, dh);
	printf("解析后的链表结构：\n");
	extract_str(dh, "软件信息", "路径", 1, &val);

	exm = strdup(val);
	load_getexe_pls(optpa, (char*)get_program_name(exm), "run", "fio-optimize.sh", &tsh);
	phy_snprintf(str, sizeof(str), "/tmp/%s \"%s ", "fio-optimize.sh", val);

	extract_str(dh, "软件信息", "版本", 1, &val);
	ver = strdup(val);
//	extract_ddlxb(dh, "参数列表", "路径", &dl);
	extract_ddlxm(dh, "参数列表",  &dl);

	rc = physql_select(add, &usr, &pwd, &res);
	if(rc != SQLITE_OK){
		phy_log(LOG_LEVEL_ERR, "load_runt: Cannot find info of %s.", add);
		return;
	}
	phy_free(res);

	ddlx *sec = dl->brch;
	while (sec) {
		strcat(str, "--");
		printf("[%s]\n", (char*)sec->data);
		extract_ddlxi(sec, 2, &val);
		iut = atoi(val);
		if(iut == 3){
			extract_ddlxi(sec, 4, &val);
			iut = atoi(val);
			extract_ddlxi(sec, 1, &val);
			printf("[%s]\n", val);
			strcat(str, (char*)sec->data);
			strcat(str, "=");
			strcat(str, val);
			strcat(str, uns[iut-1]);
			if(sec->next == NULL){
				strcat(str, "\"");
			}
			strcat(str, " ");
		}else{
			extract_ddlxi(sec, 1, &val);
			printf("[%s]\n", val);
			strcat(str, (char*)sec->data);
			strcat(str, "=");
			strcat(str, val);
			if(sec->next == NULL){
				strcat(str, "\"");
			}
			strcat(str, " ");
		}
		sec = sec->next;
	}

	extract_ddlxm(dh, "环境检查",  &dl);

	sec = dl->brch;
	while (sec) {
		printf("[%s]\n", (char*)sec->data);
		extract_ddlxi(sec, 2, &val);
		extract_ddlxi(sec, 4, &unt);
		extract_ddlxi(sec, 1, &val);
		printf("[%s]\n", val);
		strcat(env, (char*)sec->data);
		strcat(env, ":");
		strcat(env, val);
		strcat(env, " ");
		sec = sec->next;
	}

	ddlx_destory(dh);
	ddlx_init(&dh);
	load_conf_extp(exm, ver, "pre-process", &dh);
	extract_ddlxm(dh, "系统资源",  &dl);

	sec = dl->brch;
	while (sec) {
		printf("[%s]\n", (char*)sec->data);

		extract_ddlxi(sec, 2, &val);
		res = get_str_between_two_words(val, "=", NULL);
		printf("[%s]\n", res);
		if(res == NULL){
			goto out;
		}
		strcat(cnf, (char*)sec->data);
		strcat(cnf, ":");
		strcat(cnf, res);
		strcat(cnf, " ");
		sec = sec->next;
		phy_free(res);
	}

	phy_snprintf(cmd, sizeof(cmd), "scp -rp %s %s@%s:/tmp/", tsh, usr, add);
	forkpty_cutlines(add, usr, pwd, NULL, cmd, 4, &res, -1);
	phy_free(tsh);
	phy_free(res);

	memset(cmd, 0, sizeof(cmd));
	phy_snprintf(cmd, sizeof(cmd), "ls -l %s", exm);
	forkpty_cutlines(add, usr, pwd, NULL, cmd, 0, &res, -1);
	fre = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	if(NULL != strstr(fre, "No such file or directory") || NULL != strstr(fre, "没有那个文件或目录")){
		send_message(MESS, ERROR, RUN, "输入的fio文件不存在！");
		goto out;
	}
	phy_free(res);
	phy_free(fre);

	fln = get_str_between_two_words(str, "filename=", " ");
	if(fln == NULL){
		send_message(MESS, ERROR, RUN, "参数文件未设置！");
		goto out;
	}else{
		memset(cmd, 0, sizeof(cmd));
		phy_snprintf(cmd, sizeof(cmd), "ls -l %s", fln);
		forkpty_cutlines(add, usr, pwd, NULL, cmd, 0, &res, -1);
		fre = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
		if(NULL != strstr(fre, "No such file or directory") || NULL != strstr(fre, "没有那个文件或目录")){
			send_message(MESS, ERROR, RUN, "参数文件不存在！");
			goto out;
		}
	}

	phy_free(res);
	phy_free(fre);
	phy_free(fln);

	forkpty_cutlines(add, usr, pwd, NULL, str, 0, &res, -1);
	fre = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	phy_free(res);

	res = cstru_res_cont(str, env, cnf, fre);
	phy_free(fre);
	gen_res(res, add, get_program_name(exm), ver, dte, flg, &fre);
	send_message(OPTIM, RESULT, OPTIM, fre);
out:
	phy_free(exm);
	phy_free(res);
	phy_free(usr);
	phy_free(pwd);
	phy_free(ver);
	phy_free(fre);
	// 释放内存
	ddlx_destory(dh);
}

void load_conf_extp(const char* exn, const char* ver, const char* itm, ddlhx** dh)
{
#define optpa "/opt/phytune/optim"
#define dpcnf "config.cnf"
	//"deploy.cnf"
	char* pth = NULL;
	char* enm = NULL;
	enm = (char*)get_program_name(exn);
	load_getexe_pls(optpa, enm, itm, dpcnf, &pth);
	load_conf_ext(pth, dh);
	phy_free(pth);
	if(ver != NULL){
		printf("%s\n", ver);
	}
#undef optpa
#undef dpcnf
}

/* 软件信息:(I/O深度,10,1,[1-10],0,4),(I/O深度,10,1,[1-10],0,4);*/
void load_mes(ddlhx* dh, mesopt ofl)
{
//消息子项 子项名,内容,类型,范围,单位,控件类型
#define mesitm "(sitm,data,dtp,rang,unit,wtp)"
//消息体
#define mesbdy "item1:mesitm1,mesitm2;item2:mesitm1,mesitm2..."
//消息子项连接符号
#define sitmcs ","
//消息主项连接符号
#define itemcs ";"
	int flg = 0;
	char* strb = NULL;
	char* strd = NULL;
	char* strq = NULL;
	char* strp  = NULL;
	char *optmes = NULL;
	ddlx *sec = ((ddlhx*)dh)->entr;
	while (sec) {
		strp = buy_some_mem(strp, (char*)sec->data);
		strp = buy_some_mem(strp, ":");
		ddlx *it = sec->brch;
		while (it) {
			ddlx *attr = it->brch;
			while (attr) {
				switch(flg){
				case 0:
					strb = get_str_between_two_words((char*)attr->data, "=", NULL);
					strd = string_replace(mesitm, "sitm", strb);
					phy_free(strb);
				flg++;
				break;
				case 1:
					strq = get_str_between_two_words((char*)attr->data, "=", NULL);
					strb = string_replace(strd, "data", strq);
					phy_free(strd);
					phy_free(strq);
				flg++;
				break;
				case 2:
					strd = get_str_between_two_words((char*)attr->data, "=", NULL);
					strq = string_replace(strb, "dtp", strd);
					phy_free(strb);
					phy_free(strd);
				flg++;
				break;
				case 3:
					strb = get_str_between_two_words((char*)attr->data, "=", NULL);
					strd = string_replace(strq, "rang", strb);
					phy_free(strb);
					phy_free(strq);
				flg++;
				break;
				case 4:
					strq = get_str_between_two_words((char*)attr->data, "=", NULL);
					strb = string_replace(strd, "unit", strq);
					phy_free(strd);
					phy_free(strq);
				flg++;
				break;
				case 5:
					strd = get_str_between_two_words((char*)attr->data, "=", NULL);
					strq = string_replace(strb, "wtp", strd);
					phy_free(strb);
					phy_free(strd);
					flg = 0;
				break;
				}
				attr = attr->next;
			}
			strp = buy_some_mem(strp, strq);
			phy_free(strq);
			strp = buy_some_mem(strp, sitmcs);
			it = it->next;
		}
		strp = buy_some_mem(strp, itemcs);
		sec = sec->next;
	}
	optmes = string_replace(strp, ",;", ";");
	phy_free(strp);
	send_message(OPTIM, ofl, OPTIM, optmes);
	phy_log(LOG_LEVEL_TRACE, "$$$ %s", optmes);
	phy_free(optmes);
}

void load_deploy_data(const char* exnm, const char* ver, const char* env, ddlhx** dh)
{
	ddlx *sec = ((ddlhx*)dh)->entr;
	while (sec) {
		ddlx *it = sec->brch;
		while (it) {
			ddlx *attr = it->brch;
			while (attr) {
				attr = attr->next;
			}
			it = it->next;
		}
		sec = sec->next;
	}
	if(env != NULL){
		printf("%s\n", env);
	}
	if(ver != NULL){
		printf("%s\n", ver);
	}
	if(exnm != NULL){
		printf("%s\n", exnm);
	}

}

//void load_deploy_mes(const char* ver, const char* env, const)
//{
//
//}

void load_getexe_ext(const char* dir, const char* exn, const char* ver, const char* fnm, char** pth)
{
	int ret;
	char str[256] = {0};
	userdata  *dat;
	userelem  *el;
	ddlhx *dh = NULL;
    ddlx *sct = NULL;


	phy_snprintf(str, sizeof(str), "%s/%s/%s", dir, exn, ver);
	ldr = hashmap_create();
	ddlx_init(&dh);
	load_fils(str, &dh);

    sct = dh->entr;

	while(sct)
	{
		el = (userelem *)malloc(sizeof(userelem));
		memset(el, 0, sizeof(userelem));
		phy_snprintf(el->key, 128, "%s", get_file_name(((char*)(sct->data))));

		dat = (userdata *)malloc(sizeof(userdata));
		memset(dat, 0, sizeof(userdata));
		/* 创建子 hashmap */
		dat->map = hashmap_create();

		el->value = (char*) phy_malloc(el->value, strlen(((char*)(sct->data))) + 1);
		phy_snprintf(el->value, strlen(((char*)(sct->data))) + 1, "%s", ((char*)(sct->data)));
		ret = hashmap_put(dat->map, el->key, el);
		if(ret!=HMAP_S_OK){
			goto mapputkey_err;
		}

		phy_snprintf(dat->name, 128, "%s", el->key);
		ret = hashmap_put(ldr, dat->name, dat);
		if(ret!=HMAP_S_OK){
			goto mapputsub_err;
		}
		sct = sct->next;
	}

	ret = hashmap_get(ldr, fnm, (void_ptr *)&dat);
	if(ret==HMAP_S_OK)
	{
		memset(str, 0, sizeof(str));
		hashmap_iterate(dat->map, iter_elem, str);
		*pth = (char*) phy_malloc(*pth, strlen(str) + 1);
		memset(*pth, 0, strlen(str) + 1);
		phy_snprintf(*pth, strlen(str) + 1, "%s", str);
	}else{
		goto mapget_err;
	}

out:
#undef optpa
	hashmap_destroy(ldr, free_data, 0);
	ddlx_destory(dh);
	return;
mapputkey_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map put key: %s error.", el->key);
	goto out;
mapputsub_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map put sub: %s error.", dat->name);
	goto out;
mapget_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map get: %s error.", fnm);
	goto out;

}

void load_getexe_plx(const char* mdir, const char* enm, const char* ver, const char* fnm, char** pth)
{
	char str[256]= {0};
	userdata  *dat;
	userelem  *el;
	ddlhx *dh = NULL;
	ddlx *sct = NULL;

	int ret;

	ldr = hashmap_create();
	ddlx_init(&dh);
	phy_snprintf(str, sizeof(str), "%s/%s/%s", mdir, enm, ver);
	load_fils(str, &dh);

	sct = dh->entr;

	while(sct)
	{
		el = (userelem *)malloc(sizeof(userelem));
		memset(el, 0, sizeof(userelem));
		phy_snprintf(el->key, 128, "%s", get_file_name(((char*)(sct->data))));

		dat = (userdata *)malloc(sizeof(userdata));
		memset(dat, 0, sizeof(userdata));
		/* 创建子 hashmap */
		dat->map = hashmap_create();

		el->value = (char*) phy_malloc(el->value, strlen(((char*)(sct->data))) + 1);
		phy_snprintf(el->value, strlen(((char*)(sct->data))) + 1, "%s", ((char*)(sct->data)));
		ret = hashmap_put(dat->map, el->key, el);
		if(ret!=HMAP_S_OK){
			goto mapputkey_err;
		}

		phy_snprintf(dat->name, 128, "%s", el->key);
		ret = hashmap_put(ldr, dat->name, dat);
		if(ret!=HMAP_S_OK){
			goto mapputsub_err;
		}
		sct = sct->next;
	}

	ret = hashmap_get(ldr, fnm, (void_ptr *)&dat);
	if(ret==HMAP_S_OK)
	{
		memset(str, 0, sizeof(str));
		hashmap_iterate(dat->map, iter_elem, str);
		*pth = (char*) phy_malloc(*pth, strlen(str) + 1);
		memset(*pth, 0, strlen(str) + 1);
		phy_snprintf(*pth, strlen(str) + 1, "%s", str);
	}else{
		goto mapget_err;
	}

out:
	hashmap_destroy(ldr, free_data, 0);
	ddlx_destory(dh);
	return;
mapputkey_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map put key: %s error.", el->key);
	goto out;
mapputsub_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map put sub: %s error.", dat->name);
	goto out;
mapget_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map get: %s error.", fnm);
	goto out;
}

void load_getexe_pls(const char* dir, const char* exn, const char* itm, const char* fnm, char** pth)
{
	char str[256]= {0};

	userdata  *dat;
	userelem  *el;
	ddlhx *dh = NULL;
    ddlx *sct = NULL;

	int ret;

	ldr = hashmap_create();
	ddlx_init(&dh);
	phy_snprintf(str, sizeof(str), "%s/%s/%s", dir, exn, itm);
	load_fils(str, &dh);

    sct = dh->entr;

	while(sct)
	{
		el = (userelem *)malloc(sizeof(userelem));
		memset(el, 0, sizeof(userelem));
		phy_snprintf(el->key, 128, "%s", get_file_name(((char*)(sct->data))));

		dat = (userdata *)malloc(sizeof(userdata));
		memset(dat, 0, sizeof(userdata));
		/* 创建子 hashmap */
		dat->map = hashmap_create();

		el->value = (char*) phy_malloc(el->value, strlen(((char*)(sct->data))) + 1);
		phy_snprintf(el->value, strlen(((char*)(sct->data))) + 1, "%s", ((char*)(sct->data)));
		ret = hashmap_put(dat->map, el->key, el);
		if(ret!=HMAP_S_OK){
			goto mapputkey_err;
		}

		phy_snprintf(dat->name, 128, "%s", el->key);
		ret = hashmap_put(ldr, dat->name, dat);
		if(ret!=HMAP_S_OK){
			goto mapputsub_err;
		}
		sct = sct->next;
	}

	ret = hashmap_get(ldr, fnm, (void_ptr *)&dat);
	if(ret==HMAP_S_OK)
	{
		memset(str, 0, sizeof(str));
		hashmap_iterate(dat->map, iter_elem, str);
		*pth = (char*) phy_malloc(*pth, strlen(str) + 1);
		memset(*pth, 0, strlen(str) + 1);
		phy_snprintf(*pth, strlen(str) + 1, "%s", str);
	}else{
		goto mapget_err;
	}

out:
	hashmap_destroy(ldr, free_data, 0);
	ddlx_destory(dh);
	return;
mapputkey_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map put key: %s error.", el->key);
	goto out;
mapputsub_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map put sub: %s error.", dat->name);
	goto out;
mapget_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map get: %s error.", fnm);
	goto out;
}

void load_getexe(const char* name, char** pth)
{
#define optpa "/opt/phytune/optim"
	char tistr[PHRASE]= {0};

	userdata  *dat;
	userelem  *el;
	ddlhx *dh = NULL;
    ddlx *sct = NULL;

	int ret;

	ldr = hashmap_create();
	ddlx_init(&dh);
	load_fils(optpa, &dh);

    sct = dh->entr;

	while(sct)
	{
		el = (userelem *)malloc(sizeof(userelem));
		memset(el, 0, sizeof(userelem));
		phy_snprintf(el->key, 128, "%s", get_file_name(((char*)(sct->data))));

		dat = (userdata *)malloc(sizeof(userdata));
		memset(dat, 0, sizeof(userdata));
		/* 创建子 hashmap */
		dat->map = hashmap_create();

		el->value = (char*) phy_malloc(el->value, strlen(((char*)(sct->data))) + 1);
		phy_snprintf(el->value, strlen(((char*)(sct->data))) + 1, "%s", ((char*)(sct->data)));
		ret = hashmap_put(dat->map, el->key, el);
		if(ret!=HMAP_S_OK){
			goto mapputkey_err;
		}

		phy_snprintf(dat->name, 128, "%s", el->key);
		ret = hashmap_put(ldr, dat->name, dat);
		if(ret!=HMAP_S_OK){
			goto mapputsub_err;
		}
		sct = sct->next;
	}

	ret = hashmap_get(ldr, name, (void_ptr *)&dat);
	if(ret==HMAP_S_OK)
	{
		memset(tistr, 0, PHRASE);
		hashmap_iterate(dat->map, iter_elem, tistr);
		*pth = (char*) phy_malloc(*pth, strlen(tistr) + 1);
		memset(*pth, 0, strlen(tistr) + 1);
		phy_snprintf(*pth, strlen(tistr) + 1, "%s", tistr);
	}else{
		goto mapget_err;
	}

out:
#undef optpa
	hashmap_destroy(ldr, free_data, 0);
	ddlx_destory(dh);
	return;
mapputkey_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map put key: %s error.", el->key);
	goto out;
mapputsub_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map put sub: %s error.", dat->name);
	goto out;
mapget_err:
	phy_log(LOG_LEVEL_ERR, "load_filpath:  map get: %s error.", name);
	goto out;
}

typedef struct kpair{
	char key[20];
	char ipt[20];
}kpair;


void load_get_deps_rmt(const char* add, const char* exn, char** mes)
{
#define optdir "/opt/phytune/optim"
#define fildep "get_deps.sh"

	int rc = 0;
	char* usr = NULL;
	char* pwd = NULL;
	char* res = NULL;
	char* fre = NULL;
	char* enm = NULL;
	char str[256] = {0};
	enm = (char*)get_program_name(exn);
	rc = physql_select(add, &usr, &pwd, &res);
	if(rc != SQLITE_OK){
		phy_log(LOG_LEVEL_ERR, "load_get_version_rmt: Cannot find info of %s.", add);
		return;
	}
	phy_free(res);

	load_getexe_pls(optdir, enm, "deploy", fildep, &res);
	if(res == NULL){
		phy_log(LOG_LEVEL_ERR, "load_get_version_rmt: Unable to find %s file.", fildep);
		return;
	}

	memset(str, 0, sizeof(str));
	phy_snprintf(str, sizeof(str), "scp -p %s %s@%s:/tmp/", res, usr, add);
	phy_free(res);
	forkpty_cutlines(add, usr, pwd, NULL, str, 4, &res, -1);
	phy_free(res);

	memset(str, 0, sizeof(str));
	phy_snprintf(str, sizeof(str), "/tmp/%s %s", fildep);
	forkpty_cutlines(add, usr, pwd, NULL, str, 0, &res, -1);

	fre = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	phy_free(res);
	*mes = strdup(trims(fre));

	memset(str, 0, sizeof(str));
	phy_snprintf(str, sizeof(str), "rm -rf /tmp/%s", fildep);
	forkpty_cutlines(add, usr, pwd, NULL, str, 0, &res, -1);
	phy_free(res);
	phy_free(fre);
	phy_free(usr);
	phy_free(pwd);

#undef optdir
#undef fildep
}

void load_get_envinfo_rmt(const char* add, const char* exn, char** inf)
{
#define optdir "/opt/phytune/optim"
#define filenv "get_envinfo.sh"

	int rc = 0;
	char* usr = NULL;
	char* pwd = NULL;
	char* res = NULL;
	char* fre = NULL;
	char* enm = NULL;
	char str[256] = {0};
	enm = (char*)get_program_name(exn);
	rc = physql_select(add, &usr, &pwd, &res);
	if(rc != SQLITE_OK){
		phy_log(LOG_LEVEL_ERR, "load_get_version_rmt: Cannot find info of %s.", add);
		return;
	}
	phy_free(res);

	load_getexe_pls(optdir, enm, "deploy", filenv, &res);
	if(res == NULL){
		phy_log(LOG_LEVEL_ERR, "load_get_version_rmt: Unable to find %s file.", filenv);
		return;
	}

	memset(str, 0, sizeof(str));
	phy_snprintf(str, sizeof(str), "scp -p %s %s@%s:/tmp/", res, usr, add);
	phy_free(res);
	forkpty_cutlines(add, usr, pwd, NULL, str, 4, &res, -1);
	phy_free(res);

	memset(str, 0, sizeof(str));
	phy_snprintf(str, sizeof(str), "/tmp/%s %s", filenv);
	forkpty_cutlines(add, usr, pwd, NULL, str, 0, &res, -1);

	fre = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	phy_free(res);
	*inf = strdup(trims(fre));

	memset(str, 0, sizeof(str));
	phy_snprintf(str, sizeof(str), "rm -rf /tmp/%s", filenv);
	forkpty_cutlines(add, usr, pwd, NULL, str, 0, &res, -1);
	phy_free(res);
	phy_free(fre);
	phy_free(usr);
	phy_free(pwd);

#undef optdir
#undef filver
}

void load_set_cnf(const char* exn, const char* itm, const char* cntpth)
{
#define optdir "/opt/phytune/optim"
#define filcnf "config.cnf"
#define filset "set_cnf.sh"
	char* enm = NULL;
	char* res = NULL;
	char str[256] = {0};
	enm = (char*)get_program_name(exn);
	load_getexe_pls(optdir, enm, itm, filset, &res);
	strncat(str, res, strlen(res));
	phy_free(res);
	load_getexe_pls(optdir, enm, itm, filcnf, &res);
	strcat(str, " ");
	strncat(str, res, strlen(res));
	strcat(str, " ");
	strncat(str, cntpth, strlen(cntpth));
	phy_free(res);
	system(str);
#undef optdir
#undef filcnf
}

void load_get_version_rmt(const char* add, const char* exn, char** ver)
{
#define optdir "/opt/phytune/optim"
#define filver "get_version.sh"
	int rc = 0;
	char* usr = NULL;
	char* pwd = NULL;
	char* res = NULL;
	char* fre = NULL;
	char* enm = NULL;
	char str[256] = {0};

	enm = (char*)get_program_name(exn);
	rc = physql_select(add, &usr, &pwd, &res);
	if(rc != SQLITE_OK){
		phy_log(LOG_LEVEL_ERR, "load_get_version_rmt: Cannot find info of %s.", add);
		return;
	}
	phy_free(res);

	load_getexe_pls(optdir, enm, "deploy", filver, &res);
	if(res == NULL){
		phy_log(LOG_LEVEL_ERR, "load_get_version_rmt: Unable to find %s file.", "get_version.sh");
		return;
	}

	memset(str, 0, sizeof(str));
	phy_snprintf(str, sizeof(str), "scp -p %s %s@%s:/tmp/", res, usr, add);
	phy_free(res);
	forkpty_cutlines(add, usr, pwd, NULL, str, 4, &res, -1);
	phy_free(res);

	memset(str, 0, sizeof(str));
	phy_snprintf(str, sizeof(str), "/tmp/%s %s", filver, exn);
	forkpty_cutlines(add, usr, pwd, NULL, str, 0, &res, -1);

	fre = parse_results(res, "<<<This is a beautiful segmentation line1>>>", "<<<This is a beautiful segmentation line1>>>");
	phy_free(res);
	*ver = strdup(trims(fre));

	memset(str, 0, sizeof(str));
	phy_snprintf(str, sizeof(str), "rm -rf /tmp/%s", filver);
	forkpty_cutlines(add, usr, pwd, NULL, str, 0, &res, -1);
	phy_free(res);
	phy_free(fre);
	phy_free(usr);
	phy_free(pwd);

#undef optdir
#undef filver
}

void load_pmu_cnf(const char* dir, const char* cpu, const char* typ, const char* exn, const char* itm, const char* cnf)
{

}
