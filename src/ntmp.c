#include "ntmp.h"
#include <stdlib.h>
#include <string.h>
#include "phy_mix.h"

int get_hash_mks(ntmp* nmp, const char* primary, lst** p) {
    if (!nmp || !primary || !p) return HMAP_E_FAIL;
    if (strcmp(primary, reprimarykey) != 0) return HMAP_E_FAIL;
    *p = NULL;

    hml *root = nmp->slot;
    int total_ip = hashmap_size(root->dat);
    if (total_ip <= 0) return HMAP_E_NOTFOUND;

    typedef struct {
        lst *collector;
    } collect_arg;
    int collect_ip(void *elem, void *arg) {
        hml *ip_node = (hml*)elem;
        collect_arg *ca = (collect_arg*)arg;
        ca->collector = lst_app(ca->collector, ip_node->val);
        return HMAP_S_OK;
    }

    collect_arg cab = { .collector = NULL };
    hashmap_iterate(root->dat, collect_ip, &cab);
    *p = cab.collector;
    return (*p)? HMAP_S_OK : HMAP_E_NOTFOUND;
}

int get_hash_sks(ntmp* nmp, const char* ip, lst** p)
{
    if (!nmp || !ip || !p) return HMAP_E_FAIL;
    *p = NULL;

    hml *root = nmp->slot;
    void *tmp = NULL;
    if (hashmap_get(root->dat, ip, &tmp) != HMAP_S_OK) {
        return HMAP_E_NOTFOUND;
    }
    hml *ip_node = (hml*)tmp;

    int sub_count = hashmap_size(ip_node->dat);
    if (sub_count <= 0) return HMAP_E_NOTFOUND;

    typedef struct {
        lst *collector;
    } collect_arg2;
    int collect_sub(void *elem, void *arg) {
        hml *sub_node = (hml*)elem;
        collect_arg2 *ca2 = (collect_arg2*)arg;
        ca2->collector = lst_app(ca2->collector, sub_node->val);
//        ca2->collector = lst_app(ca2->collector, sub_node->val, strlen(sub_node->val) + 1);
        return HMAP_S_OK;
    }

    collect_arg2 cab2 = { .collector = NULL };
    hashmap_iterate(ip_node->dat, collect_sub, &cab2);
    *p = cab2.collector;
    return (*p)? HMAP_S_OK : HMAP_E_NOTFOUND;
}

int get_hash_ssks(ntmp* nmp,
                  const char* ip,
                  const char* subkey,
                  lst** ssks)
{
    if (!nmp || !ip || !subkey || !ssks) return HMAP_E_FAIL;
    *ssks = NULL;

    //定位 ip_node
    hml *root = nmp->slot;
    void *tmp = NULL;
    if (hashmap_get(root->dat, ip, &tmp) != HMAP_S_OK) {
        return HMAP_E_NOTFOUND;
    }
    hml *ip_node = (hml*)tmp;

    //定位 sub_node
    if (hashmap_get(ip_node->dat, subkey, &tmp) != HMAP_S_OK) {
        return HMAP_E_NOTFOUND;
    }
    hml *sub_node = (hml*)tmp;

    typedef struct {
        lst *collector;
    } collect_arg;

    int collect_ssk(void *elem, void *arg) {
        hml *ssk_node = (hml*)elem;
        collect_arg *ca = (collect_arg*)arg;
        ca->collector = lst_app(ca->collector, ssk_node->val);
//        ca->collector = lst_app(ca->collector, ssk_node->val, strlen(ssk_node->val) + 1);
        return HMAP_S_OK;
    }

    collect_arg cab = { .collector = NULL };
    hashmap_iterate(sub_node->dat, collect_ssk, &cab);

    *ssks = cab.collector;
    return (*ssks) ? HMAP_S_OK : HMAP_E_NOTFOUND;
}

int get_hash_ssv(ntmp* nmp,
                 const char* ip,
                 const char* subkey,
                 const char* ssukey,
                 lst** p)
{
    if (!nmp || !ip || !subkey || !ssukey || !p) return HMAP_E_FAIL;
    *p = NULL;

    hml *root = nmp->slot;
    void *tmp = NULL;
    if (hashmap_get(root->dat, ip, &tmp) != HMAP_S_OK) {
        return HMAP_E_NOTFOUND;
    }
    hml *ip_node = (hml*)tmp;

    if (hashmap_get(ip_node->dat, subkey, &tmp) != HMAP_S_OK) {
        return HMAP_E_NOTFOUND;
    }
    hml *sub_node = (hml*)tmp;

    void *lst_tmp = NULL;
    if (hashmap_get(sub_node->dat, ssukey, &lst_tmp) != HMAP_S_OK) {
        return HMAP_E_NOTFOUND;
    }
    lst *lt = (lst*)lst_tmp;

    lst *cursor = lt;
    while (cursor) {
        *p = lst_app(*p, cursor->dat);
//        *p = lst_app(*p, cursor->dat, cursor->len);
        cursor = cursor->next;
    }
    return (*p)? HMAP_S_OK : HMAP_E_NOTFOUND;
}

//create_ntmp 建立顶层 root，val="IP"，dat=新的哈希表
ntmp* create_ntmp() {
    ntmp *n = malloc(sizeof(ntmp));
    hml *root = malloc(sizeof(hml));
    root->val = strdup("IP");
    root->dat = hashmap_create();
    root->next = NULL;
    n->slot = root;
    return n;
}

int ins_hash_mk(ntmp* nmp, const char* ip) {
    if (!nmp || !ip) return HMAP_E_FAIL;
    hml *root = nmp->slot;
    void *tmp = NULL;
    if (hashmap_get(root->dat, ip, &tmp) == HMAP_S_OK) {
        // IP 已存在
        return HMAP_E_KEYUSED;
    }
    // 向顶层哈希表插入
    hml *ip_node = malloc(sizeof(hml));
    ip_node->val = strdup(ip);            // strdup 了 IP 字符串
    ip_node->dat = hashmap_create();      // 该子哈希表用来存第二层
    ip_node->next = NULL;
    hashmap_put(root->dat, strdup(ip), ip_node);
    return HMAP_S_OK;
}

// 第二层：插入子键 subkey（不负责自动创建第三层）
int ins_hash_sk(ntmp* nmp, const char* ip, const char* subkey) {
    if (!nmp || !ip || !subkey) return HMAP_E_FAIL;
    hml *root = nmp->slot;
    void *tmp = NULL;
    if (hashmap_get(root->dat, ip, &tmp) != HMAP_S_OK) {
        return HMAP_E_NOTFOUND;
    }
    hml *ip_node = (hml*)tmp;
    if (hashmap_get(ip_node->dat, subkey, &tmp) == HMAP_S_OK) {
        return HMAP_E_KEYUSED;
    }
    hml *sub_node = malloc(sizeof(hml));
    sub_node->val = strdup(subkey);
    sub_node->dat = hashmap_create();
    sub_node->next = NULL;
    hashmap_put(ip_node->dat, strdup(subkey), sub_node);
    return HMAP_S_OK;
}

static int insert_ssu_value(hmap_t third, const char *ssukey, const char *ssva)
{
    void *existing = NULL;
    if (hashmap_get(third, ssukey, &existing) == HMAP_S_OK) {
        // 这个 ssukey 已存在，就把新值 append 到链表
        lst *lt = (lst*)existing;
        lt = lst_app(lt, ssva);
    } else {
        lst *lt = NULL;
        lt = lst_app(lt, ssva);
        hashmap_put(third, strdup(ssukey), lt);
    }
    return HMAP_S_OK;
}

int ins_hash_ssv(ntmp* nmp,
                 const char* ip,
                 const char* subkey,
                 const char* ssukey,
                 const char* ssva)
{
    if (!nmp || !ip || !subkey || !ssukey || !ssva) return HMAP_E_FAIL;
    hml *root = nmp->slot;
    void *tmp = NULL;
    hml *ip_node = NULL;
    // 确保 ip_node 存在
    if (hashmap_get(root->dat, ip, &tmp) == HMAP_S_OK) {
        ip_node = tmp;
    } else {
        ins_hash_mk(nmp, ip);
        hashmap_get(root->dat, ip, &tmp);
        ip_node = tmp;
    }
    // 确保 sub_node 存在
    hml *sub_node = NULL;
    if (hashmap_get(ip_node->dat, subkey, &tmp) == HMAP_S_OK) {
        sub_node = tmp;
    } else {
        ins_hash_sk(nmp, ip, subkey);
        hashmap_get(ip_node->dat, subkey, &tmp);
        sub_node = tmp;
    }
    // 在第三层哈希表中插入 ssukey→ssva
    insert_ssu_value(sub_node->dat, ssukey, ssva);
    return HMAP_S_OK;
}

int ins_hash_ssk(ntmp* nmp,
                 const char* ip,
                 const char* subkey,
                 const char* ssk)
{
    if (!nmp || !ip || !subkey || !ssk) return HMAP_E_FAIL;

    hml *root = nmp->slot;
    void *tmp = NULL;
    hml *ip_node = NULL;
    if (hashmap_get(root->dat, ip, &tmp) == HMAP_S_OK) {
        ip_node = (hml*)tmp;
    } else {
        ins_hash_mk(nmp, ip);
        hashmap_get(root->dat, ip, &tmp);
        ip_node = (hml*)tmp;
    }

    hml *sub_node = NULL;
    if (hashmap_get(ip_node->dat, subkey, &tmp) == HMAP_S_OK) {
        sub_node = (hml*)tmp;
    } else {
        ins_hash_sk(nmp, ip, subkey);
        hashmap_get(ip_node->dat, subkey, &tmp);
        sub_node = (hml*)tmp;
    }

    if (hashmap_get(sub_node->dat, ssk, &tmp) == HMAP_S_OK) {
        return HMAP_E_KEYUSED;
    }
    hml *ssk_node = (hml*)malloc(sizeof(hml));
    ssk_node->val = strdup(ssk);
    ssk_node->dat = NULL;
    ssk_node->next = NULL;

    hashmap_put(sub_node->dat, strdup(ssk), ssk_node);
    return HMAP_S_OK;
}

static void destroy_third_hashmap(hmap_t third_map) {
    if (!third_map) return;

    typedef enum _use_state { unused_0 = 0, used_1 = 1 } use_state;
    typedef struct {
      char       *key;
      use_state   used;
      void_ptr    data;  // 这里 data == list*
    } hashmap_elem_t;

    typedef struct {
      int            table_size;
      int            size;
      hashmap_elem_t *elems;
    } hashmap_map_t;

    hashmap_map_t *m = (hashmap_map_t*)third_map;
    if (!m->elems) {
        free(m);
        return;
    }

    for (int i = 0; i < m->table_size; i++) {
        hashmap_elem_t *e = &m->elems[i];
        if (e->used == used_1) {
            free(e->key);

            lst *lt = (lst*)(e->data);
            while (lt) {
                lst *t = lt;
                lt = lt->next;
                free(t->dat);
                free(t);
            }
        }
    }
    free(m->elems);
    free(m);
}

static void destroy_second_hashmap(hmap_t second_map) {
    if (!second_map) return;
    typedef struct _hashmap_elem_t {
        char       *key;
        use_state   used;
        void_ptr    data;  // data = hml_sub*
    } hashmap_elem_t;
    typedef struct _hashmap_map_t {
        int            table_size;
        int            size;
        hashmap_elem_t *elems;
    } hashmap_map_t;

    hashmap_map_t *m = (hashmap_map_t*)second_map;
    if (!m->elems) {
        free(m);
        return;
    }

    for (int i = 0; i < m->table_size; i++) {
        hashmap_elem_t *e = &m->elems[i];
        if (e->used == used_1) {
            free(e->key);

            hml *sub_node = (hml*)(e->data);
            if (sub_node) {
                destroy_third_hashmap(sub_node->dat);
                free(sub_node->val);
                free(sub_node);
            }
        }
    }
    free(m->elems);
    free(m);
}

static void destroy_first_hashmap(hmap_t first_map)
{
    if (!first_map) return;
    typedef struct _hashmap_elem_t {
        char       *key;
        use_state   used;
        void_ptr    data;
    } hashmap_elem_t;

    typedef struct _hashmap_map_t {
        int            table_size;
        int            size;
        hashmap_elem_t *elems;
    } hashmap_map_t;

    hashmap_map_t *m = (hashmap_map_t*)first_map;
    if (!m->elems) {
        free(m);
        return;
    }

    for (int i = 0; i < m->table_size; i++) {
        hashmap_elem_t *e = &m->elems[i];
        if (e->used == used_1) {
            free(e->key);

            hml *ip_node = (hml*)(e->data);
            if (ip_node) {
                destroy_second_hashmap(ip_node->dat);
                free(ip_node->val);
                free(ip_node);
            }
        }
    }
    free(m->elems);
    free(m);
}

int __ins_hash_ext(ntmp *nmp, ...)
{
    if (!nmp) return HMAP_E_FAIL;

    va_list ap;
    va_start(ap, nmp);

    // 取第一级 key
    const char *key = va_arg(ap, const char*);
    if (!key) {
        va_end(ap);
        return HMAP_E_FAIL;
    }

    ins_hash_mk(nmp, key);  // HMAP_E_KEYUSED 可忽略 :contentReference[oaicite:0]{index=0}

    void *tmp = NULL;
    hashmap_get(nmp->slot->dat, key, &tmp);
    hml *curr = (hml*)tmp;
    hmap_t map = curr->dat;

    while ((key = va_arg(ap, const char*)) != NULL) {
        // 查看当前层是否已有该 key
        if (hashmap_get(map, key, &tmp) == HMAP_S_OK) {
            curr = (hml*)tmp;
        } else {
            // 不存在则创建新节点
            hml *node = malloc(sizeof(hml));
            node->val  = strdup(key);
            node->dat  = hashmap_create();
            node->next = NULL;
            hashmap_put(map, strdup(key), node);
            curr = node;
        }
        map = curr->dat;
    }

    va_end(ap);
    return HMAP_S_OK;
}

int __get_hash_ext(ntmp *nmp, ...)
{
    if (!nmp) return HMAP_E_FAIL;

    va_list ap;
    va_start(ap, nmp);

    const char *key;
    hml *curr = nmp->slot;
    hmap_t map = curr->dat;

    while ((key = va_arg(ap, const char*)) != NULL) {
        void *tmp = NULL;
        if (hashmap_get(map, key, &tmp) != HMAP_S_OK) {
            va_end(ap);
            return HMAP_E_NOTFOUND;
        }
        curr = (hml*)tmp;
        map = curr->dat;
    }

    lst **out = va_arg(ap, lst**);
    va_end(ap);
    if (!out) return HMAP_E_FAIL;

    *out = NULL;
    typedef struct { lst *collector; } collect_arg;
    int collect_fn(void *elem, void *arg) {
        hml *node = (hml*)elem;
        ((collect_arg*)arg)->collector = lst_app(
            ((collect_arg*)arg)->collector,
            node->val
        );
        return HMAP_S_OK;
    }

    collect_arg ca = { .collector = NULL };
    hashmap_iterate(map, collect_fn, &ca);
    *out = ca.collector;

    return (*out) ? HMAP_S_OK : HMAP_E_NOTFOUND;
}

static void destroy_hml_map(hmap_t map)
{
    if (!map) return;

    typedef enum _use_state { unused_0 = 0, used_1 = 1 } use_state;
    typedef struct {
        char     *key;    // strdup 出来的 key
        use_state used;   // 1 表示槽内有效
        void_ptr  data;   // 存放 hml* 指针
    } hashmap_elem_t;
    typedef struct {
        int             table_size;
        int             size;
        hashmap_elem_t *elems;
    } hashmap_map_t;

    hashmap_map_t *m = (hashmap_map_t*)map;
    if (!m->elems) {
        free(m);
        return;
    }

    for (int i = 0; i < m->table_size; i++) {
        hashmap_elem_t *e = &m->elems[i];
        if (e->used == used_1) {
            hml *child = (hml*)e->data;
            if (child) {
                destroy_hml_map(child->dat);
                free(child->val);
                free(child);
            }
            free(e->key);
        }
    }
    free(m->elems);
    free(m);
}

void destroy_ntmp(ntmp *nmp)
{
    if (!nmp) return;

    if (nmp->slot) {
        destroy_hml_map(nmp->slot->dat);
        free(nmp->slot->val);
        free(nmp->slot);
    }

    free(nmp);
}

void destroy_ntmp_old(ntmp *nmp)
{
    if (!nmp) return;
    hml *root = nmp->slot;
    if (root) {
        destroy_first_hashmap(root->dat);
        free(root->val);
        free(root);
    }
    free(nmp);
}

int __ins_hash_ext_arr(ntmp *nmp, char *keys[], int nkeys)
{
    if (!nmp || nkeys <= 0) return HMAP_E_FAIL;

    // 第一级
    ins_hash_mk(nmp, keys[0]);
    void *tmp = NULL;
    hashmap_get(nmp->slot->dat, keys[0], &tmp);
    hml *curr = (hml*)tmp;
    hmap_t map = curr->dat;

    // 后续级
    for (int i = 1; i < nkeys; i++) {
        if (hashmap_get(map, keys[i], &tmp) == HMAP_S_OK) {
            curr = (hml*)tmp;
        } else {
            hml *node = malloc(sizeof(hml));
            node->val  = strdup(keys[i]);
            node->dat  = hashmap_create();
            node->next = NULL;
            hashmap_put(map, strdup(keys[i]), node);
            curr = node;
        }
        map = curr->dat;
    }
    return HMAP_S_OK;
}

// 拆分 path（形如 "/a/b/c"），对每一级前缀都调用 __ins_hash_ext_arr
void ntmp_ins_ext(ntmp *nmp, const char *path)
{
    if (!nmp || !path) return;

    char *copy = strdup(path);
    if (!copy) return;

    char *parts[20];
    int cnt = 0;
    char *p = copy;

    if (*p == '/') p++;
    char *saveptr;
    char *tok = strtok_r(p, "/", &saveptr);
    while (tok && cnt < 20) {
        parts[cnt++] = tok;
        tok = strtok_r(NULL, "/", &saveptr);
    }
    for (int i = 1; i <= cnt; i++) {
        __ins_hash_ext_arr(nmp, parts, i);
    }
    free(copy);
}

extern ntmp *hwmp;
char* get_mempool_devs( const char* add, const char* typ )
{
	char* cpu = null;
	char* res = null;
	char* lty = null;
	char* nnb = null;
	char* str = null;
	char* pth = null;
	char* drt = null;
	char* cls = null;
	tbh tb;

	lst* lx = null;
	lst* slx = null;
	lst* sslx = null;
	lst* cur = null;
	lst* scu = null;
	lst* ssc = null;

	lty = strdup(typ);
	phy_strlower(lty);

//获取cpu型号
	if(	HMAP_S_OK == get_hash_ext( hwmp, add, "cpu", "type", &lx ) ) {
		lst* cur = lx;
		while (cur) {
			cpu = strdup(cur->dat);
			cur = cur->next;
		}
		lst_fre(lx);
	}

	str = string_replace(m_hwcpth, "$CPU", cpu);
	pth = string_replace(str, "$TYP", "ddr");
//ddr 配置tab
	tb = tab_ldrx(pth);
	phy_free(str);

	if (0 == phy_strcmp_natural(lty, "pcie") ) {
		lst* lx = null;
		if(	HMAP_S_OK == get_hash_ext(hwmp, add, lty, &lx) )
		{
			cur = lx;
			while (cur){
//				printf("%s\n", (char*)cur->dat);
				if(	HMAP_S_OK == get_hash_ext( hwmp, add, lty, (char*)cur->dat, "设备桥", &slx ) ) {
					scu = slx;
					while(slx){
						res = buy_some_mem((char*)(res), "[");
						res = buy_some_mem((char*)(res), (const char*)cur->dat);
						res = buy_some_mem((char*)(res), "|");
						res = buy_some_mem((char*)(res), (const char*)scu->dat);
						res = buy_some_mem((char*)(res), "]");
						break;
					}
				}
				cur = cur->next;
				lst_fre(slx);
			}
			lst_fre(lx);
		}
	}

	if (0 == phy_strcmp_natural(lty, m_ddrnam) ) {
		lst* lx = null;
		if(	HMAP_S_OK == get_hash_ext(hwmp, add, lty, &lx) )
		{
			cur = lx;
			while (cur){
				if(	HMAP_S_OK == get_hash_ext( hwmp, add, lty, (char*)cur->dat, "Configured Memory Speed", &slx ) ) {

					scu = slx;
					while(scu){

						if(strstr(scu->dat, m_ddrust)){
							break;
						}

						if(	HMAP_S_OK == get_hash_ext( hwmp, add, lty, (char*)cur->dat, "Type", &sslx ) ) {
							ssc = sslx;
							while(ssc){
								drt = strdup(ssc->dat);
								ssc = ssc->next;
							}
							lst_fre(sslx);
						}

						nnb = tab_search(&tb, "node", "nodes", (char*)cur->dat);
						phy_strlower(drt);
						cls = tab_search(&tb, "ddr", drt, "通道数");
						str = int2sstr(atoi(cls), ",");

						res = buy_some_mem((char*)(res), "[");
						res = buy_some_mem((char*)(res), nnb);
						res = buy_some_mem((char*)(res), "|");
						res = buy_some_mem((char*)(res), str);
						res = buy_some_mem((char*)(res), "]");

						phy_free(drt);
						phy_free(nnb);

						break;

						scu = scu->next;
					}
					lst_fre(slx);
				}
				cur = cur->next;
			}
			lst_fre(lx);
		}
	}
	phy_free(lty);
	return res;
}

bool get_mempool_isenabled( const char* add, const char* typ )
{
	char* cpu = null;
	char* sta = null;
	char* dps = null;
	char* pri = null;
	char* per = null;
	char* lty = null;

	tbh tb;

	lst* lx = null;

	lty = strdup(typ);
	phy_strlower(lty);

	if(	HMAP_S_OK == get_hash_ext( hwmp, add, "cpu", "type", &lx ) ) {
		lst* cur = lx;
		while (cur) {
			cpu = strdup(cur->dat);
			cur = cur->next;
		}
		lst_fre(lx);
	}

	if( 0 != phy_strcmp_natural(cpu, "S5000C") ){
		phy_free(cpu);
		phy_free(lty);
		send_message(MESS, ERROR, MIX, "该cpu类型不支持此性能检测!");
		return false;
	}

	if(	HMAP_S_OK == get_hash_ext( hwmp, add, "system", "依赖", &lx ) ) {
		lst* cur = lx;
		while (cur) {
			dps = strdup(cur->dat);
			if( null == strstr(dps, "ok") ){
				send_message(MESS, ERROR, MIX, dps);
				lst_fre(lx);
				phy_free(dps);
				return false;
			}
			cur = cur->next;
		}
		lst_fre(lx);
	}


	if(	HMAP_S_OK == get_hash_ext( hwmp, add, "system", "权限", &lx ) ) {
		lst* cur = lx;
		while (cur) {
			pri = strdup(cur->dat);
			if( null == strstr(pri, "ok") ){
				send_message(MESS, ERROR, MIX, pri);
				lst_fre(lx);
				phy_free(pri);
				return false;
			}
			cur = cur->next;
		}
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext( hwmp, add, "system", "perf", &lx ) ) {
		lst* cur = lx;
		while (cur) {
			per = strdup(cur->dat);
			if( null == strstr(per, "ok") ){
				send_message(MESS, ERROR, MIX, per);
				lst_fre(lx);
				phy_free(per);
				return false;
			}
			cur = cur->next;
		}
		lst_fre(lx);
	}

	if(	HMAP_S_OK == get_hash_ext( hwmp, add, "driver", lty, &lx ) ) {
		lst* cur = lx;
		while (cur) {
			sta = strdup(cur->dat);
			if( null == strstr(sta, "ok") ){
				send_message(MESS, ERROR, MIX, sta);
				lst_fre(lx);
				phy_free(sta);
				return false;
			}
			cur = cur->next;
		}
		lst_fre(lx);
	}

	return true;
}
