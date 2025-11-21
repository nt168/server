#ifndef NTTABS_H
#define NTTABS_H
// 表格结构体定义
typedef struct tbl {
    char   *des;        // 描述（表名）
    char   *cut;        // 分隔线
    char  **tit;        // 表头字段数组
    int     tit_count;  // 表头字段个数
    char  **col;        // 第一列字段（行名）数组
    int     col_count;  // 行数
    char ***dat;        // 数据矩阵 dat[row][col]
} tbl;

// 链式节点存储表
typedef struct tbs {
    tbl        *dat;
    struct tbs *nex;
} tbs;

// 表集头，数组和链表并存
typedef struct tbh {
    tbs   *ent;   // 链表头
    tbl  **tbs;   // 表对象数组
    int    cnt;   // 表格个数
} tbh;

void free_tbh(tbh *hd);
tbh tab_ldr(const char *path);
tbh tab_ldrx(const char *path);
char* tab_search(tbh *hd, const char* tbn, const char* ron, const char* con);

#endif


