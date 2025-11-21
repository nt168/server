#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "nttabs.h"

#define MAXLINE 4096
const char* chns[] = {
    "单通道(单向)", "x1带宽", " ", " ",
    "x4带宽", " ", " ", " ",
    "x8带宽", " ", " ", " ",
    " ", " ", " ", " ",
    "x16带宽(单向)"
};
const char* bris[] = {
		"rev00",
		"rev01", "rev02",
		"rev03", "rev04", "rev05",
		"rev06", "rev07", "rev08",
};

// 去除字符串首尾空白
static void trim(char *s) {
    char *p = s, *end;
    while (isspace((unsigned char)*p)){
    	p++;
    }
    if (p != s) memmove(s, p, strlen(p)+1);
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)){
    	*end-- = '\0';
    }
}

int istab(int c) {
    return (c == '\t');
}

// 按空白字符分割一行，返回字段数组及数量
static char** split_ws(const char *line, int *count) {
    int cap = 8, n = 0;
    char **a = malloc(sizeof(char*) * cap);
    const char *p = line;
    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        const char *start = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        int len = p - start;
        char *tok = malloc(len + 1);
        memcpy(tok, start, len);
        tok[len] = '\0';
        if (n >= cap) a = realloc(a, sizeof(char*) * (cap *= 2));
        a[n++] = tok;
    }
    *count = n;
    return a;
}

// 按空'\t'分割，返回字段数组及数量
static char** split_tb(const char *line, int *count) {
    int cap = 8, n = 0;
    char **a = malloc(sizeof(char*) * cap);
    const char *p = line;
    while (*p) {
        while (*p && istab((unsigned char)*p)) p++;
        if (!*p) break;
        const char *start = p;
        while (*p && !istab((unsigned char)*p)) p++;
        int len = p - start;
        char *tok = malloc(len + 1);
        memcpy(tok, start, len);
        tok[len] = '\0';
        if (n >= cap) a = realloc(a, sizeof(char*) * (cap *= 2));
        a[n++] = tok;
    }
    *count = n;
    return a;
}

// 加载文件并构建 tbh
tbh tab_ldr(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
    	perror("无法打开文件"); exit(1);
    }

    char buf[MAXLINE];
    int cnt = 0;
    while (fgets(buf, sizeof(buf), fp)){
    	if (buf[0] == '[') {
    		cnt++;
    	}
    }

    rewind(fp);

    tbh hd = { .ent = NULL, .tbs = malloc(sizeof(tbl*) * cnt), .cnt = cnt };
    int idx = 0;

    while (fgets(buf, sizeof(buf), fp)) {
        if (buf[0] != '[') continue;
        trim(buf);
        char *des = strdup(buf + 1);
        des[strcspn(des, "]")] = '\0';
        trim(des);
        fgets(buf, sizeof(buf), fp); trim(buf);
        int tit_n;
        char **tit = split_ws(buf, &tit_n);
        fgets(buf, sizeof(buf), fp); trim(buf);
        char *cut = strdup(buf);

        int max_rows = 8, row_n = 0;
        char **col = malloc(sizeof(char*) * max_rows);
        char ***dat = malloc(sizeof(char**) * max_rows);
        long pos;
        while (1) {
            pos = ftell(fp);
            if (!fgets(buf, sizeof(buf), fp)) break;
            if (buf[0] == '[' || buf[0] == '\n') {
            	fseek(fp, pos, SEEK_SET); break;
            }
            trim(buf);
            int fields;
            char **row = split_ws(buf, &fields);
            if (fields != tit_n) {
                row = realloc(row, sizeof(char*) * tit_n);
                for (int i = fields; i < tit_n; i++) {
                	row[i] = strdup("");
                }
            }
            if (row_n >= max_rows) {
                max_rows *= 2;
                col = realloc(col, sizeof(char*) * max_rows);
                dat = realloc(dat, sizeof(char**) * max_rows);
            }
            col[row_n] = strdup(row[0]);
            dat[row_n] = row;
            row_n++;
        }

        tbl *t = malloc(sizeof(*t));
        t->des = des;
        t->cut = cut;
        t->tit = tit;
        t->tit_count = tit_n;
        t->col = col;
        t->col_count = row_n;
        t->dat = dat;

        hd.tbs[idx++] = t;
        tbs *node = malloc(sizeof(*node));
        node->dat = t;
        node->nex = hd.ent;
        hd.ent = node;
    }
    fclose(fp);
    return hd;
}

tbh tab_ldrx(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
    	perror("无法打开文件"); exit(1);
    }

    char buf[MAXLINE];
    int cnt = 0;
    while (fgets(buf, sizeof(buf), fp)){
    	if (buf[0] == '[') {
    		cnt++;
    	}
    }

    rewind(fp);

    tbh hd = { .ent = NULL, .tbs = malloc(sizeof(tbl*) * cnt), .cnt = cnt };
    int idx = 0;

    while (fgets(buf, sizeof(buf), fp)) {
        if (buf[0] != '[') continue;
        trim(buf);
        char *des = strdup(buf + 1);
        des[strcspn(des, "]")] = '\0';
        trim(des);
        fgets(buf, sizeof(buf), fp); trim(buf);
        int tit_n;
        char **tit = split_tb(buf, &tit_n);
        fgets(buf, sizeof(buf), fp); trim(buf);
        char *cut = strdup(buf);

        int max_rows = 8, row_n = 0;
        char **col = malloc(sizeof(char*) * max_rows);
        char ***dat = malloc(sizeof(char**) * max_rows);
        long pos;
        while (1) {
            pos = ftell(fp);
            if (!fgets(buf, sizeof(buf), fp)) break;
            if (buf[0] == '[' || buf[0] == '\n') {
            	fseek(fp, pos, SEEK_SET); break;
            }
            trim(buf);
            int fields;
            char **row = split_tb(buf, &fields);
            if (fields != tit_n) {
                row = realloc(row, sizeof(char*) * tit_n);
                for (int i = fields; i < tit_n; i++) {
                	row[i] = strdup("");
                }
            }
            if (row_n >= max_rows) {
                max_rows *= 2;
                col = realloc(col, sizeof(char*) * max_rows);
                dat = realloc(dat, sizeof(char**) * max_rows);
            }
            col[row_n] = strdup(row[0]);
            dat[row_n] = row;
            row_n++;
        }

        tbl *t = malloc(sizeof(*t));
        t->des = des;
        t->cut = cut;
        t->tit = tit;
        t->tit_count = tit_n;
        t->col = col;
        t->col_count = row_n;
        t->dat = dat;

        hd.tbs[idx++] = t;
        tbs *node = malloc(sizeof(*node));
        node->dat = t;
        node->nex = hd.ent;
        hd.ent = node;
    }
    fclose(fp);
    return hd;
}

// 释放 tbh 内存
void free_tbh(tbh *hd)
{
    if (!hd) return;
    for (int i = 0; i < hd->cnt; i++) {
        tbl *t = hd->tbs[i];
        free(t->des);
        free(t->cut);

        for (int j = 0; j < t->tit_count; j++) {
        	free(t->tit[j]);
        }

        free(t->tit);

        for (int r = 0; r < t->col_count; r++) {
            free(t->col[r]);
            for (int c = 0; c < t->tit_count; c++) {
            	free(t->dat[r][c]);
            }
            free(t->dat[r]);
        }
        free(t->col);
        free(t->dat);
        free(t);
    }
    free(hd->tbs);
    for (tbs *p = hd->ent; p; ) {
        tbs *n = p->nex;
        free(p);
        p = n;
    }
    hd->ent = NULL;
    hd->cnt = 0;
}

// 查询函数
char* tab_search(tbh *hd, const char* tbn, const char* ron, const char* con)
{
    for (int i = 0; i < hd->cnt; i++) {
        tbl *t = hd->tbs[i];
        if (strcmp(t->des, tbn) == 0) {
            int ri = -1, ci = -1;
            for (int r = 0; r < t->col_count; r++) {
            	if (strcmp(t->col[r], ron) == 0) {
            		ri = r;
            	}
            }

            for (int c = 0; c < t->tit_count; c++) {
            	if (strcmp(t->tit[c], con) == 0) {
            		ci = c;
            	}
            }

            if (ri >= 0 && ci >= 0) {
            	return t->dat[ri][ci];
            }
        }
    }
    return NULL;
}
