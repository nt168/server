#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#include <dirent.h>
#include <time.h>
#include <string.h>
#include <sys/sem.h>
#include <assert.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <pwd.h>
#include <netinet/ip_icmp.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdbool.h>
#include <libgen.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libssh/libssh.h>
#include "sysinc.h"
#include "phytypes.h"
#include "version.h"

#define LEVEL_WARNING	3
#define LEVEL_DEBUG		4

#define BUFLEN 1024
#define SMFILE 2048
#define STRING_LEN 1024
#define PHRASELEN 128
#define CMDLEN 1024
#define PHRASE 100
#define LPHRASE 256
#define SCMDLEN 512
#define SHORTPHRASELEN 32
#define PATHLENGTH 2048

#define ISL 12

#define OFFSETOF(type, mbr) ((size_t)&(((type *)0)->mbr))

#define DBPIPESTARTMODE 0
#define GORGEOUSDIVIDER "IMANUNBENCHGORGEOUSDIVIDER"

#define SEM_SERVER_RUN "/sem_server_run" //"/home/uos/tmp/sem_server_run"
#define SEM_QTWINDOW_RUN "/sem_qtwindow_run" //"/home/uos/tmp/sem_qtwindow_run"

#	define phy_int64_t	 int64_t
#	define phy_uint64_t	uint64_t
# define phy_uint     unsigned int
#	define un_int64_t	  int64_t

#define null ((void*)0)
//////////////////////////////////////////////////////////////////////
#define ARG_INPUT_ERR "argument error !"
#define PHY_NULL2STR(str)	(NULL != str ? str : "(null)")
#define PHY_NULL2EMPTY_STR(str)	(NULL != (str) ? (str) : "")
#define PHY_PTR_SIZE		sizeof(void *)

#define INCREMENT 512
struct mmana{
        unsigned int len;
        unsigned int remain;
};
#define MMANAPOS(str) str+strlen(str)+1
#define GETMMANA(str, mn) mn = (struct mmana*)(MMANAPOS(str))

char* buy_some_mem(char* data, const char* msg);

//#define NTSTRCMP(a, b) ((0 == strcmp((a), (b))) ? 2 : 1)
#define ISEQLEN(a, b) (strlen(a) == strlen(b) ? true : false)
#define ISNLEN(str) (0 != strlen(str) ? true : false)
#define ISNULL(str)	(NULL != str ? ISNLEN(str) : false)
#define NTSTRSTR(str, spt) ((true == ISNULL(str)) ? strstr(str, spt) : NULL)
#define NULL2ZERO(str) ISNULL(str) ? str : "0"
char* mystrstr(const char* str, size_t len, const char* spt);

#define FOR(i, start, end, step, action) 		  \
	for( int i = (start); i<(end); i+= (step)){ \
		action 									  \
	}

#define MYSTRSTR(str, len, spt) mystrstr((str), (len), (spt))
//////////////////////////////////////////////////////////////

typedef struct combptr{
	uintptr_t ptrs[2];
}combptr;
#define ACCFIELDP(cbptr, pos) (cbptr->ptrs[pos])
#define ACCFIELD(cbptr, pos) (cbptr.ptrs[pos])
#define COMBPTR(ptr1, ptr2) ((combptr){ .ptrs = {(uintptr_t)(ptr1),(uintptr_t)(ptr2)} })

//#define NTSTRISEQ(stra, strb) (true == ISNULL(stra) && true == ISNULL(strb) && ISEQLEN(stra, strb)) ? NTSTRCMP(stra, strb) : 2
//#define NTADDLSPACE(str) ISNULL(str) ?

typedef enum
{
	PHY_TASK_START = 0,
	PHY_TASK_PRINT_SUPPORTED,
	PHY_TASK_TEST_METRIC,
	PHY_TASK_SHOW_USAGE,
	PHY_TASK_SHOW_VERSION,
	PHY_TASK_SHOW_HELP,
	PHY_TASK_RUNTIME_CONTROL
}
phy_task_t;

typedef struct
{
	char ipaddr[SHORTPHRASELEN];
	unsigned int port;
	char user[SHORTPHRASELEN];
	char passwd[SHORTPHRASELEN];
	char adpasswd[SHORTPHRASELEN];
	char inspath[SHORTPHRASELEN];
	char statedescription[PHRASE];
	char arch[SHORTPHRASELEN];
	un_int64_t timestamp;
	bool status;
	bool heartbeatstatus;
}phy_agent_list;

////#	define phy_uint64_t	unsigned int64_t
//#	define PHY_FS_UI64	"%I64u"
//#	define PHY_FS_UO64	"%I64o"
//#	define PHY_FS_UX64	"%I64x"
//
////#	define phy_int64_t	int64_t
//#	define PHY_FS_I64	"%I64d"
//#	define PHY_FS_O64	"%I64o"
//#	define PHY_FS_X64	"%I64x"

#define NAME_LEN 20
typedef struct {
	char name[NAME_LEN];
	int age;
}ckx;

int sharememory(int ipc_size,int flag);
int create_ipc(int ipc_size);
int get_ipc(int ipc_size);


#define PHY_FS_SIZE_T		PHY_FS_UI64
#define PHY_FS_SSIZE_T		PHY_FS_I64
#define phy_fs_size_t		phy_uint64_t	/* use this type only in calls to printf() for formatting size_t */
#define phy_fs_ssize_t		phy_int64_t

#define phy_fs_size_t		phy_uint64_t
#define MEM_MIN_SIZE		__UINT64_C(128)
#define MEM_MAX_SIZE		__UINT64_C(0x1000000000)	/* 64 GB */

#define POLLER_DELAY	5

//#define PHY_CONST_STRING(str) ""str
//#define PHY_CONST_STRLEN(str) (sizeof(PHY_CONST_STRING(str)) - 1)

#if defined(__GNUC__) && __GNUC__ >= 7
#	define PHY_FALLTHROUGH	__attribute__ ((fallthrough))
#else
#	define PHY_FALLTHROUGH
#endif

typedef struct
{
	char	*addr;
	double	min;
	double	sum;
	double	max;
	int	rcv;
	int	cnt;
	char	*status;	/* array of individual response statuses: 1 - valid, 0 - timeout */
}
PHY_FPING_HOST;

typedef enum
{
	ICMPPING = 0,
	ICMPPINGSEC,
	ICMPPINGLOSS
}
icmpping_t;

typedef enum
{
	ICMPPINGSEC_MIN = 0,
	ICMPPINGSEC_AVG,
	ICMPPINGSEC_MAX
}
icmppingsec_type_t;

typedef struct
{
	int			count;
	int			interval;
	int			size;
	int			timeout;
	uint64_t		itemid;
	char			*addr;
	icmpping_t		icmpping;
	icmppingsec_type_t	type;
}icmpitem_t;

#	define PHY_THREAD_LOCAL
//static PHY_THREAD_LOCAL volatile sig_atomic_t	phy_timed_out;

#define ARRSIZE(a)	(sizeof(a) / sizeof(*a))
#define PHY_UNUSED(var) (void)(var)

extern const char	*progname;
extern const char	title_message[];
extern const char	syslog_app_name[];
extern const char	*usage_message[];
extern const char	*help_message[];
extern unsigned char	program_type;
extern char *CONFIG_PID_FILE;

typedef struct
{
	phy_task_t	task;
	int		flags;
	int		data;
}PHY_TASK_EX;

typedef enum
{
	INTERFACE_TYPE_UNKNOWN = 0,
	INTERFACE_TYPE_AGENT,
	INTERFACE_TYPE_SNMP,
	INTERFACE_TYPE_IPMI,
	INTERFACE_TYPE_JMX,
	INTERFACE_TYPE_ANY = 255
}
phy_interface_type_t;

#define PHY_UNUSED(var) (void)(var)

typedef struct
{
	int	sec;	/* seconds */
	int	ns;	/* nanoseconds */
}
phy_timespec_t;

/* time zone offset */
typedef struct
{
	char	tz_sign;	/* '+' or '-' */
	int	tz_hour;
	int	tz_min;
}
phy_timezone_t;


#define INTERFACE_TYPE_COUNT	4	/* number of interface types */
extern const int	INTERFACE_TYPE_PRIORITY[INTERFACE_TYPE_COUNT];

#define SNMP_BULK_DISABLED	0
#define SNMP_BULK_ENABLED	1

#define PHY_IF_SNMP_VERSION_1	1
#define PHY_IF_SNMP_VERSION_2	2
#define PHY_IF_SNMP_VERSION_3	3

#define PHY_FLAG_DISCOVERY_NORMAL	0x00
#define PHY_FLAG_DISCOVERY_RULE		0x01
#define PHY_FLAG_DISCOVERY_PROTOTYPE	0x02
#define PHY_FLAG_DISCOVERY_CREATED	0x04

#define PHY_HOST_PROT_INTERFACES_INHERIT	0
#define PHY_HOST_PROT_INTERFACES_CUSTOM		1

#	define PHY_MUTEX		int
#define PHY_LENGTH_UNLIMITED	0x7fffffff
#define PHY_UNIT_SYMBOLS	"KMGTsmhdw"
#define PHY_FLAG_DOUBLE_PLAIN	0x00
#define PHY_FLAG_DOUBLE_SUFFIX	0x01
#define PHY_DOUBLE_EPSILON	0.000001
int	phy_double_compare(double a, double b);
typedef enum
{
	PHY_FUNCTION_TYPE_UNKNOWN,
	PHY_FUNCTION_TYPE_HISTORY,
	PHY_FUNCTION_TYPE_TIMER,
	PHY_FUNCTION_TYPE_TRENDS
}
phy_function_type_t;

//typedef enum
//{
//	ITEM_TYPE_PHY = 0,
///*	ITEM_TYPE_SNMPv1,*/
//	ITEM_TYPE_TRAPPER = 2,
//	ITEM_TYPE_SIMPLE,
///*	ITEM_TYPE_SNMPv2c,*/
//	ITEM_TYPE_INTERNAL = 5,
///*	ITEM_TYPE_SNMPv3,*/
//	ITEM_TYPE_PHY_ACTIVE = 7,
///*	ITEM_TYPE_AGGREGATE, */
//	ITEM_TYPE_HTTPTEST = 9,
//	ITEM_TYPE_EXTERNAL,
//	ITEM_TYPE_DB_MONITOR,
//	ITEM_TYPE_IPMI,
//	ITEM_TYPE_SSH,
//	ITEM_TYPE_TELNET,
//	ITEM_TYPE_CALCULATED,
//	ITEM_TYPE_JMX,
//	ITEM_TYPE_SNMPTRAP,
//	ITEM_TYPE_DEPENDENT,
//	ITEM_TYPE_HTTPAGENT,
//	ITEM_TYPE_SNMP,
//	ITEM_TYPE_SCRIPT	/* 21 */
//}
//phy_item_type_t;

void	phy_strlower(char *str);
void	phy_strupper(char *str);

int	str_in_list(const char *list, const char *value, char delimiter);
int	str_n_in_list(const char *list, const char *value, size_t len, char delimiter);

phy_function_type_t	phy_get_function_type(const char *func);
double		phy_time(void);
void		phy_timespec(phy_timespec_t *ts);
double		phy_current_time(void);
void		phy_get_time(struct tm *tm, long *milliseconds, phy_timezone_t *tz);
void phy_get_times(struct tm *tm, long *milliseconds, un_int64_t *st, phy_timezone_t *tz);
long		phy_get_timezone_offset(time_t t, struct tm *tm);
struct tm	*phy_localtime(const time_t *time, const char *tz);
int		phy_utc_time(int year, int mon, int mday, int hour, int min, int sec, int *t);
int		phy_day_in_month(int year, int mon);
phy_uint64_t	phy_get_duration_ms(const phy_timespec_t *ts);

#if defined(__GNUC__) || defined(__clang__)
#	define __phy_attr_format_printf(idx1, idx2) __attribute__((__format__(__printf__, (idx1), (idx2))))
#else
#	define __phy_attr_format_printf(idx1, idx2)
#endif

typedef struct phy_custom_interval	phy_custom_interval_t;

int	is_uint_n_range(const char *str, size_t n, void *value, size_t size, uint64_t min, uint64_t max);
int	is_hex_n_range(const char *str, size_t n, void *value, size_t size, phy_uint64_t min, phy_uint64_t max);

#define PHY_MAX_BYTES_IN_UTF8_CHAR	4
size_t	phy_utf8_char_len(const char *text);
size_t	phy_strlen_utf8(const char *text);
char	*phy_strshift_utf8(char *text, size_t num);
size_t	phy_strlen_utf8_nchars(const char *text, size_t utf8_maxlen);
size_t	phy_strlen_utf8_nbytes(const char *text, size_t maxlen);
size_t	phy_charcount_utf8_nbytes(const char *text, size_t maxlen);

#define PHY_UTF8_REPLACE_CHAR	'?'
void	phy_replace_invalid_utf8(char *text);

int	phy_cesu8_to_utf8(const char *cesu8, char **utf8);

void	dos2unix(char *str);
int	str2uint64(const char *str, const char *suffixes, phy_uint64_t *value);
double	str2double(const char *str);

#define is_uint64_n(str, n, value) \
	is_uint_n_range(str, n, value, 8, 0x0, __UINT64_C(0xFFFFFFFFFFFFFFFF))

#define is_uint_range(str, value, min, max) \
	is_uint_n_range(str, PHY_SIZE_T_MAX, value, sizeof(unsigned int), min, max)

#define PHY_TASK_FLAG_MULTIPLE_AGENTS 0x01
#define PHY_TASK_FLAG_FOREGROUND      0x02

#define get_parent_dir(filename)	__get_parent_dir(__FILE__, __LINE__, filename)
#define get_file_suffix(filename)	__get_file_suffix(__FILE__, __LINE__, filename)
#define get_file_name(filename)  __get_file_name(__FILE__, __LINE__, filename)
#define get_rsstr_pos(oristr, sstr)  __get_rsstr_pos(__FILE__, __LINE__, oristr, sstr)
#define get_str_between_two_words(res, k1, k2) __get_str_between_two_words(__FILE__, __LINE__, res, k1, k2)
#define get_nearest_key(res, prefix) __get_nearest_key(__FILE__, __LINE__, res, prefix);

char  *__get_parent_dir(const char *projectsfile, int line, const char * filename);
char  *__get_file_suffix(const char *projectsfile, int line, const char * filename);
char  *__get_file_name(const char *projectsfile, int line, const char * filename);
size_t __get_rsstr_pos(const char *projectsfile, int line, const char * oristr, const char * sstr);

char* __get_str_between_two_words(const char *filename, int line, const char* res, const char* k1, const char* k2);
char* __get_nearest_key(const char *filename, int line, const char* res, const char* prefix);

typedef struct stat	phy_stat_t;

#define MAX_ID_LEN		21
#define MAX_STRING_LEN		2048
#define MAX_BUFFER_LEN		65536
#define MAX_PHY_HOSTNAME_LEN	128
#define MAX_PHY_DNSNAME_LEN	255	/* maximum host DNS name length from RFC 1035 (without terminating '\0') */
#define MAX_EXECUTE_OUTPUT_LEN	(512 * PHY_KIBIBYTE)

#define PHY_MAX_UINT64		(~__UINT64_C(0))
#define PHY_MAX_UINT64_LEN	21

#define	SUCCEED		0
#define	FAIL		-1
#define	NOTSUPPORTED	-2
#define	NETWORK_ERROR	-3
#define	TIMEOUT_ERROR	-4
#define	AGENT_ERROR	-5
#define	GATEWAY_ERROR	-6
#define	CONFIG_ERROR	-7

#define PHY_KIBIBYTE		1024
#define PHY_MEBIBYTE		1048576
#define PHY_GIBIBYTE		1073741824
#define PHY_TEBIBYTE		__UINT64_C(1099511627776)

#define SEC_PER_MIN		60
#define SEC_PER_HOUR		3600
#define SEC_PER_DAY		86400
#define SEC_PER_WEEK		(7 * SEC_PER_DAY)
#define SEC_PER_MONTH		(30 * SEC_PER_DAY)
#define SEC_PER_YEAR		(365 * SEC_PER_DAY)
#define PHY_JAN_2038		2145916800
#define PHY_JAN_1970_IN_SEC	2208988800.0	/* 1970 - 1900 in seconds */

#define PHY_MAX_RECV_DATA_SIZE	(128 * PHY_MEBIBYTE)

/* group internal flag */
#define PHY_INTERNAL_GROUP		1

/* program type */
#define PHY_PROGRAM_TYPE_SERVER		0x01
#define PHY_PROGRAM_TYPE_PROXY_ACTIVE	0x02
#define PHY_PROGRAM_TYPE_PROXY_PASSIVE	0x04
#define PHY_PROGRAM_TYPE_PROXY		0x06	/* PHY_PROGRAM_TYPE_PROXY_ACTIVE | PHY_PROGRAM_TYPE_PROXY_PASSIVE */
#define PHY_PROGRAM_TYPE_AGENTD		0x08
#define PHY_PROGRAM_TYPE_SENDER		0x10
#define PHY_PROGRAM_TYPE_GET		0x20

#ifdef HAVE___VA_ARGS__
#	define phy_dsprintf(dest, fmt, ...) __phy_phy_dsprintf(dest, PHY_CONST_STRING(fmt), ##__VA_ARGS__)
#	define phy_strdcatf(dest, fmt, ...) __phy_phy_strdcatf(dest, PHY_CONST_STRING(fmt), ##__VA_ARGS__)
#else
#	define phy_dsprintf __phy_phy_dsprintf
#	define phy_strdcatf __phy_phy_strdcatf
#endif
char	*__phy_phy_dsprintf(char *dest, const char *f, ...);

#ifdef HAVE___VA_ARGS__
#	define phy_error(fmt, ...) __phy_phy_error(PHY_CONST_STRING(fmt), ##__VA_ARGS__)
#	define phy_snprintf(str, count, fmt, ...) __phy_phy_snprintf(str, count, PHY_CONST_STRING(fmt), ##__VA_ARGS__)
#	define phy_snprintf_alloc(str, alloc_len, offset, fmt, ...) \
       			__phy_phy_snprintf_alloc(str, alloc_len, offset, PHY_CONST_STRING(fmt), ##__VA_ARGS__)
#else
#	define phy_error __phy_phy_error
#	define phy_snprintf __phy_phy_snprintf
#	define phy_snprintf_alloc __phy_phy_snprintf_alloc
#endif

#ifdef HAVE___VA_ARGS__
#	define phy_setproctitle(fmt, ...) __phy_phy_setproctitle(PHY_CONST_STRING(fmt), ##__VA_ARGS__)
#else
#	define phy_setproctitle __phy_phy_setproctitle
#endif


#define PS_PSTAT_ARGV
//#define HAVE_FUNCTION_SETPROCTITLE
#define PS_OVERWRITE_ARGV
void	__phy_phy_setproctitle(const char *fmt, ...);

void	__phy_phy_error(const char *fmt, ...);
char	*phy_strerror(int errnum);
long int	phy_get_thread_id();

#define PHY_MESSAGE_BUF_SIZE	1024

#define strscpy(x, y)	phy_strlcpy(x, y, sizeof(x))
#define strscat(x, y)	phy_strlcat(x, y, sizeof(x))
size_t	phy_strlcpy(char *dst, const char *src, size_t siz);
void	phy_strlcat(char *dst, const char *src, size_t siz);
size_t	phy_strlcpy_utf8(char *dst, const char *src, size_t size);
size_t	__phy_phy_snprintf(char *str, size_t count, const char *fmt, ...);
char	*phy_dvsprintf(char *dest, const char *f, va_list args);

#define get_segment_data(src, spliter, n) __get_segment_data(__FILE__, __LINE__, src, spliter, n);
char* __get_segment_data(const char *filename, int line, const char *src, const char* spliter, int n);
//int	is_leap_year(int year);
size_t	phy_vsnprintf(char *str, size_t count, const char *fmt, va_list args);

/* max length of base64 data */
#define PHY_MAX_B64_LEN		(16 * PHY_KIBIBYTE)

#define phy_free(ptr)		\
				\
do				\
{				\
	if (ptr)		\
	{			\
		free(ptr);	\
		ptr = NULL;	\
	}			\
}				\
while (0)

#define phy_fclose(file)	\
				\
do				\
{				\
	if (file)		\
	{			\
		fclose(file);	\
		file = NULL;	\
	}			\
}				\
while (0)

#ifndef MAX
#	define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#	define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define THIS_SHOULD_NEVER_HAPPEN	phy_error("ERROR [file:%s,line:%d] "				\
							"Something impossible has just happened.",	\
							__FILE__, __LINE__)


#define PHY_SOCKET_COUNT	256
#define PHY_STAT_BUF_LEN	2048

#if defined(HAVE_IPV6)
#	define PHY_SOCKADDR struct sockaddr_storage
#else
#	define PHY_SOCKADDR struct sockaddr_in
#endif

#ifdef _WINDOWS
typedef SOCKET	PHY_SOCKET;
#else
typedef int	PHY_SOCKET;
#endif

typedef enum
{
	PHY_BUF_TYPE_STAT = 0,
	PHY_BUF_TYPE_DYN
}
phy_buf_type_t;

typedef struct
{
	PHY_SOCKET			socket;
	PHY_SOCKET			socket_orig;
	size_t				read_bytes;
	char				*buffer;
	char				*next_line;
#if defined(HAVE_POLARSSL) || defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL)
	phy_tls_context_t		*tls_ctx;
#endif
	unsigned int 			connection_type;	/* type of connection actually established: */
								/* PHY_TCP_SEC_UNENCRYPTED, PHY_TCP_SEC_TLS_PSK or */
								/* PHY_TCP_SEC_TLS_CERT */
	int				timeout;
	phy_buf_type_t			buf_type;
	unsigned char			accepted;
	int				num_socks;
	PHY_SOCKET			sockets[PHY_SOCKET_COUNT];
	char				buf_stat[PHY_STAT_BUF_LEN];
	PHY_SOCKADDR			peer_info;		/* getpeername() result */
	/* Peer host DNS name or IP address for diagnostics (after TCP connection is established). */
	/* TLS connection may be shut down at any time and it will not be possible to get peer IP address anymore. */
	char				peer[MAX_PHY_DNSNAME_LEN + 1];
}
phy_socket_t;

#define ISNLEN(str) (0 != strlen(str) ? true : false)
#define ISNULL(str)	(NULL != str ? ISNLEN(str) : false)
#define NTSTRSTR(str, spt) ((true == ISNULL(str)) ? strstr(str, spt) : NULL)
#define NTCPTEND(str, op) (((true == ISNULL(str)) && (op >= str)) ? (strlen(str) - (op - str)) : false)
#ifdef HAVE___VA_ARGS__
#	define phy_setproctitle(fmt, ...) __phy_phy_setproctitle(PHY_CONST_STRING(fmt), ##__VA_ARGS__)
#else
#	define phy_setproctitle __phy_phy_setproctitle
#endif
void	__phy_phy_setproctitle(const char *fmt, ...);

#define phy_calloc(old, nmemb, size)	phy_calloc2(__FILE__, __LINE__, old, nmemb, size)
#define phy_malloc(old, size)		phy_malloc2(__FILE__, __LINE__, old, size)
#define phy_realloc(src, size)		phy_realloc2(__FILE__, __LINE__, src, size)
#define phy_strdup(old, str)		phy_strdup2(__FILE__, __LINE__, old, str)

#define PHY_STRDUP(var, str)	(var = phy_strdup(var, str))

void    *phy_calloc2(const char *filename, int line, void *old, size_t nmemb, size_t size);
void    *phy_malloc2(const char *filename, int line, void *old, size_t size);
void    *phy_realloc2(const char *filename, int line, void *old, size_t size);
char    *phy_strdup2(const char *filename, int line, char *old, const char *str);


struct strlist{
    char* data;
    struct strlist* next;
};

#define END (char*)NULL
bool matches_any_one_of_the_strings(const char* line, ...);
void	*phy_guaranteed_memset(void *v, int c, size_t n);
void create_strlist(struct strlist** head);
void iterator_strlist(struct strlist* head);
void iterator_strlistah(struct strlist* head);
void destory_strlist(struct strlist* head);
void strlist_add(struct strlist** head, const char* str);

int	phy_rtrim(char *str, const char *charlist);
void	phy_ltrim(char *str, const char *charlist);
int	str2uint64(const char *str, const char *suffixes, uint64_t *value);
void	phy_trim_str_list(char *list, char delimiter);
void	phy_strarr_add(char ***arr, char *ent);
void	phy_strarr_del(char ***arr, char *ent);
const char	*get_program_name(const char *path);
void	phy_alarm_flag_set(void);
void	phy_on_exit(void); /* calls exit() at the end! */
int get_result_str(const char* cmd, char** dst);
int do_ping(const char* ipv4);
int ping_status(char *ip);
int remote_cp(const char* src_file, const char* user, const char* ip, const char* dest_file, const char* password);
int remote_vcp(const char* src_file, const char* user, const char* ip, const char* dest_file, const char* password);
int remote_cp_proxy(const char* src_file, const char* user, const char* ip, const char* proxyusr, const char* proxyip, const char* dest_file, const char* password, const char* proxypass);
int remote_execute(const char* remote_ip, const char* command, const char* user, const char* password);
int remote_execute_fork(const char* remote_ip, const char* command, const char* user, const char* password);
int remote_execute_fork_proxy(const char* remote_ip, const char* command, const char* user, const char* password, const char* proxy_ip, const char* proxy_user, const char* proxy_pass);
void	clean_file(const char* filepath);


///* process type */

#define SYSINFO_RET_OK		0
#define SYSINFO_RET_FAIL	1

#define CF_HAVEPARAMS		0x01
#define CF_MODULE			0x02
#define CF_USERPARAMETER	0x04

#define TRIGGER_RECOVERY_MODE_EXPRESSION		0
#define TRIGGER_RECOVERY_MODE_RECOVERY_EXPRESSION	1
#define TRIGGER_RECOVERY_MODE_NONE			2

#define ITEM_LOGTYPE_INFORMATION	1
#define ITEM_LOGTYPE_WARNING		2
#define ITEM_LOGTYPE_ERROR		4
#define ITEM_LOGTYPE_FAILURE_AUDIT	7
#define ITEM_LOGTYPE_SUCCESS_AUDIT	8
#define ITEM_LOGTYPE_CRITICAL		9
#define ITEM_LOGTYPE_VERBOSE		10

typedef enum
{
	PERM_DENY = 0,
	PERM_READ = 2,
	PERM_READ_WRITE
}
phy_user_permission_t;

typedef enum
{
	ITEM_VALUE_TYPE_FLOAT = 0,
	ITEM_VALUE_TYPE_STR,
	ITEM_VALUE_TYPE_LOG,
	ITEM_VALUE_TYPE_UINT64,
	ITEM_VALUE_TYPE_TEXT,
	/* the number of defined value types */
	ITEM_VALUE_TYPE_MAX,
	ITEM_VALUE_TYPE_NONE,
}
phy_item_value_type_t;

typedef enum
{
	SVC_SSH = 0,
	SVC_LDAP,
	SVC_SMTP,
	SVC_FTP,
	SVC_HTTP,
	SVC_POP,
	SVC_NNTP,
	SVC_IMAP,
	SVC_TCP,
	SVC_AGENT,
	SVC_SNMPv1,
	SVC_SNMPv2c,
	SVC_ICMPPING,
	SVC_SNMPv3,
	SVC_HTTPS,
	SVC_TELNET
}
phy_dservice_type_t;

typedef enum
{
	ALERT_TYPE_MESSAGE = 0,
	ALERT_TYPE_COMMAND
}
phy_alert_type_t;

typedef enum
{
	ALERT_STATUS_NOT_SENT = 0,
	ALERT_STATUS_SENT,
	ALERT_STATUS_FAILED,
	ALERT_STATUS_NEW
}
phy_alert_status_t;

///////////////////////////////////
#define LINELEN 1024
struct cnfinfo{
	char item[LINELEN];
	char belong[PHRASE];
	char dir[LINELEN];
//                      char compl[LINELEN];
	char compf[LINELEN];
	char exe[LINELEN];
	char dist[LINELEN];
	char sorcf[LINELEN];
	char tscal[LINELEN];
	char scanpath[LINELEN];
	char sudo[LINELEN];
	phy_uint64_t   dcont;
	phy_uint       pthds;
	phy_uint64_t   duration;
	char desc[LINELEN];
	char args[LINELEN];
	bool          swch;
};

#define VARIANT_NONE          0
#define VARIANT_UNCR          1
#define VARIANT_UI64          2
#define VARIANT_DOBL          3
#define VARIANT_CARS          4
#define VARIANT_ARRY          5
#define VARIANT_STRC          6

#define unsigned64bitinterger uint64_t
#define doubleprecision       double
#define unsignedchar          unsigned char
#define characterstring       struct mystring
#define stringarray           struct strlist
#define structarray           struct datalist

union variant_data_t{
    unsigned64bitinterger  ui64;
    doubleprecision        dbl;
    unsignedchar           uc;
    characterstring        *ms;
    stringarray            *sl;
    structarray            *stl;
};

struct vriant_t{
    unsigned char type;
    bool 			swch;
    char     	descr[PHRASE];
    union variant_data_t data;
};

struct field_chain{
	struct vriant_t*     field_t;
	char                 descr[PHRASE];
	struct field_chain*  curr;
	struct field_chain*  next;
	uint64_t             fdnum;
	bool                 swch;
};

typedef enum{
	NATIVESECTION=1,
	REMOTESECTION
}cnfsct;

void create_field_chain(struct field_chain** head);
void field_chain_add(struct field_chain** head, struct vriant_t* data, bool swch);
void field_chain_node_copy(struct field_chain** head, struct vriant_t* data, bool swch);
//void field_chain_add(struct field_chain** head, struct vriant_t* data, bool swch);
void field_node_grow(struct field_chain* fhd, const char* fldt, bool swchsta);
void insert_unit_of_item(struct field_chain* fhd, const char* fldt, const char* item, const char* unit, void* data);
void new_data_node(struct field_chain* fhd, const char* fldt, cnfsct dtp, const char* item);
void field_node_delete(struct field_chain* fhd, const char* domain);
void destroy_field_chain(struct field_chain* head);
void iterator_field_chain(struct field_chain* head);
/* escalation statuses */
typedef enum
{
	ESCALATION_STATUS_ACTIVE = 0,
	ESCALATION_STATUS_RECOVERY,	/* only in server code, never in DB, deprecated */
	ESCALATION_STATUS_SLEEP,
	ESCALATION_STATUS_COMPLETED	/* only in server code, never in DB */
}
phy_escalation_status_t;

typedef enum
{
	REQUEST_PARAMETER_TYPE_UNDEFINED = 0,
	REQUEST_PARAMETER_TYPE_STRING,
	REQUEST_PARAMETER_TYPE_ARRAY
}
phy_request_parameter_type_t;

#define PHY_SIZE_T_MAX	(~(size_t)0)

#define is_ushort(str, value) \
	is_uint_n_range(str, PHY_SIZE_T_MAX, value, sizeof(unsigned short), 0x0, 0xFFFF)

#define is_uint32(str, value) \
	is_uint_n_range(str, PHY_SIZE_T_MAX, value, 4, 0x0, 0xFFFFFFFF)

#define is_uint64(str, value) \
	is_uint_n_range(str, PHY_SIZE_T_MAX, value, 8, 0x0, __UINT64_C(0xFFFFFFFFFFFFFFFF))

#define is_uint64_n(str, n, value) \
	is_uint_n_range(str, n, value, 8, 0x0, __UINT64_C(0xFFFFFFFFFFFFFFFF))

#define is_uint31(str, value) \
	is_uint_n_range(str, PHY_SIZE_T_MAX, value, 4, 0x0, 0x7FFFFFFF)

#define is_hex(str, value) \
		is_hex_n_range(str, PHY_SIZE_T_MAX, value, 8, 0x0, __UINT64_C(0xFFFFFFFFFFFFFFFF))

int	is_uhex(const char *str);
char* is_hex_string(const char *str);

#define PHY_MAX_UINT31_1	0x7FFFFFFE
#define is_uint31_1(str, value) \
	is_uint_n_range(str, PHY_SIZE_T_MAX, value, 4, 0x0, PHY_MAX_UINT31_1)

#define PHY_COMPONENT_VERSION(major, minor)	((major << 16) | minor)
#define PHY_COMPONENT_VERSION_MAJOR(version)	(version >> 16)
#define PHY_COMPONENT_VERSION_MINOR(version)	(version & 0xFFFF)

int	phy_number_parse(const char *number, int *len);
int	is_hostname_char(unsigned char c);

#define AGENTFL_SYNCER 0
#define PHYDB_SYNCER 1

typedef struct lnbuf{
	void *data;
	size_t len;
	struct lnbuf* next;
	bool stflg;
}lnbuf;

typedef struct lnbhd{
	lnbuf* lnbl;
	lnbuf* curr;
}lnbhd;

struct datalist{
	void* data;
	int	  len;
	char  descr[PHRASE];
	bool  swch;
	struct datalist* next;
	struct datalist* current;
};

typedef void* ntvdp;
typedef unsigned int ntln;
// ntlst
typedef struct{
	char dsc[64];
	char value[16];
	char units[32];
}metric;

typedef struct{
	char level[8];
	char stage[8];
}group;

//space list
/*         |
   |-{...} |
   |       |-{...} <metric
|--|-------|---- <group
^time
.
|--
*/
/*
|________________________
|		|___       |
.		|_______   |
.		|          |
.				   |
|__                |
|
*/

#define REMOVE_NEWLINE(str, len, nlen) do {	\
		char *src, *dst; 					\
		size_t n = 0;						\
		for(src = dst = str, n = 0; n < len; ++src, ++n){\
			if(*src != '\n'){		 		\
				*dst++ = *src;				\
			}								\
		}									\
		nlen = dst - str;	  				\
}while(0)

#define NTCAT(a, b, c)  a c b
char *__ntcat(char *a, char *b, char *c, ...);
#define ntcat(...)  __ntcat(__VA_ARGS__, NULL)

typedef struct list {
    char *dependency;
    struct list *next;
} list;
//void str_insert_opos(char* dst, size_t pos, const char* ks);
void binary_write_file(const void * data, size_t size, const char* path);
void write_file(const char* filepath, const char* line);
void writes_file(const char* filepath, const char* line, size_t len);
char *string_replace(const char *str, const char *sub_str1, const char *sub_str2);
void create_datalist(struct datalist** head);
void iterator_datalist(struct datalist* head);
void destory_datalist(struct datalist* head);
void destory_datalistp(struct datalist** head);
void datalist_add(struct datalist** head, void* data, size_t len);
void datalist_del(struct datalist** head,  struct datalist** data);
void phy_strarr_init(char ***arr);
void str_to_arr(const char* res, const char* spliter, char*** arr);
void phy_strarr_free(char **arr);
void delete_file(const char* file);
void un_remove_str(register char *str, const char *charlist);
void get_result_strlist(const char* cmd, struct strlist* head, bool display);
void cp_file(const char* srcpath, const char* dstpath);
void insert_content_to_file(const char* filepath, const char* keyline, const char* content);
void insert_content_to_filex(const char* sfilepath, const char* dfilepath, const char* keyline, const char* content);
void clean_dir(const char* dir);
void phy_rm_dir(const char* dir);
char *trim_buf(char *buf);
int	phy_is_utf8(const char *text);
int	is_ip4(const char *ip);
char* insert_string(const char *str, const char *key, const char *insertstr, bool foa);
unsigned int get_pid(const char* keyword);
bool if_finish(const char* keyword);
void percentage(int numerator, int denominator, int* dst);
//char* get_pdir_name(const char* path);
char* get_pdir_name(char* path);
void trave_dir(const char* path, struct strlist** head);
bool phy_isdir(const char* path);
void delete_strlist(struct strlist* head, struct strlist* data);
bool phy_rcmp(const char* rstr, const char* key);
void strlist_delete_p(struct strlist** head, struct strlist** node);
bool strlist_delete_px(struct strlist** head, struct strlist** node);
bool strlist_delete_relkey(struct strlist** head, const char* relkey);
void strlist_reverse(struct strlist** head);
void strlist2file(struct strlist* head, const char* file);
void remove_file(const char* fpath);
typedef void(*pfun)(void* args);
void phy_timer(pfun pf, void* args, int dur);
void phy_fork_timer(pfun pf, void* args, int dur);
void terminate_signal_handler(int sig, siginfo_t *siginfo, void *context);
void phy_set_common_signal_handlers(void);
bool is_exist(const char* file_name);
void* mythread(void* arg);
bool keyword_at_the_end_of_the_string(const char* str, const char* key);
bool keyword_at_the_middle_of_the_string(const char* str, const char* key);
char* string_add(char* str, const char* key);
void strlist_insert_str(struct strlist** head, const char* str, bool flag);
void strlist_reverse(struct strlist** head);
int	phy_strcmp_natural(const char *s1, const char *s2);
unsigned long get_file_size(const char *path);
void uncompress(const char* tagfile, const char* dstdir);
//void file2mem(const char* file, char** content);
void jsonfile2mem(const char* file, char** content);
bool move_nbytes_ahead_of_string(char ** str, size_t n);
void strlist_replace(struct strlist** head, const char* key, const char* str);
void nt_access(const char* path);
int listen_local_port(int*  pport);
int gets_random_number_between_two_numbers(int a, int b);
char* uint64s2ip4(const char* str);
char* ip42uint64s(const char* ipadd);
void move_one_to_right(char** dst, size_t dl, size_t pos);
void str_insert_opos(char** dst, size_t dl, size_t pos, const char* ks);
char* str_joint(const char* s1, ...);
char* nt_fl2string(const char* flpt);
char* labeling_repeat_substring(const char* res, const char* sbstr);
bool is_alphanum(const char* res);
bool is_number(const char* res);
char* get_numbers(const char* res, bool mt);
bool is_placeholder(const char* res);
int find_free_port();
bool matches_strings(const char* line, bool flg, ...);
bool left_search_substring(const char* res, const char* sbs, size_t hmp);
void remove_ansi_escape_sequences(const char *input, char *output);
void remove_ansi_sequences(char *str);
void remove_special_chars(char *str);
//void row_extractor(const char* str, lnbhd** lbhd);
void row_extractor(const char* str, size_t olen, lnbhd** lbhd);
int str_reverse_search(const char * oristr, size_t len, const char * sstr);
void	server_on_exit(void);
void remove_blank_lines(const char *filename);
void remove_null_lines(const char *filename);
bool strlist_delete_tooshort(struct strlist** head, int len);
char* load_filpath(const char* inpath, const char* name);
bool fil_isexist(const char* filnm);
bool fil_remove(const char* filnm);
void print_buffer(const char *buffer, int len);
int custom_strstr(const char *haystack, int haystack_len, const char *needle);
list* check_dependency(const char* add, const char* usr, const char* pwd, const char* prgm);
void free_list(list* head);
void trim(char *str);
bool is_file_empty(const char *filename);
void phy_mkdir(const char* path);
int write_pid(pid_t pid);
//nt list

typedef struct lst{
	char* dat;
	struct lst*  next;
}lst;

typedef struct lvn {
	void* dat;
	size_t len;
	struct lvn*  next;
}lvn;

typedef struct lvh {
	size_t cnt;
	struct lvn*  ent;
	struct lvn*  cur;
}lvh;

typedef void (*lvh_pfun)(void* dat);
lvh* lvh_app(lvh *hed, void* dat, size_t len);
void lvh_fre(lvh *hed);
void lvh_prt(lvh *hed, lvh_pfun pfu);

lst* lst_app(lst *head, const char *s);
//lst* lst_app(lst *head, void* dat, size_t len);
void lst_fre(lst *head);
void lst_prt(lst* p);

typedef struct ntlst ntlst;
struct ntlst{
	char* dsc;
	ntvdp data;
	ntlst* rigt;
	ntln  ln;
	ntlst* next;
};

typedef unsigned long VALUE;

typedef struct ddlx {
    void *data;
    size_t dln;
    struct ddlx* brch;
    struct ddlx* next;
    struct ddlx* prev;
} ddlx;

typedef struct ddlhx {
    ddlx* entr;
    ddlx* tail;
    ddlx* curr;
    ddlx* pos;
    size_t num;
} ddlhx;

typedef struct spo {
	size_t	x;
	size_t	y;
	char*	dat;
} spo;

typedef struct spl {
	spo dat;
	spo	*nex;
} spl;

//typedef struct tab {
//    void *data;
//    size_t dln;
//    spl* brc;
//    spl* nex;
//    spl* pre;
//} tab;

typedef struct tab{
	char* des;
	spo **dat;
}tab;

typedef struct tsh {
    tab* tai;
    tab* cur;
    tab* ent;
    size_t num;
} tsh;

int strcmpx(const char *s1, const char *s2);
char* int2sstr(int num, char* c);

void ddlx_init(ddlhx **dh);
void ddlx_insert_end(ddlhx **dh, ddlx* di);
void ddlx_insert(ddlhx **dh, void* data, size_t len, int flg);
void ddlx_insert_brch(ddlhx **dh, void* data, size_t len, int flg);
void ddlx_destory_node(ddlx *node);
void ddlx_destory(ddlhx *dh);

size_t *stroffstr(const char *str, const char *pat, size_t off, size_t *cnt);
void load_fils(const char* path, ddlhx **dh);
int free_data(void* data, void *arg);
void fre_lins(char **lns);
char **rd_lns(const char *dat);
void fre_lns(char **lines);
#endif
