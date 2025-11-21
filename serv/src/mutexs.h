#ifndef PHY_MUTEXS_H
#define PHY_MUTEXS_H

//#define HAVE_PTHREAD_PROCESS_SHARED

#ifdef _WINDOWS
#	define PHY_MUTEX_NULL		NULL

#	define PHY_MUTEX_LOG		phy_mutex_create_per_process_name(L"PHY_MUTEX_LOG")
#	define PHY_MUTEX_PERFSTAT	phy_mutex_create_per_process_name(L"PHY_MUTEX_PERFSTAT")

typedef wchar_t * phy_mutex_name_t;
typedef HANDLE phy_mutex_t;
#else	/* not _WINDOWS */
typedef enum
{
	PHY_MUTEX_LOG = 0,
//	PHY_MUTEX_CACHE,
//	PHY_MUTEX_TRENDS,
//	PHY_MUTEX_CACHE_IDS,
//	PHY_MUTEX_SELFMON,
//	PHY_MUTEX_CPUSTATS,
//	PHY_MUTEX_DISKSTATS,
//	PHY_MUTEX_ITSERVICES,
//	PHY_MUTEX_VALUECACHE,
//	PHY_MUTEX_VMWARE,
//	PHY_MUTEX_SQLITE3,
//	PHY_MUTEX_PROCSTAT,
//	PHY_MUTEX_PROXY_HISTORY,
//#ifdef HAVE_VMINFO_T_UPDATES
//	PHY_MUTEX_KSTAT,
//#endif
//	PHY_MUTEX_MODBUS,
//	PHY_MUTEX_TREND_FUNC,
//	/* NOTE: Do not forget to sync changes here with mutex names in diag_add_locks_info()! */
	PHY_MUTEX_COUNT
}
phy_mutex_name_t;

typedef enum
{
	PHY_RWLOCK_CONFIG = 0,
	PHY_RWLOCK_VALUECACHE,
	PHY_RWLOCK_COUNT,
}
phy_rwlock_name_t;

#ifdef HAVE_PTHREAD_PROCESS_SHARED
#	define PHY_MUTEX_NULL			NULL
#	define PHY_RWLOCK_NULL			NULL

#	define phy_rwlock_wrlock(rwlock)	__phy_rwlock_wrlock(__FILE__, __LINE__, rwlock)
#	define phy_rwlock_rdlock(rwlock)	__phy_rwlock_rdlock(__FILE__, __LINE__, rwlock)
#	define phy_rwlock_unlock(rwlock)	__phy_rwlock_unlock(__FILE__, __LINE__, rwlock)

typedef pthread_mutex_t * phy_mutex_t;
typedef pthread_rwlock_t * phy_rwlock_t;

void	__phy_rwlock_wrlock(const char *filename, int line, phy_rwlock_t rwlock);
void	__phy_rwlock_rdlock(const char *filename, int line, phy_rwlock_t rwlock);
void	__phy_rwlock_unlock(const char *filename, int line, phy_rwlock_t rwlock);
void	phy_rwlock_destroy(phy_rwlock_t *rwlock);
void	phy_locks_disable(void);
#else	/* fallback to semaphores if read-write locks are not available */
#	define PHY_RWLOCK_NULL				-1
#	define PHY_MUTEX_NULL				-1

#	define phy_rwlock_wrlock(rwlock)		__phy_mutex_lock(__FILE__, __LINE__, rwlock)
#	define phy_rwlock_rdlock(rwlock)		__phy_mutex_lock(__FILE__, __LINE__, rwlock)
#	define phy_rwlock_unlock(rwlock)		__phy_mutex_unlock(__FILE__, __LINE__, rwlock)
#	define phy_rwlock_destroy(rwlock)		phy_mutex_destroy(rwlock)

typedef int phy_mutex_t;
typedef int phy_rwlock_t;
#endif
int		phy_locks_create(char **error);
int		phy_rwlock_create(phy_rwlock_t *rwlock, phy_rwlock_name_t name, char **error);
phy_mutex_t	phy_mutex_addr_get(phy_mutex_name_t mutex_name);
phy_rwlock_t	phy_rwlock_addr_get(phy_rwlock_name_t rwlock_name);
#endif	/* _WINDOWS */
#	define phy_mutex_lock(mutex)		__phy_mutex_lock(__FILE__, __LINE__, mutex)
#	define phy_mutex_unlock(mutex)		__phy_mutex_unlock(__FILE__, __LINE__, mutex)

int	phy_mutex_create(phy_mutex_t *mutex, phy_mutex_name_t name, char **error);
void	__phy_mutex_lock(const char *filename, int line, phy_mutex_t mutex);
void	__phy_mutex_unlock(const char *filename, int line, phy_mutex_t mutex);
void	phy_mutex_destroy(phy_mutex_t *mutex);

#ifdef _WINDOWS
phy_mutex_name_t	phy_mutex_create_per_process_name(const phy_mutex_name_t prefix);
#endif

#endif	/* PHY_MUTEXS_H */
