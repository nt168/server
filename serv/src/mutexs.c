#include "common.h"
#include "log.h"
#include "mutexs.h"

#	if !HAVE_SEMUN
		union semun
		{
			int			val;	/* value for SETVAL */
			struct semid_ds		*buf;	/* buffer for IPC_STAT & IPC_SET */
			unsigned short int	*array;	/* array for GETALL & SETALL */
			struct seminfo		*__buf;	/* buffer for IPC_INFO */
		};

#		undef HAVE_SEMUN
#		define HAVE_SEMUN 1
#	endif	/* HAVE_SEMUN */

#	include "cfg.h"
//#	include "phythreads.h"

static int		PHY_SEM_LIST_ID;
static unsigned char	mutexes;

int	phy_locks_create(char **error)
{
	union semun	semopts;
	int		i;

	if (-1 == (PHY_SEM_LIST_ID = semget(IPC_PRIVATE, PHY_MUTEX_COUNT + PHY_RWLOCK_COUNT, 0600)))
	{
		*error = phy_dsprintf(*error, "cannot create semaphore set: %s", phy_strerror(errno));
		return FAIL;
	}

	/* set default semaphore value */

	semopts.val = 1;
	for (i = 0; PHY_MUTEX_COUNT + PHY_RWLOCK_COUNT > i; i++)
	{
		if (-1 != semctl(PHY_SEM_LIST_ID, i, SETVAL, semopts))
			continue;

		*error = phy_dsprintf(*error, "cannot initialize semaphore: %s", phy_strerror(errno));

		if (-1 == semctl(PHY_SEM_LIST_ID, 0, IPC_RMID, 0))
			phy_error("cannot remove semaphore set %d: %s", PHY_SEM_LIST_ID, phy_strerror(errno));

		PHY_SEM_LIST_ID = -1;

		return FAIL;
	}
	return SUCCEED;
}

phy_mutex_t	phy_mutex_addr_get(phy_mutex_name_t mutex_name)
{
	return mutex_name;
}

phy_rwlock_t	phy_rwlock_addr_get(phy_rwlock_name_t rwlock_name)
{
	return rwlock_name + PHY_MUTEX_COUNT;
}

int	phy_rwlock_create(phy_rwlock_t *rwlock, phy_rwlock_name_t name, char **error)
{
	PHY_UNUSED(error);
	*rwlock = name + PHY_MUTEX_COUNT;
	mutexes++;
	return SUCCEED;
}

int	phy_mutex_create(phy_mutex_t *mutex, phy_mutex_name_t name, char **error)
{
	PHY_UNUSED(error);
	mutexes++;
	*mutex = name;
	return SUCCEED;
}

void	__phy_mutex_lock(const char *filename, int line, phy_mutex_t mutex)
{

	struct sembuf	sem_lock;

	if (PHY_MUTEX_NULL == mutex)
		return;

	sem_lock.sem_num = mutex;
	sem_lock.sem_op = -1;
	sem_lock.sem_flg = SEM_UNDO;

	while (-1 == semop(PHY_SEM_LIST_ID, &sem_lock, 1))
	{
		if (EINTR != errno)
		{
			phy_error("[file:'%s',line:%d] lock failed: %s", filename, line, phy_strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}

void	__phy_mutex_unlock(const char *filename, int line, phy_mutex_t mutex)
{
	struct sembuf	sem_unlock;

	if (PHY_MUTEX_NULL == mutex)
		return;

	sem_unlock.sem_num = mutex;
	sem_unlock.sem_op = 1;
	sem_unlock.sem_flg = SEM_UNDO;

	while (-1 == semop(PHY_SEM_LIST_ID, &sem_unlock, 1))
	{
		if (EINTR != errno)
		{
			phy_error("[file:'%s',line:%d] unlock failed: %s", filename, line, phy_strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

}

void	phy_mutex_destroy(phy_mutex_t *mutex)
{
	if (0 == --mutexes && -1 == semctl(PHY_SEM_LIST_ID, 0, IPC_RMID, 0))
		phy_error("cannot remove semaphore set %d: %s", PHY_SEM_LIST_ID, phy_strerror(errno));

	*mutex = PHY_MUTEX_NULL;
}

