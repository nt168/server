#include "common.h"
#include "log.h"
#include "mutexs.h"
#include "cfg.h"
#include "phythreads.h"

static char		log_filename[MAX_STRING_LEN];
static int		log_type = LOG_TYPE_UNDEFINED;
static phy_mutex_t	log_access = PHY_MUTEX_NULL;
int			phy_log_level = LOG_LEVEL_WARNING;

extern const char	syslog_app_name[];

#	define LOCK_LOG		lock_log()
#	define UNLOCK_LOG	unlock_log()


#define PHY_MESSAGE_BUF_SIZE	1024

#	define PHY_DEV_NULL	"/dev/null"

#ifndef _WINDOWS
const char	*phy_get_log_level_string(void)
{
	switch (phy_log_level)
	{
		case LOG_LEVEL_EMPTY:
			return "0 (none)";
		case LOG_LEVEL_CRIT:
			return "1 (critical)";
		case LOG_LEVEL_ERR:
			return "2 (error)";
		case LOG_LEVEL_WARNING:
			return "3 (warning)";
		case LOG_LEVEL_DEBUG:
			return "4 (debug)";
		case LOG_LEVEL_TRACE:
			return "5 (trace)";
	}

	THIS_SHOULD_NEVER_HAPPEN;
	exit(EXIT_FAILURE);
}

int	phy_increase_log_level(void)
{
	if (LOG_LEVEL_TRACE == phy_log_level)
		return FAIL;

	phy_log_level = phy_log_level + 1;

	return SUCCEED;
}

int	phy_decrease_log_level(void)
{
	if (LOG_LEVEL_EMPTY == phy_log_level)
		return FAIL;

	phy_log_level = phy_log_level - 1;

	return SUCCEED;
}
#endif

int	phy_redirect_stdio(const char *filename)
{
	const char	default_file[] = PHY_DEV_NULL;
	int		open_flags = O_WRONLY, fd;

	if (NULL != filename && '\0' != *filename)
		open_flags |= O_CREAT | O_APPEND;
	else
		filename = default_file;

	if (-1 == (fd = open(filename, open_flags, 0666)))
	{
		phy_error("cannot open \"%s\": %s", filename, phy_strerror(errno));
		return FAIL;
	}

	fflush(stdout);
	if (-1 == dup2(fd, STDOUT_FILENO))
		phy_error("cannot redirect stdout to \"%s\": %s", filename, phy_strerror(errno));

	fflush(stderr);
	if (-1 == dup2(fd, STDERR_FILENO))
		phy_error("cannot redirect stderr to \"%s\": %s", filename, phy_strerror(errno));

	close(fd);

	if (-1 == (fd = open(default_file, O_RDONLY)))
	{
		phy_error("cannot open \"%s\": %s", default_file, phy_strerror(errno));
		return FAIL;
	}

	if (-1 == dup2(fd, STDIN_FILENO))
		phy_error("cannot redirect stdin to \"%s\": %s", default_file, phy_strerror(errno));

	close(fd);

	return SUCCEED;
}

static void	rotate_log(const char *filename)
{
	phy_stat_t		buf;
	phy_uint64_t		new_size;
	static phy_uint64_t	old_size = PHY_MAX_UINT64; /* redirect stdout and stderr */

	if (0 != phy_stat(filename, &buf))
	{
		phy_redirect_stdio(filename);
		return;
	}

	new_size = buf.st_size;

	if (0 != CONFIG_LOG_FILE_SIZE && (phy_uint64_t)CONFIG_LOG_FILE_SIZE * PHY_MEBIBYTE < new_size)
	{
		char	filename_old[MAX_STRING_LEN];

		strscpy(filename_old, filename);
		phy_strlcat(filename_old, ".old", MAX_STRING_LEN);
		remove(filename_old);

		if (0 != rename(filename, filename_old))
		{
			FILE	*log_file = NULL;

			if (NULL != (log_file = fopen(filename, "w")))
			{
				long		milliseconds;
				struct tm	tm;

				phy_get_time(&tm, &milliseconds, NULL);

				fprintf(log_file, "%6li:%.4d%.2d%.2d:%.2d%.2d%.2d.%03ld"
						" cannot rename log file \"%s\" to \"%s\": %s\n",
						phy_get_thread_id(),
						tm.tm_year + 1900,
						tm.tm_mon + 1,
						tm.tm_mday,
						tm.tm_hour,
						tm.tm_min,
						tm.tm_sec,
						milliseconds,
						filename,
						filename_old,
						phy_strerror(errno));

				fprintf(log_file, "%6li:%.4d%.2d%.2d:%.2d%.2d%.2d.%03ld"
						" Logfile \"%s\" size reached configured limit"
						" LogFileSize but moving it to \"%s\" failed. The logfile"
						" was truncated.\n",
						phy_get_thread_id(),
						tm.tm_year + 1900,
						tm.tm_mon + 1,
						tm.tm_mday,
						tm.tm_hour,
						tm.tm_min,
						tm.tm_sec,
						milliseconds,
						filename,
						filename_old);

				phy_fclose(log_file);

				new_size = 0;
			}
		}
		else
			new_size = 0;
	}

	if (old_size > new_size)
		phy_redirect_stdio(filename);

	old_size = new_size;
}

#ifndef _WINDOWS
static sigset_t	orig_mask;

static void	lock_log(void)
{
	sigset_t	mask;

	/* block signals to prevent deadlock on log file mutex when signal handler attempts to lock log */
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGUSR2);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGHUP);

	if (0 > sigprocmask(SIG_BLOCK, &mask, &orig_mask))
		phy_error("cannot set sigprocmask to block the user signal");

	phy_mutex_lock(log_access);
}

static void	unlock_log(void)
{
	phy_mutex_unlock(log_access);

	if (0 > sigprocmask(SIG_SETMASK, &orig_mask, NULL))
		phy_error("cannot restore sigprocmask");
}
#else
static void	lock_log(void)
{
#ifdef PHY_AGENT
	if (0 == (PHY_MUTEX_LOGGING_DENIED & get_thread_global_mutex_flag()))
#endif
		LOCK_LOG;
}

static void	unlock_log(void)
{
#ifdef PHY_AGENT
	if (0 == (PHY_MUTEX_LOGGING_DENIED & get_thread_global_mutex_flag()))
#endif
		UNLOCK_LOG;
}
#endif

void	phy_handle_log(void)
{
	if (LOG_TYPE_FILE != log_type)
		return;

	LOCK_LOG;

	rotate_log(log_filename);

	UNLOCK_LOG;
}

int	phy_open_log(int type, int level, const char *filename, char **error)
{
	log_type = type;
	phy_log_level = level;

	if (LOG_TYPE_SYSTEM == type)
	{
		openlog(syslog_app_name, LOG_PID, LOG_DAEMON);
	}
	else if (LOG_TYPE_FILE == type)
	{
		FILE	*log_file = NULL;

		if (MAX_STRING_LEN <= strlen(filename))
		{
			*error = phy_strdup(*error, "too long path for logfile");
			return FAIL;
		}

		if (SUCCEED != phy_mutex_create(&log_access, PHY_MUTEX_LOG, error))
			return FAIL;

		if (NULL == (log_file = fopen(filename, "a+")))
		{
			*error = phy_dsprintf(*error, "unable to open log file [%s]: %s", filename, phy_strerror(errno));
			return FAIL;
		}

		strscpy(log_filename, filename);
		phy_fclose(log_file);
	}
	else if (LOG_TYPE_CONSOLE == type || LOG_TYPE_UNDEFINED == type)
	{
		if (SUCCEED != phy_mutex_create(&log_access, PHY_MUTEX_LOG, error))
		{
			*error = phy_strdup(*error, "unable to create mutex for standard output");
			return FAIL;
		}

		fflush(stderr);
		if (-1 == dup2(STDOUT_FILENO, STDERR_FILENO))
			phy_error("cannot redirect stderr to stdout: %s", phy_strerror(errno));
	}
	else
	{
		*error = phy_strdup(*error, "unknown log type");
		return FAIL;
	}

	return SUCCEED;
}

void	phy_close_log(void)
{
	if (LOG_TYPE_SYSTEM == log_type)
	{
		closelog();
	}
	else if (LOG_TYPE_FILE == log_type || LOG_TYPE_CONSOLE == log_type || LOG_TYPE_UNDEFINED == log_type)
	{
		phy_mutex_destroy(&log_access);
	}
}

void	__phy_phy_log(int level, const char *fmt, ...)
{
	char		message[MAX_BUFFER_LEN];
	va_list		args;
	char       title[PHRASE] = {0};

	switch(level)
	{
		case LOG_LEVEL_CRIT:
			phy_strlcat(title, "CRIT  ", PHRASE);
		break;
		case LOG_LEVEL_ERR:
			phy_strlcat(title, "ERR   ", PHRASE);
		break;
		case LOG_LEVEL_WARNING:
			phy_strlcat(title, "WARN  ", PHRASE);
		break;
		case LOG_LEVEL_DEBUG:
			phy_strlcat(title, "DEBUG ", PHRASE);
		break;
		case LOG_LEVEL_TRACE:
			phy_strlcat(title, "TRACE ", PHRASE);
		break;
		default:
			phy_strlcat(title, "UNKNOW", PHRASE);
		break;
    }
#ifndef PHY_PHY_LOG_CHECK
	if (SUCCEED != PHY_CHECK_LOG_LEVEL(level))
		return;
#endif
	if (LOG_TYPE_FILE == log_type)
	{
		FILE	*log_file;

		LOCK_LOG;

		if (0 != CONFIG_LOG_FILE_SIZE)
			rotate_log(log_filename);

		if (NULL != (log_file = fopen(log_filename, "a+")))
		{
			long		milliseconds;
			struct tm	tm;

			phy_get_time(&tm, &milliseconds, NULL);

			fprintf(log_file,
					"[%s]%6li:%.4d%.2d%.2d:%.2d%.2d%.2d.%03ld ",
					title,
					phy_get_thread_id(),
					tm.tm_year + 1900,
					tm.tm_mon + 1,
					tm.tm_mday,
					tm.tm_hour,
					tm.tm_min,
					tm.tm_sec,
					milliseconds
					);

			va_start(args, fmt);
			vfprintf(log_file, fmt, args);
			va_end(args);

			fprintf(log_file, "\n");

			phy_fclose(log_file);
		}
		else
		{
			phy_error("failed to open log file: %s", phy_strerror(errno));

			va_start(args, fmt);
			phy_vsnprintf(message, sizeof(message), fmt, args);
			va_end(args);

			phy_error("failed to write [%s] into log file", message);
		}

		UNLOCK_LOG;

		return;
	}

	if (LOG_TYPE_CONSOLE == log_type)
	{
		long		milliseconds;
		struct tm	tm;

		LOCK_LOG;

		phy_get_time(&tm, &milliseconds, NULL);

		fprintf(stdout,
				"%6li:%.4d%.2d%.2d:%.2d%.2d%.2d.%03ld ",
				phy_get_thread_id(),
				tm.tm_year + 1900,
				tm.tm_mon + 1,
				tm.tm_mday,
				tm.tm_hour,
				tm.tm_min,
				tm.tm_sec,
				milliseconds
				);

		va_start(args, fmt);
		vfprintf(stdout, fmt, args);
		va_end(args);

		fprintf(stdout, "\n");

		fflush(stdout);

		UNLOCK_LOG;

		return;
	}

	va_start(args, fmt);
	phy_vsnprintf(message, sizeof(message), fmt, args);
	va_end(args);

	if (LOG_TYPE_SYSTEM == log_type)
	{
		/* for nice printing into syslog */
		switch (level)
		{
			case LOG_LEVEL_CRIT:
				syslog(LOG_CRIT, "%s", message);
				break;
			case LOG_LEVEL_ERR:
				syslog(LOG_ERR, "%s", message);
				break;
			case LOG_LEVEL_WARNING:
				syslog(LOG_WARNING, "%s", message);
				break;
			case LOG_LEVEL_DEBUG:
			case LOG_LEVEL_TRACE:
				syslog(LOG_DEBUG, "%s", message);
				break;
			case LOG_LEVEL_INFORMATION:
				syslog(LOG_INFO, "%s", message);
				break;
			default:
				/* LOG_LEVEL_EMPTY - print nothing */
				break;
		}
	}	/* LOG_TYPE_SYSLOG */
	else	/* LOG_TYPE_UNDEFINED == log_type */
	{
		LOCK_LOG;

		switch (level)
		{
			case LOG_LEVEL_CRIT:
				phy_error("ERROR: %s", message);
				break;
			case LOG_LEVEL_ERR:
				phy_error("Error: %s", message);
				break;
			case LOG_LEVEL_WARNING:
				phy_error("Warning: %s", message);
				break;
			case LOG_LEVEL_DEBUG:
				phy_error("DEBUG: %s", message);
				break;
			case LOG_LEVEL_TRACE:
				phy_error("TRACE: %s", message);
				break;
			default:
				phy_error("%s", message);
				break;
		}

		UNLOCK_LOG;
	}
}

int	phy_get_log_type(const char *logtype)
{
	const char	*logtypes[] = {PHY_OPTION_LOGTYPE_SYSTEM, PHY_OPTION_LOGTYPE_FILE, PHY_OPTION_LOGTYPE_CONSOLE};
	int		i;

	for (i = 0; i < (int)ARRSIZE(logtypes); i++)
	{
		if (0 == strcmp(logtype, logtypes[i]))
			return i + 1;
	}

	return LOG_TYPE_UNDEFINED;
}

int	phy_validate_log_parameters(PHY_TASK_EX *task)
{
	if (LOG_TYPE_UNDEFINED == CONFIG_LOG_TYPE)
	{
		phy_log(LOG_LEVEL_CRIT, "invalid \"LogType\" configuration parameter: '%s'", CONFIG_LOG_TYPE_STR);
		return FAIL;
	}

	if (LOG_TYPE_CONSOLE == CONFIG_LOG_TYPE && 0 == (task->flags & PHY_TASK_FLAG_FOREGROUND) &&
			PHY_TASK_START == task->task)
	{
		phy_log(LOG_LEVEL_CRIT, "\"LogType\" \"console\" parameter can only be used with the"
				" -f (--foreground) command line option");
		return FAIL;
	}

	if (LOG_TYPE_FILE == CONFIG_LOG_TYPE && (NULL == CONFIG_LOG_FILE || '\0' == *CONFIG_LOG_FILE))
	{
		phy_log(LOG_LEVEL_CRIT, "\"LogType\" \"file\" parameter requires \"LogFile\" parameter to be set");
		return FAIL;
	}

	return SUCCEED;
}

char	*phy_strerror(int errnum)
{
	/* !!! Attention: static !!! Not thread-safe for Win32 */
	static char	utf8_string[PHY_MESSAGE_BUF_SIZE];

	phy_snprintf(utf8_string, sizeof(utf8_string), "[%d] %s", errnum, strerror(errnum));

	return utf8_string;
}

char	*strerror_from_system(unsigned long error)
{
	PHY_UNUSED(error);

	return phy_strerror(errno);
}
