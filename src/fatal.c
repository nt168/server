#include "config.h"

#ifdef HAVE_SIGNAL_H
#	if !defined(_GNU_SOURCE)
#		define _GNU_SOURCE
#	endif
#	include <signal.h>
#endif

#ifdef HAVE_SYS_UCONTEXT_H
#	if !defined(_GNU_SOURCE)
#		define _GNU_SOURCE	/* required for getting at program counter */
#	endif
#	include <sys/ucontext.h>
#endif

#ifdef	HAVE_EXECINFO_H
#	include <execinfo.h>
#endif

#include "common.h"
#include "log.h"

#include "fatal.h"

const char	*get_signal_name(int sig)
{
	switch (sig)
	{
		case SIGALRM:	return "SIGALRM";
		case SIGILL:	return "SIGILL";
		case SIGFPE:	return "SIGFPE";
		case SIGSEGV:	return "SIGSEGV";
		case SIGBUS:	return "SIGBUS";
		case SIGQUIT:	return "SIGQUIT";
		case SIGHUP:	return "SIGHUP";
		case SIGINT:	return "SIGINT";
		case SIGTERM:	return "SIGTERM";
		case SIGPIPE:	return "SIGPIPE";
		case SIGUSR1:	return "SIGUSR1";
		case SIGUSR2:	return "SIGUSR2";
		default:	return "unknown";
	}
}

void	phy_backtrace(void)
{
#	define	PHY_BACKTRACE_SIZE	60
#ifdef	HAVE_EXECINFO_H
	char	**bcktrc_syms;
	void	*bcktrc[PHY_BACKTRACE_SIZE];
	int	bcktrc_sz, i;

	phy_log(LOG_LEVEL_CRIT, "=== Backtrace: ===");

	bcktrc_sz = backtrace(bcktrc, PHY_BACKTRACE_SIZE);
	bcktrc_syms = backtrace_symbols(bcktrc, bcktrc_sz);

	if (NULL == bcktrc_syms)
	{
		phy_log(LOG_LEVEL_CRIT, "error in backtrace_symbols(): %s", phy_strerror(errno));

		for (i = 0; i < bcktrc_sz; i++)
			phy_log(LOG_LEVEL_CRIT, "%d: %p", bcktrc_sz - i - 1, bcktrc[i]);
	}
	else
	{
		for (i = 0; i < bcktrc_sz; i++)
			phy_log(LOG_LEVEL_CRIT, "%d: %s", bcktrc_sz - i - 1, bcktrc_syms[i]);

		phy_free(bcktrc_syms);
	}
#else
	phy_log(LOG_LEVEL_CRIT, "backtrace is not available for this platform");
#endif	/* HAVE_EXECINFO_H */
}

void	phy_log_fatal_info(void *context, unsigned int flags)
{
#ifdef	HAVE_SYS_UCONTEXT_H

#if defined(REG_EIP) || defined(REG_RIP)
	ucontext_t	*uctx = (ucontext_t *)context;
#endif

	/* look for GET_PC() macro in sigcontextinfo.h files */
	/* of glibc if you wish to add more CPU architectures */

#	if	defined(REG_EIP)	/* i386 */

#		define PHY_GET_REG(uctx, reg)	(uctx)->uc_mcontext.gregs[reg]
#		define PHY_GET_PC(uctx)		PHY_GET_REG(uctx, REG_EIP)

#	elif	defined(REG_RIP)	/* x86_64 */

#		define PHY_GET_REG(uctx, reg)	(uctx)->uc_mcontext.gregs[reg]
#		define PHY_GET_PC(uctx)		PHY_GET_REG(uctx, REG_RIP)

#	endif

#endif	/* HAVE_SYS_UCONTEXT_H */
//	int	i;
	FILE	*fd;

	phy_log(LOG_LEVEL_CRIT, "====== Fatal information: ======");

	if (0 != (flags & PHY_FATAL_LOG_PC_REG_SF))
	{
#ifdef	HAVE_SYS_UCONTEXT_H

#ifdef	PHY_GET_PC
		/* On 64-bit GNU/Linux PHY_GET_PC() returns 'greg_t' defined as 'long long int' (8 bytes). */
		/* On 32-bit GNU/Linux it is defined as 'int' (4 bytes). To print registers in a common way we print */
		/* them as 'long int' or 'unsigned long int' which is 8 bytes on 64-bit GNU/Linux and 4 bytes on */
		/* 32-bit system. */

		phy_log(LOG_LEVEL_CRIT, "Program counter: %p", (void *)(PHY_GET_PC(uctx)));
		phy_log(LOG_LEVEL_CRIT, "=== Registers: ===");

		for (i = 0; i < NGREG; i++)
		{
			phy_log(LOG_LEVEL_CRIT, "%-7s = %16lx = %20lu = %20ld", get_register_name(i),
					(unsigned long int)(PHY_GET_REG(uctx, i)),
					(unsigned long int)(PHY_GET_REG(uctx, i)),
					(long int)(PHY_GET_REG(uctx, i)));
		}
#ifdef	REG_EBP	/* dump a bit of stack frame for i386 */
		phy_log(LOG_LEVEL_CRIT, "=== Stack frame: ===");

		for (i = 16; i >= 2; i--)
		{
			unsigned int	offset = (unsigned int)i * PHY_PTR_SIZE;

			phy_log(LOG_LEVEL_CRIT, "+0x%02x(%%ebp) = ebp + %2d = %08x = %10u = %11d%s",
					offset, (int)offset,
					*(unsigned int *)((void *)PHY_GET_REG(uctx, REG_EBP) + offset),
					*(unsigned int *)((void *)PHY_GET_REG(uctx, REG_EBP) + offset),
					*(int *)((void *)PHY_GET_REG(uctx, REG_EBP) + offset),
					i == 2 ? " <--- call arguments" : "");
		}
		phy_log(LOG_LEVEL_CRIT, "+0x%02x(%%ebp) = ebp + %2d = %08x%28s<--- return address",
					PHY_PTR_SIZE, (int)PHY_PTR_SIZE,
					*(unsigned int *)((void *)PHY_GET_REG(uctx, REG_EBP) + PHY_PTR_SIZE), "");
		phy_log(LOG_LEVEL_CRIT, "     (%%ebp) = ebp      = %08x%28s<--- saved ebp value",
					*(unsigned int *)((void *)PHY_GET_REG(uctx, REG_EBP)), "");

		for (i = 1; i <= 16; i++)
		{
			unsigned int	offset = (unsigned int)i * PHY_PTR_SIZE;

			phy_log(LOG_LEVEL_CRIT, "-0x%02x(%%ebp) = ebp - %2d = %08x = %10u = %11d%s",
					offset, (int)offset,
					*(unsigned int *)((void *)PHY_GET_REG(uctx, REG_EBP) - offset),
					*(unsigned int *)((void *)PHY_GET_REG(uctx, REG_EBP) - offset),
					*(int *)((void *)PHY_GET_REG(uctx, REG_EBP) - offset),
					i == 1 ? " <--- local variables" : "");
		}
#endif	/* REG_EBP */
#else
		phy_log(LOG_LEVEL_CRIT, "program counter not available for this architecture");
		phy_log(LOG_LEVEL_CRIT, "=== Registers: ===");
		phy_log(LOG_LEVEL_CRIT, "register dump not available for this architecture");
#endif	/* PHY_GET_PC */
#endif	/* HAVE_SYS_UCONTEXT_H */
	}

	if (0 != (flags & PHY_FATAL_LOG_BACKTRACE))
		phy_backtrace();

	if (0 != (flags & PHY_FATAL_LOG_MEM_MAP))
	{
		phy_log(LOG_LEVEL_CRIT, "=== Memory map: ===");

		if (NULL != (fd = fopen("/proc/self/maps", "r")))
		{
			char line[1024];

			while (NULL != fgets(line, sizeof(line), fd))
			{
				if (line[0] != '\0')
					line[strlen(line) - 1] = '\0'; /* remove trailing '\n' */

				phy_log(LOG_LEVEL_CRIT, "%s", line);
			}

			phy_fclose(fd);
		}
		else
			phy_log(LOG_LEVEL_CRIT, "memory map not available for this platform");
	}

#ifdef	PHY_GET_PC
	phy_log(LOG_LEVEL_CRIT, "================================");
	phy_log(LOG_LEVEL_CRIT, "Please consider attaching a disassembly listing to your bug report.");
	phy_log(LOG_LEVEL_CRIT, "This listing can be produced with, e.g., objdump -DSswx %s.", progname);
#endif

	phy_log(LOG_LEVEL_CRIT, "================================");
}
