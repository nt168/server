#ifndef PHY_FATAL_H
#define PHY_FATAL_H

#include <signal.h>

//#define PHY_GET_PC
#define PHY_FATAL_LOG_PC_REG_SF		0x0001
#define PHY_FATAL_LOG_BACKTRACE		0x0002
#define PHY_FATAL_LOG_MEM_MAP		0x0004
#define PHY_FATAL_LOG_FULL_INFO		(PHY_FATAL_LOG_PC_REG_SF | PHY_FATAL_LOG_BACKTRACE | PHY_FATAL_LOG_MEM_MAP)

const char	*get_signal_name(int sig);
void	phy_log_fatal_info(void *context, unsigned int flags);

#endif
