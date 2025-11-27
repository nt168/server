#ifndef PHY_CFG_H
#define PHY_CFG_H

//#include "phyalgo.h"
#include "common.h"

#define	TYPE_INT		0
#define	TYPE_STRING		1
#define	TYPE_MULTISTRING	2
#define	TYPE_UINT64		3
#define	TYPE_STRING_LIST	4
#define	TYPE_CUSTOM		5

#define	PARM_OPT	0
#define	PARM_MAND	1

/* config file parsing options */
#define	PHY_CFG_FILE_REQUIRED	0
#define	PHY_CFG_FILE_OPTIONAL	1

#define	PHY_CFG_NOT_STRICT	0
#define	PHY_CFG_STRICT		1

#define PHY_PROXY_HEARTBEAT_FREQUENCY_MAX	SEC_PER_HOUR
#define PHY_PROXY_LASTACCESS_UPDATE_FREQUENCY	5

extern char	*CONFIG_FILE;
extern char	*CONFIG_LOG_TYPE_STR;
extern int	CONFIG_LOG_TYPE;
extern char	*CONFIG_LOG_FILE;
extern int	CONFIG_LOG_FILE_SIZE;
extern int	CONFIG_ALLOW_ROOT;
extern int	CONFIG_TIMEOUT;

struct cfg_line
{
	const char	*parameter;
	void		*variable;
	int		type;
	int		mandatory;
	phy_uint64_t	min;
	phy_uint64_t	max;
};

int	parse_cfg_file(const char *cfg_file, struct cfg_line *cfg, int optional, int strict, bool rflag);

int	check_cfg_feature_int(const char *parameter, int value, const char *feature);
int	check_cfg_feature_str(const char *parameter, const char *value, const char *feature);

#endif
