#include "common.h"
#include "cfg.h"
#include "log.h"
#include "phytypes.h"
#include <stdbool.h>
//#include "comms.h"

extern struct datalist *agentlist;

//char	*CONFIG_FILE		= "../conf/phy_controller.cnf";

char	*CONFIG_LOG_TYPE_STR	= NULL;
int	CONFIG_LOG_TYPE		= LOG_TYPE_UNDEFINED;
char	*CONFIG_LOG_FILE	= NULL;
int	CONFIG_LOG_FILE_SIZE	= 1;
int	CONFIG_ALLOW_ROOT	= 0;
int	CONFIG_TIMEOUT		= 3;

static int	__parse_cfg_file(const char *cfg_file, struct cfg_line *cfg, int level, int optional, int strict, bool rflag);


static int	match_glob(const char *file, const char *pattern)
{
	const char	*f, *g, *p, *q;

	f = file;
	p = pattern;

	while (1)
	{
		/* corner case */

		if ('\0' == *p)
			return '\0' == *f ? SUCCEED : FAIL;

		/* find a set of literal characters */

		while ('*' == *p)
			p++;

		for (q = p; '\0' != *q && '*' != *q; q++)
			;

		/* if literal characters are at the beginning... */

		if (pattern == p)
		{

			if (0 != strncmp(f, p, q - p))

				return FAIL;

			f += q - p;
			p = q;

			continue;
		}

		/* if literal characters are at the end... */

		if ('\0' == *q)
		{
			for (g = f; '\0' != *g; g++)
				;

			if (g - f < q - p)
				return FAIL;

			return 0 == strcmp(g - (q - p), p) ? SUCCEED : FAIL;

		}

		/* if literal characters are in the middle... */

		while (1)
		{
			if ('\0' == *f)
				return FAIL;

			if (0 == strncmp(f, p, q - p))

			{
				f += q - p;
				p = q;

				break;
			}

			f++;
		}
	}
}

static int	parse_glob(const char *glob, char **path, char **pattern)
{
	const char	*p;

	if (NULL == (p = strchr(glob, '*')))
	{
		*path = phy_strdup(NULL, glob);
		*pattern = NULL;

		goto trim;
	}

	if (NULL != strchr(p + 1, PATH_SEPARATOR))
	{
		phy_error("%s: glob pattern should be the last component of the path", glob);
		return FAIL;
	}

	do
	{
		if (glob == p)
		{
			phy_error("%s: path should be absolute", glob);
			return FAIL;
		}

		p--;
	}
	while (PATH_SEPARATOR != *p);

	*path = phy_strdup(NULL, glob);
	(*path)[p - glob] = '\0';

	*pattern = phy_strdup(NULL, p + 1);
trim:

	if (0 != phy_rtrim(*path, "/") && NULL == *pattern)
		*pattern = phy_strdup(NULL, "*");			/* make sure path is a directory */

	if ('\0' == (*path)[0] && '/' == glob[0])			/* retain forward slash for "/" */
	{
		(*path)[0] = '/';
		(*path)[1] = '\0';
	}

	return SUCCEED;
}

static int	parse_cfg_dir(const char *path, const char *pattern, struct cfg_line *cfg, int level, int strict, bool rflag)
{
	DIR		*dir;
	struct dirent	*d;
	phy_stat_t	sb;
	char		*file = NULL;
	int		ret = FAIL;

	if (NULL == (dir = opendir(path)))
	{
		phy_error("%s: %s", path, phy_strerror(errno));
		goto out;
	}

	while (NULL != (d = readdir(dir)))
	{
		file = phy_dsprintf(file, "%s/%s", path, d->d_name);

		if (0 != phy_stat(file, &sb) || 0 == S_ISREG(sb.st_mode))
			continue;

		if (NULL != pattern && SUCCEED != match_glob(d->d_name, pattern))
			continue;

		if (SUCCEED != __parse_cfg_file(file, cfg, level, PHY_CFG_FILE_REQUIRED, strict, rflag))
			goto close;
	}

	ret = SUCCEED;
close:
	if (0 != closedir(dir))
	{
		phy_error("%s: %s", path, phy_strerror(errno));
		ret = FAIL;
	}

	phy_free(file);
out:
	return ret;
}

static int	parse_cfg_object(const char *cfg_file, struct cfg_line *cfg, int level, int strict, bool rflag)
{
	int		ret = FAIL;
	char		*path = NULL, *pattern = NULL;
	phy_stat_t	sb;

	if (SUCCEED != parse_glob(cfg_file, &path, &pattern))
		goto clean;

	if (0 != phy_stat(path, &sb))
	{
		phy_error("%s: %s", path, phy_strerror(errno));
		goto clean;
	}

	if (0 == S_ISDIR(sb.st_mode))
	{
		if (NULL == pattern)
		{
			ret = __parse_cfg_file(path, cfg, level, PHY_CFG_FILE_REQUIRED, strict, rflag);
			goto clean;
		}

		phy_error("%s: base path is not a directory", cfg_file);
		goto clean;
	}

	ret = parse_cfg_dir(path, pattern, cfg, level, strict, rflag);
clean:
	phy_free(pattern);
	phy_free(path);

	return ret;
}

void parse_agentlist(const char* sline, phy_agent_list* ual)
{
	char **arr = NULL;
	phy_strarr_init(&arr);
	str_to_arr(sline, " ", &arr);

	char** stmp = NULL;
	char * line = NULL;
	line = phy_malloc(line, STRING_LEN);
	int i = 0;
	for (stmp = arr; NULL != *stmp; stmp++)
	{
		switch(i)
		{
			case 0:
				phy_snprintf(ual->ipaddr, SHORTPHRASELEN, "%s", *stmp);
				break;
			case 1:
				ual->port = atoi(*stmp);
				break;
			case 2:
				phy_snprintf(ual->user, SHORTPHRASELEN, "%s", *stmp);
				break;
			case 3:
				phy_snprintf(ual->passwd, SHORTPHRASELEN, "%s", *stmp);
				break;
			case 4:
				phy_snprintf(ual->inspath, SHORTPHRASELEN, "%s", *stmp);
//				trim_buf(ual->inspath);
				break;
			case 5:
				phy_snprintf(ual->adpasswd, SHORTPHRASELEN, "%s", *stmp);
				trim_buf(ual->adpasswd);
				break;
			default:
				break;
		}
		i++;
	}
	phy_strarr_free(arr);
	if(i != 6){
		phy_log(LOG_LEVEL_ERR, "%s", "Agent List Conf Err");
		exit(-1);
	}
}

static int	__parse_cfg_file(const char *cfg_file, struct cfg_line *cfg, int level, int optional, int strict, bool rflag)
{
#define PHY_MAX_INCLUDE_LEVEL	10

#define PHY_CFG_LTRIM_CHARS	"\t "
#define PHY_CFG_RTRIM_CHARS	PHY_CFG_LTRIM_CHARS "\r\n"

	FILE		*file;
	int		i, lineno, param_valid;
	char		line[MAX_STRING_LEN + 3], *parameter, *value;
	phy_uint64_t	var;
	size_t		len;
	bool palf = false;

	if (++level > PHY_MAX_INCLUDE_LEVEL)
	{
		phy_error("Recursion detected! Skipped processing of '%s'.", cfg_file);
		return FAIL;
	}

	if (NULL != cfg_file)
	{
		if (NULL == (file = fopen(cfg_file, "r")))
			goto cannot_open;

		for (lineno = 1; NULL != fgets(line, sizeof(line), file); lineno++)
		{
//			printf("%s\n", line);
			if(strstr(line, "Agent List") || palf == true){
				if(palf == false){
					palf = true;
					continue;
				}

				if(rflag == true)
				{
					 //phydb_select(CONFIG_PHY_DB, "serverinfo", "ip,arch,username,userpass");
//					 phydb_2agentlist(CONFIG_PHY_DB, "serverinfo", "ip,arch,username,userpass");
					 fclose(file);
					 return SUCCEED;
				}

				if ('#' == *line || '\0' == *line)
					continue;
				if(rflag == false){
					phy_agent_list ual;
					memset(&ual, 0, sizeof(phy_agent_list));
					parse_agentlist(line, &ual);
					datalist_add(&agentlist, &ual, sizeof(phy_agent_list));
				}
				continue;
			}
			/* check if line length exceeds limit (max. 2048 bytes) */
			len = strlen(line);
			if (MAX_STRING_LEN < len && NULL == strchr("\r\n", line[MAX_STRING_LEN]))
				goto line_too_long;

			phy_ltrim(line, PHY_CFG_LTRIM_CHARS);
			phy_rtrim(line, PHY_CFG_RTRIM_CHARS);

			if ('#' == *line || '\0' == *line)
				continue;

			/* we only support UTF-8 characters in the config file */
			if (SUCCEED != phy_is_utf8(line))
				goto non_utf8;

			parameter = line;
			if (NULL == (value = strchr(line, '=')))
				goto non_key_value;

			*value++ = '\0';

			phy_rtrim(parameter, PHY_CFG_RTRIM_CHARS);
			phy_ltrim(value, PHY_CFG_LTRIM_CHARS);

			phy_log(LOG_LEVEL_DEBUG, "cfg: para: [%s] val [%s]", parameter, value);

			if (0 == strcmp(parameter, "Include"))
			{
				if (FAIL == parse_cfg_object(value, cfg, level, strict, rflag))
				{
					fclose(file);
					goto error;
				}

				continue;
			}

			param_valid = 0;

			for (i = 0; NULL != cfg[i].parameter; i++)
			{
				if (0 != strcmp(cfg[i].parameter, parameter))
					continue;

				param_valid = 1;

				phy_log(LOG_LEVEL_DEBUG, "accepted configuration parameter: '%s' = '%s'",
						parameter, value);

				switch (cfg[i].type)
				{
					case TYPE_INT:
						if (FAIL == str2uint64(value, "KMGT", &var))
							goto incorrect_config;

						if (cfg[i].min > var || (0 != cfg[i].max && var > cfg[i].max))
							goto incorrect_config;

						*((int *)cfg[i].variable) = (int)var;
						break;
					case TYPE_STRING_LIST:
						phy_trim_str_list(value, ',');
//						PHY_FALLTHROUGH;
					case TYPE_STRING:
						*((char **)cfg[i].variable) =
								phy_strdup(*((char **)cfg[i].variable), value);
						break;
					case TYPE_MULTISTRING:
						phy_strarr_add((char ***)cfg[i].variable, value);
						break;
					case TYPE_UINT64:
						if (FAIL == str2uint64(value, "KMGT", &var))
							goto incorrect_config;

						if (cfg[i].min > var || (0 != cfg[i].max && var > cfg[i].max))
							goto incorrect_config;

						*((phy_uint64_t *)cfg[i].variable) = var;
						break;
#if 0
					case TYPE_CUSTOM:
						if (NULL != cfg[i].variable)
						{
							cfg_custom_parameter_parser_t custom_parser =
									(cfg_custom_parameter_parser_t)cfg[i].variable;

							if (SUCCEED != custom_parser(value, &cfg[i]))
								goto incorrect_config;

							continue;
						}
						break;
#endif
					default:
						assert(0);
				}
			}

			if (0 == param_valid && PHY_CFG_STRICT == strict)
				goto unknown_parameter;
		}
		fclose(file);
	}

	if (1 != level)
		return SUCCEED;

	for (i = 0; NULL != cfg[i].parameter; i++)
	{
		if (PARM_MAND != cfg[i].mandatory)
			continue;

		switch (cfg[i].type)
		{
			case TYPE_INT:
				if (0 == *((int *)cfg[i].variable))
					goto missing_mandatory;
				break;
			case TYPE_STRING:
			case TYPE_STRING_LIST:
				if (NULL == (*(char **)cfg[i].variable))
					goto missing_mandatory;
				break;
			default:
				assert(0);
		}
	}

	return SUCCEED;
cannot_open:
	if (PHY_CFG_FILE_REQUIRED != optional)
		return SUCCEED;
	phy_error("cannot open config file \"%s\": %s", cfg_file, phy_strerror(errno));
	goto error;
line_too_long:
	fclose(file);
	phy_error("line %d exceeds %d byte length limit in config file \"%s\"", lineno, MAX_STRING_LEN, cfg_file);
	goto error;
non_utf8:
	fclose(file);
	phy_error("non-UTF-8 character at line %d \"%s\" in config file \"%s\"", lineno, line, cfg_file);
	goto error;
non_key_value:
	fclose(file);
	phy_error("invalid entry \"%s\" (not following \"parameter=value\" notation) in config file \"%s\", line %d",line, cfg_file, lineno);
	goto error;
incorrect_config:
	fclose(file);
	phy_error("wrong value of \"%s\" in config file \"%s\", line %d", cfg[i].parameter, cfg_file, lineno);
	goto error;
unknown_parameter:
	fclose(file);
	return SUCCEED;
	phy_error("unknown parameter \"%s\" in config file \"%s\", line %d", parameter, cfg_file, lineno);
	goto error;
missing_mandatory:
	return SUCCEED;
	phy_error("missing mandatory parameter \"%s\" in config file \"%s\"", cfg[i].parameter, cfg_file);
error:
	exit(EXIT_FAILURE);
}

int	parse_cfg_file(const char *cfg_file, struct cfg_line *cfg, int optional, int strict, bool rflag)
{
	return __parse_cfg_file(cfg_file, cfg, 0, optional, strict, rflag);
}
