#include "common.h"
#include "phythreads.h"

int	num_param(const char *p);
int	is_key_char(unsigned char c);
int	get_param(const char *p, int num, char *buf, size_t max_len, phy_request_parameter_type_t *type);
#ifdef HAVE_ICONV
#	include <iconv.h>
#endif

//	printf("%s (Phy) %s\n", title_message, PHY_VERSION);

void	phy_error(const char *fmt, ...)
{
	va_list	args;

	va_start(args, fmt);

	fprintf(stderr, "%s [%li]: ", progname, phy_get_thread_id());
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	fflush(stderr);

	va_end(args);
}

size_t	phy_snprintf(char *str, size_t count, const char *fmt, ...)
{
	size_t	written_len;
	va_list	args;

	va_start(args, fmt);
	written_len = phy_vsnprintf(str, count, fmt, args);
	va_end(args);

	return written_len;
}

void	phy_snprintf_alloc(char **str, size_t *alloc_len, size_t *offset, const char *fmt, ...)
{
	va_list	args;
	size_t	avail_len, written_len;
retry:
	if (NULL == *str)
	{
		va_start(args, fmt);
		*alloc_len = vsnprintf(NULL, 0, fmt, args) + 2;	/* '\0' + one byte to prevent the operation retry */
		va_end(args);
		*offset = 0;
		*str = (char *)phy_malloc(*str, *alloc_len);
	}

	avail_len = *alloc_len - *offset;
	va_start(args, fmt);
	written_len = phy_vsnprintf(*str + *offset, avail_len, fmt, args);
	va_end(args);

	if (written_len == avail_len - 1)
	{
		*alloc_len *= 2;
		*str = (char *)phy_realloc(*str, *alloc_len);

		goto retry;
	}

	*offset += written_len;
}

size_t	phy_vsnprintf(char *str, size_t count, const char *fmt, va_list args)
{
	int	written_len = 0;

	if (0 < count)
	{
		if (0 > (written_len = vsnprintf(str, count, fmt, args)))
			written_len = (int)count - 1;		/* count an output error as a full buffer */
		else
			written_len = MIN(written_len, (int)count - 1);		/* result could be truncated */
	}
	str[written_len] = '\0';	/* always write '\0', even if buffer size is 0 or vsnprintf() error */

	return (size_t)written_len;
}

void	phy_strncpy_alloc(char **str, size_t *alloc_len, size_t *offset, const char *src, size_t n)
{
	if (NULL == *str)
	{
		*alloc_len = n + 1;
		*offset = 0;
		*str = (char *)phy_malloc(*str, *alloc_len);
	}
	else if (*offset + n >= *alloc_len)
	{
		while (*offset + n >= *alloc_len)
			*alloc_len *= 2;
		*str = (char *)phy_realloc(*str, *alloc_len);
	}

	while (0 != n && '\0' != *src)
	{
		(*str)[(*offset)++] = *src++;
		n--;
	}

	(*str)[*offset] = '\0';
}

void	phy_str_memcpy_alloc(char **str, size_t *alloc_len, size_t *offset, const char *src, size_t n)
{
	if (NULL == *str)
	{
		*alloc_len = n + 1;
		*offset = 0;
		*str = (char *)phy_malloc(*str, *alloc_len);
	}
	else if (*offset + n >= *alloc_len)
	{
		while (*offset + n >= *alloc_len)
			*alloc_len *= 2;
		*str = (char *)phy_realloc(*str, *alloc_len);
	}

	memcpy(*str + *offset, src, n);
	*offset += n;
	(*str)[*offset] = '\0';
}

void	phy_strcpy_alloc(char **str, size_t *alloc_len, size_t *offset, const char *src)
{
	phy_strncpy_alloc(str, alloc_len, offset, src, strlen(src));
}

void	phy_chrcpy_alloc(char **str, size_t *alloc_len, size_t *offset, char c)
{
	phy_strncpy_alloc(str, alloc_len, offset, &c, 1);
}

void	phy_strquote_alloc(char **str, size_t *str_alloc, size_t *str_offset, const char *value_str)
{
	size_t		size;
	const char	*src;
	char		*dst;

	for (size = 2, src = value_str; '\0' != *src; src++)
	{
		switch (*src)
		{
			case '\\':
			case '"':
				size++;
		}
		size++;
	}

	if (*str_alloc <= *str_offset + size)
	{
		if (0 == *str_alloc)
			*str_alloc = size;

		do
		{
			*str_alloc *= 2;
		}
		while (*str_alloc - *str_offset <= size);

		*str = phy_realloc(*str, *str_alloc);
	}

	dst = *str + *str_offset;
	*dst++ = '"';

	for (src = value_str; '\0' != *src; src++, dst++)
	{
		switch (*src)
		{
			case '\\':
			case '"':
				*dst++ = '\\';
				break;
		}

		*dst = *src;
	}

	*dst++ = '"';
	*dst = '\0';
	*str_offset += size;
}

/* Has to be rewritten to avoid malloc */
char	*string_replace(const char *str, const char *sub_str1, const char *sub_str2)
{
	char *new_str = NULL;
	const char *p;
	const char *q;
	const char *r;
	char *t;
	long len, diff, count = 0;

	assert(str);
	assert(sub_str1);
	assert(sub_str2);

	len = (long)strlen(sub_str1);

	/* count the number of occurrences of sub_str1 */
	for ( p=str; (p = strstr(p, sub_str1)); p+=len, count++ );

	if (0 == count)
		return phy_strdup(NULL, str);

	diff = (long)strlen(sub_str2) - len;

	/* allocate new memory */
	new_str = (char *)phy_malloc(new_str, (size_t)(strlen(str) + count*diff + 1)*sizeof(char));

        for (q=str,t=new_str,p=str; (p = strstr(p, sub_str1)); )
        {
                /* copy until next occurrence of sub_str1 */
                for ( ; q < p; *t++ = *q++);
                q += len;
                p = q;
                for ( r = sub_str2; (*t++ = *r++); );
                --t;
        }
        /* copy the tail of str */
        for( ; *q ; *t++ = *q++ );

	*t = '\0';
	return new_str;
}

void	del_zeros(char *s)
{
	int	trim = 0;
	size_t	len = 0;

	while ('\0' != s[len])
	{
		if ('e' == s[len] || 'E' == s[len])
		{
			/* don't touch numbers that are written in scientific notation */
			return;
		}

		if ('.' == s[len])
		{
			/* number has decimal part */

			if (1 == trim)
			{
				/* don't touch invalid numbers with more than one decimal separator */
				return;
			}

			trim = 1;
		}

		len++;
	}

	if (1 == trim)
	{
		size_t	i;

		for (i = len - 1; ; i--)
		{
			if ('0' == s[i])
			{
				s[i] = '\0';
			}
			else if ('.' == s[i])
			{
				s[i] = '\0';
				break;
			}
			else
			{
				break;
			}
		}
	}
}

int	phy_rtrim(char *str, const char *charlist)
{
	char	*p;
	int	count = 0;

	if (NULL == str || '\0' == *str)
		return count;

	for (p = str + strlen(str) - 1; p >= str && NULL != strchr(charlist, *p); p--)
	{
		*p = '\0';
		count++;
	}

	return count;
}

void	phy_ltrim(char *str, const char *charlist)
{
	char	*p;

	if (NULL == str || '\0' == *str)
		return;

	for (p = str; '\0' != *p && NULL != strchr(charlist, *p); p++)
		;

	if (p == str)
		return;

	while ('\0' != *p)
		*str++ = *p++;

	*str = '\0';
}

void	phy_lrtrim(char *str, const char *charlist)
{
	phy_rtrim(str, charlist);
	phy_ltrim(str, charlist);
}

void	phy_remove_chars(char *str, const char *charlist)
{
	char	*p;

	if (NULL == str || NULL == charlist || '\0' == *str || '\0' == *charlist)
		return;

	for (p = str; '\0' != *p; p++)
	{
		if (NULL == strchr(charlist, *p))
			*str++ = *p;
	}

	*str = '\0';
}

char	*phy_str_printable_dyn(const char *text)
{
	size_t		out_alloc = 0;
	const char	*pin;
	char		*out, *pout;

	for (pin = text; '\0' != *pin; pin++)
	{
		switch (*pin)
		{
			case '\n':
			case '\t':
			case '\r':
				out_alloc += 2;
				break;
			default:
				out_alloc++;
				break;
		}
	}

	out = phy_malloc(NULL, ++out_alloc);

	for (pin = text, pout = out; '\0' != *pin; pin++)
	{
		switch (*pin)
		{
			case '\n':
				*pout++ = '\\';
				*pout++ = 'n';
				break;
			case '\t':
				*pout++ = '\\';
				*pout++ = 't';
				break;
			case '\r':
				*pout++ = '\\';
				*pout++ = 'r';
				break;
			default:
				*pout++ = *pin;
				break;
		}
	}
	*pout = '\0';

	return out;
}

size_t	phy_strlcpy(char *dst, const char *src, size_t siz)
{
	const char	*s = src;

	if (0 != siz)
	{
		while (0 != --siz && '\0' != *s)
			*dst++ = *s++;

		*dst = '\0';
	}

	return s - src;	/* count does not include null */
}

void	phy_strlcat(char *dst, const char *src, size_t siz)
{
	while ('\0' != *dst)
	{
		dst++;
		siz--;
	}

	phy_strlcpy(dst, src, siz);
}

size_t	phy_strlcpy_utf8(char *dst, const char *src, size_t size)
{
	size = phy_strlen_utf8_nbytes(src, size - 1);
	memcpy(dst, src, size);
	dst[size] = '\0';

	return size;
}

char	*phy_dvsprintf(char *dest, const char *f, va_list args)
{
	char	*string = NULL;
	int	n, size = MAX_STRING_LEN >> 1;

	va_list curr;

	while (1)
	{
		string = (char *)phy_malloc(string, size);

		va_copy(curr, args);
		n = vsnprintf(string, size, f, curr);
		va_end(curr);

		if (0 <= n && n < size)
			break;

		/* result was truncated */
		if (-1 == n)
			size = size * 3 / 2 + 1;	/* the length is unknown */
		else
			size = n + 1;	/* n bytes + trailing '\0' */

		phy_free(string);
	}

	phy_free(dest);

	return string;
}

char	*phy_dsprintf(char *dest, const char *f, ...)
{
	char	*string;
	va_list args;

	va_start(args, f);

	string = phy_dvsprintf(dest, f, args);

	va_end(args);

	return string;
}


char	*phy_strdcat(char *dest, const char *src)
{
	size_t	len_dest, len_src;

	if (NULL == src)
		return dest;

	if (NULL == dest)
		return phy_strdup(NULL, src);

	len_dest = strlen(dest);
	len_src = strlen(src);

	dest = (char *)phy_realloc(dest, len_dest + len_src + 1);

	phy_strlcpy(dest + len_dest, src, len_src + 1);

	return dest;
}


char	*phy_strdcatf(char *dest, const char *f, ...)
{
	char	*string, *result;
	va_list	args;

	va_start(args, f);
	string = phy_dvsprintf(NULL, f, args);
	va_end(args);

	result = phy_strdcat(dest, string);

	phy_free(string);

	return result;
}

int	phy_check_hostname(const char *hostname, char **error)
{
	int	len = 0;

	while ('\0' != hostname[len])
	{
		if (FAIL == is_hostname_char(hostname[len]))
		{
			if (NULL != error)
				*error = phy_dsprintf(NULL, "name contains invalid character '%c'", hostname[len]);
			return FAIL;
		}

		len++;
	}

	if (0 == len)
	{
		if (NULL != error)
			*error = phy_strdup(NULL, "name is empty");
		return FAIL;
	}

	if (MAX_PHY_HOSTNAME_LEN < len)
	{
		if (NULL != error)
			*error = phy_dsprintf(NULL, "name is too long (max %d characters)", MAX_PHY_HOSTNAME_LEN);
		return FAIL;
	}

	return SUCCEED;
}

char	*phy_age2str(int age)
{
	size_t		offset = 0;
	int		days, hours, minutes, seconds;
	static char	buffer[32];

	days = (int)((double)age / SEC_PER_DAY);
	hours = (int)((double)(age - days * SEC_PER_DAY) / SEC_PER_HOUR);
	minutes = (int)((double)(age - days * SEC_PER_DAY - hours * SEC_PER_HOUR) / SEC_PER_MIN);
	seconds = (int)((double)(age - days * SEC_PER_DAY - hours * SEC_PER_HOUR - minutes * SEC_PER_MIN));

	if (0 != days)
		offset += phy_snprintf(buffer + offset, sizeof(buffer) - offset, "%dd ", days);
	if (0 != days || 0 != hours)
		offset += phy_snprintf(buffer + offset, sizeof(buffer) - offset, "%dh ", hours);
	if (0 != days || 0 != hours || 0 != minutes)
		offset += phy_snprintf(buffer + offset, sizeof(buffer) - offset, "%dm ", minutes);

	phy_snprintf(buffer + offset, sizeof(buffer) - offset, "%ds", seconds);

	return buffer;
}

char	*phy_date2str(time_t date, const char *tz)
{
	static char	buffer[11];
	struct tm	*tm;

	tm = phy_localtime(&date, tz);
	phy_snprintf(buffer, sizeof(buffer), "%.4d.%.2d.%.2d",
			tm->tm_year + 1900,
			tm->tm_mon + 1,
			tm->tm_mday);

	return buffer;
}

char	*phy_time2str(time_t time, const char *tz)
{
	static char	buffer[9];
	struct tm	*tm;

	tm = phy_localtime(&time, tz);
	phy_snprintf(buffer, sizeof(buffer), "%.2d:%.2d:%.2d",
			tm->tm_hour,
			tm->tm_min,
			tm->tm_sec);
	return buffer;
}

int	phy_strncasecmp(const char *s1, const char *s2, size_t n)
{
	if (NULL == s1 && NULL == s2)
		return 0;

	if (NULL == s1)
		return 1;

	if (NULL == s2)
		return -1;

	while (0 != n && '\0' != *s1 && '\0' != *s2 &&
			tolower((unsigned char)*s1) == tolower((unsigned char)*s2))
	{
		s1++;
		s2++;
		n--;
	}

	return 0 == n ? 0 : tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
}

char	*phy_strcasestr(const char *haystack, const char *needle)
{
	size_t		sz_h, sz_n;
	const char	*p;

	if (NULL == needle || '\0' == *needle)
		return (char *)haystack;

	if (NULL == haystack || '\0' == *haystack)
		return NULL;

	sz_h = strlen(haystack);
	sz_n = strlen(needle);
	if (sz_h < sz_n)
		return NULL;

	for (p = haystack; p <= &haystack[sz_h - sz_n]; p++)
	{
		if (0 == phy_strncasecmp(p, needle, sz_n))
			return (char *)p;
	}

	return NULL;
}

int	cmp_key_id(const char *key_1, const char *key_2)
{
	const char	*p, *q;

	for (p = key_1, q = key_2; *p == *q && '\0' != *q && '[' != *q; p++, q++)
		;

	return ('\0' == *p || '[' == *p) && ('\0' == *q || '[' == *q) ? SUCCEED : FAIL;
}


const char	*phy_permission_string(int perm)
{
	switch (perm)
	{
		case PERM_DENY:
			return "dn";
		case PERM_READ:
			return "r";
		case PERM_READ_WRITE:
			return "rw";
		default:
			return "unknown";
	}
}


const char	*phy_item_value_type_string(phy_item_value_type_t value_type)
{
	switch (value_type)
	{
		case ITEM_VALUE_TYPE_FLOAT:
			return "Numeric (float)";
		case ITEM_VALUE_TYPE_STR:
			return "Character";
		case ITEM_VALUE_TYPE_LOG:
			return "Log";
		case ITEM_VALUE_TYPE_UINT64:
			return "Numeric (unsigned)";
		case ITEM_VALUE_TYPE_TEXT:
			return "Text";
		default:
			return "unknown";
	}
}


const char	*phy_result_string(int result)
{
	switch (result)
	{
		case SUCCEED:
			return "SUCCEED";
		case FAIL:
			return "FAIL";
		case CONFIG_ERROR:
			return "CONFIG_ERROR";
		case NOTSUPPORTED:
			return "NOTSUPPORTED";
		case NETWORK_ERROR:
			return "NETWORK_ERROR";
		case TIMEOUT_ERROR:
			return "TIMEOUT_ERROR";
		case AGENT_ERROR:
			return "AGENT_ERROR";
		case GATEWAY_ERROR:
			return "GATEWAY_ERROR";
		default:
			return "unknown";
	}
}

const char	*phy_item_logtype_string(unsigned char logtype)
{
	switch (logtype)
	{
		case ITEM_LOGTYPE_INFORMATION:
			return "Information";
		case ITEM_LOGTYPE_WARNING:
			return "Warning";
		case ITEM_LOGTYPE_ERROR:
			return "Error";
		case ITEM_LOGTYPE_FAILURE_AUDIT:
			return "Failure Audit";
		case ITEM_LOGTYPE_SUCCESS_AUDIT:
			return "Success Audit";
		case ITEM_LOGTYPE_CRITICAL:
			return "Critical";
		case ITEM_LOGTYPE_VERBOSE:
			return "Verbose";
		default:
			return "unknown";
	}
}

const char	*phy_escalation_status_string(unsigned char status)
{
	switch (status)
	{
		case ESCALATION_STATUS_ACTIVE:
			return "active";
		case ESCALATION_STATUS_SLEEP:
			return "sleep";
		case ESCALATION_STATUS_COMPLETED:
			return "completed";
		default:
			return "unknown";
	}
}

char	*convert_to_utf8(char *in, size_t in_size, const char *encoding)
{
	iconv_t		cd;
	size_t		in_size_left, out_size_left, sz, out_alloc = 0;
	const char	to_code[] = "UTF-8";
	char		*out = NULL, *p;

	out_alloc = in_size + 1;
	p = out = (char *)phy_malloc(out, out_alloc);

	/* try to guess encoding using BOM if it exists */
	if ('\0' == *encoding)
	{
		if (3 <= in_size && 0 == strncmp("\xef\xbb\xbf", in, 3))
		{
			encoding = "UTF-8";
		}
		else if (2 <= in_size && 0 == strncmp("\xff\xfe", in, 2))
		{
			encoding = "UTF-16LE";
		}
		else if (2 <= in_size && 0 == strncmp("\xfe\xff", in, 2))
		{
			encoding = "UTF-16BE";
		}
	}

	if ('\0' == *encoding || (iconv_t)-1 == (cd = iconv_open(to_code, encoding)))
	{
		memcpy(out, in, in_size);
		out[in_size] = '\0';
		return out;
	}

	in_size_left = in_size;
	out_size_left = out_alloc - 1;

	while ((size_t)(-1) == iconv(cd, &in, &in_size_left, &p, &out_size_left))
	{
		if (E2BIG != errno)
			break;

		sz = (size_t)(p - out);
		out_alloc += in_size;
		out_size_left += in_size;
		p = out = (char *)phy_realloc(out, out_alloc);
		p += sz;
	}

	*p = '\0';

	iconv_close(cd);

	/* remove BOM */
	if (3 <= p - out && 0 == strncmp("\xef\xbb\xbf", out, 3))
		memmove(out, out + 3, (size_t)(p - out - 2));

	return out;
}


size_t	phy_strlen_utf8(const char *text)
{
	size_t	n = 0;

	while ('\0' != *text)
	{
		if (0x80 != (0xc0 & *text++))
			n++;
	}

	return n;
}

char	*phy_strshift_utf8(char *text, size_t num)
{
	while ('\0' != *text && 0 < num)
	{
		if (0x80 != (0xc0 & *(++text)))
			num--;
	}

	return text;
}


size_t	phy_utf8_char_len(const char *text)
{
	if (0 == (*text & 0x80))		/* ASCII */
		return 1;
	else if (0xc0 == (*text & 0xe0))	/* 11000010-11011111 starts a 2-byte sequence */
		return 2;
	else if (0xe0 == (*text & 0xf0))	/* 11100000-11101111 starts a 3-byte sequence */
		return 3;
	else if (0xf0 == (*text & 0xf8))	/* 11110000-11110100 starts a 4-byte sequence */
		return 4;
#if PHY_MAX_BYTES_IN_UTF8_CHAR != 4
#	error "phy_utf8_char_len() is not synchronized with PHY_MAX_BYTES_IN_UTF8_CHAR"
#endif
	return 0;				/* not a valid UTF-8 character */
}


size_t	phy_strlen_utf8_nchars(const char *text, size_t utf8_maxlen)
{
	size_t		sz = 0, csz = 0;
	const char	*next;

	while ('\0' != *text && 0 < utf8_maxlen && 0 != (csz = phy_utf8_char_len(text)))
	{
		next = text + csz;
		while (next > text)
		{
			if ('\0' == *text++)
				return sz;
		}
		sz += csz;
		utf8_maxlen--;
	}

	return sz;
}


size_t	phy_strlen_utf8_nbytes(const char *text, size_t maxlen)
{
	size_t	sz;

	sz = strlen(text);

	if (sz > maxlen)
	{
		sz = maxlen;

		/* ensure that the string is not cut in the middle of UTF-8 sequence */
		while (0x80 == (0xc0 & text[sz]) && 0 < sz)
			sz--;
	}

	return sz;
}


size_t	phy_charcount_utf8_nbytes(const char *text, size_t maxlen)
{
	size_t	n = 0;

	maxlen = phy_strlen_utf8_nbytes(text, maxlen);

	while ('\0' != *text && maxlen > 0)
	{
		if (0x80 != (0xc0 & *text++))
			n++;

		maxlen--;
	}

	return n;
}


int	phy_is_utf8(const char *text)
{
	unsigned int	utf32;
	unsigned char	*utf8;
	size_t		i, mb_len, expecting_bytes = 0;

	while ('\0' != *text)
	{
		/* single ASCII character */
		if (0 == (*text & 0x80))
		{
			text++;
			continue;
		}

		/* unexpected continuation byte or invalid UTF-8 bytes '\xfe' & '\xff' */
		if (0x80 == (*text & 0xc0) || 0xfe == (*text & 0xfe))
			return FAIL;

		/* multibyte sequence */

		utf8 = (unsigned char *)text;

		if (0xc0 == (*text & 0xe0))		/* 2-bytes multibyte sequence */
			expecting_bytes = 1;
		else if (0xe0 == (*text & 0xf0))	/* 3-bytes multibyte sequence */
			expecting_bytes = 2;
		else if (0xf0 == (*text & 0xf8))	/* 4-bytes multibyte sequence */
			expecting_bytes = 3;
		else if (0xf8 == (*text & 0xfc))	/* 5-bytes multibyte sequence */
			expecting_bytes = 4;
		else if (0xfc == (*text & 0xfe))	/* 6-bytes multibyte sequence */
			expecting_bytes = 5;

		mb_len = expecting_bytes + 1;
		text++;

		for (; 0 != expecting_bytes; expecting_bytes--)
		{
			/* not a continuation byte */
			if (0x80 != (*text++ & 0xc0))
				return FAIL;
		}

		/* overlong sequence */
		if (0xc0 == (utf8[0] & 0xfe) ||
				(0xe0 == utf8[0] && 0x00 == (utf8[1] & 0x20)) ||
				(0xf0 == utf8[0] && 0x00 == (utf8[1] & 0x30)) ||
				(0xf8 == utf8[0] && 0x00 == (utf8[1] & 0x38)) ||
				(0xfc == utf8[0] && 0x00 == (utf8[1] & 0x3c)))
		{
			return FAIL;
		}

		utf32 = 0;

		if (0xc0 == (utf8[0] & 0xe0))
			utf32 = utf8[0] & 0x1f;
		else if (0xe0 == (utf8[0] & 0xf0))
			utf32 = utf8[0] & 0x0f;
		else if (0xf0 == (utf8[0] & 0xf8))
			utf32 = utf8[0] & 0x07;
		else if (0xf8 == (utf8[0] & 0xfc))
			utf32 = utf8[0] & 0x03;
		else if (0xfc == (utf8[0] & 0xfe))
			utf32 = utf8[0] & 0x01;

		for (i = 1; i < mb_len; i++)
		{
			utf32 <<= 6;
			utf32 += utf8[i] & 0x3f;
		}

		/* according to the Unicode standard the high and low
		 * surrogate halves used by UTF-16 (U+D800 through U+DFFF)
		 * and values above U+10FFFF are not legal
		 */
		if (utf32 > 0x10ffff || 0xd800 == (utf32 & 0xf800))
			return FAIL;
	}

	return SUCCEED;
}

void	phy_replace_invalid_utf8(char *text)
{
	char	*out = text;

	while ('\0' != *text)
	{
		if (0 == (*text & 0x80))			/* single ASCII character */
			*out++ = *text++;
		else if (0x80 == (*text & 0xc0) ||		/* unexpected continuation byte */
				0xfe == (*text & 0xfe))		/* invalid UTF-8 bytes '\xfe' & '\xff' */
		{
			*out++ = PHY_UTF8_REPLACE_CHAR;
			text++;
		}
		else						/* multibyte sequence */
		{
			unsigned int	utf32;
			unsigned char	*utf8 = (unsigned char *)out;
			size_t		i, mb_len, expecting_bytes = 0;
			int		ret = SUCCEED;

			if (0xc0 == (*text & 0xe0))		/* 2-bytes multibyte sequence */
				expecting_bytes = 1;
			else if (0xe0 == (*text & 0xf0))	/* 3-bytes multibyte sequence */
				expecting_bytes = 2;
			else if (0xf0 == (*text & 0xf8))	/* 4-bytes multibyte sequence */
				expecting_bytes = 3;
			else if (0xf8 == (*text & 0xfc))	/* 5-bytes multibyte sequence */
				expecting_bytes = 4;
			else if (0xfc == (*text & 0xfe))	/* 6-bytes multibyte sequence */
				expecting_bytes = 5;

			*out++ = *text++;

			for (; 0 != expecting_bytes; expecting_bytes--)
			{
				if (0x80 != (*text & 0xc0))	/* not a continuation byte */
				{
					ret = FAIL;
					break;
				}

				*out++ = *text++;
			}

			mb_len = out - (char *)utf8;

			if (SUCCEED == ret)
			{
				if (0xc0 == (utf8[0] & 0xfe) ||	/* overlong sequence */
						(0xe0 == utf8[0] && 0x00 == (utf8[1] & 0x20)) ||
						(0xf0 == utf8[0] && 0x00 == (utf8[1] & 0x30)) ||
						(0xf8 == utf8[0] && 0x00 == (utf8[1] & 0x38)) ||
						(0xfc == utf8[0] && 0x00 == (utf8[1] & 0x3c)))
				{
					ret = FAIL;
				}
			}

			if (SUCCEED == ret)
			{
				utf32 = 0;

				if (0xc0 == (utf8[0] & 0xe0))
					utf32 = utf8[0] & 0x1f;
				else if (0xe0 == (utf8[0] & 0xf0))
					utf32 = utf8[0] & 0x0f;
				else if (0xf0 == (utf8[0] & 0xf8))
					utf32 = utf8[0] & 0x07;
				else if (0xf8 == (utf8[0] & 0xfc))
					utf32 = utf8[0] & 0x03;
				else if (0xfc == (utf8[0] & 0xfe))
					utf32 = utf8[0] & 0x01;

				for (i = 1; i < mb_len; i++)
				{
					utf32 <<= 6;
					utf32 += utf8[i] & 0x3f;
				}

				/* according to the Unicode standard the high and low
				 * surrogate halves used by UTF-16 (U+D800 through U+DFFF)
				 * and values above U+10FFFF are not legal
				 */
				if (utf32 > 0x10ffff || 0xd800 == (utf32 & 0xf800))
					ret = FAIL;
			}

			if (SUCCEED != ret)
			{
				out -= mb_len;
				*out++ = PHY_UTF8_REPLACE_CHAR;
			}
		}
	}

	*out = '\0';
}

static int	utf8_decode_3byte_sequence(const char *ptr, phy_uint32_t *out)
{
	*out = ((unsigned char)*ptr++ & 0xF) << 12;
	if (0x80 != (*ptr & 0xC0))
		return FAIL;

	*out |= ((unsigned char)*ptr++ & 0x3F) << 6;
	if (0x80 != (*ptr & 0xC0))
		return FAIL;

	*out |= ((unsigned char)*ptr & 0x3F);
	return SUCCEED;
}

int	phy_cesu8_to_utf8(const char *cesu8, char **utf8)
{
	const char	*in, *end;
	char		*out;
	size_t		len;

	len = strlen(cesu8);
	out = *utf8 = phy_malloc(*utf8, len + 1);
	end = cesu8 + len;

	for (in = cesu8; in < end;)
	{
		if (0x7f >= (unsigned char)*in)
		{
			*out++ = *in++;
			continue;
		}

		if (0xdf >= (unsigned char)*in)
		{
			if (2 > end - in)
				goto fail;

			*out++ = *in++;
			*out++ = *in++;
			continue;
		}

		if (0xef >= (unsigned char)*in)
		{
			phy_uint32_t	c1, c2, u;

			if (3 > end - in || FAIL == utf8_decode_3byte_sequence(in, &c1))
				goto fail;

			if (0xd800 > c1 || 0xdbff < c1)
			{
				/* normal 3-byte sequence */
				*out++ = *in++;
				*out++ = *in++;
				*out++ = *in++;
				continue;
			}

			/* decode unicode supplementary character represented as surrogate pair */
			in += 3;
			if (3 > end - in || FAIL == utf8_decode_3byte_sequence(in, &c2) || 0xdc00 > c2 || 0xdfff < c2)
				goto fail;

			u = 0x10000 + ((((phy_uint32_t)c1 & 0x3ff) << 10) | (c2 & 0x3ff));
			*out++ = 0xf0 |  u >> 18;
			*out++ = 0x80 | (u >> 12 & 0x3f);
			*out++ = 0x80 | (u >> 6 & 0x3f);
			*out++ = 0x80 | (u & 0x3f);
			in += 3;
			continue;
		}

		/* the four-byte UTF-8 style supplementary character sequence is not supported by CESU-8 */
		goto fail;
	}
	*out = '\0';
	return SUCCEED;
fail:
	phy_free(*utf8);
	return FAIL;
}

void	dos2unix(char *str)
{
	char	*o = str;

	while ('\0' != *str)
	{
		if ('\r' == str[0] && '\n' == str[1])	/* CR+LF (Windows) */
			str++;
		*o++ = *str++;
	}
	*o = '\0';
}

int	is_ascii_string(const char *str)
{
	while ('\0' != *str)
	{
		if (0 != ((1 << 7) & *str))	/* check for range 0..127 */
			return FAIL;

		str++;
	}

	return SUCCEED;
}

char	*str_linefeed(const char *src, size_t maxline, const char *delim)
{
	size_t		src_size, dst_size, delim_size, left;
	int		feeds;		/* number of feeds */
	char		*dst = NULL;	/* output with linefeeds */
	const char	*p_src;
	char		*p_dst;

	assert(NULL != src);
	assert(0 < maxline);

	/* default delimiter */
	if (NULL == delim)
		delim = "\n";

	src_size = strlen(src);
	delim_size = strlen(delim);

	/* make sure we don't feed the last line */
	feeds = (int)(src_size / maxline - (0 != src_size % maxline || 0 == src_size ? 0 : 1));

	left = src_size - feeds * maxline;
	dst_size = src_size + feeds * delim_size + 1;

	/* allocate memory for output */
	dst = (char *)phy_malloc(dst, dst_size);

	p_src = src;
	p_dst = dst;

	/* copy chunks appending linefeeds */
	while (0 < feeds--)
	{
		memcpy(p_dst, p_src, maxline);
		p_src += maxline;
		p_dst += maxline;

		memcpy(p_dst, delim, delim_size);
		p_dst += delim_size;
	}

	if (0 < left)
	{
		/* copy what's left */
		memcpy(p_dst, p_src, left);
		p_dst += left;
	}

	*p_dst = '\0';

	return dst;
}

void	phy_strarr_init(char ***arr)
{
	*arr = (char **)phy_malloc(*arr, sizeof(char *));
	**arr = NULL;
}

void	phy_strarr_add(char ***arr, char *ent)
{
	int	i;

	assert(ent);

	for (i = 0; NULL != (*arr)[i]; i++)
		;

	*arr = (char **)phy_realloc(*arr, sizeof(char *) * (i + 2));

	(*arr)[i] = phy_strdup((*arr)[i], ent);
	(*arr)[++i] = NULL;
}

void	phy_strarr_del(char ***arr, char *ent)
{
	int	i = 0;
	int j = 0;
	int k = 0;
	char** narr = null;
	assert(ent);

	while((*arr)[i]){
		if(ent == (*arr)[i]){
			j = i;
		}
		i++;
	}

	k = i;
	phy_strarr_init(&narr);
	for (i = 0; i < j; i++){
		phy_strarr_add(&narr, (*arr)[i]);
	}

	for (i = j + 1; i < k; i++ ){
		phy_strarr_add(&narr, (*arr)[i]);
	}

	phy_strarr_free(*arr);
	*arr = narr;
}

void	phy_strarr_free(char **arr)
{
	char	**p;

	for (p = arr; NULL != *p; p++)
		phy_free(*p);
	phy_free(arr);
}

void	phy_replace_string(char **data, size_t l, size_t *r, const char *value)
{
	size_t	sz_data, sz_block, sz_value;
	char	*src, *dst;

	sz_value = strlen(value);
	sz_block = *r - l + 1;

	if (sz_value != sz_block)
	{
		sz_data = *r + strlen(*data + *r);
		sz_data += sz_value - sz_block;

		if (sz_value > sz_block)
			*data = (char *)phy_realloc(*data, sz_data + 1);

		src = *data + l + sz_block;
		dst = *data + l + sz_value;

		memmove(dst, src, sz_data - l - sz_value + 1);

		*r = l + sz_value - 1;
	}

	memcpy(&(*data)[l], value, sz_value);
}

void	phy_trim_str_list(char *list, char delimiter)
{
	/* NB! strchr(3): "terminating null byte is considered part of the string" */
	const char	*whitespace = " \t";
	char		*out, *in;

	out = in = list;

	while ('\0' != *in)
	{
		/* trim leading spaces from list item */
		while ('\0' != *in && NULL != strchr(whitespace, *in))
			in++;

		/* copy list item */
		while (delimiter != *in && '\0' != *in)
			*out++ = *in++;

		/* trim trailing spaces from list item */
		if (out > list)
		{
			while (NULL != strchr(whitespace, *(--out)))
				;
			out++;
		}
		if (delimiter == *in)
			*out++ = *in++;
	}
	*out = '\0';
}

int	phy_strcmp_null(const char *s1, const char *s2)
{
	if (NULL == s1)
		return NULL == s2 ? 0 : -1;

	if (NULL == s2)
		return 1;

	return strcmp(s1, s2);
}


void	remove_param(char *param, int num)
{
	int	state = 0;	/* 0 - unquoted parameter, 1 - quoted parameter */
	int	idx = 1, skip_char = 0;
	char	*p;

	for (p = param; '\0' != *p; p++)
	{
		switch (state)
		{
			case 0:			/* in unquoted parameter */
				if (',' == *p)
				{
					if (1 == idx && 1 == num)
						skip_char = 1;
					idx++;
				}
				else if ('"' == *p)
					state = 1;
				break;
			case 1:			/* in quoted parameter */
				if ('"' == *p && '\\' != *(p - 1))
					state = 0;
				break;
		}
		if (idx != num && 0 == skip_char)
			*param++ = *p;

		skip_char = 0;
	}

	*param = '\0';
}

int	str_n_in_list(const char *list, const char *value, size_t len, char delimiter)
{
	const char	*end;
	size_t		token_len, next = 1;

	while ('\0' != *list)
	{
		if (NULL != (end = strchr(list, delimiter)))
		{
			token_len = end - list;
			next = 1;
		}
		else
		{
			token_len = strlen(list);
			next = 0;
		}

		if (len == token_len && 0 == memcmp(list, value, len))
			return SUCCEED;

		list += token_len + next;
	}

	if (1 == next && 0 == len)
		return SUCCEED;

	return FAIL;
}

int	str_in_list(const char *list, const char *value, char delimiter)
{
	return str_n_in_list(list, value, strlen(value), delimiter);
}

int	get_key_param(char *param, int num, char *buf, size_t max_len)
{
	int	ret;
	char	*pl, *pr;

	pl = strchr(param, '[');
	pr = strrchr(param, ']');

	if (NULL == pl || NULL == pr || pl > pr)
		return 1;

	*pr = '\0';
	ret = get_param(pl + 1, num, buf, max_len, NULL);
	*pr = ']';

	return ret;
}

int	num_key_param(char *param)
{
	int	ret;
	char	*pl, *pr;

	if (NULL == param)
		return 0;

	pl = strchr(param, '[');
	pr = strrchr(param, ']');

	if (NULL == pl || NULL == pr || pl > pr)
		return 0;

	*pr = '\0';
	ret = num_param(pl + 1);
	*pr = ']';

	return ret;
}

int	phy_replace_mem_dyn(char **data, size_t *data_alloc, size_t *data_len, size_t offset, size_t sz_to,
		const char *from, size_t sz_from)
{
	size_t	sz_changed = sz_from - sz_to;

	if (0 != sz_changed)
	{
		char	*to;

		*data_len += sz_changed;

		if (*data_len > *data_alloc)
		{
			while (*data_len > *data_alloc)
				*data_alloc *= 2;

			*data = (char *)phy_realloc(*data, *data_alloc);
		}

		to = *data + offset;
		memmove(to + sz_from, to + sz_to, *data_len - (to - *data) - sz_from);
	}

	memcpy(*data + offset, from, sz_from);

	return (int)sz_changed;
}

void	phy_strsplit(const char *src, char delimiter, char **left, char **right)
{
	char	*delimiter_ptr;

	if (NULL == (delimiter_ptr = strchr(src, delimiter)))
	{
		*left = phy_strdup(NULL, src);
		*right = NULL;
	}
	else
	{
		size_t	left_size;
		size_t	right_size;

		left_size = (size_t)(delimiter_ptr - src) + 1;
		right_size = strlen(src) - (size_t)(delimiter_ptr - src);

		*left = phy_malloc(NULL, left_size);
		*right = phy_malloc(NULL, right_size);

		memcpy(*left, src, left_size - 1);
		(*left)[left_size - 1] = '\0';
		memcpy(*right, delimiter_ptr + 1, right_size);
	}
}


static void	phy_trim_number(char *str, int strip_plus_sign)
{
	char	*left = str;			/* pointer to the first character */
	char	*right = strchr(str, '\0') - 1; /* pointer to the last character, not including terminating null-char */

	if (left > right)
	{
		/* string is empty before any trimming */
		return;
	}

	while (' ' == *left)
	{
		left++;
	}

	while (' ' == *right && left < right)
	{
		right--;
	}

	if ('"' == *left && '"' == *right && left < right)
	{
		left++;
		right--;
	}

	if (0 != strip_plus_sign && '+' == *left)
	{
		left++;
	}

	if (left > right)
	{
		/* string is empty after trimming */
		*str = '\0';
		return;
	}

	if (str < left)
	{
		while (left <= right)
		{
			*str++ = *left++;
		}
		*str = '\0';
	}
	else
	{
		*(right + 1) = '\0';
	}
}

void	phy_trim_integer(char *str)
{
	phy_trim_number(str, 1);
}

void	phy_trim_float(char *str)
{
	phy_trim_number(str, 0);
}

int	phy_get_component_version(char *value)
{
	char	*pminor, *ptr;

	if (NULL == (pminor = strchr(value, '.')))
		return FAIL;

	*pminor++ = '\0';

	if (NULL != (ptr = strchr(pminor, '.')))
		*ptr = '\0';

	return PHY_COMPONENT_VERSION(atoi(value), atoi(pminor));
}

int	phy_str_extract(const char *text, size_t len, char **value)
{
	char		*tmp, *out;
	const char	*in;

	tmp = phy_malloc(NULL, len + 1);

	if (0 == len)
	{
		*tmp = '\0';
		*value = tmp;
		return SUCCEED;
	}

	if ('"' != *text)
	{
		memcpy(tmp, text, len);
		tmp[len] = '\0';
		*value = tmp;
		return SUCCEED;
	}

	if (2 > len)
		goto fail;

	for (out = tmp, in = text + 1; '"' != *in; in++)
	{
		if ((size_t)(in - text) >= len - 1)
			goto fail;

		if ('\\' == *in)
		{
			if ((size_t)(++in - text) >= len - 1)
				goto fail;

			if ('"' != *in && '\\' != *in)
				goto fail;
		}
		*out++ = *in;
	}

	if ((size_t)(in - text) != len - 1)
		goto fail;

	*out = '\0';
	*value = tmp;
	return SUCCEED;
fail:
	phy_free(tmp);
	return FAIL;
}

const char	*phy_truncate_itemkey(const char *key, const size_t char_max, char *buf, const size_t buf_len)
{
#	define PHY_SUFFIX	"..."
#	define PHY_BSUFFIX	"[...]"

	size_t	key_byte_count, key_char_total;
	int	is_bracket = 0;
	char	*bracket_l;

	if (char_max >= (key_char_total = phy_strlen_utf8(key)))
		return key;

	if (NULL != (bracket_l = strchr(key, '[')))
		is_bracket = 1;

	if (char_max < PHY_CONST_STRLEN(PHY_SUFFIX) + 2 * is_bracket)	/* [...] or ... */
		return key;

	if (0 != is_bracket)
	{
		size_t	key_char_count, param_char_count, param_byte_count;

		key_char_count = phy_charcount_utf8_nbytes(key, bracket_l - key);
		param_char_count = key_char_total - key_char_count;

		if (param_char_count <= PHY_CONST_STRLEN(PHY_BSUFFIX))
		{
			if (char_max < param_char_count + PHY_CONST_STRLEN(PHY_SUFFIX))
				return key;

			key_byte_count = 1 + phy_strlen_utf8_nchars(key, char_max - param_char_count -
					PHY_CONST_STRLEN(PHY_SUFFIX));
			param_byte_count = 1 + phy_strlen_utf8_nchars(bracket_l, key_char_count);

			if (buf_len < key_byte_count + PHY_CONST_STRLEN(PHY_SUFFIX) + param_byte_count - 1)
				return key;

			key_byte_count = phy_strlcpy_utf8(buf, key, key_byte_count);
			key_byte_count += phy_strlcpy_utf8(&buf[key_byte_count], PHY_SUFFIX, sizeof(PHY_SUFFIX));
			phy_strlcpy_utf8(&buf[key_byte_count], bracket_l, param_byte_count);

			return buf;
		}

		if (key_char_count + PHY_CONST_STRLEN(PHY_BSUFFIX) > char_max)
		{
			if (char_max <= PHY_CONST_STRLEN(PHY_SUFFIX) + PHY_CONST_STRLEN(PHY_BSUFFIX))
				return key;

			key_byte_count = 1 + phy_strlen_utf8_nchars(key, char_max - PHY_CONST_STRLEN(PHY_SUFFIX) -
					PHY_CONST_STRLEN(PHY_BSUFFIX));

			if (buf_len < key_byte_count + PHY_CONST_STRLEN(PHY_SUFFIX) + PHY_CONST_STRLEN(PHY_BSUFFIX))
				return key;

			key_byte_count = phy_strlcpy_utf8(buf, key, key_byte_count);
			key_byte_count += phy_strlcpy_utf8(&buf[key_byte_count], PHY_SUFFIX, sizeof(PHY_SUFFIX));
			phy_strlcpy_utf8(&buf[key_byte_count], PHY_BSUFFIX, sizeof(PHY_BSUFFIX));

			return buf;
		}
	}

	key_byte_count = 1 + phy_strlen_utf8_nchars(key, char_max - (PHY_CONST_STRLEN(PHY_SUFFIX) + is_bracket));

	if (buf_len < key_byte_count + PHY_CONST_STRLEN(PHY_SUFFIX) + is_bracket)
		return key;

	key_byte_count = phy_strlcpy_utf8(buf, key, key_byte_count);
	phy_strlcpy_utf8(&buf[key_byte_count], PHY_SUFFIX, sizeof(PHY_SUFFIX));

	if (0 != is_bracket)
		phy_strlcpy_utf8(&buf[key_byte_count + PHY_CONST_STRLEN(PHY_SUFFIX)], "]", sizeof("]"));

	return buf;

#	undef PHY_SUFFIX
#	undef PHY_BSUFFIX
}

const char	*phy_truncate_value(const char *val, const size_t char_max, char *buf, const size_t buf_len)
{
#	define PHY_SUFFIX	"..."

	size_t	key_byte_count;

	if (char_max >= phy_strlen_utf8(val))
		return val;

	key_byte_count = 1 + phy_strlen_utf8_nchars(val, char_max - PHY_CONST_STRLEN(PHY_SUFFIX));

	if (buf_len < key_byte_count + PHY_CONST_STRLEN(PHY_SUFFIX))
		return val;

	key_byte_count = phy_strlcpy_utf8(buf, val, key_byte_count);
	phy_strlcpy_utf8(&buf[key_byte_count], PHY_SUFFIX, sizeof(PHY_SUFFIX));

	return buf;

#	undef PHY_SUFFIX
}


const char	*phy_print_double(char *buffer, size_t size, double val)
{
	phy_snprintf(buffer, size, "%.15G", val);

	if (atof(buffer) != val)
		phy_snprintf(buffer, size, PHY_FS_DBL64, val);

	return buffer;
}

char	*phy_substr_unquote(const char *src, size_t left, size_t right)
{
	char	*str, *ptr;

	if ('"' == src[left])
	{
		src += left + 1;
		str = phy_malloc(NULL, right - left);
		ptr = str;

		while ('"' != *src)
		{
			if ('\\' == *src)
			{
				switch (*(++src))
				{
					case '\\':
						*ptr++ = '\\';
						break;
					case '"':
						*ptr++ = '"';
						break;
					case '\0':
						THIS_SHOULD_NEVER_HAPPEN;
						*ptr = '\0';
						return str;
				}
			}
			else
				*ptr++ = *src;
			src++;
		}
		*ptr = '\0';
	}
	else
	{
		str = phy_malloc(NULL, right - left + 2);
		memcpy(str, src + left, right - left + 1);
		str[right - left + 1] = '\0';
	}

	return str;
}

char	*phy_substr(const char *src, size_t left, size_t right)
{
	char	*str;

	str = phy_malloc(NULL, right - left + 2);
	memcpy(str, src + left, right - left + 1);
	str[right - left + 1] = '\0';

	return str;
}


int	phy_number_parse(const char *number, int *len)
{
	int	digits = 0, dots = 0;

	*len = 0;

	while (1)
	{
		if (0 != isdigit(number[*len]))
		{
			(*len)++;
			digits++;
			continue;
		}

		if ('.' == number[*len])
		{
			(*len)++;
			dots++;
			continue;
		}

		if ('e' == number[*len] || 'E' == number[*len])
		{
			(*len)++;

			if ('-' == number[*len] || '+' == number[*len])
				(*len)++;

			if (0 == isdigit(number[*len]))
				return FAIL;

			while (0 != isdigit(number[++(*len)]));

			if ('.' == number[*len] ||'e' == number[*len] || 'E' == number[*len])
				return FAIL;
		}

		if (1 > digits || 1 < dots)
			return FAIL;

		return SUCCEED;
	}
}

int	get_param(const char *p, int num, char *buf, size_t max_len, phy_request_parameter_type_t *type)
{
#define PHY_ASSIGN_PARAM				\
{							\
	if (buf_i == max_len)				\
		return 1;	/* buffer overflow */	\
	buf[buf_i++] = *p;				\
}

	int	state;	/* 0 - init, 1 - inside quoted param, 2 - inside unquoted param */
	int	array, idx = 1;
	size_t	buf_i = 0;

	if (NULL != type)
		*type = REQUEST_PARAMETER_TYPE_UNDEFINED;

	if (0 == max_len)
		return 1;	/* buffer overflow */

	max_len--;	/* '\0' */

	for (state = 0, array = 0; '\0' != *p && idx <= num; p++)
	{
		switch (state)
		{
			/* init state */
			case 0:
				if (',' == *p)
				{
					if (0 == array)
						idx++;
					else if (idx == num)
						PHY_ASSIGN_PARAM;
				}
				else if ('"' == *p)
				{
					state = 1;

					if (idx == num)
					{
						if (NULL != type && REQUEST_PARAMETER_TYPE_UNDEFINED == *type)
							*type = REQUEST_PARAMETER_TYPE_STRING;

						if (0 != array)
							PHY_ASSIGN_PARAM;
					}
				}
				else if ('[' == *p)
				{
					if (idx == num)
					{
						if (NULL != type && REQUEST_PARAMETER_TYPE_UNDEFINED == *type)
							*type = REQUEST_PARAMETER_TYPE_ARRAY;

						if (0 != array)
							PHY_ASSIGN_PARAM;
					}
					array++;
				}
				else if (']' == *p && 0 != array)
				{
					array--;
					if (0 != array && idx == num)
						PHY_ASSIGN_PARAM;

					/* skip spaces */
					while (' ' == p[1])
						p++;

					if (',' != p[1] && '\0' != p[1] && (0 == array || ']' != p[1]))
						return 1;	/* incorrect syntax */
				}
				else if (' ' != *p)
				{
					if (idx == num)
					{
						if (NULL != type && REQUEST_PARAMETER_TYPE_UNDEFINED == *type)
							*type = REQUEST_PARAMETER_TYPE_STRING;

						PHY_ASSIGN_PARAM;
					}

					state = 2;
				}
				break;
			case 1:
				/* quoted */

				if ('"' == *p)
				{
					if (0 != array && idx == num)
						PHY_ASSIGN_PARAM;

					/* skip spaces */
					while (' ' == p[1])
						p++;

					if (',' != p[1] && '\0' != p[1] && (0 == array || ']' != p[1]))
						return 1;	/* incorrect syntax */

					state = 0;
				}
				else if ('\\' == *p && '"' == p[1])
				{
					if (idx == num && 0 != array)
						PHY_ASSIGN_PARAM;

					p++;

					if (idx == num)
						PHY_ASSIGN_PARAM;
				}
				else if (idx == num)
					PHY_ASSIGN_PARAM;
				break;
			case 2:
				/* unquoted */

				if (',' == *p || (']' == *p && 0 != array))
				{
					p--;
					state = 0;
				}
				else if (idx == num)
					PHY_ASSIGN_PARAM;
				break;
		}

		if (idx > num)
			break;
	}
#undef PHY_ASSIGN_PARAM

	/* missing terminating '"' character */
	if (1 == state)
		return 1;

	/* missing terminating ']' character */
	if (0 != array)
		return 1;

	buf[buf_i] = '\0';

	if (idx >= num)
		return 0;

	return 1;
}

int	num_param(const char *p)
{
/* 0 - init, 1 - inside quoted param, 2 - inside unquoted param */
	int	ret = 1, state, array;

	if (p == NULL)
		return 0;

	for (state = 0, array = 0; '\0' != *p; p++)
	{
		switch (state) {
		/* Init state */
		case 0:
			if (',' == *p)
			{
				if (0 == array)
					ret++;
			}
			else if ('"' == *p)
				state = 1;
			else if ('[' == *p)
			{
				if (0 == array)
					array = 1;
				else
					return 0;	/* incorrect syntax: multi-level array */
			}
			else if (']' == *p && 0 != array)
			{
				array = 0;

				while (' ' == p[1])	/* skip trailing spaces after closing ']' */
					p++;

				if (',' != p[1] && '\0' != p[1])
					return 0;	/* incorrect syntax */
			}
			else if (']' == *p && 0 == array)
				return 0;		/* incorrect syntax */
			else if (' ' != *p)
				state = 2;
			break;
		/* Quoted */
		case 1:
			if ('"' == *p)
			{
				while (' ' == p[1])	/* skip trailing spaces after closing quotes */
					p++;

				if (',' != p[1] && '\0' != p[1] && (0 == array || ']' != p[1]))
					return 0;	/* incorrect syntax */

				state = 0;
			}
			else if ('\\' == *p && '"' == p[1])
				p++;
			break;
		/* Unquoted */
		case 2:
			if (',' == *p || (']' == *p && 0 != array))
			{
				p--;
				state = 0;
			}
			else if (']' == *p && 0 == array)
				return 0;		/* incorrect syntax */
			break;
		}
	}

	/* missing terminating '"' character */
	if (state == 1)
		return 0;

	/* missing terminating ']' character */
	if (array != 0)
		return 0;

	return ret;
}
