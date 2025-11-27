#ifndef PHY_TYPES_H
#define PHY_TYPES_H
#include "sysinc.h"
#	if !defined(PHY_THREAD_LOCAL)
#		define PHY_THREAD_LOCAL
#	endif


typedef unsigned char 		ucha;
typedef unsigned short int  usho;
typedef unsigned int 		uint;
typedef unsigned long int 	ulon;

typedef __ssize_t			size;
typedef signed char			int8;
typedef unsigned char		uin8;
typedef signed short int 	in16;
typedef unsigned short int 	ui16;
typedef signed int 			in32;
typedef unsigned int 		ui32;
#if __WORDSIZE == 64
typedef signed long int 	in64;
typedef unsigned long int 	ui64;
#else
__extension__ typedef signed long long int in64;
__extension__ typedef unsigned long long int ui64;
#endif

#	define phy_open(pathname, flags)	open(pathname, flags)
#	define PATH_SEPARATOR	'/'

#	define phy_stat(path, buf)		stat(path, buf)
#	define phy_fstat(fd, buf)		fstat(fd, buf)

#	define phy_uint64_t	 uint64_t
#	define PHY_FS_UI64	"%lu"
#	define PHY_FS_UO64	"%lo"
#	define PHY_FS_UX64	"%lx"

#	define phy_int64_t	int64_t
#	define PHY_FS_I64	"%ld"
#	define PHY_FS_O64	"%lo"
#	define PHY_FS_X64	"%lx"

typedef uint32_t	phy_uint32_t;

typedef off_t	phy_offset_t;
#	define phy_lseek(fd, offset, whence)	lseek(fd, (phy_offset_t)(offset), whence)

#define PHY_FS_DBL		"%lf"
#define PHY_FS_DBL_EXT(p)	"%." #p "lf"
#define PHY_FS_DBL64		"%.17G"

#ifdef HAVE_ORACLE
#	define PHY_FS_DBL64_SQL	PHY_FS_DBL64 "d"
#else
#	define PHY_FS_DBL64_SQL	PHY_FS_DBL64
#endif

#define PHY_PTR_SIZE		sizeof(void *)
#define PHY_FS_SIZE_T		PHY_FS_UI64
#define PHY_FS_SSIZE_T		PHY_FS_I64
#define PHY_FS_TIME_T		PHY_FS_I64
#define phy_fs_size_t		phy_uint64_t
#define phy_fs_ssize_t		phy_int64_t
#define phy_fs_time_t		phy_int64_t

#ifndef S_ISREG
#	define S_ISREG(x) (((x) & S_IFMT) == S_IFREG)
#endif

#ifndef S_ISDIR
#	define S_ISDIR(x) (((x) & S_IFMT) == S_IFDIR)
#endif

#define PHY_STR2UINT64(uint, string) is_uint64(string, &uint)
#define PHY_OCT2UINT64(uint, string) sscanf(string, PHY_FS_UO64, &uint)
#define PHY_HEX2UINT64(uint, string) sscanf(string, PHY_FS_UX64, &uint)

#define PHY_STR2UCHAR(var, string) var = (unsigned char)atoi(string)

#define PHY_CONST_STRING(str) "" str
#define PHY_CONST_STRLEN(str) (sizeof(PHY_CONST_STRING(str)) - 1)

typedef struct
{
	phy_uint64_t	lo;
	phy_uint64_t	hi;
}
phy_uint128_t;

#define PHY_SIZE_T_ALIGN8(size)	(((size) + 7) & ~(size_t)7)
#define PHY_IS_TOP_BIT_SET(x)	(0 != ((__UINT64_C(1) << ((sizeof(x) << 3) - 1)) & (x)))
typedef struct phy_variant phy_variant_t;

#endif
