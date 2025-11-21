#define _XOPEN_SOURCE 600
#include "konsole_wcwidth.h"

#ifdef HAVE_UTF8PROC
#include <utf8proc.h>
#else
#include <wchar.h>
#endif

int konsole_wcwidth(wchar_t ucs)
{
#ifdef HAVE_UTF8PROC
    utf8proc_category_t category = utf8proc_category(ucs);
    if (category == UTF8PROC_CATEGORY_CO) {
        return 1;
    }
    return utf8proc_charwidth(ucs);
#else
    return wcwidth(ucs);
#endif
}

int string_width(const wchar_t *wstr)
{
    if (wstr == NULL) {
        return 0;
    }
    int width = 0;
    for (size_t i = 0; wstr[i] != L'\0'; ++i) {
        width += konsole_wcwidth(wstr[i]);
    }
    return width;
}
