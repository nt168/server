#ifndef KONSOLE_WCWIDTH_H
#define KONSOLE_WCWIDTH_H

#include <stddef.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

int konsole_wcwidth(wchar_t ucs);
int string_width(const wchar_t *wstr);

#ifdef __cplusplus
}
#endif

#endif /* KONSOLE_WCWIDTH_H */
