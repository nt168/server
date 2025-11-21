#ifndef KPTYPROCESS_H
#define KPTYPROCESS_H

#include <stdbool.h>

#include "kprocess.h"
#include "kptydevice.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    KProcess process;
    KPtyDevice device;
    bool use_utmp;
} KPtyProcess;

void kptyprocess_init(KPtyProcess *process);
void kptyprocess_destroy(KPtyProcess *process);
void kptyprocess_set_use_utmp(KPtyProcess *process, bool value);
bool kptyprocess_use_utmp(const KPtyProcess *process);
KPtyDevice *kptyprocess_device(KPtyProcess *process);

#ifdef __cplusplus
}
#endif

#endif /* KPTYPROCESS_H */
