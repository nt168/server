#include "kptyprocess.h"

void kptyprocess_init(KPtyProcess *process)
{
    if (process == NULL) {
        return;
    }
    kprocess_init(&process->process);
    kptydevice_init(&process->device);
    process->use_utmp = false;
}

void kptyprocess_destroy(KPtyProcess *process)
{
    if (process == NULL) {
        return;
    }
    kptydevice_close(&process->device);
    kprocess_destroy(&process->process);
}

void kptyprocess_set_use_utmp(KPtyProcess *process, bool value)
{
    if (process == NULL) {
        return;
    }
    process->use_utmp = value;
}

bool kptyprocess_use_utmp(const KPtyProcess *process)
{
    return process != NULL && process->use_utmp;
}

KPtyDevice *kptyprocess_device(KPtyProcess *process)
{
    if (process == NULL) {
        return NULL;
    }
    return &process->device;
}
