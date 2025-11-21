#ifndef CHANNEL_CLIENT_H
#define CHANNEL_CLIENT_H

#include <stdbool.h>
#include "config.h"
#include "protocol.h"

bool send_mix_history(const struct get_config *cfg, const char *receiver, mesdet detect_type, int timeout_sec);
bool send_ctrlagt_insert(const struct get_config *cfg, const char *addr, const char *user, const char *password, int timeout_sec);

#endif // CHANNEL_CLIENT_H
