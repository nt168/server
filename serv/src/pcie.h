#ifndef PCIE_H
#define PCIE_H
#include "common.h"
#include "hashmap.h"
#include "phy_def.h"
#include "nttabs.h"
#include "log.h"
#include "messtype.h"
#include "ntmp.h"
#include "phy_tty.h"
#include "cjson.h"
#include "channel.h"
#include "history.h"

void run_pcie(const char* add, const char* usr, const char* pwd, trandst td);

#endif
