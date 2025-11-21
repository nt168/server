#include "channel.h"
#include "common.h"
#include "log.h"
#include "messtype.h"
//char* arg_parser(const char* msg, enum MESSAGETYPE);
//
#define arg_parser(msg, intarpro, mstp)	__arg_parser(__FILE__, __LINE__, msg, intarpro, mstp)
char* __arg_parser(const char *cfile, int line, const char* msg, const char* intarpro, mesdet mstp);
//#define arg_validity_check(msg, intarpro, mstp)	__arg_validity_check(__FILE__, __LINE__, msg, intarpro, mstp)
//char* __arg_validity_check(const char *cfile, int line, const char* msg, const char* intarpro, enum MESTYPE mstp);
