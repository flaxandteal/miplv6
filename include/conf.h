#ifndef CONF_H
#define CONF_H

#include <netinet/in.h>
#include "mip6.h"

int set_sysctl_int(char *name, int value);
int get_sysctl_int(char *name);

#endif
