/*
 *	Configuration functions
 *
 *	Authors:
 *	Antti Tuominen          <ajtuomin@tml.hut.fi>
 *
 *	$Id: s.conf.c 1.3 02/12/11 11:22:05+02:00 antti@traci.mipl.mediapoli.com $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include "mip6.h"

#define UID0 0
#define SYSCTL_DEBUGLEVEL 1
#define SYSCTL_TUNNEL_SL  2

int set_sysctl_int(char *name, int value)
{
	FILE *sctl;
	char entry[1024];

	strcpy(entry, "/proc/sys/");
	strcat(entry, name);

	if (geteuid() != UID0 ) {
		return -EPERM;
	}
	sctl = fopen(entry, "r+");

	if (sctl == NULL)
		return -ENOENT;

	if (fprintf(sctl, "%d", value) <= 0) {
		fclose(sctl);
		return -EIO;
	}
	fclose(sctl);

	return 0;
}

int get_sysctl_int(char *name)
{
	FILE *sctl;
	char entry[1024];
	int rval = 0;

	strcpy(entry, "/proc/sys/");
	strcat(entry, name);

	sctl = fopen(entry, "ro");

	if (sctl == NULL)
		return -ENOENT;

	if (fscanf(sctl, "%d", &rval) <= 0) {
		fclose(sctl);
		return -EIO;
	}
	fclose(sctl);

	return rval;
}
