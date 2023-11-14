/*
 *	Diagnostics functions
 *
 *	Authors:
 *	Antti Tuominen          <ajtuomin@tml.hut.fi>
 *
 *	$Id: s.diag.c 1.7 03/04/08 11:05:15+03:00 anttit@jon.mipl.mediapoli.com $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "diag.h"
#include "mip6.h"

bc_t *get_bc(void)
{
	FILE *bcache;
	bc_t *bc, *e;
	int n = 1, ret = 0;

	bcache = fopen("/proc/net/mip6_bcache", "r");
	if (bcache == NULL)
		return NULL;

	bc = malloc(sizeof(bc_t));
	memset(bc, 0, sizeof(bc_t));
	e = bc;
	while (!feof(bcache)) {
		long int callback_time = 0;
		int type = 0;
		struct in6_addr ha, coa;
		ret = fscanf(bcache, "%8x%8x%8x%8x %8x%8x%8x%8x %ld %d\n",
		       &ha.s6_addr32[0], &ha.s6_addr32[1],
		       &ha.s6_addr32[2], &ha.s6_addr32[3],
		       &coa.s6_addr32[0], &coa.s6_addr32[1],
		       &coa.s6_addr32[2], &coa.s6_addr32[3],
		       &callback_time, &type);
		if (ret == 0) {
			fclose(bcache);
			return NULL;
		}
		if (ret < 0)
			continue;
		e->homeaddr.s6_addr32[0] = htonl(ha.s6_addr32[0]);
		e->homeaddr.s6_addr32[1] = htonl(ha.s6_addr32[1]);
		e->homeaddr.s6_addr32[2] = htonl(ha.s6_addr32[2]);
		e->homeaddr.s6_addr32[3] = htonl(ha.s6_addr32[3]);
		e->careofaddr.s6_addr32[0] = htonl(coa.s6_addr32[0]);
		e->careofaddr.s6_addr32[1] = htonl(coa.s6_addr32[1]);
		e->careofaddr.s6_addr32[2] = htonl(coa.s6_addr32[2]);
		e->careofaddr.s6_addr32[3] = htonl(coa.s6_addr32[3]);
		e->expires = callback_time;
		e->type = type;
		bc = realloc(bc, ++n * sizeof(bc_t));
		e = bc + (n - 1);
		memset(e, 0, sizeof(bc_t));
	}
	fclose(bcache);

	return bc;
}

void free_bc(bc_t *bc)
{
	if (bc == NULL) return;
	free(bc);
}

bu_t *get_bu(void)
{
	FILE *bulist;
	bu_t *bul, *e;
	int n = 1, ret = 0;

	bulist = fopen("/proc/net/mip6_bul", "r");
	if (bulist == NULL)
		return NULL;
	bul = malloc(sizeof(bu_t));
	memset(bul, 0, sizeof(bu_t));
	e = bul;
	while (!feof(bulist)) {
		int seq = 0, sta = 0, del = 0, mdl = 0;
		long int exp = 0, cbs = 0;
		struct in6_addr cna, ha, coa;

		ret = fscanf(bulist, "%8x%8x%8x%8x %8x%8x%8x%8x %8x%8x%8x%8x\n%ld %d %d %d %d %ld\n",
			     &cna.s6_addr32[0], &cna.s6_addr32[1],
			     &cna.s6_addr32[2], &cna.s6_addr32[3],
			     &ha.s6_addr32[0], &ha.s6_addr32[1],
			     &ha.s6_addr32[2], &ha.s6_addr32[3],
			     &coa.s6_addr32[0], &coa.s6_addr32[1],
			     &coa.s6_addr32[2], &coa.s6_addr32[3],
			     &exp, &seq, &sta, &del, &mdl, &cbs);
		if (ret == 0) {
			fclose(bulist);
			return NULL;
		}
		if (ret < 0)
			continue;
		e->rcptaddr.s6_addr32[0] = htonl(cna.s6_addr32[0]);
		e->rcptaddr.s6_addr32[1] = htonl(cna.s6_addr32[1]);
		e->rcptaddr.s6_addr32[2] = htonl(cna.s6_addr32[2]);
		e->rcptaddr.s6_addr32[3] = htonl(cna.s6_addr32[3]);
		e->homeaddr.s6_addr32[0] = htonl(ha.s6_addr32[0]);
		e->homeaddr.s6_addr32[1] = htonl(ha.s6_addr32[1]);
		e->homeaddr.s6_addr32[2] = htonl(ha.s6_addr32[2]);
		e->homeaddr.s6_addr32[3] = htonl(ha.s6_addr32[3]);
		e->careofaddr.s6_addr32[0] = htonl(coa.s6_addr32[0]);
		e->careofaddr.s6_addr32[1] = htonl(coa.s6_addr32[1]);
		e->careofaddr.s6_addr32[2] = htonl(coa.s6_addr32[2]);
		e->careofaddr.s6_addr32[3] = htonl(coa.s6_addr32[3]);

		e->expires = exp;
		e->seq = seq;
		e->state = sta;
		e->delay = del;
		e->maxdelay = mdl;
		e->cb_time = cbs;

		bul = realloc(bul, ++n * sizeof(bu_t));
		e = bul + (n - 1);
		memset(e, 0, sizeof(bu_t));
	}
	fclose(bulist);

	return bul;
}

void free_bu(bu_t *bu)
{
	if (bu == NULL) return;
	free(bu);
}

stat_t *get_stat(void)
{
	stat_t *stat, *e;
	FILE *stats;
	int n = 1, ret = 0;

	stats = fopen("/proc/net/mip6_stat", "r");
	if (stats == NULL)
		return NULL;
	stat = malloc(sizeof(stat_t));
	if (stat == NULL)
		return NULL;
	memset(stat, 0, sizeof(stat_t));
	e = stat;
	while (!feof(stats)) {
		ret = fscanf(stats, "%s = %lu\n", e->name, &e->value);
		if (ret == 0) {
			fclose(stats);
			return NULL;
		}
		if (ret < 0)
			continue;
		stat = realloc(stat, ++n * sizeof(stat_t));
		if (stat == NULL)
			return NULL;
		e = stat + (n - 1);
		memset(e, 0, sizeof(stat_t));
	}
	fclose(stats);

	return stat;
}

void free_stat(stat_t *stat)
{
	if (stat == NULL) return;
	free(stat);
}

ha_t *get_ha(void)
{
	FILE *hal;
	ha_t *ha, *e;
	int n = 1, ret = 0;

	hal = fopen("/proc/net/mip6_home_agents", "r");
	if (hal == NULL)
		return NULL;

	ha = malloc(sizeof(ha_t));
	memset(ha, 0, sizeof(ha_t));
	e = ha;
	while (!feof(hal)) {
		struct in6_addr gl, ll;
		ret = fscanf(hal, "%d %8x%8x%8x%8x %8x%8x%8x%8x %d %ld\n",
		       &e->ifindex, 
		       &gl.s6_addr32[0], &gl.s6_addr32[1], 
		       &gl.s6_addr32[2], &gl.s6_addr32[3],
		       &ll.s6_addr32[0], &ll.s6_addr32[1], 
		       &ll.s6_addr32[2], &ll.s6_addr32[3],
		       &e->preference, &e->expire);
		if (ret == 0) {
			fclose(hal);
			return NULL;
		}
		if (ret < 0)
			continue;
		e->global_addr.s6_addr32[0] = htonl(gl.s6_addr32[0]);
		e->global_addr.s6_addr32[1] = htonl(gl.s6_addr32[1]);
		e->global_addr.s6_addr32[2] = htonl(gl.s6_addr32[2]);
		e->global_addr.s6_addr32[3] = htonl(gl.s6_addr32[3]);
		e->link_local_addr.s6_addr32[0] = htonl(ll.s6_addr32[0]);
		e->link_local_addr.s6_addr32[1] = htonl(ll.s6_addr32[1]);
		e->link_local_addr.s6_addr32[2] = htonl(ll.s6_addr32[2]);
		e->link_local_addr.s6_addr32[3] = htonl(ll.s6_addr32[3]);
		ha = realloc(ha, ++n * sizeof(ha_t));
		e = ha + (n - 1);
		memset(e, 0, sizeof(ha_t));
	}
	fclose(hal);

	return ha;
}

void free_ha(ha_t *ha)
{
	if (ha == NULL) return;
	free(ha);
}

struct mn_info_ext *get_mninfo(void)
{
	FILE *mns;
	struct mn_info_ext *mn, *e;
	int n = 1, ret = 0;

	mns = fopen("/proc/net/mip6_mninfo", "r");
	if (mns == NULL)
		return NULL;

	mn = malloc(sizeof(*mn));
	if (mn == NULL)
		return NULL;
	memset(mn, 0, sizeof(*mn));
	e = mn;

	while (!feof(mns)) {
		struct in6_addr h, ha;
		int p, ho, r;
		ret = fscanf(mns, "%d %8x%8x%8x%8x %x %8x%8x%8x%8x %d %d\n",
			     &e->ifindex,
			     &h.s6_addr32[0], &h.s6_addr32[1], 
			     &h.s6_addr32[2], &h.s6_addr32[3], &p,
			     &ha.s6_addr32[0], &ha.s6_addr32[1], 
			     &ha.s6_addr32[2], &ha.s6_addr32[3],
			     &ho, &r);
		if (ret == 0) {
			fclose(mns);
			return NULL;
		}
		if (ret < 0)
			continue;
		e->home_plen = p;
		e->is_at_home = ho;
		e->has_home_reg = r;
		e->home_addr.s6_addr32[0] = htonl(h.s6_addr32[0]);
		e->home_addr.s6_addr32[1] = htonl(h.s6_addr32[1]);
		e->home_addr.s6_addr32[2] = htonl(h.s6_addr32[2]);
		e->home_addr.s6_addr32[3] = htonl(h.s6_addr32[3]);
		e->ha.s6_addr32[0] = htonl(ha.s6_addr32[0]);
		e->ha.s6_addr32[1] = htonl(ha.s6_addr32[1]);
		e->ha.s6_addr32[2] = htonl(ha.s6_addr32[2]);
		e->ha.s6_addr32[3] = htonl(ha.s6_addr32[3]);
		mn = realloc(mn, ++n * sizeof(struct mn_info_ext));
		e = mn + (n - 1);
		memset(e, 0, sizeof(struct mn_info_ext));
	}
	fclose(mns);

	return mn;
}

void free_mninfo(struct mn_info_ext *mn)
{
	if (mn == NULL) return;
	free(mn);
}

struct ma_if_info *get_iface(void)
{
	FILE *ifs;
	struct ma_if_info *iface, *e;
	int flag_r = 0, flag_c = 0;
	int n = 1, ret = 0;

	ifs = fopen("/proc/net/mip6_iface", "r");
	if (ifs == NULL)
		return NULL;

	iface = malloc(sizeof(struct ma_if_info));
	if (iface == NULL)
		return NULL;
	memset(iface, 0, sizeof(struct ma_if_info));
	e = iface;
	
	while (!feof(ifs)) {
		ret = fscanf(ifs, "%02d %010d %1d %1d\n", &e->interface_id,
			     &e->preference, &flag_r, &flag_c);
		e->status |= flag_r ? MA_IFACE_HAS_ROUTER : 0;
		e->status |= flag_c ? MA_IFACE_CURRENT : 0;

		if (ret == 0) {
			fclose(ifs);
			return NULL;
		}
		if (ret < 0)
			continue;

		iface = realloc(iface, ++n * sizeof(struct ma_if_info));
		if (iface == NULL)
			return NULL;
		e = iface + (n - 1);
		memset(e, 0, sizeof(struct ma_if_info));
	}

	fclose(ifs);
	return iface;
}

void free_iface(struct ma_if_info *iface)
{
	if (iface == NULL) return;
	free(iface);
}

int dump_ha(void (*format)(ha_t *entry))
{
	ha_t *hal, *e;

	hal = get_ha();
	if (hal == NULL)
		return -ENOENT;
	e = hal;

	while (e->ifindex > 0) {
		format(e++);
	}
	free_ha(hal);
	hal = e = NULL;
	return 0;
}

int dump_bc(void (*format)(bc_t *entry))
{
	bc_t *bcache, *e;

	bcache = get_bc();
	if (bcache == NULL)
		return -ENOENT;
	e = bcache;

	while (!IN6_IS_ADDR_UNSPECIFIED(&e->homeaddr)) {
		format(e++);
	}
	free_bc(bcache);
	bcache = e = NULL;
	return 0;
}

int dump_bu(void (*format)(bu_t *entry))
{
	bu_t *bul, *e;

	bul = get_bu();
	if (bul == NULL) 
		return -ENOENT;
	e = bul;

	while (!IN6_IS_ADDR_UNSPECIFIED(&e->rcptaddr)) {
		format(e++);
	}
	free_bu(bul);
	bul = e = NULL;
	return 0;
}

int dump_mninfo(void (*format)(struct mn_info_ext *entry))
{
	struct mn_info_ext *mn, *e;

	mn = get_mninfo();
	if (mn == NULL)
		return -ENOENT;
	e = mn;

	while (!IN6_IS_ADDR_UNSPECIFIED(&e->home_addr)) {
		format(e++);
	}
	free_mninfo(mn);
	mn = e = NULL;
	return 0;
}

int dump_stat(void (*format)(stat_t *entry))
{
	stat_t *stats, *e;

	stats = get_stat();
	if (stats == NULL) 
		return -ENOENT;
	e = stats;

	while (strlen(e->name) > 0) {
		format(e++);
	}
	free_stat(stats);
	stats = e = NULL;
	return 0;
}

int dump_iface(void (*format)(struct ma_if_info *entry))
{
	struct ma_if_info *ifaces, *e;

	ifaces = get_iface();
	if (ifaces == NULL)
		return -ENOENT;
	e = ifaces;

	while (e->interface_id > 0) {
		format(e++);
	}
	free_iface(ifaces);
	ifaces = e = NULL;
	return 0;
}
