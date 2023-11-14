/*
 *      MIPL Diagnostics utility
 *
 *      Authors:
 *      Antti Tuominen          <ajtuomin@tml.hut.fi>
 *
 *      $Id: s.mipdiag.c 1.58 03/10/03 15:43:29+03:00 henkku@mart10.hut.mediapoli.com $
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 */


#include <errno.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ctype.h>

#include <fcntl.h>
#include <sys/ioctl.h>

#include "mip6.h"
#include "diag.h"
#include "conf.h"
#include "libnetlink.h"
#include "ll_map.h"
#define EINVDIGIT       1
#define ESRCTOOLONG     2
#define ESRCTOOSHORT    3

#define UID0 0

#ifndef IFA_F_HOMEADDR
#error "Incorrect /usr/include/linux/ directory see INSTALL"
#endif

static char miplversion[] = "MIPL Mobile IPv6 1.0";
static char progversion[] = "mipdiag 0.27 (2003-10-03) Antti Tuominen";

void usage()
{
	fprintf(stderr, 
		"Usage: \n"
		"  mipdiag [-clmsI]\n"
		"  mipdiag [-d[value]] [-t[value]]\n"
		"  mipdiag -i ifname -h addr/plen -H[addr/plen]\n"
		"  mipdiag -i ifname -P integer \n\n"
		"  mipdiag [-?|--help]       Detailed usage syntax\n"
		"  mipdiag [-V|--version]    Display version/author and exit\n\n"
		"   -d, --debuglevel         get/set modules debug level\n"
		"   -t, --tunnel_sitelocal   get/set tunnel sitelocal option\n"
		"   -c, --bcache             show binding cache\n"
		"   -l, --bulist             show bingding update list\n"
		"   -m, --mninfo             show MN information\n"
		"   -s, --statistics         show statistics\n"
		"   -i, --if_name            set interface for -P or -h\n"
		"   -h, --homeaddress        set MN's home address and prefix length\n"
		"   -H, --homeagent          set MN's home agent's address\n"
		"   -P, --set_if_pref        set priority for an interface\n"
		"   -I, --ifaces             show current interfaces and priorities\n"
		);
}

void bcache_do_one(bc_t *entry)
{
	char haddr[INET6_ADDRSTRLEN], coaddr[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &entry->homeaddr, haddr, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &entry->careofaddr, coaddr, INET6_ADDRSTRLEN);
	printf("%-44s%-44s%-10ld%-5d\n", haddr, coaddr, 
	       entry->expires, entry->type);
}

void bulist_do_one(bu_t *e)
{
	char rcpt[INET6_ADDRSTRLEN], haddr[INET6_ADDRSTRLEN], coaddr[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &e->rcptaddr, rcpt, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &e->homeaddr, haddr, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &e->careofaddr, coaddr, INET6_ADDRSTRLEN);
	printf("Recipient CN: %s\n", rcpt);
	printf("BINDING home address: %s care-of address: %s\n", haddr, coaddr);
	printf("        expires: %ld sequence: %d state: %d\n", e->expires, 
	       e->seq, e->state);
	printf("        delay: %d max delay %d callback time: %d\n\n", e->delay, 
	       e->maxdelay, e->cb_time);
}

void mninfo_do_one(struct mn_info_ext *e)
{
	char home[INET6_ADDRSTRLEN], agent[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &e->home_addr, home, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &e->ha, agent, INET6_ADDRSTRLEN);
	printf("%02d %-36s/%3d %-36s %d %d\n",
	       e->ifindex, home, e->home_plen, agent, e->is_at_home, e->has_home_reg);
}

void stats_do_one(stat_t *stat)
{
	printf("%-25s : %ld\n", stat->name, stat->value);
}

void iface_do_one(struct ma_if_info *info)
{
	char ifname[IFNAMSIZ];

	if (if_indextoname(info->interface_id, ifname) == NULL) {
		fprintf(stderr, "Error mapping index to interface name\n");
		exit(1);
	}
	printf("%-16s %-5d %-4s     %-4s\n", ifname, info->preference,
	       info->status & MA_IFACE_HAS_ROUTER ? "*" : " ",
	       info->status & MA_IFACE_CURRENT ? "*" : " ");
}

int get_ma_current_iface(void) 
{
	FILE *ma_info; 
	char used_if[IFNAMSIZ], name[IFNAMSIZ];
	char type[INTERFACE_TYPE_MAX];
	char addr[INET6_ADDRSTRLEN];
	int id, avail, state, pref;

	ma_info = fopen("/proc/multiaccess/info", "r");

	if (ma_info != NULL) {
		printf ("Currently used interface: ");

		while (!feof(ma_info)) {
			memset(name, 0, IFNAMSIZ);
			memset(type, 0, INTERFACE_TYPE_MAX);
			memset(addr, 0, INET6_ADDRSTRLEN);
			fscanf(ma_info, "%d\t%s\t%d\t%d\t%s\t%d\t%s\n", 
			       &id, name, &avail, &state, type, &pref, addr);
			if (state == MULTIACCESS_IFACE_IS_USED)
				strcpy(used_if, name);
		}
		printf ("%s\n", used_if);
		fclose(ma_info);
	} else {
		fprintf(stderr, "Could not read Multiaccess information.\n");
		exit(ENOENT);
	}

    return 0;
}

int set_ma_set_preference(int ifi, char *preference) /* MULTIACCESS */
{
	int fd, ret;
	struct ma_if_info ifinfo;

	if (geteuid() != UID0) {
		fprintf(stderr, "You must be root (uid = 0) to do this.\n");
		exit(EPERM);
	}

	fd = open(CTLFILE, 0);
	if (fd < 0) {
		perror("open:");
		return -ENOENT;
	}

	memset(&ifinfo, 0, sizeof(ifinfo));
	ifinfo.interface_id = ifi;
	ifinfo.preference = atoi(preference);

	ret = ioctl(fd, MA_IOCTL_SET_IFACE_PREFERENCE, &ifinfo);
	if (ret < 0) {
		fprintf(stderr, "ioctl failed\n");
		return ret;
	}
	close(fd);

	return 0;
}

void debuglevel(char *level)
{
	int ilevel;
	int ret = 0;

	if (level == NULL) {
		ret = get_sysctl_int("net/ipv6/mobility/debuglevel");
		if (ret < 0) {
			fprintf(stderr, "Could not get debug level. Is module loaded?\n");
			exit(ret);
		}
		printf("Debug level is %d.\n", ret);
		exit(0);
	}
	ilevel = atoi(level);

	if (ilevel == 0 && level[0] != '0') {
		fprintf(stderr, "Debug level must be a positive integer value\n");
		exit(1);
	}
	ret = set_sysctl_int("net/ipv6/mobility/debuglevel", ilevel);

	switch (ret) {
	case -EPERM:
		fprintf(stderr, "You must be root (uid = 0) to do this.\n");
		exit(ret);
		break;
	case -ENOENT:
		fprintf(stderr, "Could not set debug level. Is module loaded?\n");
		exit(ret);
		break;
	case -EIO:
		fprintf(stderr, "Unable to set debug level.\n");
		exit(ret);
		break;
	default:
		if (ret < 0) {
			fprintf(stderr, "Unknown error.\n");
			exit(ret);
		}
	}
}

void tunnel_sitelocal(char *opt)
{
	int iopt = -1, ret = 0;

	if (opt == NULL) {
		ret = get_sysctl_int("net/ipv6/mobility/tunnel_sitelocal");
		if (ret < 0) {
			fprintf(stderr, "Could not get tunnel site-local setting. Is module loaded?\n");
			exit(ret);
		}
		printf("Tunnel site-local is %s.\n", ret ? "ON" : "OFF");
		exit(0);
	}

	if (!strcasecmp(opt, "YES") || !strcasecmp(opt, "ON") || 
	    !strcasecmp(opt, "Y") || !strcmp(opt, "1"))
		iopt = 1;
	else if (!strcasecmp(opt, "NO") || !strcasecmp(opt, "OFF") ||
		 !strcasecmp(opt, "N") || !strcmp(opt, "0"))
		iopt = 0;
	else {
		fprintf(stderr, "Invalid value for option: %s\n", opt);
		exit(EINVAL);
	}

	ret = set_sysctl_int("net/ipv6/mobility/tunnel_sitelocal", iopt);

	switch (ret) {
	case -EPERM:
		fprintf(stderr, "You must be root (uid = 0) to do this.\n");
		exit(ret);
		break;
	case -ENOENT:
		fprintf(stderr, "Could not set tunnel sitelocal option. Is module loaded?\n");
		exit(ret);
		break;
	case -EIO:
		fprintf(stderr, "Unable to set tunnel sitelocal option.\n");
		exit(ret);
		break;
	default:
		if (ret < 0) {
			fprintf(stderr, "Unknown error.\n");
			exit(ret);
		}
	}
}

/* Setting home address and home agent */
int rtn_set_mn_info(int ifindex, struct in6_ifreq *home, struct in6_ifreq *ha)
{
	struct rtnl_handle rth;
	struct {
		struct nlmsghdr 	n;
		struct ifaddrmsg 	ifa;
		char   			buf[256];
	} req;

	if (geteuid() != UID0) {
		fprintf(stderr, "You must be root (uid = 0) to do this.\n");
		exit(EPERM);
	}
	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_NEWADDR;
	req.ifa.ifa_family = AF_INET6;
	req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
	req.ifa.ifa_flags = IFA_F_HOMEADDR;

	req.ifa.ifa_prefixlen = home->ifr6_prefixlen;
	addattr_l(&req.n, sizeof(req), IFA_ADDRESS, &home->ifr6_addr, 
		  sizeof(struct in6_addr));
	addattr_l(&req.n, sizeof(req), IFA_HOMEAGENT, &ha->ifr6_addr,
		  sizeof(struct in6_addr));

	if (rtnl_open(&rth, 0) < 0)
		return -1;

	ll_init_map(&rth);

	if ((req.ifa.ifa_index = ifindex) == 0) {
		fprintf(stderr, "Cannot find device with index %d\n", ifindex);
		return -1;
	}

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		return -2;

	return 0;
}

int set_homeaddress(char *addr, struct in6_ifreq *ifr)
{
	char *p, *n;

	memset(ifr, 0, sizeof(struct in6_ifreq));
	n = strchr(addr, '/');
	if (n) {
		p = n + 1;
		*n = '\0';
		ifr->ifr6_prefixlen = strtoul(p, &p, 10);
		if (*p) ifr->ifr6_prefixlen = 128;
	} else {
		fprintf(stderr, "Invalid home address: no prefix length\n");
		exit(-1);
	}
	if (inet_pton(AF_INET6, addr, &ifr->ifr6_addr) <= 0) {
		fprintf(stderr, "Invalid home address: parse error\n");
		exit(-1);
	}

	return 0;
}

int set_homeagent(char *addr, struct in6_ifreq *ifr)
{
	char *p, *n;

	if (addr == NULL) {
		memset(ifr, 0, sizeof(struct in6_ifreq));
		return 0;
	}
	n = strchr(addr, '/');
	if (n) {
		p = n + 1;
		*n = '\0';
		ifr->ifr6_prefixlen = strtoul(p, &p, 10);
		if (*p) ifr->ifr6_prefixlen = 64;
	} else {
		fprintf(stderr, "Invalid home agent: no prefix length\n");
		exit(-1);
	}
	if (inet_pton(AF_INET6, addr, &ifr->ifr6_addr) <= 0) {
		fprintf(stderr, "Invalid home agent address: parse error\n");
		exit(-1);
	}

	return 0;
}

/* Main program */
int main (int argc, char **argv)
{
	int ha_addr_set = 0, haddr_set = 0, mn_conf = 0;
	struct in6_ifreq home_ifr, ha_ifr;
	int ifindex = 0;

	int c;
     	
	while (1)
	{
		int option_index = 0;
		static struct option long_options[] =
		{
			{"if_name", 1, 0, 'i'}, /* MULTIACCESS */
			{"ifaces", 0, 0, 'I'}, /* MULTIACCESS */
			{"set_if_pref", 1, 0, 'P'}, /* MULTIACCESS */
			{"mninfo", 0, 0, 'm'},
			{"statistics", 0, 0, 's'},
			{"bulist", 0, 0, 'l'},
			{"bcache", 0, 0, 'c'},
			{"help", 0, 0, '?'},
			{"version", 0, 0, 'V'},
			{"debuglevel", 2, 0, 'd'},
			{"tunnel_sitelocal", 2, 0, 't'},
			{"homeagent", 2, 0, 'H'},
			{"homeaddress", 1, 0, 'h'},
			{0, 0, 0, 0}
		};
		

		c = getopt_long (argc, argv,
				 "i:IP:mslc?Vd::t::H::h:",
				 long_options, &option_index);
		if (c == -1)
			break;
		
		switch (c)
		{
		case 'c':
			printf("Mobile IPv6 Binding cache\n");
			printf("%-44s%-44s%-10s%-5s\n", "Home Address", "Care-of Address", 
			       "Lifetime", "Type");
			if (dump_bc(bcache_do_one) < 0)
				fprintf(stderr, "Could not read binding cache information.\n");
			break;
		case 'l':
			printf ("Mobile IPv6 Binding update list\n");
			if (dump_bu(bulist_do_one) < 0) {
				fprintf(stderr, "Could not read binding update list information.\n");
				exit(1);
			}
			break;
		case 's':
			printf("Mobile IPv6 Statistics\n");
			if (dump_stat(stats_do_one) < 0) {
				fprintf(stderr, "Could not read statistics.\n");
				exit(1);
			}
			break;
		case 'd':
			debuglevel(optarg);
			break;
		case 't':
			tunnel_sitelocal(optarg);
			break;
		case 'i':
			ifindex = if_nametoindex(optarg);
			break;
		case 'I':
			printf("Interfaces Preference List\n");
			printf("%-16s %-5s HAS RTR  CURRENT\n",
			       "Interface", "Pref");
			if (dump_iface(iface_do_one) < 0) {
				fprintf(stderr, "Could not read interface information.\n");
				exit(1);
			}
			break;
		case 'P': /* MULTIACCESS */
			set_ma_set_preference(ifindex, optarg);
			break;
		case 'H':
			set_homeagent(optarg, &ha_ifr);
			ha_addr_set = 1;
			mn_conf = 1;
			break;
		case 'm':
			printf("%2s %-40s %-36s %s %s\n",
			       "If", "Home Address/prefix length", "Home Agent", "H", "R");
			if (dump_mninfo(mninfo_do_one) < 0) {
				fprintf(stderr, "Could not read MN information.\n");
				exit(1);
			}
			break;
		case 'h':
			set_homeaddress(optarg, &home_ifr);
			haddr_set = 1;
			mn_conf = 1;
			break;
		case 'V':
			fprintf (stderr, "%s\n", miplversion);
			fprintf (stderr, "%s\n", progversion);
			break;
		case '?':
			usage();
			break;
			
		default:
			printf ("mipdiag: invalid option -- %c. Try -? for help.\n", c);
		}
	}
	if (argc == 1)
		usage();
	if (optind < argc)
	{
		printf ("non-option ARGV-elements: ");
		while (optind < argc)
			printf ("%s ", argv[optind++]);
		printf ("\n");
	}

	if (mn_conf && !ifindex) {
		fprintf(stderr, "You must specify device with -i.\n");
		exit(1);
	}
	if (!!ha_addr_set ^ !!haddr_set) {
		fprintf(stderr, "Options -h and -H must be used together.\n");
		exit(1);
	}
	if (mn_conf)
		return rtn_set_mn_info(ifindex, &home_ifr, &ha_ifr);

	exit (0);
}
