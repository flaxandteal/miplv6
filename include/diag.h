#ifndef DIAG_H
#define DIAG_H

#include <netinet/in.h>

typedef struct bc_entry {
	struct in6_addr homeaddr;
	struct in6_addr careofaddr;
	unsigned long expires;
	int type;
} bc_t;

typedef struct bu_entry {
	struct in6_addr rcptaddr;
	struct in6_addr homeaddr;
	struct in6_addr careofaddr;
	unsigned long expires;
	unsigned int seq;
	int state;
	int delay;
	int maxdelay;
	int cb_time;
} bu_t;

typedef struct stat_entry {
	char name[40];
	unsigned long value;
} stat_t;

typedef struct ha_entry {
	int ifindex;
	struct in6_addr link_local_addr;
	struct in6_addr global_addr;
	int preference;
	unsigned long expire;
} ha_t;

bc_t *get_bc(void);
void free_bc(bc_t *bc);

bu_t *get_bu(void);
void free_bu(bu_t *bu);

stat_t *get_stat(void);
void free_stat(stat_t *stat);

ha_t *get_ha(void);
void free_ha(ha_t *ha);

struct ma_if_info *get_iface(void);
void free_iface(struct ma_if_info *iface);

struct mn_info_ext *get_mninfo(void);
void free_mninfo(struct mn_info_ext *mn);

int dump_bc(void (*format)(bc_t *e));
int dump_bu(void (*format)(bu_t *e));
int dump_mninfo(void (*format)(struct mn_info_ext *e));
int dump_stat(void (*format)(stat_t *e));
int dump_ha(void (*format)(ha_t *e));
int dump_iface(void (*format)(struct ma_if_info *e));

#endif
