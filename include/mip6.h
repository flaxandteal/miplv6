#ifndef MIP6_H
#define MIP6_H

#define OUTBOUND                1
#define INBOUND                 2
#define ALG_AUTH_HMAC_MD5       3
#define ALG_AUTH_HMAC_SHA1      4
/* MULTIACCESS */
#define INTERFACE_NAME_MAX 5
#define INTERFACE_TYPE_MAX 5
#define PREFIX_MAX 48
/* availability */
#define MULTIACCESS_IFACE_NOT_PRESENT    0x0    // Link is not attached
#define MULTIACCESS_IFACE_NO_ROUTER      0x1    // Link doesn't have a reachable router
#define MULTIACCESS_IFACE_HAS_ROUTER	 0x2    // Link has a reachable router
/* state */
#define MULTIACCESS_IFACE_NOT_USED       0x0    // Link is not used
#define MULTIACCESS_IFACE_REQUESTED      0x1    // Handover requested
#define MULTIACCESS_IFACE_IS_USED        0x4    // Link is in use

/*
 * Struct for passing security associations
 */

struct sa_ioctl {
	u_int8_t auth_alg; 
	u_int8_t direction;
	u_int8_t key_auth[64];
	u_int32_t lifetime; 
	u_int32_t soft_lifetime; /* In seconds */
	u_int32_t key_auth_len;
	u_int32_t spi; 
	struct in6_addr addr;	/* address of peer */

};
/*
 * Struct for passing Home Agent Address information
 */
struct ha_info {
	struct in6_addr	addr;
	u_int32_t	prefixlen;
	int		preference;
	unsigned long	lifetime;
};
/*
 * Mobile Node information record
 */
struct mn_info_ext {
	struct in6_addr home_addr;
	struct in6_addr ha;
	u_int8_t home_plen;
	u_int8_t is_at_home;
	u_int8_t has_home_reg;
	u_int8_t man_conf;
	int ifindex;
	unsigned long home_addr_expires;
};

/* MULTIACCESS - struct for passing interface information */
struct ma_if_info {
	int        interface_id;
	int        preference;
	u_int8_t   status;
};

/*
 * Struct for passing Home Address information
 */
struct in6_ifreq {
	struct in6_addr	ifr6_addr;
	u_int32_t	ifr6_prefixlen;
	int		ifr6_ifindex; 
};

/*
 * Struct for ACL rules
 */
struct mipv6_acl_record {
	struct in6_addr mask;
	unsigned char prefix_len;
	unsigned char action;
};

#define ACL_DENY 0
#define ACL_ALLOW 1
#define ACL_FLUSH 2

#define MA_IFACE_NOT_PRESENT 0x01
#define MA_IFACE_NOT_USED    0x02
#define MA_IFACE_HAS_ROUTER  0x04
#define MA_IFACE_CURRENT     0x10

#define CTLFILE "/dev/mipv6_dev"

#include <linux/ioctl.h> 

int mipv6_initialize_ioctl(void);
void mipv6_shutdown_ioctl(void);
void set_sa_acq(void);
void un_set_sa_acq(void);
#define MAJOR_NUM 0xf9 /* 249 reserved for local and experimental use*/

/* Deletes a SA bundle */
#define IOCTL_DEL_SA_BUNDLE _IOWR(MAJOR_NUM, 0, void *)

/* Adds an outbound SA as a result of ACQUIRE */
#define IOCTL_ADD_OB_SA _IOWR(MAJOR_NUM, 1, void *) 

/* Adds an outbound SA as a result of ACQUIRE */
#define IOCTL_ADD_IB_SA _IOWR(MAJOR_NUM, 2, void *) 

/* Tells the kmd to create a SA */
#define IOCTL_ACQUIRE_SA _IOR(MAJOR_NUM, 3, void *)

/* Prints a sa_bundle */
#define IOCTL_PRINT_SA _IOWR(MAJOR_NUM, 4, void *)

/* Set home address information for Mobile Node */
#define IOCTL_SET_HOMEADDR _IOR(MAJOR_NUM, 5, void *)

/* Set home agent information for Mobile Node */
#define IOCTL_SET_HOMEAGENT _IOR(MAJOR_NUM, 6, void *)

/* Get home address information for Mobile Node */
#define IOCTL_GET_HOMEADDR _IOWR(MAJOR_NUM, 7, void *)

/* Get home agent information for Mobile Node */
#define IOCTL_GET_HOMEAGENT _IOWR(MAJOR_NUM, 8, void *)

/* Get Care-of address information for Mobile Node */
#define IOCTL_GET_CAREOFADDR _IOWR(MAJOR_NUM, 9, void *)


/* MULTIACCESS */
#define MA_IOCTL_REQUEST_IFACE _IOR (MAJOR_NUM, 10, void *)
#define MA_IOCTL_PRINT_CURRENT_IFACE _IOWR (MAJOR_NUM, 11, void *)
#define MA_IOCTL_PRINT_IFACE_PREFERENCES _IOWR (MAJOR_NUM, 12, void *)
#define MA_IOCTL_SET_IFACE_PREFERENCE _IOR (MAJOR_NUM, 13, void *)

/* Set home address and corresponding home agent address */

#define IOCTL_SET_MN_INFO _IOR(MAJOR_NUM, 14, void *)
#define IOCTL_GET_MN_INFO _IOWR(MAJOR_NUM, 15, void *)

/* Add ACL rule */
#define IOCTL_ADD_ACL_RULE _IOWR(MAJOR_NUM, 16, void *)
 
#endif
