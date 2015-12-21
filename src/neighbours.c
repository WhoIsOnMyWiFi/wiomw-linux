/**
 * Copyright 2013, 2014 Who Is On My WiFi.
 *
 * This file is part of Who Is On My WiFi Linux.
 *
 * Who Is On My WiFi Linux is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Who Is On My WiFi Linux is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Who Is On My WiFi Linux.  If not, see <http://www.gnu.org/licenses/>.
 *
 * More information about Who Is On My WiFi Linux can be found at
 * <http://www.whoisonmywifi.com/>.
 */

#include <config.h>
#include "neighbours.h"
#include "syslog_syserror.h"

#include <syslog.h>
#include "sockaddr_helpers.h" 
#include "configuration.h"
#include "mac_ntop.h"
#include "host_lookup.h"
#include "signal_handler.h"
#include <stdio.h>
#include <linux/version.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19) && LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
#include <linux/neighbour.h>
#endif
#include <libmnl/libmnl.h>
#include <sys/socket.h>
#include <sysexits.h>
#include <regex.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>



#define LOOPBACK_NAME "lo"

#ifndef IFA_RTA
#define IFA_RTA(r) \
 ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))
#endif
#ifndef IFA_PAYLOAD
#define IFA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifaddrmsg))
#endif

#ifndef IFLA_RTA
#define IFLA_RTA(r) \
 ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#endif
#ifndef IFLA_PAYLOAD
#define IFLA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
#endif

#ifndef NDA_RTA
#define NDA_RTA(r) \
 ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif
#ifndef NDA_PAYLOAD
#define NDA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ndmsg))
#endif
 


typedef struct {
	unsigned char family;
	unsigned char mask;
	unsigned char flags;
	unsigned char scope;
	struct sockaddr* addr;
	struct sockaddr* local;
	char* label;
	struct sockaddr* bcast;
	struct sockaddr* acast;
} if_addr_t;

typedef struct if_addr_list_struct {
	if_addr_t* data;
	struct if_addr_list_struct* next;
} * if_addr_list_t;

typedef struct {
	unsigned char family;
	unsigned short type;
	int index;
	unsigned int flags;
	char* name;
	unsigned char mac[6];
	unsigned char bmac[6];
	uint32_t mtu;
	int link;
	char* qdsp;
	bool blacklisted;
	bool loopback;
	if_addr_list_t addr_list;
} if_item_t;

typedef struct if_list_struct {
	if_item_t* data;
	struct if_list_struct* next;
} * if_list_t;

typedef struct {
	regex_t* compiled_regex;
	config_t* config;
	if_list_t* if_list;
} get_if_list_cb_data_t;

typedef struct {
	FILE* fd;
	config_t* config;
	if_list_t* if_list;
	host_lookup_table_t host_lookup_table;
} print_neigh_list_cb_data_t;

typedef struct {
	if_list_t* if_list;
	config_t* config;
} get_if_addr_list_cb_data_t;


#define PACKETSIZE  64
struct packet
{
    struct icmphdr hdr;
    char msg[PACKETSIZE-sizeof(struct icmphdr)];
};




static if_addr_t* new_if_addr()
{
	if_addr_t* if_addr = (if_addr_t*)malloc(sizeof(if_addr_t));
	if (if_addr == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
		exit(EX_OSERR);
	} else {
		if_addr->family = AF_UNSPEC;
		if_addr->mask = 0;
		if_addr->flags = 0;
		if_addr->scope = 0;
		if_addr->label = NULL;
		if_addr->addr = NULL;
		if_addr->local = NULL;
		if_addr->bcast = NULL;
		if_addr->acast = NULL;
		return if_addr;
	}
}

static void destroy_if_addr(if_addr_t** if_addr)
{
	if (if_addr != NULL && *if_addr != NULL) {
		free((*if_addr)->label);
		free((*if_addr)->addr);
		free((*if_addr)->local);
		free((*if_addr)->bcast);
		free((*if_addr)->acast);
		free(*if_addr);
		*if_addr = NULL;
	}
}


static if_addr_list_t new_if_addr_list()
{
	return (if_addr_list_t)NULL;
}

static void destroy_if_addr_list(if_addr_list_t* if_addr_list)
{
	while (if_addr_list != NULL && *if_addr_list != NULL) {
		if_addr_list_t temp = *if_addr_list;
		destroy_if_addr(&(temp->data));
		*if_addr_list = temp->next;
		free(temp);
	}
}


static if_item_t* new_if_item()
{
	if_item_t* if_item = (if_item_t*)malloc(sizeof(if_item_t));
	if (if_item == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
		exit(EX_OSERR);
	}
	if_item->family = AF_UNSPEC;
	if_item->type = 0;
	if_item->index = -1;
	if_item->flags = 0;
	if_item->name = NULL;
	if_item->mac[0] = 0x00;
	if_item->mac[1] = 0x00;
	if_item->mac[2] = 0x00;
	if_item->mac[3] = 0x00;
	if_item->mac[4] = 0x00;
	if_item->mac[5] = 0x00;
	if_item->bmac[0] = 0x00;
	if_item->bmac[1] = 0x00;
	if_item->bmac[2] = 0x00;
	if_item->bmac[3] = 0x00;
	if_item->bmac[4] = 0x00;
	if_item->bmac[5] = 0x00;
	if_item->mtu = 0;
	if_item->link = -1;
	if_item->qdsp = NULL;
	if_item->blacklisted = false;
	if_item->loopback = false;
	if_item->addr_list = new_if_addr_list();
	return if_item;
}

static void destroy_if_item(if_item_t** if_item)
{
	if (if_item == NULL || *if_item == NULL) {
		syslog(LOG_DEBUG, "Internal error (unable to destroy an empty interface object)");
	} else {
		free((*if_item)->name);
		free((*if_item)->qdsp);
		destroy_if_addr_list(&((*if_item)->addr_list));
		free(*if_item);
		*if_item = NULL;
	}
}



static if_list_t new_if_list()
{
	return (if_list_t)NULL;
}

static void destroy_if_list(if_list_t* if_list)
{
	while (if_list != NULL && *if_list != NULL) {
		if_list_t temp = *if_list;
		destroy_if_item(&(temp->data));
		*if_list = temp->next;
		free(temp);
	}
}



static get_if_list_cb_data_t new_get_if_list_cb_data(regex_t* compiled_regex, config_t* config, if_list_t* if_list)
{
	get_if_list_cb_data_t result;
	result.compiled_regex = compiled_regex;
	result.config = config;
	result.if_list = if_list;
	return result;
}

static void destroy_get_if_list_cb_data(get_if_list_cb_data_t* get_if_list_cb_data)
{
	if (get_if_list_cb_data == NULL) {
		syslog(LOG_DEBUG, "Internal error (unable to destroy an empty interface list callback argument)");
	} else {
		get_if_list_cb_data->compiled_regex = NULL;
		get_if_list_cb_data->config = NULL;
		get_if_list_cb_data->if_list = NULL;
	}
}


static print_neigh_list_cb_data_t new_print_neigh_list_cb_data(FILE* fd, if_list_t* if_list, config_t* config, host_lookup_table_t lookup_table)
{
	print_neigh_list_cb_data_t result;
	result.fd = fd;
	result.if_list = if_list;
	result.config = config;
	result.host_lookup_table = lookup_table;
	return result;
}

static void destroy_print_neigh_list_cb_data(print_neigh_list_cb_data_t* print_neigh_list_cb_data)
{
	if (print_neigh_list_cb_data == NULL) {
		syslog(LOG_DEBUG, "Internal error (unable to destroy an empty print neighbour list callback argument)");
	}
}

static get_if_addr_list_cb_data_t new_get_if_addr_list_cb_data(if_list_t* if_list, config_t* config)
{
	get_if_addr_list_cb_data_t result;
	result.if_list = if_list;
	result.config = config;
	return result;
}







static if_addr_list_t push_if_addr(if_addr_list_t* if_addr_list, if_addr_t* if_addr)
{
	if_addr_list_t temp = (if_addr_list_t)malloc(sizeof(struct if_addr_list_struct));
	if (temp == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
		exit(EX_OSERR);
	}

	temp->data = if_addr;
	temp->next = *if_addr_list;
	*if_addr_list = temp;
	return *if_addr_list;
}

/*
static if_addr_t* pop_if_addr(if_addr_list_t* if_addr_list)
{
	if_addr_list_t temp = *if_addr_list;
	if_addr_t* if_addr = temp->data;
	*if_addr_list = temp->next;
	free(temp);
	return if_addr;
}
*/

static if_list_t push_if_item(if_list_t* if_list, if_item_t* if_item)
{
	if_list_t temp = (if_list_t)malloc(sizeof(struct if_list_struct));
	if (temp == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
		exit(EX_OSERR);
	}
	temp->data = if_item;
	temp->next = *if_list;
	*if_list = temp;
	return *if_list;
}

/*
static if_item_t* pop_if_item(if_list_t* if_list)
{
	if_list_t temp = *if_list;
	if_item_t* if_item = temp->data;
	*if_list = temp->next;
	free(temp);
	return if_item;
}
*/


static if_item_t* get_if_item_by_index(if_list_t if_list, const int if_index)
{
	if_list_t temp = if_list;
	while (temp != NULL) {
		if (temp->data->index == if_index) {
			return temp->data;
		} else {
			temp = temp->next;
		}
	}
	return (if_item_t*)NULL;
}


char* get_nlmsg_error(const struct nlmsghdr* nl_head)
{
	if (nl_head != NULL && nl_head->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr* nl_err = mnl_nlmsg_get_payload(nl_head);
		if (nl_err->error != 0) {
			return strerror(-1 * nl_err->error);
		}
	}
	return NULL;
}


static int print_nlmsg_error_cb(const struct nlmsghdr* nl_head, void* cb_data)
{
	if (nl_head != NULL) {
		char* errstring = get_nlmsg_error(nl_head);
		if (errstring != NULL) {
			if (cb_data != NULL) {
				syslog(LOG_ALERT, "%s: Netlink error: %s", (char*)cb_data, errstring);
			} else {
				syslog(LOG_ALERT, "Netlink error: %s", errstring);
			}
			return MNL_CB_ERROR;
		}
	}
	return MNL_CB_OK;
}

typedef struct {
	FILE* fd;
	unsigned char family;
	host_lookup_table_t host_lookup_table;
} print_neigh_cb_data_t;

typedef struct {
	regex_t* compiled_regex;
	config_t* config;
	if_item_t* if_item;
} get_if_item_cb_data_t;

static print_neigh_cb_data_t new_print_neigh_cb_data(FILE* fd, unsigned char family, host_lookup_table_t lookup_table)
{
	print_neigh_cb_data_t result;
	result.fd = fd;
	result.family = family;
	result.host_lookup_table = lookup_table;
	return result;
}

static void destroy_print_neigh_cb_data(print_neigh_cb_data_t* print_neigh_cb_data)
{
	if (print_neigh_cb_data == NULL) {
		syslog(LOG_DEBUG, "Internal error (unable to destroy an empty print neighbour callback argument)");
	}
}

static get_if_item_cb_data_t new_get_if_item_cb_data(regex_t* compiled_regex, config_t* config, if_item_t* if_item)
{
	get_if_item_cb_data_t result;
	result.compiled_regex = compiled_regex;
	result.config = config;
	result.if_item = if_item;
	return result;
}

static void destroy_get_if_item_cb_data(get_if_item_cb_data_t* get_if_item_cb_data)
{
	if (get_if_item_cb_data == NULL) {
		syslog(LOG_DEBUG, "Internal error (unable to destroy an empty interface item callback argument)");
	}
}





static int get_if_item_cb(const struct nlattr* nl_attr, void* cb_data)
{
	get_if_item_cb_data_t* item_cb_data = (get_if_item_cb_data_t*)cb_data;
	if (item_cb_data == NULL || item_cb_data->compiled_regex == NULL || item_cb_data->if_item == NULL) {
		syslog(LOG_CRIT, "Internal error (inavlid argument received in interface item callback)");
		return MNL_CB_ERROR;
	} else if (mnl_attr_type_valid(nl_attr, IFLA_MAX) < 0) {
		syslog_syserror(LOG_ALERT, "Received invalid netlink attribute type");
		return MNL_CB_ERROR;
	} else if (item_cb_data->if_item->loopback) {
		return MNL_CB_OK;
	} else if (item_cb_data->config->ignore_blacklist_iface && item_cb_data->if_item->blacklisted) {
		return MNL_CB_OK;
	} else {
		switch (mnl_attr_get_type(nl_attr)) {
		case IFLA_IFNAME:
			if (mnl_attr_validate(nl_attr, MNL_TYPE_NUL_STRING) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid interface name from netlink");
				return MNL_CB_ERROR;
			} else {
				int errcode = 0;
				const char* if_name = mnl_attr_get_str(nl_attr);
				item_cb_data->if_item->name = (char*)malloc(strlen(if_name) + 1);
				if (item_cb_data->if_item->name == NULL) {
					syslog_syserror(LOG_EMERG, "Unable to allocate memory");
					exit(EX_OSERR);
				}
				strcpy(item_cb_data->if_item->name, if_name);
				if (strcmp(item_cb_data->if_item->name, LOOPBACK_NAME) == 0) {
					item_cb_data->if_item->blacklisted = true;
					item_cb_data->if_item->loopback = true;
				} else {
					errcode = regexec(item_cb_data->compiled_regex, item_cb_data->if_item->name, 0, NULL, 0);
					if (errcode == 0) {
						item_cb_data->if_item->blacklisted = true;
					} else if (errcode == REG_NOMATCH) {
						item_cb_data->if_item->blacklisted = false;
					} else {
						syslog_syserror(LOG_CRIT, "Unable to evaluate the interface blacklist regex");
						return MNL_CB_ERROR;
					}
				}
			}
			break;
		case IFLA_ADDRESS:
			if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, 6) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid MAC address from netlink");
				return MNL_CB_ERROR;
			} else {
				const unsigned char* mac = mnl_attr_get_payload(nl_attr);
				memcpy(item_cb_data->if_item->mac, mac, 6);
			}
			break;
		case IFLA_BROADCAST:
			if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, 6) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid broadcast MAC address from netlink");
				return MNL_CB_ERROR;
			} else {
				const unsigned char* bmac = mnl_attr_get_payload(nl_attr);
				memcpy(item_cb_data->if_item->bmac, bmac, 6);
			}
			break;
		case IFLA_MTU:
			if (mnl_attr_validate(nl_attr, MNL_TYPE_U32) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid MTU from netlink");
				return MNL_CB_ERROR;
			} else {
				item_cb_data->if_item->mtu = mnl_attr_get_u32(nl_attr);
			}
			break;
		case IFLA_LINK:
			if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(int)) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid link type from netlink");
				return MNL_CB_ERROR;
			} else {
				int* link_ptr = mnl_attr_get_payload(nl_attr);
				item_cb_data->if_item->link = *link_ptr;
			}
			break;
		case IFLA_QDISC:
			if (mnl_attr_validate(nl_attr, MNL_TYPE_NUL_STRING) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid queue discipline from netlink");
				return MNL_CB_ERROR;
			} else {
				const char* qdsp = mnl_attr_get_str(nl_attr);
				item_cb_data->if_item->qdsp = (char*)malloc(strlen(qdsp) + 1);
				if (item_cb_data->if_item->qdsp == NULL) {
					syslog_syserror(LOG_EMERG, "Unable to allocate memory");
					exit(EX_OSERR);
				}
				strcpy(item_cb_data->if_item->qdsp, qdsp);
			}
			break;
		}
		return MNL_CB_OK;
	}
}

static int get_if_addr_cb(const struct nlattr* nl_attr, void* cb_data)
{
	if_addr_t* if_addr = (if_addr_t*)cb_data;
	if (if_addr == NULL) {
		syslog(LOG_CRIT, "Internal error (invalid argument received in interface address callback)");
		return MNL_CB_ERROR;
	} else if (mnl_attr_type_valid(nl_attr, IFA_MAX) < 0) {
		syslog_syserror(LOG_ALERT, "Received invalid netlink attribute type");
		return MNL_CB_ERROR;
	} else {
		switch(mnl_attr_get_type(nl_attr)) {
		case IFA_ADDRESS:
			if (if_addr->family == AF_INET && mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct in_addr)) >= 0) {
				struct in_addr* bin_addr = mnl_attr_get_payload(nl_attr);
				struct sockaddr_in* addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
				if (addr == NULL) {
					syslog_syserror(LOG_EMERG, "Unable to allocate memory");
					exit(EX_OSERR);
				}
				memset(addr, 0, sizeof(struct sockaddr_in));
				addr->sin_family = AF_INET;
				memcpy(&(addr->sin_addr.s_addr), bin_addr, sizeof(struct in_addr));
				if_addr->addr = (struct sockaddr*)addr;
			} else if (if_addr->family == AF_INET6 && mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct in6_addr)) >= 0) {
				struct in6_addr* bin6_addr = mnl_attr_get_payload(nl_attr);
				struct sockaddr_in6* addr = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6));
				if (addr == NULL) {
					syslog_syserror(LOG_EMERG, "Unable to allocate memory");
					exit(EX_OSERR);
				}
				memset(addr, 0, sizeof(struct sockaddr_in6));
				addr->sin6_family = AF_INET6;
				memcpy(&(addr->sin6_addr.s6_addr), bin6_addr, sizeof(struct in6_addr));
				if_addr->addr = (struct sockaddr*)addr;
			} else {
				syslog_syserror(LOG_ALERT, "Received invalid address from netlink");
				return MNL_CB_ERROR;
			}
			break;
		case IFA_LOCAL:
			if (if_addr->family == AF_INET && mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct in_addr)) >= 0) {
				struct in_addr* bin_addr = mnl_attr_get_payload(nl_attr);
				struct sockaddr_in* addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
				if (addr == NULL) {
					syslog_syserror(LOG_EMERG, "Unable to allocate memory");
					exit(EX_OSERR);
				}
				memset(addr, 0, sizeof(struct sockaddr_in));
				addr->sin_family = AF_INET;
				memcpy(&(addr->sin_addr.s_addr), bin_addr, sizeof(struct in_addr));
				if_addr->local = (struct sockaddr*)addr;
			} else if (if_addr->family == AF_INET6 && mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct in6_addr)) >= 0) {
				struct in6_addr* bin6_addr = mnl_attr_get_payload(nl_attr);
				struct sockaddr_in6* addr = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6));
				if (addr == NULL) {
					syslog_syserror(LOG_EMERG, "Unable to allocate memory");
					exit(EX_OSERR);
				}
				memset(addr, 0, sizeof(struct sockaddr_in6));
				addr->sin6_family = AF_INET6;
				memcpy(&(addr->sin6_addr.s6_addr), bin6_addr, sizeof(struct in6_addr));
				if_addr->local = (struct sockaddr*)addr;
			} else {
				syslog_syserror(LOG_ALERT, "Received invalid local address from netlink");
				return MNL_CB_ERROR;
			}
			break;
		case IFA_LABEL:
			if (mnl_attr_validate(nl_attr, MNL_TYPE_NUL_STRING) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid address label from netlink");
				return MNL_CB_ERROR;
			} else {
				const char* label = mnl_attr_get_payload(nl_attr);
				if_addr->label = (char*)malloc(strlen(label) + 1);
				if (if_addr->label == NULL) {
					syslog_syserror(LOG_EMERG, "Unable to allocate memory");
					exit(EX_OSERR);
				}
				strcpy(if_addr->label, label);
			}
			break;
		case IFA_BROADCAST:
			if (if_addr->family == AF_INET && mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct in_addr)) >= 0) {
				struct in_addr* bin_addr = mnl_attr_get_payload(nl_attr);
				struct sockaddr_in* addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
				if (addr == NULL) {
					syslog_syserror(LOG_EMERG, "Unable to allocate memory");
					exit(EX_OSERR);
				}
				memset(addr, 0, sizeof(struct sockaddr_in));
				addr->sin_family = AF_INET;
				memcpy(&(addr->sin_addr.s_addr), bin_addr, sizeof(struct in_addr));
				if_addr->bcast = (struct sockaddr*)addr;
			} else if (if_addr->family == AF_INET6 && mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct in6_addr)) >= 0) {
				struct in6_addr* bin6_addr = mnl_attr_get_payload(nl_attr);
				struct sockaddr_in6* addr = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6));
				if (addr == NULL) {
					syslog_syserror(LOG_EMERG, "Unable to allocate memory");
					exit(EX_OSERR);
				}
				memset(addr, 0, sizeof(struct sockaddr_in6));
				addr->sin6_family = AF_INET6;
				memcpy(&(addr->sin6_addr.s6_addr), bin6_addr, sizeof(struct in6_addr));
				if_addr->bcast = (struct sockaddr*)addr;
			} else {
				syslog_syserror(LOG_ALERT, "Received invalid broadcast address from netlink");
				return MNL_CB_ERROR;
			}
			break;
		case IFA_ANYCAST:
			if (if_addr->family == AF_INET && mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct in_addr)) >= 0) {
				struct in_addr* bin_addr = mnl_attr_get_payload(nl_attr);
				struct sockaddr_in* addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
				if (addr == NULL) {
					syslog_syserror(LOG_EMERG, "Unable to allocate memory");
					exit(EX_OSERR);
				}
				memset(addr, 0, sizeof(struct sockaddr_in));
				addr->sin_family = AF_INET;
				memcpy(&(addr->sin_addr.s_addr), bin_addr, sizeof(struct in_addr));
				if_addr->acast = (struct sockaddr*)addr;
			} else if (if_addr->family == AF_INET6 && mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct in6_addr)) >= 0) {
				struct in6_addr* bin6_addr = mnl_attr_get_payload(nl_attr);
				struct sockaddr_in6* addr = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6));
				if (addr == NULL) {
					syslog_syserror(LOG_EMERG, "Unable to allocate memory");
					exit(EX_OSERR);
				}
				memset(addr, 0, sizeof(struct sockaddr_in6));
				addr->sin6_family = AF_INET6;
				memcpy(&(addr->sin6_addr.s6_addr), bin6_addr, sizeof(struct in6_addr));
				if_addr->acast = (struct sockaddr*)addr;
			} else {
				syslog_syserror(LOG_ALERT, "Received invalid anycast address from netlink");
				return MNL_CB_ERROR;
			}
			break;
		}
		return MNL_CB_OK;
	}
}

static int print_neigh_cb(const struct nlattr* nl_attr, void* cb_data)
{
	print_neigh_cb_data_t* neigh_cb_data = (print_neigh_cb_data_t*)cb_data;
	if (neigh_cb_data == NULL || neigh_cb_data->fd == NULL) {
		syslog(LOG_CRIT, "Internal error (invalid argument received in print neighbour callback)");
		return MNL_CB_ERROR;
	} else if (mnl_attr_type_valid(nl_attr, NDA_MAX) < 0) {
		syslog_syserror(LOG_ALERT, "Received invalid netlink attribute type");
		return MNL_CB_ERROR;
	} else {
		switch(mnl_attr_get_type(nl_attr)) {
		case NDA_DST:
			if (neigh_cb_data->family == AF_INET && mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct in_addr)) >= 0) {
				struct in_addr* bin_addr = mnl_attr_get_payload(nl_attr);
				char str_temp[BUFSIZ];
				if (NULL == inet_ntop(AF_INET, bin_addr, str_temp, BUFSIZ)) {
					syslog_syserror(LOG_CRIT, "Unable to print destination address");
					return MNL_CB_ERROR;
				}
				fprintf(neigh_cb_data->fd, "\"ipaddress\":\"%s\",", str_temp);
			} else if (neigh_cb_data->family == AF_INET6 && mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct in6_addr)) >= 0) {
				struct in6_addr* bin6_addr = mnl_attr_get_payload(nl_attr);
				char str_temp[BUFSIZ];
				if (NULL == inet_ntop(AF_INET6, bin6_addr, str_temp, BUFSIZ)) {
					syslog_syserror(LOG_CRIT, "Unable to print destination address");
					return MNL_CB_ERROR;
				}
				fprintf(neigh_cb_data->fd, "\"ip6\":\"%s\",", str_temp);
			} else {
				syslog_syserror(LOG_ALERT, "Received invalid destination address from netlink");
				return MNL_CB_ERROR;
			}
			break;
		case NDA_LLADDR:
			if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, 6) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid MAC address from netlink");
				return MNL_CB_ERROR;
			} else {
				const unsigned char* mac = mnl_attr_get_payload(nl_attr);
				char str_temp[BUFSIZ];
				char* hostname = NULL;
				if (NULL == mac_ntop(mac, str_temp, 6)) {
					syslog(LOG_CRIT, "Unable to print MAC address");
					return MNL_CB_ERROR;
				}
				fprintf(neigh_cb_data->fd, "\"macaddress\":\"%s\",", str_temp);
				if ((hostname = host_lookup(neigh_cb_data->host_lookup_table, str_temp)) != NULL) {
					fprintf(neigh_cb_data->fd, "\"netbios\":\"%s\",", hostname);
				} else {
					fprintf(neigh_cb_data->fd, "\"netbios\":\"\",");
				}
			}
			break;
		}
		return MNL_CB_OK;
	}
}

static int get_if_list_cb(const struct nlmsghdr* nl_head, void* cb_data)
{
	get_if_list_cb_data_t* list_cb_data = (get_if_list_cb_data_t*)cb_data;
	if (list_cb_data == NULL || list_cb_data->compiled_regex == NULL) {
		syslog(LOG_CRIT, "Internal error (invalid argument received in interface list callback)");
		return MNL_CB_ERROR;
	} else if (nl_head->nlmsg_type == NLMSG_ERROR) {
		char* errstring = get_nlmsg_error(nl_head);
		if (errstring != NULL) {
			syslog(LOG_ALERT, "Unable to retrieve interface list: Netlink error: %s", errstring);
			return MNL_CB_ERROR;
		} else {
			return MNL_CB_OK;
		}
	} else {
		struct ifinfomsg* if_msg = mnl_nlmsg_get_payload(nl_head);
	
		if (!(if_msg->ifi_flags & IFF_LOOPBACK) && (list_cb_data->config->show_down_iface || if_msg->ifi_flags & IFF_RUNNING)) {
			if_item_t* if_item = new_if_item();
			get_if_item_cb_data_t item_cb_data = new_get_if_item_cb_data(list_cb_data->compiled_regex, list_cb_data->config, if_item);
			if_item->index = if_msg->ifi_index;
			if_item->type = if_msg->ifi_type;
			if_item->flags = if_msg->ifi_flags;
			if_item->family = if_msg->ifi_family;
			mnl_attr_parse(nl_head, sizeof(struct ifinfomsg), &get_if_item_cb, &item_cb_data);
			destroy_get_if_item_cb_data(&item_cb_data);
			if (if_item->loopback) {
				destroy_if_item(&if_item);
			} else if (list_cb_data->config->ignore_blacklist_iface || !if_item->blacklisted) {
				*(list_cb_data->if_list) = push_if_item(list_cb_data->if_list, if_item);
			} else {
				destroy_if_item(&if_item);
			}
		}
	
		return MNL_CB_OK;
	}
}

static int get_if_addr_list_cb(const struct nlmsghdr* nl_head, void* cb_data)
{
	get_if_addr_list_cb_data_t* addr_list_cb_data = (get_if_addr_list_cb_data_t*)cb_data;
	if (cb_data == NULL) {
		syslog(LOG_CRIT, "Internal error (invalid argument received in interface address list callback)");
		return MNL_CB_ERROR;
	} else if (nl_head->nlmsg_type == NLMSG_ERROR) {
		char* errstring = get_nlmsg_error(nl_head);
		if (errstring != NULL) {
			syslog(LOG_ALERT, "Unable to retrieve interface address list: Netlink error: %s", errstring);
			return MNL_CB_ERROR;
		} else {
			return MNL_CB_OK;
		}
	} else {
		struct ifaddrmsg* if_addr_msg = mnl_nlmsg_get_payload(nl_head);
		if_item_t* if_item = get_if_item_by_index(*addr_list_cb_data->if_list, if_addr_msg->ifa_index);

		if (if_item != NULL && (addr_list_cb_data->config->show_secondary_iface_addr || !(if_addr_msg->ifa_flags & IFA_F_SECONDARY))) {
			if_addr_t* if_addr = new_if_addr();
			if_addr->family = if_addr_msg->ifa_family;
			if_addr->mask = if_addr_msg->ifa_prefixlen;
			if_addr->flags = if_addr_msg->ifa_flags;
			if_addr->scope = if_addr_msg->ifa_scope;
			mnl_attr_parse(nl_head, sizeof(struct ifaddrmsg), &get_if_addr_cb, if_addr);
			if_item->addr_list = push_if_addr(&(if_item->addr_list), if_addr);
		}

		return MNL_CB_OK;
	}
}

static int print_neigh_list_cb(const struct nlmsghdr* nl_head, void* cb_data)
{
	print_neigh_list_cb_data_t* neigh_list_cb_data = (print_neigh_list_cb_data_t*)cb_data;
	if (neigh_list_cb_data == NULL || neigh_list_cb_data->fd == NULL) {
		syslog(LOG_CRIT, "Internal error (invalid argument received in neighbour list printing callback)");
		return MNL_CB_ERROR;
	} else if (nl_head->nlmsg_type == NLMSG_ERROR) {
		char* errstring = get_nlmsg_error(nl_head);
		if (errstring != NULL) {
			syslog(LOG_ALERT, "Unable to retrieve neighbour list: Netlink error: %s", errstring);
			return MNL_CB_ERROR;
		} else {
			return MNL_CB_OK;
		}
	} else {
		struct ndmsg* nd_msg = mnl_nlmsg_get_payload(nl_head);
		if_item_t* if_item = get_if_item_by_index(*(neigh_list_cb_data->if_list), nd_msg->ndm_ifindex);

		if (if_item != NULL && (neigh_list_cb_data->config->show_unreachable_neighs || nd_msg->ndm_state & NUD_REACHABLE || nd_msg->ndm_state & NUD_STALE) && (neigh_list_cb_data->config->show_known_blacklist_iface_neighs || !if_item->blacklisted)) {
			print_neigh_cb_data_t neigh_cb_data = new_print_neigh_cb_data(neigh_list_cb_data->fd, nd_msg->ndm_family, neigh_list_cb_data->host_lookup_table);
			fprintf(neigh_list_cb_data->fd, ",{");

			if (nd_msg->ndm_state & NUD_INCOMPLETE) {
				fprintf(neigh_list_cb_data->fd, "\"incomplete\":1,");
			}
			if (nd_msg->ndm_state & NUD_STALE) {
				fprintf(neigh_list_cb_data->fd, "\"stale\":1,");
			}
			if (nd_msg->ndm_state & NUD_REACHABLE) {
				fprintf(neigh_list_cb_data->fd, "\"reachable\":1,\"state\":\"reachable\",");
			} else if (nd_msg->ndm_state & NUD_STALE) {
				fprintf(neigh_list_cb_data->fd, "\"reachable\":0,\"state\":\"stale\",");
			} else {
				fprintf(neigh_list_cb_data->fd, "\"reachable\":0,\"state\":\"unreachable\",");
			}
			if (nd_msg->ndm_state & NUD_DELAY) {
				fprintf(neigh_list_cb_data->fd, "\"delay\":1,");
			}
			if (nd_msg->ndm_state & NUD_PROBE) {
				fprintf(neigh_list_cb_data->fd, "\"probe\":1,");
			}
			if (nd_msg->ndm_state & NUD_FAILED) {
				fprintf(neigh_list_cb_data->fd, "\"failed\":1,");
			}
			if (nd_msg->ndm_state & NUD_NOARP) {
				fprintf(neigh_list_cb_data->fd, "\"noarp\":1,");
			}
			if (nd_msg->ndm_state & NUD_PERMANENT) {
				fprintf(neigh_list_cb_data->fd, "\"permanent\":1,");
			}
			if (nd_msg->ndm_flags & NTF_PROXY) {
				fprintf(neigh_list_cb_data->fd, "\"proxy\":1,");
			}
			if (nd_msg->ndm_flags & NTF_ROUTER) {
				fprintf(neigh_list_cb_data->fd, "\"router\":1,");
			}
			mnl_attr_parse(nl_head, sizeof(struct ndmsg), &print_neigh_cb, &neigh_cb_data);
			destroy_print_neigh_cb_data(&neigh_cb_data);
			fprintf(neigh_list_cb_data->fd, "\"iface\":\"%s\"}", if_item->name);
		}

		return MNL_CB_OK;
	}
}






static void get_if_list(struct mnl_socket* nl_sock, regex_t* compiled_regex, if_list_t* if_list, config_t* config)
{
	char* buf;
	struct nlmsghdr* nl_head;
	struct rtgenmsg* rtnl_head;
	int errcode = 0;
	unsigned int seq;
	unsigned int portid;
	get_if_list_cb_data_t get_if_list_cb_data = new_get_if_list_cb_data(compiled_regex, config, if_list);
	const size_t bufsiz = MNL_SOCKET_BUFFER_SIZE;
	buf = (char*)malloc(bufsiz);
	if (buf == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
		exit(EX_OSERR);
	}

	nl_head = mnl_nlmsg_put_header(buf);
	nl_head->nlmsg_type = RTM_GETLINK;
	nl_head->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_head->nlmsg_seq = seq = time(NULL);
	rtnl_head = mnl_nlmsg_put_extra_header(nl_head, sizeof(struct rtgenmsg));
	rtnl_head->rtgen_family = AF_PACKET;

	portid = mnl_socket_get_portid(nl_sock);

	if (mnl_socket_sendto(nl_sock, nl_head, nl_head->nlmsg_len) < 0) {
		syslog_syserror(LOG_CRIT, "Unable to send interface list request to netlink");
		exit(EX_OSERR);
	}

	do {
		errcode = mnl_socket_recvfrom(nl_sock, buf, bufsiz);
	} while (errcode > 0 && (errcode = mnl_cb_run(buf, errcode, seq, portid, &get_if_list_cb, &get_if_list_cb_data)) > MNL_CB_STOP);

	if (errcode < -1) {
		syslog_syserror(LOG_CRIT, "Unable to retrieve interface list from netlink");
		exit(EX_OSERR);
	}

	destroy_get_if_list_cb_data(&get_if_list_cb_data);
	free(buf);
}

static void get_if_addrs(struct mnl_socket* nl_sock, if_list_t* if_list, config_t* config)
{
	char* buf;
	struct nlmsghdr* nl_head;
	struct rtgenmsg* rtnl_head;
	int errcode = 0;
	unsigned int seq;
	unsigned int portid;
	int i = 0;
	get_if_addr_list_cb_data_t addr_list_cb_data = new_get_if_addr_list_cb_data(if_list, config);
	const size_t bufsiz = MNL_SOCKET_BUFFER_SIZE;
	buf = (char*)malloc(bufsiz);
	if (buf == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
		exit(EX_OSERR);
	}

	nl_head = mnl_nlmsg_put_header(buf);
	nl_head->nlmsg_type = RTM_GETADDR;
	nl_head->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_head->nlmsg_seq = seq = time(NULL);
	rtnl_head = mnl_nlmsg_put_extra_header(nl_head, sizeof(struct rtgenmsg));
	rtnl_head->rtgen_family = AF_PACKET;

	portid = mnl_socket_get_portid(nl_sock);

	if (mnl_socket_sendto(nl_sock, nl_head, nl_head->nlmsg_len) < 0) {
		syslog_syserror(LOG_CRIT, "Unable to send interface address list request to netlink");
		exit(EX_OSERR);
	}

	do {
		errcode = mnl_socket_recvfrom(nl_sock, buf, bufsiz);
		i++;
	} while (errcode > 0 && (errcode = mnl_cb_run(buf, errcode, seq, portid, &get_if_addr_list_cb, &addr_list_cb_data)) > MNL_CB_STOP);

	if (errcode < -1) {
		syslog_syserror(LOG_CRIT, "Unable to retrieve interface address list from netlink");
		exit(EX_OSERR);
	}

	free(buf);
}


static void print_neigh_list(struct mnl_socket* nl_sock, FILE* fd, if_list_t if_list, config_t* config, host_lookup_table_t lookup_table)
{
	char* buf;
	struct nlmsghdr* nl_head;
	struct rtgenmsg* rtnl_head;
	int errcode = 0;
	unsigned int seq;
	unsigned int portid;
	print_neigh_list_cb_data_t neigh_list_cb_data = new_print_neigh_list_cb_data(fd, &if_list, config, lookup_table);
	const size_t bufsiz = MNL_SOCKET_BUFFER_SIZE;
	buf = (char*)malloc(bufsiz);
	if (buf == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
		exit(EX_OSERR);
	}

	nl_head = mnl_nlmsg_put_header(buf);
	nl_head->nlmsg_type = RTM_GETNEIGH;
	nl_head->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_head->nlmsg_seq = seq = time(NULL);
	rtnl_head = mnl_nlmsg_put_extra_header(nl_head, sizeof(struct rtgenmsg));
	rtnl_head->rtgen_family = AF_UNSPEC;

	portid = mnl_socket_get_portid(nl_sock);

	if (mnl_socket_sendto(nl_sock, nl_head, nl_head->nlmsg_len) < 0) {
		syslog_syserror(LOG_CRIT, "Unable to send neighbour list request to netlink");
		exit(EX_OSERR);
	}

	do {
		errcode = mnl_socket_recvfrom(nl_sock, buf, bufsiz);
	} while (errcode > 0 && (errcode = mnl_cb_run(buf, errcode, seq, portid, &print_neigh_list_cb, &neigh_list_cb_data)) > MNL_CB_STOP);

	if (errcode < -1) {
		/* TODO: get upstream error message */
		syslog_syserror(LOG_CRIT, "Unable to retrieve neighbour list from netlink");
		exit(EX_OSERR);
	}
	destroy_print_neigh_list_cb_data(&neigh_list_cb_data);


	free(buf);
}

static void print_if_list(FILE* subnet_fd, FILE* devices_fd, if_list_t if_list, config_t* config, host_lookup_table_t lookup_table)
{
	if_list_t if_list_iter = if_list;

	while (if_list_iter != NULL) {
		if_item_t* if_item = if_list_iter->data;
		if (!config->ignore_blacklist_iface || !if_item->blacklisted) {
			if_addr_list_t if_addr_list_iter = if_item->addr_list;
			if_item_t* real_if_item = NULL;

			if (if_item->index != if_item->link) {
				real_if_item = get_if_item_by_index(if_list, if_item->link);
			}

			while (if_addr_list_iter != NULL) {
				char str_temp[BUFSIZ];
				if_addr_t* if_addr = if_addr_list_iter->data;
				fprintf(subnet_fd, ",{");
				fprintf(devices_fd, ",{");

				if (if_item->flags & IFF_UP) {
					fprintf(devices_fd, "\"ifup\":1,");
				}
				if (if_item->flags & IFF_BROADCAST) {
					fprintf(devices_fd, "\"bcastset\":1,");
				}
				if (if_item->flags & IFF_POINTOPOINT) {
					fprintf(devices_fd, "\"ptp\":1,");
				}
				if (if_item->flags & IFF_NOARP) {
					fprintf(devices_fd, "\"noarp\":1,");
				}
				if (if_item->flags & IFF_PROMISC) {
					fprintf(devices_fd, "\"promiscuous\":1,");
				}
				if (if_item->flags & IFF_NOTRAILERS) {
					fprintf(devices_fd, "\"notrailers\":1,");
				}
				if (if_item->flags & IFF_ALLMULTI) {
					fprintf(devices_fd, "\"recvallmcast\":1,");
				}
				if (if_item->flags & IFF_MASTER) {
					fprintf(devices_fd, "\"lbmaster\":1,");
				}
				if (if_item->flags & IFF_SLAVE) {
					fprintf(devices_fd, "\"lbslave\":1,");
				}
				if (if_item->flags & IFF_MULTICAST) {
					fprintf(devices_fd, "\"supportmcast\":1,");
				}
				if (if_item->flags & IFF_PORTSEL) {
					fprintf(devices_fd, "\"portsel\":1,");
				}
				if (if_item->flags & IFF_AUTOMEDIA) {
					fprintf(devices_fd, "\"automedia\":1,");
				}
				if (if_item->flags & IFF_DYNAMIC) {
					fprintf(devices_fd, "\"dynamic\":1,");
				}
				fprintf(subnet_fd, "\"iface\":\"%s\",", if_item->name);
				fprintf(devices_fd, "\"iface\":\"%s\",", if_item->name);
				if (NULL == mac_ntop(if_item->mac, str_temp, 6)) {
					syslog(LOG_CRIT, "Unable to print MAC address for %s", if_item->name);
					fprintf(devices_fd, "\"netbios\":\"\",");
				} else {
					char* hostname = NULL;
					fprintf(devices_fd, "\"macaddress\":\"%s\",", str_temp);
					if ((hostname = host_lookup(lookup_table, str_temp)) != NULL) {
						fprintf(devices_fd, "\"netbios\":\"%s\",", hostname);
					} else {
						fprintf(devices_fd, "\"netbios\":\"\",");
					}
				}
				if (NULL == mac_ntop(if_item->bmac, str_temp, 6)) {
					syslog(LOG_CRIT, "Unable to print broadcast MAC address for %s", if_item->name);
				} else {
					fprintf(devices_fd, "\"bmac\":\"%s\",", str_temp);
				}
				fprintf(devices_fd, "\"mtu\":%"PRIu32",", if_item->mtu);
				if (real_if_item != NULL) {
					fprintf(subnet_fd, "\"realiface\":\"%s\",", real_if_item->name);
					fprintf(devices_fd, "\"realiface\":\"%s\",", real_if_item->name);
				}
				fprintf(devices_fd, "\"qdiscipline\":\"%s\",", if_item->qdsp);
				if (if_addr->flags & IFA_F_SECONDARY) {
					fprintf(devices_fd, "\"secondaryaddr\":1,");
				}
				if (if_addr->flags & IFA_F_PERMANENT) {
					fprintf(devices_fd, "\"permanent\":1,");
				}
				fprintf(devices_fd, "\"addrname\":\"%s\",", if_addr->label);
				fprintf(devices_fd, "\"masklength\":%u,", if_addr->mask);
				if (if_addr->family == AF_INET) {
					if (if_addr->addr == NULL) {
						/*syslog(LOG_DEBUG, "No address to print for %s", if_item->name);*/
					} else if (NULL == inet_ntop(AF_INET, &(((struct sockaddr_in*)(if_addr->addr))->sin_addr.s_addr), str_temp, BUFSIZ)) {
						syslog_syserror(LOG_CRIT, "Unable to print an IP address for %s", if_item->name);
					} else {
						fprintf(subnet_fd, "\"iprange\":\"%s/%u\"", str_temp, if_addr->mask);
						fprintf(devices_fd, "\"ipaddress\":\"%s\",", str_temp);
					}
					if (if_addr->local == NULL) {
						/*syslog(LOG_DEBUG, "No local address to print for %s", if_item->name);*/
					} else if (NULL == inet_ntop(AF_INET, &(((struct sockaddr_in*)(if_addr->local))->sin_addr.s_addr), str_temp, BUFSIZ)) {
						syslog_syserror(LOG_CRIT, "Unable to print an internal IP address for %s", if_item->name);
					} else {
						fprintf(devices_fd, "\"internalip\":\"%s\",", str_temp);
					}
					if (if_addr->bcast == NULL) {
						/*syslog(LOG_DEBUG, "No broadcast address to print for %s", if_item->name);*/
					} else if (NULL == inet_ntop(AF_INET, &(((struct sockaddr_in*)(if_addr->bcast))->sin_addr.s_addr), str_temp, BUFSIZ)) {
						syslog_syserror(LOG_CRIT, "Unable to print a broadcast IP address for %s", if_item->name);
					} else {
						fprintf(devices_fd, "\"bcast\":\"%s\",", str_temp);
					}
					if (if_addr->acast == NULL) {
						/*syslog(LOG_DEBUG, "No anycast address to print for %s", if_item->name);*/
					} else if (NULL == inet_ntop(AF_INET, &(((struct sockaddr_in*)(if_addr->acast))->sin_addr.s_addr), str_temp, BUFSIZ)) {
						syslog_syserror(LOG_CRIT, "Unable to print an anycast IP address for %s", if_item->name);
					} else {
						fprintf(devices_fd, "\"acast\":\"%s\",", str_temp);
					}
				} else if (if_addr->family == AF_INET6) {
					if (if_addr->addr == NULL) {
						/*syslog(LOG_DEBUG, "No address to print for %s", if_item->name);*/
					} else if (NULL == inet_ntop(AF_INET6, &(((struct sockaddr_in6*)(if_addr->addr))->sin6_addr.s6_addr), str_temp, BUFSIZ)) {
						syslog_syserror(LOG_CRIT, "Unable to print an IP address for %s", if_item->name);
					} else {
						fprintf(subnet_fd, "\"ip6range\":\"%s/%u\"", str_temp, if_addr->mask);
						fprintf(devices_fd, "\"ip6\":\"%s\",", str_temp);
					}
					if (if_addr->local == NULL) {
						/*syslog(LOG_DEBUG, "No local address to print for %s", if_item->name);*/
					} else if (NULL == inet_ntop(AF_INET6, &(((struct sockaddr_in6*)(if_addr->local))->sin6_addr.s6_addr), str_temp, BUFSIZ)) {
						syslog_syserror(LOG_CRIT, "Unable to print an internal IP address for %s", if_item->name);
					} else {
						fprintf(devices_fd, "\"internalip\":\"%s\",", str_temp);
					}
					if (if_addr->bcast == NULL) {
						/* syslog(LOG_DEBUG, "No broadcast address to print for %s", if_item->name); */
					} else if (NULL == inet_ntop(AF_INET6, &(((struct sockaddr_in6*)(if_addr->bcast))->sin6_addr.s6_addr), str_temp, BUFSIZ)) {
						syslog_syserror(LOG_CRIT, "Unable to print a broadcast IP address for %s", if_item->name);
					} else {
						fprintf(devices_fd, "\"bcast\":\"%s\",", str_temp);
					}
					if (if_addr->acast == NULL) {
						/*syslog(LOG_DEBUG, "No anycast address to print for %s", if_item->name);*/
					} else if (NULL == inet_ntop(AF_INET6, &(((struct sockaddr_in6*)(if_addr->acast))->sin6_addr.s6_addr), str_temp, BUFSIZ)) {
						syslog_syserror(LOG_CRIT, "Unable to print an anycast IP address for %s", if_item->name);
					} else {
						fprintf(devices_fd, "\"acast\":\"%s\",", str_temp);
					}
				} else {
					syslog(LOG_CRIT, "Interface address was neither IPv4 nor IPv6");
				}
				fprintf(subnet_fd, "}");
				fprintf(devices_fd, "\"isagent\":1}");
				if_addr_list_iter = if_addr_list_iter->next;
			}
		}
		if_list_iter = if_list_iter->next;
	}
}


/*--------------------------------------------------------------------*/
/*--- checksum - standard 1s complement checksum                   ---*/
/*--------------------------------------------------------------------*/
unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}


/*----------------------------------------------------------------------------*/
/*--- icmp_probe - Create icmp echo message and send to force arp response ---*/
/*----------------------------------------------------------------------------*/
int icmp_probe(char *ipaddress)
{
    const int val=255;
    int sock;
    int pid=-1;
    int echo_cnt=1; 
    int i;
    struct protoent *proto=NULL;    
    struct packet pckt;
    struct sockaddr_in r_addr;
    struct hostent *hname;
    struct sockaddr_in addr_ping,*addr;

    //setup socket
    pid = getpid();
    proto = getprotobyname("ICMP");
    hname = gethostbyname(ipaddress);
    bzero(&addr_ping, sizeof(addr_ping));
    addr_ping.sin_family = hname->h_addrtype;
    addr_ping.sin_port = 0;
    addr_ping.sin_addr.s_addr = *(long*)hname->h_addr;

    addr = &addr_ping;

    sock = socket(PF_INET, SOCK_RAW, proto->p_proto);
    if ( sock < 0 )
    {
        syslog_syserror(LOG_ALERT, "ICMP Socket Init Error");
        return 0;
    }
    if ( setsockopt(sock, SOL_IP, IP_TTL, &val, sizeof(val)) != 0)
    {
	syslog_syserror(LOG_ALERT, "ICMP Set TTL option");
        return 0;
    }
    if ( fcntl(sock, F_SETFL, O_NONBLOCK) != 0 )
    {
        syslog_syserror(LOG_ALERT, "ICMP Request nonblocking I/O");
        return 0;
    }
    
    //send icmp probe
    bzero(&pckt, sizeof(pckt));
    pckt.hdr.type = ICMP_ECHO;
    pckt.hdr.un.echo.id = pid;
    for (i = 0; i < sizeof(pckt.msg)-1; i++ )
    {	pckt.msg[i] = i+'0';
    }
    pckt.msg[i] = 0;
    pckt.hdr.un.echo.sequence = echo_cnt++;
    pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));
    if ( sendto(sock, &pckt, sizeof(pckt), 0, (struct sockaddr*)addr, sizeof(*addr)) <= 0 )
    {	syslog_syserror(LOG_ALERT, "ICMP SendTo Error");
    }

    //resource cleanup
    close(sock);    

    return 0;
}




static void scan_network(struct sockaddr* addr, uint8_t mask, int ifindex, struct mnl_socket* nl_sock)
{

	size_t remote_addr_size;
	struct sockaddr* remote_addr;
	if (addr->sa_family == AF_INET) {
		remote_addr_size = sizeof(struct sockaddr_in);
	} else if (addr->sa_family == AF_INET6) {
		if (CONFIG_OPTION_IPV6_PROBES) {
			remote_addr_size = sizeof(struct sockaddr_in6);
		} else {
			syslog(LOG_INFO, "Not configured to send IPv6 probes, skipping scan of IPv6 range");
			return;
		}
	} else {
		syslog(LOG_ERR, "Unexpected address family for network scanning");
		return;
	}
	remote_addr = (struct sockaddr*)malloc(remote_addr_size);
	if (remote_addr == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
		exit(EX_OSERR);
	}
	memset(remote_addr, 0, remote_addr_size);


	//check netlink for each mac address
	syslog(LOG_INFO, "Scan Subnet and Check Netlink for Mac Address");
	
	while (increment_addr(addr, mask, remote_addr) > 0) {
		char* buf;
		struct nlmsghdr* nl_head;
		struct ndmsg* ndm_head;
		int errcode = 0;
		unsigned int seq;
		unsigned int portid;
		const size_t bufsiz = MNL_SOCKET_BUFFER_SIZE;
		const uint8_t blank_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		buf = (char*)malloc(bufsiz);
		if (buf == NULL) {
			syslog_syserror(LOG_EMERG, "Unable to allocate memory");
			exit(EX_OSERR);
		}
		
		//send an icmp echo probe just before checking netlink to get an inventory
		struct sockaddr_in* addr = (struct sockaddr_in*) remote_addr;
		char *ip = inet_ntoa(addr->sin_addr);		
		icmp_probe(ip);
		
		//check netlink for Mac Address
		nl_head = mnl_nlmsg_put_header(buf);
		nl_head->nlmsg_type = RTM_NEWNEIGH;
		nl_head->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
		nl_head->nlmsg_seq = seq = time(NULL);
		ndm_head = mnl_nlmsg_put_extra_header(nl_head, sizeof(struct ndmsg));
		ndm_head->ndm_family = remote_addr->sa_family;
		ndm_head->ndm_ifindex = ifindex;
		ndm_head->ndm_state = NUD_NONE;
		ndm_head->ndm_flags = 0;
	
		if (remote_addr->sa_family == AF_INET) {
			if (!mnl_attr_put_check(nl_head, MNL_SOCKET_BUFFER_SIZE, NDA_DST, sizeof(struct in_addr), &(((struct sockaddr_in*)remote_addr)->sin_addr))) {
				syslog(LOG_CRIT, "Unable to prepare netlink message with a placeholder neighbour");
				exit(EX_SOFTWARE);
			}
		} else if (remote_addr->sa_family == AF_INET6) {
			if (!mnl_attr_put_check(nl_head, MNL_SOCKET_BUFFER_SIZE, NDA_DST, sizeof(struct in6_addr), &(((struct sockaddr_in6*)remote_addr)->sin6_addr))) {
				syslog(LOG_CRIT, "Unable to prepare netlink message with a placeholder neighbour");
				exit(EX_SOFTWARE);
			}
		} else {
			syslog(LOG_CRIT, "Internal error (address iterator has an unexpected address family)");
			exit(EX_SOFTWARE);
		}

		if (!mnl_attr_put_check(nl_head, MNL_SOCKET_BUFFER_SIZE, NDA_LLADDR, 6, blank_mac)) {
			syslog(LOG_CRIT, "Unable to prepare netlink message with a placholder neighbour MAC address");
			exit(EX_SOFTWARE);
		}
		
		portid = mnl_socket_get_portid(nl_sock);
	
		if (mnl_socket_sendto(nl_sock, nl_head, nl_head->nlmsg_len) < 0) {
			syslog_syserror(LOG_CRIT, "Unable to send placeholder neighbour through netlink");
			exit(EX_OSERR);
		}
	
		do {
			errcode = mnl_socket_recvfrom(nl_sock, buf, bufsiz);
		} while (errcode > 0 && (errcode = mnl_cb_run(buf, errcode, seq, portid, &print_nlmsg_error_cb, NULL)) > MNL_CB_STOP);
	
		if (errcode < -1) {
			syslog_syserror(LOG_CRIT, "Unable to add placeholder neighbour via netlink");
			exit(EX_OSERR);
		}
	
	
		free(buf);
	}
	free(remote_addr);


}

static void scan_networks(struct mnl_socket* nl_sock, if_list_t if_list, config_t* config)
{
	if_list_t if_item_iter = if_list;

	while (nl_sock != NULL && if_item_iter != NULL) {
		if_item_t* if_item = if_item_iter->data;
		if_addr_list_t if_addr_iter = if_item->addr_list;

		while (if_addr_iter != NULL) {
			if_addr_t* if_addr = if_addr_iter->data;

			if (config->autoscan && !if_item->blacklisted && check_autoscannable_range(if_addr->addr, if_addr->mask) > 0) {
				scan_network(if_addr->addr, if_addr->mask, if_item->index, nl_sock);
			} else if ((!config->blacklist_overrides_networks || !if_item->blacklisted) && config->networks != NULL) {
				network_list_t overlapping_networks = get_overlapping_networks(if_addr->addr, if_addr->mask, config->networks);
				network_list_t network_iterator = overlapping_networks;
				while (network_iterator != NULL) {
					scan_network(network_iterator->addr_base, network_iterator->prefix, if_item->index, nl_sock);
					network_iterator = network_iterator->next;
				}
				destroy_network_list(&overlapping_networks);
			}

			if_addr_iter = if_addr_iter->next;
		}

		if_item_iter = if_item_iter->next;
	}
}










void print_neighbours(config_t* config, FILE* subnet_fd, FILE* devices_fd)
{
	char uncompiled_regex[CONFIG_OPTION_IFACE_BLACKLIST_REGEX_LENGTH + CONFIG_OPTION_PERMANENT_IFACE_BLACKLIST_REGEX_LENGTH + 1];
	regex_t compiled_regex;
	if_list_t if_list = new_if_list();
	struct mnl_socket* nl_sock;
	int errcode = 0;
	host_lookup_table_t lookup_table;

	if (config == NULL) {
		syslog(LOG_CRIT, "Internal error (empty config received inside print neighbours)");
		exit(EX_SOFTWARE);
	} else if ((subnet_fd == NULL) || (devices_fd == NULL)) {
		syslog(LOG_CRIT, "Bad file descriptor received");
		exit(EX_SOFTWARE);
	}

	if (config->iface_blacklist_regex != NULL && strlen(config->iface_blacklist_regex) > 0) {
		snprintf(
				uncompiled_regex,
				CONFIG_OPTION_IFACE_BLACKLIST_REGEX_LENGTH + CONFIG_OPTION_PERMANENT_IFACE_BLACKLIST_REGEX_LENGTH + 1,
				CONFIG_OPTION_PERMANENT_IFACE_BLACKLIST_REGEX "|%s",
				config->iface_blacklist_regex);
	} else {
		strcpy(uncompiled_regex, CONFIG_OPTION_PERMANENT_IFACE_BLACKLIST_REGEX);
	}
	errcode = regcomp(&compiled_regex, uncompiled_regex, REG_EXTENDED | REG_ICASE);
	if (errcode != 0) {
		char str_temp[BUFSIZ];
		regerror(errcode, &compiled_regex, str_temp, BUFSIZ);
		syslog(LOG_CRIT, "Unable to prepare the network interface regex: %s", str_temp);
		exit(EX_SOFTWARE);
	}

	nl_sock = mnl_socket_open(NETLINK_ROUTE);
	if (nl_sock == NULL) {
		syslog_syserror(LOG_CRIT, "Unable to open netlink socket");
		exit(EX_OSERR);
	}

	if (mnl_socket_bind(nl_sock, 0, MNL_SOCKET_AUTOPID) < 0) {
		syslog_syserror(LOG_CRIT, "Unable to bind netlink socket to port");
		exit(EX_OSERR);
	}


	get_if_list(nl_sock, &compiled_regex, &if_list, config);

	get_if_addrs(nl_sock, &if_list, config);

	scan_networks(nl_sock, if_list, config);

	if (full_sleep(CONFIG_OPTION_SCAN_RESULT_TIMEOUT)) 
	{
		fprintf(subnet_fd, "[\"%s\"", config->session_id);
		fprintf(devices_fd, "[\"%s\"", config->session_id);
	
		lookup_table = get_host_lookup_table(config);
	
		print_if_list(subnet_fd, devices_fd, if_list, config, lookup_table);
	
		fprintf(subnet_fd, "]");
	
		print_neigh_list(nl_sock, devices_fd, if_list, config, lookup_table);
	
		fprintf(devices_fd, "]");
	}

	mnl_socket_close(nl_sock);

	destroy_host_lookup_table(&lookup_table);
	destroy_if_list(&if_list);
	regfree(&compiled_regex);
}



