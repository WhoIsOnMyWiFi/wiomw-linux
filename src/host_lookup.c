#include "host_lookup.h"
#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sysexits.h>
#include "print_error.h"

#define DNSMASQ_DUMP_COMMAND "cat %s | awk '{print $2 $4}'"

/* TODO: Add a check to autoconf. */
#define ENABLE_DNSMASQ_LEASE_HOST_LOOKUP false

struct _host_lookup_table_struct {
	char mac_addr[18];
	struct _host_lookup_table_struct* next;
	char* hostname;
};

host_lookup_table_t get_host_lookup_table(config_t* config)
{
	if (ENABLE_DNSMASQ_LEASE_HOST_LOOKUP && config != NULL) {
		host_lookup_table_t lookup_table = NULL;
		host_lookup_table_t* temp = &lookup_table;
		char command[BUFSIZ];
		FILE* output;
		snprintf(command, BUFSIZ, DNSMASQ_DUMP_COMMAND, config->dnsmasq_lease_file);
		output = popen(command, "r");
		if (output == NULL) {
			print_syserror("Unable to parse the dnsmasq lease file");
			exit(EX_OSERR);
		} else {
			char line[BUFSIZ];
			while (fgets(line, BUFSIZ, output) != NULL) {
				size_t hostname_length = strnlen(line + 17, BUFSIZ - 17);
				if (hostname_length != BUFSIZ - 17) {
					*temp = (host_lookup_table_t)malloc(sizeof(struct _host_lookup_table_struct));
					if (*temp == NULL) {
						print_syserror("Unable to allocate hostname lookup table entry");
						exit(EX_OSERR);
					}
					(*temp)->hostname = (char*)malloc(hostname_length);
					if ((*temp)->hostname == NULL) {
						print_syserror("Unable to allocate hostname string");
						exit(EX_OSERR);
					}
					strncpy((*temp)->mac_addr, line, 17);
					(*temp)->mac_addr[17] = '\0';
					strncpy((*temp)->hostname, line + 17, hostname_length);
					(*temp)->next = NULL;
					temp = &((*temp)->next);
				}
			}
		}
		return lookup_table;
	} else {
		return NULL;
	}
}

char* host_lookup(host_lookup_table_t table, char* mac_addr)
{
	host_lookup_table_t temp = table;
	while (temp != NULL) {
		if (strncmp(temp->mac_addr, mac_addr, 18) == 0) {
			return temp->hostname;
		}
	}
	return NULL;
}

void destroy_host_lookup_table(host_lookup_table_t* table)
{
	if (table != NULL) {
		while (*table != NULL) {
			host_lookup_table_t temp = *table;
			*table = temp->next;
			free(temp->hostname);
			free(temp);
		}
	}
}


