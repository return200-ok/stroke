#include <unistd.h>  
#include <errno.h>  
#include <stdio.h>  
#include <stdlib.h>  
#include <sys/types.h>  
#include <netinet/in.h>  
#include <pcap.h>  
#include <signal.h>  
#include "./oui.h"

#define SNAPLEN         34  
#define PROMISC         1  
#define TIMEOUT         500  
#define FILTER          "ip"  
#define HASH_TABLE_SIZE 1009     /* should be tunable to network size */

struct table_entry
{
u_char mac[6];  /* holds the MAC address */
struct table_entry *next;   /* pointer to the next entry */
};

const char *b_search(u_char *);
char *eprintf(u_char *);
char *iprintf(u_char *);
int interesting(u_char *, struct table_entry **);
int ht_dup_check(u_char *, struct table_entry **, int);
int ht_add_entry(u_char *, struct table_entry **, int);
u_long ht_hash(u_char *);
void ht_int_table(struct table_entry **);
void cleanup(int);
int catch_sig(int, void(*)());
