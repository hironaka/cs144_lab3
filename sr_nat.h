
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>

#define TCP_MIN_EXT_PORT 1024

/* Define several flags used to transition between states. */ 
#define RECEIVE_ACK 0x01
#define SEND_ACK	  0x02
#define RECEIVE_SYN	0x04
#define SEND_SYN		0x08
#define RECEIVE_FIN	0x10
#define SEND_FIN		0x20

struct sr_instance;

enum sr_nat_mapping_type{
  nat_mapping_icmp,
  nat_mapping_tcp,
};

enum sr_nat_connection_state{
	connection_state_open,				/* Connection state open. One syn received. */
	connection_state_established,	/* Established connection. */
	connection_state_close,				/* Two fins sent, waiting on acks. */
	connection_state_tear_down,		/* All communication is done. Teardown the connection state. */
};	

typedef struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t ip_dst;
  uint16_t port_dst;
	enum sr_nat_connection_state state;	/* Stores the tcp connection state. */
	int incoming_ack;								/* Boolean indicating received incoming ack. */
	int outgoing_ack;								/* Boolean indicating received outgoing ack. */
	int incoming_fin;								/* Boolean indicating received incoming fin. */
	int outgoing_fin;								/* Boolean indicating received outgoing fin. */
	uint32_t incoming_fin_seqno;		/* Used to ensure that the final fins are acked. Host byte order. */
	uint32_t outgoing_fin_seqno;		/* Used to ensure that the final fins are acked. Host byte order. */
  struct sr_nat_connection *next;
} sr_nat_connection;

/* Auxiliary info struct for a tcp connection state update. Passed to lookup function. */
typedef struct sr_nat_tcp_aux {
	uint16_t transition;
	uint16_t port_dst;
	uint32_t ip_dst;
	uint32_t seqno;
	uint32_t ackno;
} sr_nat_tcp_aux;

typedef struct sr_nat_mapping {
  enum sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
}sr_nat_mapping;

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
	uint16_t next_port;			/* Next external port number for generated TCP mapping. */
	uint16_t next_id;				/* Next external id number for generated ICMP mapping. */
	int icmp_to; 						/* icmp idle time out in seconds */
  int tcp_estab_to; 			/* tcp established idle time out in seconds */
  int tcp_trans_to; 			/* tcp transitory idle time out in seconds */
  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_instance *sr, struct sr_nat *nat); /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, enum sr_nat_mapping_type type, struct sr_nat_tcp_aux *aux);

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, enum sr_nat_mapping_type type, struct sr_nat_tcp_aux *aux);

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint32_t ip_ext, uint16_t aux_int, 
  enum sr_nat_mapping_type type, struct sr_nat_tcp_aux *aux);

#endif