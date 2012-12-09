#include <time.h>
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "sr_utils.h"
#include "sr_router.h"

/* Internal Function Prototypes */
void update_connection_state(struct sr_nat_mapping *mapping, struct sr_nat_tcp_aux *aux);
struct sr_nat_connection *get_connection(struct sr_nat_mapping *mapping, struct sr_nat_tcp_aux *aux);

int sr_nat_init(struct sr_instance *sr, struct sr_nat *nat) { /* Initializes the nat */
	
  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */
  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */
  
  /* Initialize any variables here */
  nat->mappings = NULL;
	nat->next_port = TCP_MIN_EXT_PORT;
	nat->next_id = 1;
	nat->icmp_to = sr->icmp_to;
  nat->tcp_estab_to = sr->tcp_estab_to;
  nat->tcp_trans_to = sr->tcp_trans_to;
  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */
	struct sr_nat_mapping *mapping, *next;
	struct sr_nat_connection *connection, *next_connection;
	
  pthread_mutex_lock(&(nat->lock));

  /* Free all mappings. */
  mapping = nat->mappings;
  while (mapping) {
  	next = mapping->next;
  	
  	/* Free associated connections. */
  	connection = mapping->conns;
  	while (connection) {
  		next_connection = connection->next;
  		free(connection);
  		connection = next_connection;
  	}
  	
  	free(mapping);
  	mapping = next;
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  time_t curtime;
  struct sr_nat_mapping *mapping, *prev;
  struct sr_nat_connection *conn, *prev_conn;
  double timeout;

  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

		/* Iterate through mappings to destroy old ones. */
    curtime = time(NULL);
		mapping = nat->mappings;
		prev = NULL;
    while (mapping) {
 
    	/* For TCP, destroy old connections. */
    	if (mapping->type == nat_mapping_tcp) {
    	
    		/* Iterate through each connection and remove closed ones. */
    		conn = mapping->conns;
    		prev_conn = NULL;
    		while(conn) {
    			
    			/* Use transitory timeout. */
    			if (conn->state == connection_state_open ||
    				  conn->state == connection_state_close) {
    				  
    				timeout = nat->tcp_trans_to;
    				
    			/* Use established timeout. */  
    			} else if (conn->state == connection_state_established) {
    				timeout = nat->tcp_estab_to;
    			
    			/* This connection was closed so just delete it no matter what. */
    			} else {
						timeout = 0;
    			}
    			
    			/* The connection timed out. */
    			if (difftime(curtime, mapping->last_updated) > timeout) {
    				if (prev_conn == NULL) {
    					mapping->conns = conn->next;
    					free(conn);
    					conn = mapping->conns;
    					
 		   			} else {
    					prev_conn->next = conn->next;
    					free(conn);
    					conn = prev_conn->next;
    				}
    			
    			/* Move on. */
    			} else {
    				prev_conn = conn;
    				conn = conn->next;
    			}
    		}
    	}
    	
    	/* Destroy icmp if icmp timeout has passed. Destroy a tcp mapping if it has no 
    	 * connections. */
    	if (((mapping->type == nat_mapping_icmp) && 
    			 (difftime(curtime, mapping->last_updated) > nat->icmp_to)) || 
    			((mapping->type == nat_mapping_tcp) && (mapping->conns == NULL))) {
    			
    		if (prev == NULL) {
    				nat->mappings = mapping->next;
    				free(mapping);
    				mapping = nat->mappings;
    				
    			} else {
    				prev->next = mapping->next;
    				free(mapping);
    				mapping = prev->next;
    			}
    		
    		/* Move on. */
    		} else {
    			prev = mapping;
    			mapping = mapping->next;
    		}
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, enum sr_nat_mapping_type type,  struct sr_nat_tcp_aux *aux) {
	
  pthread_mutex_lock(&(nat->lock));

	struct sr_nat_mapping *mapping, *copy = NULL;
	
  /* handle lookup here */
  mapping = nat->mappings;
  while (mapping) {
  	if (mapping->aux_ext == aux_ext && mapping->type == type)
  		break; 
  	
  	mapping = mapping->next;
  }

	/* If there is a mapping, malloc and assign to copy, update time. */
	if (mapping) {
		if (type == nat_mapping_tcp)
			update_connection_state(mapping, aux);
		copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
    mapping->last_updated = time(NULL);
	}
	
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, enum sr_nat_mapping_type type, struct sr_nat_tcp_aux *aux) {

  pthread_mutex_lock(&(nat->lock));

	struct sr_nat_mapping *mapping, *copy = NULL;
	
  /* handle lookup here */
  mapping = nat->mappings;
  while (mapping) {
  	if (mapping->ip_int == ip_int && 
  		  mapping->type == type && 
  		  mapping->aux_int == aux_int)
  		  
  		break; 
  	
  	mapping = mapping->next;
  }

	/* If there is a mapping, malloc and assign to copy, update time and connection state. */
	if (mapping) {
		if (type == nat_mapping_tcp)
			update_connection_state(mapping, aux);
		copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
    mapping->last_updated = time(NULL);
	}

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint32_t ip_ext, uint16_t aux_int, enum sr_nat_mapping_type type, 
  struct sr_nat_tcp_aux *aux) {

  pthread_mutex_lock(&(nat->lock));

  /* Create a mapping */
  struct sr_nat_mapping *mapping = NULL, *copy = NULL;
  
  mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
	mapping->type = type;
	mapping->aux_int = aux_int;
	mapping->ip_int = ip_int;
	mapping->ip_ext = ip_ext;
	mapping->last_updated = time(NULL);
	mapping->conns = NULL;
	mapping->next = NULL;
	
	/* We can assume we will not have more than 65536-1024 open connections at once 
	 * (PIAZZA said so) we do not have to check whether this aux_ex is taken. However,
	 * For TCP connections, if the next port is < 1024, we should add to it (could occur 
	 * an overflow). */
	if (type == nat_mapping_icmp) {
		mapping->aux_ext = htons(nat->next_id);
		nat->next_id ++;
		 
	} else {
		mapping->aux_ext = htons(nat->next_port);
		nat->next_port ++;
		if (nat->next_port < TCP_MIN_EXT_PORT)
			nat->next_port += TCP_MIN_EXT_PORT;
	}
	
	/* Insert mapping */
	mapping->next = nat->mappings;
	nat->mappings = mapping;
	
	/* Add first connection here. */
	if (type == nat_mapping_tcp)
		update_connection_state(mapping, aux);
	
	/* Create copy */
	copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
    
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Update connection state of a given mapping. Insert a new connection if
 * an associated connection cannot be found. Used only for TCP connections. */
void update_connection_state(struct sr_nat_mapping *mapping, struct sr_nat_tcp_aux *aux)
{
	struct sr_nat_connection *connection;
	
	/* Find connection associated with this destination ip/port. */
	connection = get_connection(mapping, aux);

	/* Update the connection state with the new information. */		
	switch (connection->state) {
		case connection_state_open:
		
			/* You received an ack. It could be for a syn or it could be for a fin in 
			 * the FIN WAIT-2 case. */
			if (aux->transition & RECEIVE_ACK) {
				
				/* You have sent a fin before connection was fully established. Check that the 
				 * ack is for the fin explicitly. */
				if (connection->outgoing_fin) {
					if (aux->ackno == htonl(connection->outgoing_fin_seqno + 1))
						connection->incoming_ack = 1;
					
				/* This is just an incoming ack to a syn. Don't bother with the seqno stuff. */
				} else {
					connection->incoming_ack = 1;
				}
			}
			
			/* Sent an ack, for a syn. */
			if (aux->transition & SEND_ACK)
				connection->outgoing_ack = 1;
			
			/* This occurs when you are moving from SYN RCVD to FIN WAIT-1. Set that you
			 * did not receive an ack yet, because now you are looking for an ack for a 
			 * fin not a syn. */
			if (aux->transition & SEND_FIN) {
				connection->outgoing_fin = 1;
				connection->outgoing_fin_seqno = ntohl(aux->seqno);
				connection->incoming_ack = 0;
			}
			
			/* This occurs when you move from FIN WAIT-1 to FIN WAIT-2. */
			if (aux->transition & RECEIVE_FIN) {
				connection->incoming_fin = 1;
				connection->incoming_fin_seqno = ntohl(aux->seqno);
				connection->outgoing_ack = 0;
			}
			
			/* Transition to established if you have both sent and received an to the syns. */
			if (connection->incoming_ack && connection->outgoing_ack) {
				connection->state = connection_state_established;
				connection->incoming_ack = 0;
				connection->outgoing_ack = 0;
			}
			
			/* Transition to close if you have both sent fins. */
			if (connection->outgoing_fin && connection->incoming_fin) {
				connection->state = connection_state_close;
			}
			
			break;
		
		case connection_state_established:
		
			/* If you received a fin, store its seqno. */
			if (aux->transition & RECEIVE_FIN){
				connection->incoming_fin = 1;
				connection->incoming_fin_seqno = ntohl(aux->seqno);
			}
			
			/* If you send a fin, store its seqno. */
			if (aux->transition & SEND_FIN) {
				connection->outgoing_fin = 1;
				connection->outgoing_fin_seqno = ntohl(aux->seqno);
			}
			
			/* If you receive an ack, ignore unless you have sent a fin. Then check whether
			 * it corresponds to that fin. */
			if (aux->transition & RECEIVE_ACK) {
				if (connection->outgoing_fin) {
					if (aux->ackno == htonl(connection->outgoing_fin_seqno + 1))
						connection->incoming_ack = 1;
				}
			}
			
			/* If you send an ack, ignore unless you have received a fin. Then check whether it 
			 * corresponds to that fin. */
			if (aux->transition &SEND_ACK) {
				if (connection->incoming_fin) {
					if (aux->ackno == htonl(connection->incoming_fin_seqno + 1))
						connection->outgoing_ack = 1;
				}
			}
			
			/* Transition to closing state if both incoming and outgoing fins have been 
			 * received. */
			if (connection->outgoing_fin && connection->incoming_fin) {
				connection->state = connection_state_close;
			}
			
			break;
		
		case connection_state_close:
		
			/* If you receive an ack, ensure that it is with regard to the fin. */
			if (aux->transition & RECEIVE_ACK) {
				if (aux->ackno == htonl(connection->outgoing_fin_seqno + 1))
						connection->incoming_ack = 1;
			}
			
			/* If you send an ack, ensure that it is with regard to the fin you received. */
			if (aux->transition & SEND_ACK) {
				if (aux->ackno == htonl(connection->incoming_fin_seqno + 1))
						connection->outgoing_ack = 1;
			}
			
			/* If you have received an ack, and sent and ack for fins, switch to connection
			 * tear down. */
			if (connection->outgoing_ack && connection->incoming_ack) {
				connection->state = connection_state_tear_down;
			}
			
			break;
		
		case connection_state_tear_down:
			break;
	}
}

/* Find connection associated with this destination ip/port. If there is no connection 
 * with this destination ip/port, create a new one. */
struct sr_nat_connection *get_connection(struct sr_nat_mapping *mapping, struct sr_nat_tcp_aux *aux)
{
	struct sr_nat_connection *connection;
	
	/* Find connection associated with this destination ip/port. */
	connection = mapping->conns;
	while(connection) {
		if ((connection->ip_dst == aux->ip_dst) && (connection->port_dst == aux->port_dst))
			break;
		
		connection = connection->next;
	}
	
	/* If there is no connection with this destination ip/port, create a new one. */
	if (!connection) {
		connection = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
		connection->ip_dst = aux->ip_dst;
		connection->port_dst = aux->port_dst;
		connection->state = connection_state_open;	
		connection->incoming_ack = 0;
		connection->outgoing_ack = 0;
		connection->incoming_fin = 0;
		connection->outgoing_fin = 0;
		connection->incoming_fin_seqno = 0;
		connection->outgoing_fin_seqno = 0;
		
		/* Insert it into the linked list. */
		connection->next = mapping->conns;
		mapping->conns = connection;
	}
	
	return connection;
}