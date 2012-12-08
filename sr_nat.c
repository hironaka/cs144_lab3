
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "sr_utils.h"

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

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

  nat->mappings = NULL;
  /* Initialize any variables here */
	
  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */
	struct sr_nat_mapping *mapping, *next;
	
  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  mapping = nat->mappings;
  while (mapping) {
  	next = mapping->next;
  	free(mapping);
  	mapping = next;
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  /*time_t curtime;
  struct sr_nat_mapping *mapping, next;
  TODO*/
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    /*curtime = time(NULL);

     handle periodic tasks here 
    //mapping = nat->mappings;
    //while (mapping) {
    //	if ()
    //}*/

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {
	
  pthread_mutex_lock(&(nat->lock));

	struct sr_nat_mapping *mapping, *copy = NULL;
	
  /* handle lookup here */
  mapping = nat->mappings;
  while (mapping) {
  	if (mapping->aux_ext == aux_ext && mapping->type == type)
  		break; 
  	
  	mapping = mapping->next;
  }

	/* malloc and assign to copy */
	if (mapping) {
		copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
	}
	
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

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

	/* malloc and assign to copy */
	if (mapping) {
		copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
	}

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* Create a mapping */
  struct sr_nat_mapping *mapping = NULL, *copy = NULL;
  mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
	mapping->type = type;
	mapping->aux_int = aux_int;
	mapping->ip_int = ip_int;
	mapping->ip_ext = nat->ip_ext;
	
	/* We can assume we will not have more than 65536-1024 open connections at once 
	 * (PIAZZA said so) we do not have to check whether this aux_ex is taken. However,
	 * For TCP connections, if the next port is < 1024, we should add to it (could occur 
	 * an overflow). */
	if (type == nat_mapping_icmp) {
		mapping->ip_int = htons(nat->next_id);
		nat->next_id ++;
		 
	} else {
		mapping->ip_int = htons(nat->next_port);
		nat->next_port ++;
		if (nat->next_port < TCP_MIN_EXT_PORT)
			nat->next_port += TCP_MIN_EXT_PORT;
	}
	
	/* Insert mapping */
	mapping->next = nat->mappings;
	nat->mappings = mapping->next;
	
	/* Create copy */
	copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
    
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}
