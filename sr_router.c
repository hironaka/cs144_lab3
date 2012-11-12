/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Definitions
 *---------------------------------------------------------------------*/
#define MIN_IP_HDR_LEN 20 
#define MAX_IP_HDR_LEN 60
#define DEFAULT_TTL 64
#define ICMP_IP_HDR_LEN 5
#define ICMP_IP_HDR_LEN_BYTES ICMP_IP_HDR_LEN * 4
#define ICMP_COPIED_DATAGRAM_DATA_LEN 8

/*---------------------------------------------------------------------
 * Internal Function Prototypes
 *---------------------------------------------------------------------*/
void process_arp(struct sr_instance* sr,
       			     uint8_t *packet,
        				 unsigned int len,
       			     char* interface);

void process_arp_request(struct sr_instance* sr,
       			     				 struct sr_arp_hdr *arp_hdr,
       			    			   struct sr_if*);

void process_ip(struct sr_instance* sr,
       			    uint8_t *packet,
        				unsigned int len,
       			    char* interface);

void process_icmp(struct sr_instance* sr, struct sr_ip_hdr *ip_hdr);
int valid_arp(uint8_t *packet, unsigned int len);
int valid_ip(uint8_t *packet, unsigned int len);
int valid_icmp(struct sr_ip_hdr *ip_hdr);
int ping_address_match(uint32_t dip);
void forward_ip_pkt(struct sr_instance* sr, struct sr_ip_hdr *ip_hdr);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
	
	/* Ensure that the length is at least enough for an ethernet header */
	if (len < sizeof(struct sr_ethernet_hdr))
		return;

  /* Handle ARP packet */
	if (ethertype(packet) == ethertype_arp) {
		process_arp(sr, packet, len, interface);

	/* Handle IP packet */	
	} else {
		process_ip(sr, packet, len, interface);
	}
}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: sr_send_icmp(struct sr_instance* sr, uint8_t *packet, unsigned int len, 
 *										  uint8_t type, uint8_t code)
 * Scope: Global
 *
 * This function sends an icmp of the supplied type and code, using the
 * supplied packet, which is an ip datagram. 
 *
 *---------------------------------------------------------------------*/
void sr_send_icmp(struct sr_instance* sr, uint8_t *packet, unsigned int len, 
									uint8_t type, uint8_t code)
{
	uint16_t icmp_len;
	uint32_t dst;
	struct sr_ip_hdr *error_ip_hdr;
	struct sr_icmp_hdr icmp_hdr;
	struct sr_icmp_hdr *icmp_hdr_ptr;
	struct sr_if *interface;
	struct sr_ip_hdr ip_hdr;
	uint8_t *new_pkt;
	struct sr_rt *rt;
	uint16_t total_len;
	
	/* Destination unreachable message or TTL exceeded. */
	if (type == 3 || type == 11) {
	
		/* Update icmp header fields. */
		icmp_hdr.icmp_type = type;
		icmp_hdr.icmp_code = code;
		icmp_hdr.unused = 0;
		icmp_hdr.icmp_sum = 0;
		
		/* Update the IP header fields. */
		error_ip_hdr = (struct sr_ip_hdr *)packet;
		ip_hdr.ip_hl = ICMP_IP_HDR_LEN;
		ip_hdr.ip_v = ip_version_4;
		ip_hdr.ip_tos = 0;
		ip_hdr.ip_id = error_ip_hdr->ip_id;
		ip_hdr.ip_off = htons(IP_DF);
		ip_hdr.ip_ttl = DEFAULT_TTL;
		ip_hdr.ip_p = ip_protocol_icmp;
		ip_hdr.ip_sum = 0;
		ip_hdr.ip_dst = error_ip_hdr->ip_src;
	
		/* Look up longest prefix match in your routing table. If it doesn't exist, just
		 * give up. No use in sending an error message for an error message. */
		rt = sr_longest_prefix_match(sr, ip_in_addr(ip_hdr.ip_dst));
		if (rt == 0)
			return;
		
		/* Update the source IP to be the outgoing interface's ip address. */
		interface = sr_get_interface(sr, (const char*)rt->interface);
		ip_hdr.ip_src = interface->ip;
		
		/* Update length: first 8 bytes of original message, original ip header, icmp header
		 * and new ip header. */
		icmp_len = ip_ihl(error_ip_hdr) + ICMP_COPIED_DATAGRAM_DATA_LEN + sizeof(struct sr_icmp_hdr);
		total_len = icmp_len + ICMP_IP_HDR_LEN_BYTES;
		ip_hdr.ip_len = htons(total_len);
	
		/* Allocate a packet, copy everything in. */
		new_pkt = malloc(total_len);
		memcpy(new_pkt, &ip_hdr, ICMP_IP_HDR_LEN_BYTES);
		memcpy(new_pkt + ICMP_IP_HDR_LEN_BYTES, &icmp_hdr, sizeof(struct sr_icmp_hdr));
		memcpy(new_pkt + ICMP_IP_HDR_LEN_BYTES + sizeof(struct sr_icmp_hdr), 
					 error_ip_hdr, 
					 ip_ihl(error_ip_hdr) + ICMP_COPIED_DATAGRAM_DATA_LEN);
		
	/* Echo reply. */
	} else if (type == 0) {
	
		/* Update the IP header fields. */
		error_ip_hdr = (struct sr_ip_hdr *)packet;
		dst = error_ip_hdr->ip_src;
		error_ip_hdr->ip_src = error_ip_hdr->ip_dst;
		error_ip_hdr->ip_dst = dst;
		
		/* Update the type of icmp from request to reply. */
		icmp_hdr_ptr = icmp_header(error_ip_hdr);
		icmp_hdr_ptr->icmp_sum = 0;
		icmp_hdr_ptr->icmp_code = code;
		icmp_hdr_ptr->icmp_type = type;
		
		/* Allocate a copy of this packet. */
		total_len = ip_len(error_ip_hdr);
		new_pkt = malloc(total_len);
		memcpy(new_pkt, error_ip_hdr, total_len);
		
		/* Calculate the length of the icmp message for computing checksum. */
		icmp_len = total_len - ICMP_IP_HDR_LEN;
	}
	
	/* Update the checksum of the icmp message starting at 'type' field. */
	icmp_hdr_ptr = icmp_header((struct sr_ip_hdr *)new_pkt);
	icmp_hdr_ptr->icmp_sum = cksum(icmp_hdr_ptr, icmp_len); 
	
	/* Encapsulate and send */
	sr_encap_and_send_pkt(sr, new_pkt, total_len, error_ip_hdr->ip_dst, 0, ethertype_ip);
	free(new_pkt);
}

/*---------------------------------------------------------------------
 * Method: sr_encap_and_send_pkt(struct sr_instance* sr, 
 *						  							uint8_t *packet, 
 *						 		  					unsigned int len, 
 *						  	  					uint32_t dip,
 *						  							int send_icmp,
 *						  							sr_ethertype type)
 * Scope:  Global
 *
 * Sends a packet of length len and destination ip address dip, by 
 * looking up the shortest prefix match of the dip (net byte order). 
 * If the destination is not found, it sends an ICMP host unreachable. 
 * If it finds a match, it then checks the arp cache to find the 
 * associated hardware address. If the hardware address is found it 
 * sends it, otherwise it queues the packet and sends an ARP request. 
 *
 *---------------------------------------------------------------------*/
void sr_encap_and_send_pkt(struct sr_instance* sr,
						 	 					uint8_t *packet, 
						 						unsigned int len, 
						  					uint32_t dip,
						  					int send_icmp,
						  					enum sr_ethertype type)
{
	struct sr_arpentry *arp_entry;
	struct sr_arpreq *arp_req;
	struct sr_ethernet_hdr eth_hdr;
	uint8_t *eth_pkt;
	struct sr_if *interface;
	struct sr_rt *rt;
	unsigned int eth_pkt_len;
	
	/* Look up shortest prefix match in your routing table. */
	rt = sr_longest_prefix_match(sr, ip_in_addr(dip));
	
	/* If the entry doesn't exist, send ICMP host unreachable and return if necessary. */
	if (rt == 0) {
		if (send_icmp)
			sr_send_icmp(sr, packet, len, 3, 1);
		return;
	}
	
	/* Fetch the appropriate outgoing interface. */
	interface = sr_get_interface(sr, rt->interface);
	
	/* If there is already an arp entry in the cache, send now. */
	arp_entry = sr_arpcache_lookup(&sr->cache, rt->gw.s_addr);
	if (arp_entry || type == ethertype_arp) {
		
		/* Create the ethernet packet. */
		eth_pkt_len = len + sizeof(eth_hdr);
		eth_hdr.ether_type = htons(type);
		
		/* Destination is broadcast if it is an arp request. */
		if (type == ethertype_arp && ((struct sr_arp_hdr *)packet)->ar_op == ntohs(arp_op_request))
			memset(eth_hdr.ether_dhost, 255, ETHER_ADDR_LEN);
		
		/* Destination is the arp entry mac if it is an ip packet or and are reply. */
		else
			memcpy(eth_hdr.ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
		memcpy(eth_hdr.ether_shost, interface->addr, ETHER_ADDR_LEN);
		eth_pkt = malloc(eth_pkt_len);
		memcpy(eth_pkt, &eth_hdr, sizeof(eth_hdr));
		memcpy(eth_pkt + sizeof(eth_hdr), packet, len);
		sr_send_packet(sr, eth_pkt, eth_pkt_len, rt->interface);
		free(eth_pkt);
	
	/* Otherwise add it to the arp request queue. */
	} else {
		eth_pkt = malloc(len);
		memcpy(eth_pkt, packet, len);
		arp_req = sr_arpcache_queuereq(&sr->cache, rt->gw.s_addr, eth_pkt, len, rt->interface);
		sr_arpreq_handle(sr, arp_req);
		free(eth_pkt);
	}
}

/*---------------------------------------------------------------------
 * Method: process_arp(struct sr_instance* sr,
 *      			         uint8_t * packet,
 *      				 			 unsigned int len,
 *     			     			 char* interface)
 * Scope:  Internal
 *
 * This function processes an arp packe that was received. It handles 
 * two cases, one where it is a request and one where it is a response.
 *
 *---------------------------------------------------------------------*/
void process_arp(struct sr_instance* sr,
       			     uint8_t * packet,
        				 unsigned int len,
       			     char* interface)
{
	struct sr_arpentry *arp_entry;
	struct sr_arpreq *arp_req;
	struct sr_arp_hdr *arp_hdr;
	struct sr_if* rec_if;
	
	/* Validate the arp packet */
	if (!valid_arp(packet, len))
		return;
	
	/* Is the arp addressed to me? NOTE: I do not follow the RFC recommendation to
	 * update existing cache entries with the received arp packet's ip-mac mapping 
	 * before checking whether the packet was addressed me. This is because we do 
	 * not have a good way to strictly 'update' cache entries without inserting a new 
	 * one and I would like to avoid duplicate valid cache entries for the same ip. */
	rec_if = sr_get_interface(sr, interface);
	arp_hdr = arp_header(packet);
	if (rec_if->ip != arp_hdr->ar_tip)
		return;
		
	/* Add the sender's protocol address to my table. */
	arp_entry = sr_arpcache_lookup(&sr->cache, arp_hdr->ar_sip);
	
	/* Arp entry already exists. */
	if (arp_entry != 0) {
		free(arp_entry);
	
	/* Arp entry doesn't exist so add it. */
	} else {
		arp_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
		
		/* There are packets waiting on this arp request. Send them. */
		if (arp_req != 0) {
			sr_arpreq_send_packets(sr, arp_req);
		}
	}
		
	/* Handle a request. */
	if (arp_opcode(arp_hdr) == arp_op_request) {
		process_arp_request(sr, arp_hdr, rec_if);
	}
}

/*---------------------------------------------------------------------
 * Method: process_arp_request(struct sr_instance* sr,
 *		      			   	  			 uint8_t * packet,
 *      			  	     				 char* interface)
 * Scope:  Internal
 *
 * This function processes an arp packet request.
 *
 *---------------------------------------------------------------------*/
void process_arp_request(struct sr_instance* sr,
       			   	  			 struct sr_arp_hdr *arp_hdr,
       			     				 struct sr_if* interface)
{
	struct sr_arp_hdr reply_arp_hdr;
	
	/* Create a ARP header with the appropriate reply information */
	reply_arp_hdr.ar_hrd = htons(arp_hrd_ethernet);
	reply_arp_hdr.ar_pro = htons(arp_pro_ip);
	reply_arp_hdr.ar_hln = ETHER_ADDR_LEN;
	reply_arp_hdr.ar_pln = sizeof(uint32_t);
	reply_arp_hdr.ar_op = htons(arp_op_reply);
	reply_arp_hdr.ar_sip = interface->ip;
	reply_arp_hdr.ar_tip = arp_hdr->ar_sip;
	memcpy(reply_arp_hdr.ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
	memcpy(reply_arp_hdr.ar_sha, interface->addr, ETHER_ADDR_LEN);
	
	/* Encapsulate and attempt to send it. */
	sr_encap_and_send_pkt(sr, 
					    		   (uint8_t *)&reply_arp_hdr, 
					    			 sizeof(struct sr_arp_hdr), 
					    			 arp_hdr->ar_tip,
					    			 1,
					    			 ethertype_arp);
}

/*---------------------------------------------------------------------
 * Method: process_ip(struct sr_instance* sr,
 *      			    		uint8_t * packet,
 *       							unsigned int len,
 *      			   			char* interface)
 * Scope:  Internal
 *
 * Processes a received IP packet. Takes in a raw ethernet packet.
 *
 *---------------------------------------------------------------------*/
void process_ip(struct sr_instance* sr,
       			    uint8_t * packet,
        				unsigned int len,
       			    char* interface)
{
	struct sr_ip_hdr *ip_hdr;

	/* Return if it is not a valid ip packet */
	if (!valid_ip(packet, len))
		return;
	
	/* Is it destined for me?! */
	ip_hdr = ip_header(packet);
	if (sr_interface_ip_match(sr, ip_hdr->ip_dst)) {
	
		/* Process ICMP. */
		if (ip_hdr->ip_p == ip_protocol_icmp) {
			process_icmp(sr, ip_hdr);
		
		/* If it's TCP/UDP, send ICMP port unreachable. */
		} else {
			sr_send_icmp(sr, (uint8_t *)ip_hdr, ip_len(ip_hdr), 3, 3);
		}
	
	/* Forward it. */
	} else {
		forward_ip_pkt(sr, ip_hdr);
	}
}

/*---------------------------------------------------------------------
 * Method: process_icmp(struct sr_instance* sr, sr_ip_hdr *ip_hdr)
 * Scope:  Internal
 *
 * This function processes an ICMP packet that was destined for the 
 * router.
 *
 *---------------------------------------------------------------------*/
void process_icmp(struct sr_instance* sr, struct sr_ip_hdr *ip_hdr)
{
	/* Validate icmp. Drop if it not an echo request or bad checksum. */
	if (!valid_icmp(ip_hdr))
		return;
	
	/* Send icmp echo reply. */
	sr_send_icmp(sr, (uint8_t *)ip_hdr, ip_len(ip_hdr), 0, 0);
}

/*---------------------------------------------------------------------
 * Method: valid_arp(uint8_t * packet, unsigned int len)
 * Scope:  Internal
 *
 * This function processes an arp packet given the full ethernet frame. 
 * It returns true it has a valid length, valid protocol type, hardware type.
 * False otherwise. 
 *
 *---------------------------------------------------------------------*/
int valid_arp(uint8_t *packet, unsigned int len)
{
	struct sr_arp_hdr *arp_hdr;
	
	/* Ensure that the packet is long enough for an arp header */
	if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr))
		return 0;

	/* Is the hardware type ethernet? */
	arp_hdr = arp_header(packet);
	if (arp_hrd(arp_hdr) != arp_hrd_ethernet)
		return 0;
	
	/* Is it IP? */
	if (arp_pro(arp_hdr) != arp_pro_ip)
		return 0;

	return 1;
}

/*---------------------------------------------------------------------
 * Method: valid_ip(uint8_t *packet, unsigned int len)
 * Scope:  Internal
 *
 * Validates an ip packets by ensuring it has at least the minimum length
 * a valid checksum.
 *
 *---------------------------------------------------------------------*/
int valid_ip(uint8_t *packet, unsigned int len)
{
	uint16_t expected_cksum;
	struct sr_ip_hdr *ip_hdr;
	uint16_t received_cksum;
	
	/* Check that length is at least enough to contain a minimal ip header
	 * and an ethernet header. */ 
	if (len < sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr))
		return 0;
	
	/* Check that the header length specified makes a little sense before computing
	 * the checksum. */
	ip_hdr = ip_header(packet);
	if (len < sizeof(struct sr_ethernet_hdr) + ip_ihl(ip_hdr))
		return 0;
	
	/* Validate checksum. */
	received_cksum = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;
	expected_cksum = cksum(ip_hdr, ip_ihl(ip_hdr));
	if (expected_cksum != received_cksum)
		return 0;
	
	/* Now make sure the length of the entire packet is exactly correct. */
	if (len != sizeof(struct sr_ethernet_hdr) + ip_len(ip_hdr))
		return 0;
	
	/* Is it IPv4? */
	if (ip_version_4 != ip_hdr->ip_v)
		return 0;
		
	return 1;
}

/*---------------------------------------------------------------------
 * Method: valid_icmp(sr_ip_hdr *ip_hdr)
 * Scope:  Internal
 *
 * Validates an icmp packet destined for this router by checksum and
 * ensures the the length makes
 *
 *---------------------------------------------------------------------*/
int valid_icmp(struct sr_ip_hdr *ip_hdr)
{
	uint16_t expected_cksum;
	struct sr_icmp_hdr *icmp_hdr;
	uint16_t received_cksum;
	
	/* Validate the checksum. */
	icmp_hdr = icmp_header(ip_hdr);
	received_cksum = icmp_hdr->icmp_sum;
	icmp_hdr->icmp_sum = 0;
	expected_cksum = cksum(icmp_hdr, ip_len(ip_hdr) - ip_ihl(ip_hdr));
	if (expected_cksum != received_cksum)
		return 0;
	
	/* Make sure it is a icmp echo request. */
	if ((icmp_hdr->icmp_type != 8) || (icmp_hdr->icmp_code != 0))
		return 0;
	
	return 1;
}

/*---------------------------------------------------------------------
 * Method: forward_ip_pkt(struct sr_instance* sr, sr_ip_hdr *ip_hdr)
 * Scope:  Internal
 *
 * Forwards an IP packet to its next hop.
 *
 *---------------------------------------------------------------------*/
void forward_ip_pkt(struct sr_instance* sr, struct sr_ip_hdr *ip_hdr)
{
	uint8_t *fwd_ip_pkt;
	unsigned int len;

	/* Update the ip header ttl. */
	ip_hdr->ip_ttl--;
	
	/* If the ttl is equal to 0, send an ICMP Time exceeded response and return. */
	len = ip_len(ip_hdr);
	if (ip_hdr->ip_ttl == 0) {
		sr_send_icmp(sr, (uint8_t *)ip_hdr, len, 11, 0);
		return;
	}
	
	/* Update the checksum. */
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum(ip_hdr, ip_ihl(ip_hdr));
	
	/* Make a copy, encapsulate and send it on. */
	fwd_ip_pkt = malloc(len);
	memcpy(fwd_ip_pkt, ip_hdr, len);
	sr_encap_and_send_pkt(sr, fwd_ip_pkt, len, ip_hdr->ip_dst, 1, ethertype_ip);
	free(fwd_ip_pkt);
}