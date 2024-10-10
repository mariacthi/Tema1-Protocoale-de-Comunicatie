// Tudor Maria-Elena 324CC

#include <arpa/inet.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>

#define ETHERTYPE_ARP htons(0x0806)
#define ETHERTYPE_IP htons(0x0800)

#define AFTER_ETHER_HEADER sizeof(struct ether_header)
#define AFTER_IP_HEADER sizeof(struct ether_header) + sizeof(struct iphdr)

#define TTL 64

uint8_t broadcast[6] = {255, 255, 255, 255, 255, 255};

struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arptable;
int arptable_len;

uint8_t *get_my_mac(int interface)
{
	uint8_t *my_mac = malloc(6 * sizeof(uint8_t));
	get_interface_mac(interface, my_mac);
	return my_mac;
}

uint16_t get_checksum_for_ipv4(struct iphdr *ipv4_hdr)
{
	return htons(checksum((uint16_t *) ipv4_hdr, sizeof(struct iphdr)));
}

uint16_t get_checksum_for_icmp(struct icmphdr *icmp_hdr)
{
	return htons(checksum((uint16_t *) icmp_hdr, sizeof(struct icmphdr)));
}

void icmp_echo_reply(char *buf, size_t len, int interface)
{
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ipv4_hdr = (struct iphdr *) (buf + AFTER_ETHER_HEADER);
	struct icmphdr *icmp_hdr = (struct icmphdr *) (buf + AFTER_IP_HEADER);

	/* changing the Ethernet header so the reply gets back to the sender */
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, get_my_mac(interface), 6);

	/* swapping the IP addresses in the header */
	u_int32_t aux = ipv4_hdr->saddr;
	ipv4_hdr->saddr = ipv4_hdr->daddr;
	ipv4_hdr->daddr = aux;

	/* resetting TTL */
	ipv4_hdr->ttl = TTL;

	/* updating the checksum for the IP header */
	ipv4_hdr->check = 0;
	ipv4_hdr->check = get_checksum_for_ipv4(ipv4_hdr);

	/* sending "Echo reply" - type 0, code 0 */
	icmp_hdr->type = 0;
	icmp_hdr->code = 0;

	/* updating the checksum for the ICMP header */
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = get_checksum_for_icmp(icmp_hdr);

	char packet[MAX_PACKET_LEN];
	memcpy(packet, buf, len);

	/* sending the new packet */
	send_to_link(interface, packet, len);
}

void icmp_error_message(char *buf, size_t len, int interface,
						uint8_t type, uint8_t code)
{
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ipv4_hdr = (struct iphdr *) (buf + AFTER_ETHER_HEADER);
	struct icmphdr *icmp_hdr = (struct icmphdr *) (buf + AFTER_IP_HEADER);

	/* saving the ipv4_hdr and 64 bits (8B) out of the original payload */
	char *data = malloc(sizeof(struct iphdr) + 8);
	memcpy(data, ipv4_hdr, sizeof(struct iphdr) + 8);

	/* changing the Ethernet header so the error message gets
	 * back to the sender
	 */
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, get_my_mac(interface), 6);

	/* changing the IP header */
	ipv4_hdr->daddr = ipv4_hdr->saddr;
	ipv4_hdr->saddr = inet_addr(get_interface_ip(interface));

	/* resetting the TTL */
	ipv4_hdr->ttl = TTL;

	/* the new length will be the size of the IP header +
	 * the size of the payload: an ICMP header + ICMP payload
	 * (the original IP header + 64 bits)
	 */
	ipv4_hdr->tot_len = htons(sizeof(struct icmphdr) +
							  2 * sizeof(struct iphdr) + 8);
	ipv4_hdr->protocol = 1; /* for ICMP */

	/* updating checksum for IP header */
	ipv4_hdr->check = 0;
	ipv4_hdr->check = get_checksum_for_ipv4(ipv4_hdr);

	/* updating the ICMP header */
	icmp_hdr->type = type;
	icmp_hdr->code = code;

	/* saving the original data in the ICMP payload */
	memcpy(icmp_hdr + sizeof(icmp_hdr), data, sizeof(struct iphdr) + 8);
	free(data);

	/* updating checksum for ICMP header */
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = get_checksum_for_icmp(icmp_hdr);

	len = sizeof(struct ether_header) + 2 * sizeof(struct iphdr) +
		  sizeof(struct icmphdr) + 8;
	char packet[MAX_PACKET_LEN];
	memcpy(packet, buf, len);

	/* sending the new packet */
	send_to_link(interface, packet, len);
}

struct route_table_entry *get_next_hop(uint32_t d_addr)
{
	int left = 0, right = rtable_len - 1, mid;
	struct route_table_entry *next = NULL;

	/* using binary search to go through the routing table */
	while (right >= left) {
		mid = (left + right) / 2;
		if (ntohl(rtable[mid].prefix & rtable[mid].mask) <
			ntohl(d_addr & rtable[mid].mask))
			left = mid + 1;
		else if (ntohl(rtable[mid].prefix & rtable[mid].mask) >
				ntohl(d_addr & rtable[mid].mask))
			right = mid - 1;
		else {
			/* searching for the longest match (the entries in the rtable
			 * are sorted by prefix and then by mask)
			 */
			next = rtable + mid;
			left = mid + 1;
		}
	}
	return next;
}

void send_packet(char *buf, size_t len, struct route_table_entry *next)
{
	struct ether_header *eth_hdr = (struct ether_header *)buf;

	/* searching through the arptable to find the needed MAC address */
	for (int i = 0; i < arptable_len; i++) {
		if (arptable[i].ip == next->next_hop) {
			/* modifying the Ethernet header to send the packet */
			memcpy(eth_hdr->ether_shost, get_my_mac(next->interface), 6);
			memcpy(eth_hdr->ether_dhost, arptable[i].mac, 6);

			char packet[MAX_PACKET_LEN];
			memcpy(packet, buf, len);
			send_to_link(next->interface, packet, len);
		}
	}
}

void forward_ipv4(char *buf, size_t len, int interface)
{
	struct iphdr *ipv4_hdr = (struct iphdr *) (buf + AFTER_ETHER_HEADER);

	/* verifying checksum */
	uint16_t old_checksum = ipv4_hdr->check;
	ipv4_hdr->check = 0;
	if (old_checksum != get_checksum_for_ipv4(ipv4_hdr)) {
		return;
	}

	/* checking if it's for this router ("echo request") */
	if (ipv4_hdr->daddr == inet_addr(get_interface_ip(interface))) {
		icmp_echo_reply(buf, len, interface);
		return;
	}

	/* verifying ttl */
	if (ipv4_hdr->ttl <= 1) {
		/* "Time exceeded" */
		icmp_error_message(buf, len, interface, 11, 0);
		return;
	}

	/* decrementing ttl */
	ipv4_hdr->ttl--;

	/* updating checksum */
	ipv4_hdr->check = 0;
	ipv4_hdr->check = get_checksum_for_ipv4(ipv4_hdr);

	/*searching in the routing table for the next hop */
	struct route_table_entry *next = get_next_hop(ipv4_hdr->daddr);
	if (next == NULL) {
		/* Destination unreachable */
		icmp_error_message(buf, len, interface, 3, 0);
		return;
	}

	send_packet(buf, len, next);
}

int rtable_comparator(const void *a, const void *b)
{
	struct route_table_entry *r1 = (struct route_table_entry *)a;
	struct route_table_entry *r2 = (struct route_table_entry *)b;

	u_int32_t val1 = ntohl(r1->prefix & r1->mask);
	u_int32_t val2 = ntohl(r2->prefix & r2->mask);

	if (val1 == val2) {
		/* who has the longest mask */
		return (ntohl(r1->mask) - ntohl(r2->mask));
	} else {
		return val1 - val2;
	}
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	/* routing table allocation */
	rtable = (struct route_table_entry *) malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "rtable allocation failed");
	rtable_len = read_rtable(argv[1], rtable);

	/* sorting the address in the routing table for LPM algorithm later*/
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), rtable_comparator);

	/* static ARP table allocation */
	arptable = (struct arp_table_entry *) malloc(sizeof(struct arp_table_entry) * 100);
	DIE(arptable == NULL, "arptable allocation failed");
	arptable_len = parse_arp_table("arp_table.txt", arptable);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		/* checking that the destination is either the broadcast address
		 * or the router's MAC address
		 */
		if (memcmp(eth_hdr->ether_dhost, broadcast, 6) != 0 &&
			memcmp(eth_hdr->ether_dhost, get_my_mac(interface), 6) != 0) {
			continue;
		}

		/* forwarding IP packets */
		if (eth_hdr->ether_type == ETHERTYPE_IP) {
			forward_ipv4(buf, len, interface);
		}
	}

	free(rtable);
	free(arptable);
}