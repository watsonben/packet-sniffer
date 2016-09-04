/* Modified code from:
 * David C Harrison (david.harrison@ecs.vuw.ac.nz) July 2015 (main and got_packet):
 *		Use as-is, modification, and/or inclusion in derivative works is permitted only if 
 *		the original author is credited.
 *
 * and http://www.tcpdump.org/sniffex.c (for printing nicely):
 *		Version 0.1.1 (2005-07-05)
 *		Copyright (c) 2005 The Tcpdump Group
 *
 * To compile: gcc -o sniffer sniffer.c -l pcap
 *
 * To run: tcpdump -s0 -w - | ./sniffer -
 *     Or: ./sniffer <some file captured from tcpdump or wireshark>
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#define ETHERNET_SIZE 14
#define LINE_WIDTH 16

//Packet ID
int count = 0;

/*==================================================
 * Some methods for printing out the packet payload.
 *==================================================
 */
void pad_results(int len){
	if(len < 8)
		printf("  ");
	if(len < 16){
		int i;
		for(i = 0; i < LINE_WIDTH - len; i++)
			printf("   ");
	}
	printf(" ");
}

void print_hex_ascii_line(const u_char *payload, int len, int count){
	int i;
	const u_char *ch = payload;
	printf("\x1b[33m%05d\x1b[0m\t", count);
	for(i = 0; i < len; i++){
		printf("\x1b[32m%02x\x1b[0m ", *ch);
		ch++;
		if (i == 7)
			printf("  ");
	}
	pad_results(len);
	ch = payload;
	for(i = 0; i < len; i++){
		if (isprint(*ch))
			printf("\x1b[36m%c\x1b[0m", *ch);
		else
			printf("\x1b[36m.\x1b[0m");
		ch++;
	}
	printf("\n");
}

void print_payload(const char *payload, int length){
	printf("\x1b[35;1m===========================================================================\x1b[0m\n");
	int len_rem = length, line_len, byte_num = 0;
	const char *ch = payload;
	if (length <= 0){
		printf("\x1b[31mNo data to print.\x1b[0m\n");
		return;
	}
	for ( ; len_rem > LINE_WIDTH; len_rem -= line_len) {
		line_len = LINE_WIDTH % len_rem;
		print_hex_ascii_line(ch, line_len, byte_num);
		ch += line_len;
		byte_num += LINE_WIDTH;
	}
	print_hex_ascii_line(ch, len_rem, byte_num);
}

/*==================================================
 * Methods for sorting stuff at the transport layer.
 *==================================================
 */

int deal_with_ICMP_v6(struct ip6_hdr *ip, int ip_len){
	struct icmp6_hdr *ih = (struct icmp6_hdr *) (ip + ip_len / 2);
	printf("\x1b[35mProtocol: \x1b[0mICMP\n");
	printf("\x1b[35mType: \x1b[0m%d\n", ih->icmp6_type);
	printf("\x1b[35mCode: \x1b[0m%d\n", ih->icmp6_code);
	#define ICMP6_HLEN sizeof(struct icmp6_hdr)
	return ICMP6_HLEN;
}

int deal_with_ICMP(struct ip *ip, int ip_len){
	struct icmphdr *ih = (struct icmphdr *) (ip + ip_len);
	printf("\x1b[35mProtocol: \x1b[0mICMP\n");
	printf("\x1b[35mType: \x1b[0m%d\n", ih->type);
	printf("\x1b[35mCode: \x1b[0m%d\n", ih->code);
#define ICMP_HLEN 8
	return ICMP_HLEN;
}

int deal_with_TCP(struct ip *ip, int ip_len){
	struct tcphdr *th = (struct tcphdr *) (ip) + ip_len;
	printf("\x1b[35mProtocol: \x1b[0mTCP\n");
	printf("\x1b[35mSource Port: \x1b[0m%d\n", ntohs(th->source));
	printf("\x1b[35mDestination Port: \x1b[0m%d\n", ntohs(th->dest));
#define TCP_HLEN 20
	return TCP_HLEN;
}

int deal_with_UDP(struct ip *ip, int ip_len){
	struct udphdr *uh  = (struct udphdr *) (ip + ip_len);
	printf("\x1b[35mProtocol: \x1b[0mUDP\n");
	printf("\x1b[35mSource Port: \x1b[0m%d\n", ntohs(uh->uh_sport));
	printf("\x1b[35mDestination Port: \x1b[0m%d\n", ntohs(uh->uh_dport));
#define UDP_HLEN 8
	return UDP_HLEN;
}

int deal_with_unknown(struct ip *ip, int ip_len){
	printf("\x1b[31mUnknown transport protocol: %d\x1b[0m\n", ip->ip_p);
	return 0;
}

/*==================================================
 * Methods for dealing with the network layer stuff.
 *==================================================
 */

void deal_with_IPv4_protocol(struct ip *ip){
#define IPv4_HLEN ip->ip_hl / 4
	u_int8_t protocol = ip->ip_p;
	int header_len = protocol == IPPROTO_ICMP? deal_with_ICMP(ip, IPv4_HLEN):
		protocol == IPPROTO_TCP? deal_with_TCP(ip, IPv4_HLEN):
		protocol == IPPROTO_UDP? deal_with_UDP(ip, IPv4_HLEN):
		deal_with_unknown(ip, IPv4_HLEN);
#define IP_HEADER ip->ip_hl * 4
	int total_header_len = IP_HEADER + header_len;
	int payload_len = ntohs(ip->ip_len) - total_header_len;
	if(payload_len > 0){
		printf("\x1b[35mPacket Length: \x1b[0m%d\n", payload_len);
	}
	const char *payload = (u_char *)(ip) + total_header_len;
	print_payload(payload, payload_len);
}

void deal_with_IPv6_protocol(struct ip6_hdr *ip6){
#define IPv6_HLEN sizeof(struct ip6_hdr) / 16
	u_int8_t protocol = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	int header_len = protocol == IPPROTO_ICMPV6? deal_with_ICMP_v6(ip6, IPv6_HLEN):
		protocol == IPPROTO_TCP? deal_with_TCP((struct ip *)ip6, IPv6_HLEN):
		protocol == IPPROTO_UDP? deal_with_UDP((struct ip *)ip6, IPv6_HLEN):
		deal_with_unknown((struct ip *)ip6, IPv6_HLEN);
#define IPv6_HEADER sizeof(struct ip6_hdr)
	int total_header_len = header_len + IPv6_HEADER;
	int payload_len = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) - total_header_len;
	if(payload_len > 0){
		printf("\x1b[35mPacket Length: \x1b[0m%d\n", payload_len);
	}
	const char *payload = (u_char *)(ip6) + total_header_len;
	print_payload(payload, payload_len);
}

void deal_with_ipv4(const u_char *packet){
	struct ip *ip = (struct ip *) (packet + ETHERNET_SIZE);
	printf("\x1b[35mPacket ID: \x1b[0m%d\n", count);
	printf("\x1b[35mEther Type: \x1b[0mIPv4\n");
	int len = 16;
	char buffer[len];
	inet_ntop(AF_INET, &(ip->ip_src.s_addr), buffer, len);
	printf("\x1b[35mSource IP: \x1b[0m%s\n", buffer);
	inet_ntop(AF_INET, &(ip->ip_dst.s_addr), buffer, len);
	printf("\x1b[35mDestination IP: \x1b[0m%s\n", buffer);
	deal_with_IPv4_protocol(ip);
}

void deal_with_ipv6(const u_char *packet){
	struct ip6_hdr *ip = (struct ip6_hdr *) (packet + ETHERNET_SIZE);
	printf("\x1b[35mPacket ID: \x1b[0m%d\n", count);
	printf("\x1b[35mEther Type: \x1b[0mIPv6\n");
	printf("\x1b[35mSource IP: \x1b[0m%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", (int)ip->ip6_src.s6_addr[0],
			(int)ip->ip6_src.s6_addr[1], (int)ip->ip6_src.s6_addr[2], (int)ip->ip6_src.s6_addr[3], (int)ip->ip6_src.s6_addr[4],
			(int)ip->ip6_src.s6_addr[5], (int)ip->ip6_src.s6_addr[6], (int)ip->ip6_src.s6_addr[7], (int)ip->ip6_src.s6_addr[8],
			(int)ip->ip6_src.s6_addr[9], (int)ip->ip6_src.s6_addr[10], (int)ip->ip6_src.s6_addr[11], (int)ip->ip6_src.s6_addr[12],
			(int)ip->ip6_src.s6_addr[13], (int)ip->ip6_src.s6_addr[14], (int)ip->ip6_src.s6_addr[15]);
	printf("\x1b[35mDestination IP: \x1b[0m%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", (int)ip->ip6_dst.s6_addr[0],
			(int)ip->ip6_dst.s6_addr[1], (int)ip->ip6_dst.s6_addr[2], (int)ip->ip6_dst.s6_addr[3], (int)ip->ip6_dst.s6_addr[4],
			(int)ip->ip6_dst.s6_addr[5], (int)ip->ip6_dst.s6_addr[6], (int)ip->ip6_dst.s6_addr[7], (int)ip->ip6_dst.s6_addr[8],
			(int)ip->ip6_dst.s6_addr[9], (int)ip->ip6_dst.s6_addr[10], (int)ip->ip6_dst.s6_addr[11], (int)ip->ip6_dst.s6_addr[12],
			(int)ip->ip6_dst.s6_addr[13], (int)ip->ip6_dst.s6_addr[14], (int)ip->ip6_dst.s6_addr[15]);
	deal_with_IPv6_protocol(ip);
}
/*==================================================
 * Methods for sorting out the datalink layer stuff.
 *==================================================
 */

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	count ++;
	struct ethhdr *ethernet = (struct ethhdr *)(packet);
	u_short ether_type = ntohs(ethernet->h_proto);
	ether_type == 2048? deal_with_ipv4(packet):
		ether_type == 34525? deal_with_ipv6(packet):
		printf("\x1b[35mUnknown Ether Type(\x1b[0m%d\x1b[35m)\x1b[0m\n", ether_type);
	printf("\x1b[35;1m===========================================================================\x1b[0m\n");
}

int main(int argc, char **argv){
	if (argc < 2) {
		fprintf(stderr, "Must have an argument, either a file name or '-'\n");
		return -1;
	}
	pcap_t *handle = pcap_open_offline(argv[1], NULL);
	pcap_loop(handle, 1024*1024, got_packet, NULL);
	pcap_close(handle);
	return 0;
}
