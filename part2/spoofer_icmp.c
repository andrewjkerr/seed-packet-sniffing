#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <features.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/time.h>
#include <net/icmp.h>

/*
Added in TCP state: 0 = use ICMP, 1 = use TCP
Added ICMP struct and CreateICMP method
Added basic logic in main to only construct TCP or ICMP header based off of TCP state
Modified IP header to calc size of packet based on which protocol is used

Todo:
Stitch ICMP header into packet when TCP == 0
Re-organize code (restructure functions, abstract out final packet creation, etc)
Code should be modular enough to easily support the addition of new protocols
Keep defines as default values, but add ability for user to override them from CL input
Remove unused / unneeded includes (ie time.h etc)
Check for dangeling pointers
Test the hell out of it
*/

#define DATA_SIZE  100
#define TCP	1

#define SRC_IP "192.168.0.1"
#define DST_IP "192.168.0.100"
#define SRC_ETHER_ADDR	"aa:aa:aa:aa:aa:aa"
#define DST_ETHER_ADDR	"ff:ff:ff:ff:ff:ff"
#define SRC_PORT	80
#define DST_PORT	10000

typedef struct PseudoHeader{

	unsigned long int source_ip;
	unsigned long int dest_ip;
	unsigned char reserved;
	unsigned char protocol;
	unsigned short int tcp_length;

}PseudoHeader;

int CreateRawSocket(int protocol_to_sniff)
{
	int rawsock;

	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))== -1)
	{
		perror("Error creating raw socket: ");
		exit(-1);
	}

	return rawsock;
}

int BindRawSocketToInterface(char *device, int rawsock, int protocol)
{
	
	struct sockaddr_ll sll;
	struct ifreq ifr;

	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));
	
	/* First Get the Interface Index  */


	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
	{
		printf("Error getting Interface index !\n");
		exit(-1);
	}

	/* Bind our raw socket to this interface */

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocol); 


	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
	{
		perror("Error binding raw socket to interface\n");
		exit(-1);
	}

	return 1;
	
}


int SendRawPacket(int rawsock, unsigned char *pkt, int pkt_len)
{
	int sent= 0;

	/* A simple write on the socket ..thats all it takes ! */

	if((sent = write(rawsock, pkt, pkt_len)) != pkt_len)
	{
		/* Error */
		printf("Could only send %d bytes of packet of length %d\n", sent, pkt_len);
		return 0;
	}

	return 1;
	

}

struct ethhdr* CreateEthernetHeader(char *src_mac, char *dst_mac, int protocol)
{
	struct ethhdr *ethernet_header;

	
	ethernet_header = (struct ethhdr *)malloc(sizeof(struct ethhdr));

	/* copy the Src mac addr */

	memcpy(ethernet_header->h_source, (void *)ether_aton(src_mac), 6);

	/* copy the Dst mac addr */

	memcpy(ethernet_header->h_dest, (void *)ether_aton(dst_mac), 6);

	/* copy the protocol */

	ethernet_header->h_proto = htons(protocol);

	/* done ...send the header back */

	return (ethernet_header);


}

/* Ripped from Richard Stevans Book */

unsigned short ComputeChecksum(unsigned char* data, int len)
{
         long sum = 0;  /* assume 32 bit long, 16 bit short */
	 unsigned short* temp = (unsigned short *)data;

         while(len > 1){
             sum += *temp++;
             if(sum & 0x80000000)   /* if high order bit set, fold */
               sum = (sum & 0xFFFF) + (sum >> 16);
             len -= 2;
         }

         if(len)       /* take care of left over byte */
             sum += (unsigned short) *((unsigned char *)temp);
          
         while(sum>>16)
             sum = (sum & 0xFFFF) + (sum >> 16);

        return ~sum;
}


struct iphdr* CreateIPHeader(char* src_ip, char* dst_ip)
{
	/******Construct Packet*****/
	struct iphdr* ip_header;
	ip_header = (struct iphdr* )malloc(sizeof(struct iphdr));

	__u16 iphdr_len =  sizeof(struct iphdr) + DATA_SIZE + (?(TCP) sizeof(struct tcphdr) : sizeof(struct icmphdr) );

	ip_header->version = 4;
	ip_header->ihl = (sizeof(struct iphdr))/4 ;
	ip_header->tos = 0;
	ip_header->tot_len = htons(iphdr_len);
	ip_header->id = htons(111);
	ip_header->frag_off = 0;
	ip_header->ttl = 111;
	ip_header->protocol = IPPROTO_TCP;
	ip_header->check = 0; /* We will calculate the checksum later */
	ip_header->saddr = inet_addr(src_ip);
	ip_header->daddr = inet_addr(dst_ip);


	/* Calculate the IP checksum now : 
	   The IP Checksum is only over the IP header */

	ip_header->check = ComputeChecksum((unsigned char *)ip_header, ip_header->ihl*4);

	return (ip_header);

}

struct tcphdr* CreateTcpHeader()
{
	struct tcphdr* tcp_header;

	/* Check /usr/include/linux/tcp.h for header definiation */

	tcp_header = (struct tcphdr *)malloc(sizeof(struct tcphdr));

	
	tcp_header->source = htons(SRC_PORT);
	tcp_header->dest = htons(DST_PORT);
	tcp_header->seq = htonl(111);
	tcp_header->ack_seq = htonl(111);
	tcp_header->res1 = 0;
	tcp_header->doff = (sizeof(struct tcphdr))/4;
	tcp_header->syn = 1;
	tcp_header->window = htons(100);
	tcp_header->check = 0; /* Will calculate the checksum with pseudo-header later */
	tcp_header->urg_ptr = 0;

	return (tcp_header);
}

/*
 * ICMP_ECHO/ICMP_ECHO_REPLY prototype
 */
struct icmphdr
{
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short identifier;
	unsigned short sequence;
	// char data[MTU]; 
};

/***Create ICMP Packet***/
struct icmphrd* CreateIcmpHeader(){
	icmp_header = (struct icmphdr*)malloc(sizeof(struct icmphdr));
	
	//populate icmp
	icmp_header->code = 0;
	icmp_header->type = ICMP_ECHO;
	icmp_header->sequence = rand(); //Why rand()??
	icmp_header->checksum = 0;
	icmp_header->identifier = rand(); //Again, why?
	//icmp_header->data = NULL; //Nothing is in the data field currently

	//checksum
	icmp_header->check = ComputeChecksum((unsigned char *)icmp_header, (sizeof struct icmphdr) );
	
	return (icmp_header);
}

CreatePseudoHeaderAndComputeTcpChecksum(struct tcphdr *tcp_header, struct iphdr *ip_header, unsigned char *data)
{
	/*The TCP Checksum is calculated over the PseudoHeader + TCP header +Data*/

	/* Find the size of the TCP Header + Data */
	int segment_len = ntohs(ip_header->tot_len) - ip_header->ihl*4; 

	/* Total length over which TCP checksum will be computed */
	int header_len = sizeof(PseudoHeader) + segment_len;

	/* Allocate the memory */

	unsigned char *hdr = (unsigned char *)malloc(header_len);

	/* Fill in the pseudo header first */
	
	PseudoHeader* pseudo_header = (PseudoHeader *) hdr;

	pseudo_header->source_ip = ip_header->saddr;
	pseudo_header->dest_ip = ip_header->daddr;
	pseudo_header->reserved = 0;
	pseudo_header->protocol = ip_header->protocol;
	pseudo_header->tcp_length = htons(segment_len);

	
	/* Now copy TCP */

	memcpy((hdr + sizeof(PseudoHeader)), (void *)tcp_header, tcp_header->doff*4);

	/* Now copy the Data */

	memcpy((hdr + sizeof(PseudoHeader) + tcp_header->doff*4), data, DATA_SIZE);

	/* Calculate the Checksum */

	tcp_header->check = ComputeChecksum(hdr, header_len);

	/* Free the PseudoHeader */
	free(hdr);

	return ;

}

unsigned char* CreateData(int len)
{
	unsigned char* data = (unsigned char *)malloc(len);  
	int counter = len;	

	for(counter = 0 ; counter < len; counter++)
		data[counter] = 0;

	return data;
}


/* argv[1] is the device e.g. eth0    */
 
main(int argc, char **argv)
{
	/*Usage*/
	if(argc < 2){
		fprintf(stderr, "Usage: ./Spoofer [char* device]\n");
		exit(1);
	}
	
	int raw;
	unsigned char* packet;
	struct ethhdr* ethernet_header;
	struct iphdr* ip_header;
	unsigned char* data;
	int pkt_len;

	
	/* Create the raw socket */
	raw = CreateRawSocket(ETH_P_ALL);

	/* Bind raw socket to interface */
	BindRawSocketToInterface(argv[1], raw, ETH_P_ALL);

	/* create Ethernet header */
	ethernet_header = CreateEthernetHeader(SRC_ETHER_ADDR, DST_ETHER_ADDR, ETHERTYPE_IP);

	/* Create IP Header */
	ip_header = CreateIPHeader(SRC_IP,DST_IP);

	/* Create TCP or ICMP Header */
	if(TCP){
		struct tcphdr* tcp_header = CreateTcpHeader();
		CreatePseudoHeaderAndComputeTcpChecksum(tcp_header, ip_header, data);
	}
	else	{struct icmphdr* icmp_header = CreateIcmpHeader();}

	/* Create Data */
	data = CreateData(DATA_SIZE);

	/* Packet length = ETH + IP header + TCP or ICMP header + Data */
	pkt_len = sizeof(struct ethhdr) + ntohs(ip_header->tot_len);

	/* Allocate memory */
	packet = (unsigned char *)malloc(pkt_len);

	/* Copy the Ethernet header first */
	memcpy(packet, ethernet_header, sizeof(struct ethhdr));

	/* Copy the IP header -- but after the ethernet header */
	memcpy((packet + sizeof(struct ethhdr)), ip_header, ip_header->ihl*4);

	/* Copy the TCP or ICMP header after the IP header */
	if(TCP) 
		memcpy((packet + sizeof(struct ethhdr) + ip_header->ihl*4),tcp_header, tcp_header->doff*4);
	else
		memcpy((packet + sizeof(struct ethhdr) + ip_header->ihl*4),icmp_header, tcp_header->doff*4);
	
	/* Copy the Data after the TCP header */
	memcpy((packet + sizeof(struct ethhdr) + ip_header->ihl*4 + tcp_header->doff*4), data, DATA_SIZE);

	/* send the packet on the wire */
	if(!SendRawPacket(raw, packet, pkt_len))
	{
		perror("Error sending packet");
	}
	else
		printf("Packet sent successfully\n");

	/* Free the headers back to the heavenly heap */

	free(ethernet_header);
	free(ip_header);
	free(tcp_header);
	free(data);
	free(packet);

	close(raw);

	return 0;
}

/**Sources:
	https://gist.github.com/securitytube/5325126 (TCP Packets)
	code.securitytube.net/Ethernet-Packet-Injection.c (Ethernet Packets)
	code.securitytube.net.s3.amazonaws.com/IP-Packet_Injection.c (IP Packets)
**/
