/*
 * How to read a packet capture file.
 */
//read http://linux.die.net/man/3/pcap for detail
//packet types
//DLT_LINUX_SLL  linux cooked capture no ethernet header
//DLT_EN10MB Ethernet packet
//DLT_RAW            raw IP; the packet begins with an IP header.

/*
 * Step 1 - Add includes
 */
#include <string>
#include <iostream>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

#define FOUND_STORE_FILE "found.txt"
#define NOT_FOUND_STORE_FILE "not_found.txt"


/*
 * A DLT_LINUX_SLL fake link-layer header.
 */
#define SLL_HDR_LEN	16		/* total header length */
#define SLL_ADDRLEN	8		/* length of address field */

struct sll_header {
	u_int16_t sll_pkttype;		/* packet type */
	u_int16_t sll_hatype;		/* link-layer address type */
	u_int16_t sll_halen;		/* link-layer address length */
	u_int8_t sll_addr[SLL_ADDRLEN];	/* link-layer address */
	u_int16_t sll_protocol;		/* protocol */
};

// 20 bytes IP Header
typedef struct ip_header{
	u_char ver_ihl; // Version (4 bits) + Internet header length (4 bits)
	u_char tos; // Type of service
	u_short tlen; // Total length
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	struct in_addr saddr; // Source address
	struct in_addr daddr; // Destination address
	u_int op_pad; // Option + Padding -- NOT NEEDED!
}ip_header;

//udp header
typedef struct udp_header{
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;

//ipv6 header
typedef struct ipv6_header
{
	unsigned int
		version : 4,
			traffic_class : 8,
			flow_label : 20;
	uint16_t length;
	uint8_t  next_header;
	uint8_t  hop_limit;
	struct in6_addr src;
	struct in6_addr dst;
}ip6_header;


using namespace std;
int compare_with_other(u_short id ,string file);

int not_found_count =0;
int found_count =0;
char str[INET_ADDRSTRLEN];  /*hold v4 address*/
char str1[INET_ADDRSTRLEN]; /*hold v4 address*/


int compare_with_other(u_short id ,string file)
{
	char errbuff[PCAP_ERRBUF_SIZE];
	int found =0;
	struct pcap_pkthdr *header;
	const u_char *data;
	pcap_t * pcap ;
	u_short nid = 0;
	struct ether_header *eptr;  /* net/ethernet.h */
	ip_header *ip; //ip header
	int packet_type = 0;
	struct sll_header  *sll_hdr;
	char command[500];
	pcap = pcap_open_offline(file.c_str(), errbuff);
	struct in6_addr src_tmp,dest_tmp;
	if (!pcap)
	{
		perror ("\nunable to open pcap\n");
		exit(0);
	}
	packet_type= pcap_datalink(pcap);
	
	while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)   
		//header will pinter to header & data will point to data(ether+ip+tcp+data)
	{
		if (DLT_EN10MB == packet_type) //if ethernet header is there
		{
			eptr = (struct ether_header *) data;
			/* Do a couple of checks to see what packet type we have..*/
			if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
			{
				ip = (ip_header*)(data + sizeof(struct ether_header));
				nid=ntohs(ip->identification);
				//	printf ("\ngoint to campare id=%x NID=%x\n",id,nid);
				if (id == nid)
				{
					found =1;
					found_count++;
					snprintf(command, 500, "echo 'FOUND current count=%d	ipv4 PACKid =0x%04x	source ip=%s		destination ip  %s	protocol %d ' >> %s",found_count ,id,inet_ntop(AF_INET, &ip->saddr, str, INET_ADDRSTRLEN),inet_ntop(AF_INET, &ip->daddr, str1, INET_ADDRSTRLEN),ip->proto,FOUND_STORE_FILE);
					system (command);
					break;
				}
				else
				{
				}
			}
			else
			{
				//printf ("\nnot ip packet\n");
			}
		}
		else if (DLT_LINUX_SLL == packet_type) //linux cooked capture
		{
			sll_hdr = (struct sll_header *) data;
			/* Do a couple of checks to see what packet type we have..*/
			if (ntohs (sll_hdr->sll_protocol) == ETHERTYPE_IP)
			{
				ip = (ip_header*)(data + sizeof(struct sll_header));
				nid=ntohs(ip->identification);
				if (id == nid)
				{
					found =1;
					found_count++;
					snprintf(command, 500, "echo 'FOUND current count=%d	ipv4 PACKid =0x%04x	source ip=%s		destination ip  %s	protocol %d  ' >> %s",found_count ,id,inet_ntop(AF_INET, &ip->saddr, str, INET_ADDRSTRLEN),inet_ntop(AF_INET, &ip->daddr, str1, INET_ADDRSTRLEN),ip->proto,FOUND_STORE_FILE);
					system (command);
					break;
				}

			}
		}
		else if (DLT_RAW == packet_type)  //raw ip
		{
			ip = (ip_header*)(data);
			nid=ntohs(ip->identification);
			if (id == nid)
			{
				found =1;
				found_count++;
				snprintf(command, 500, "echo 'FOUND current count=%d	ipv4 PACKid =0x%04x	source ip=%s		destination ip  %s	protocol %d ' >> %s",found_count ,id,inet_ntop(AF_INET, &ip->saddr, str, INET_ADDRSTRLEN),inet_ntop(AF_INET, &ip->daddr, str1, INET_ADDRSTRLEN),ip->proto,FOUND_STORE_FILE);
				system (command);
				break;
			}
		}
		else
		{

		}

	}
	if (found ==0)
	{
		not_found_count++;
		snprintf (command,500,"echo 'NOT FOUND current count=%d	ipv4 PACKid =0x%04x	source ip=%s		destination ip   %s	protocol %d  ' >> %s " ,not_found_count,id,inet_ntop(AF_INET, &ip->saddr, str, INET_ADDRSTRLEN),inet_ntop(AF_INET, &ip->daddr, str1, INET_ADDRSTRLEN),ip->proto,NOT_FOUND_STORE_FILE);
		system (command);
	}
	if (found < 0 );
	//printf ("\nfound failed\n");

	pcap_close(pcap);

}
void print_packet_type (int packt_int)
{
	if (DLT_EN10MB == packt_int)
		printf ("Ethernet packet type\n");
	else if (DLT_LINUX_SLL == packt_int)
		printf ("Linux cooked capture type\n");
	else if (DLT_RAW == packt_int)
		printf ("raw IP type\n");
	else
		printf ("Invalid type type\n");

}
int is_invalid_packet_type(int packt_int)
{
	if (DLT_EN10MB == packt_int || DLT_LINUX_SLL == packt_int || DLT_RAW == packt_int)
		return 0;
	else
		return 1;
}

int check_filter_condition(struct in_addr *src_tmp, struct in_addr *dest_tmp,char *and_or,ip_header *ip)
{
	if (src_tmp == NULL && dest_tmp ==NULL) //no filter is given by user  .camparision on id
	{
		return true;
	}
	else if (src_tmp == NULL )
	{
		if( dest_tmp->s_addr == ip->daddr.s_addr) //camparision on by destination address
		{
			return true;
		}
		else
			return false;
	}
	else if (dest_tmp == NULL )
	{
		if( src_tmp->s_addr == ip->saddr.s_addr) //camparision on by source address
		{
			return true;
		}
		else
			return false;
	}
	else if ((src_tmp->s_addr == ip->saddr.s_addr))//camparision on by source address & destination
	{
		if (!strcmp(and_or,"||"))
			return true;
		else if (!strcmp(and_or,"&&")  && (dest_tmp->s_addr == ip->daddr.s_addr))
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	else if ((dest_tmp->s_addr == ip->daddr.s_addr))
	{
		if (!strcmp(and_or,"||"))
			return true;
		else if (!strcmp(and_or,"&&")  && (src_tmp->s_addr == ip->saddr.s_addr))
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	return false;

}

int main(int argc, char *argv[])
{
	char str[INET6_ADDRSTRLEN];  /*hold v6 address*/
	char str1[INET6_ADDRSTRLEN]; /*hold v6 address*/
	ip_header *ip; //ip header
	ip6_header *ip6; //ip header
	udp_header *udp;
	u_int ip_len;
	u_short sport,dport;
	string file,file1;
	struct ether_header *eptr;  /* net/ethernet.h */
	char errbuff[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *data;
	u_int packetCount = 0;
	int packet_type = 0,packet_type1;
	struct sll_header  *sll_hdr;
	pcap_t * pcap ,*pcap1;
	char command[500];
	char source_ip[INET_ADDRSTRLEN+1]={0};
	char dest_ip[INET_ADDRSTRLEN+1]={0};
	char and_or[4]={0};
	struct in_addr *src_tmp=NULL,*dest_tmp=NULL;
	int ret_src_tmp=-1,ret_dest_tmp=-1;
	src_tmp=(struct in_addr *)malloc(sizeof(struct in_addr));
	dest_tmp=(struct in_addr *)malloc(sizeof(struct in_addr));

	/*
	 * Step 2 - Get a file name
	 */
	if( argc == 3 ) {
		printf("The argument supplied is source file=%s dest file =%s\n", argv[1],argv[2]);
	}
	else if( argc > 3 ) {
		printf("Too many arguments supplied.\n");
		printf("two argument expected. source wireshark file, destination wireshark file\n");
		exit(0);
	}
	else {
		printf("\ntwo argument expected.\n");
		printf("\ntwo argument expected. source wireshark file, destination wireshark file\n");
		exit(0);
	}
	file = argv[1]; //pcap source  file name
	file1 = argv[2]; //to compare file
	// Use pcap_open_offline to open pcap file
	//sorce wireshark file detail
	pcap = pcap_open_offline(file.c_str(), errbuff);
	if (!pcap)
	{
		printf ("\nunable to open pcap\n");
		exit(0);
	}
	packet_type = pcap_datalink(pcap);
	printf ("\nsource wireshart file packet type=%s\n",pcap_datalink_val_to_name(packet_type));
	//print packet type
	printf ("\nsource wireshart more detail::");
	print_packet_type(packet_type);

	// Use pcap_open_offline to open pcap file
	//destination wireshark file detail
	pcap1 = pcap_open_offline(file1.c_str(), errbuff);
	if (!pcap1)
	{
		printf ("\nunable to open pcap\n");
		exit(0);
	}
	packet_type1 = pcap_datalink(pcap1);
	printf ("\ndestination wireshart file packet type=%s\n",pcap_datalink_val_to_name(packet_type1));
	//print packet type
	printf ("\ndestination wireshart more detail::");
	print_packet_type(packet_type1);
	pcap_close(pcap1);
	if (is_invalid_packet_type(packet_type1) || is_invalid_packet_type(packet_type1))
	{
		printf ("\npacket type not supported !!! exit\n");
		exit(0);
	}
	printf ("\nEnter filter source ip . press enter for exit::");
	fgets(source_ip, sizeof(source_ip), stdin);
	source_ip[strlen(source_ip)-1] = '\0';
	if (inet_pton(AF_INET,source_ip,src_tmp) <=0)
	{
		free(src_tmp);
		src_tmp=NULL;
		printf("\nInvalid source ip\n");
	}
	if (strlen(source_ip)!=0)
	{
		printf ("\nEnter '&&' for 'and condition' ,enter '||' for 'or condition'::");
		fgets(and_or, sizeof(and_or), stdin);
		and_or[strlen(and_or)-1] = '\0';
	}
	printf ("\nEnter filter enter destination ip . press enter for exit::");
	fgets(dest_ip, sizeof(dest_ip), stdin);
	dest_ip[strlen(dest_ip)-1] = '\0';
	if (inet_pton(AF_INET,dest_ip,dest_tmp) <=0 )
	{
		free(dest_tmp);
		dest_tmp=NULL;
		printf("\nInvalid destination ip\n");
	}

	//remove & creating file to store found/not found packet
	snprintf(command, 500, "rm -rf %s",FOUND_STORE_FILE);
	system (command);
	snprintf(command, 500, "rm -rf %s",NOT_FOUND_STORE_FILE);
	system (command);
	snprintf(command, 500, "touch %s",FOUND_STORE_FILE);
	system (command);
	snprintf(command, 500, "touch %s",NOT_FOUND_STORE_FILE);
	system (command);

	if (src_tmp == NULL && dest_tmp == NULL)
		printf ("\nYou havent entered any filter . Now comparision will on based on ipv4 id\n~~source_pcap_file== 	%s\n~~dest_pcap_file==	%s\n",file.c_str(),file1.c_str());
	else if(dest_tmp == NULL)
		printf ("\nYou have enter source ip=%s as filter . Now comparision will on based on this source ip\n~~source_pcap_file==	%s\n~~dest_pcap_file==	%s\n",source_ip,file.c_str(),file1.c_str());
	else if(src_tmp == NULL)
		printf ("\nYou have enter destination ip=%s as filter . Now comparision will on based on this destination ip\n~~source_pcap_file==	%s\n~~dest_pcap_file==	%s\n",dest_ip,file.c_str(),file1.c_str());
	else
		printf ("\nYou have enter source ip=%s mutual condistion=%s destination ip=%s as filter . \nNow comparision will on based on ((source_ip=%s %s dest_ip=%s))\n~~source_pcap_file==	%s\n~~dest_pcap_file==	%s\n",source_ip,and_or,dest_ip,source_ip,and_or,dest_ip,file.c_str(),file1.c_str());
	printf ("\n\n~~~~~~~doing comparision . please wait!~~~~~~~ \n");


	while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)   
		//header will pinter to header & data will point to data(ether+ip+tcp+data)
	{
		if (DLT_EN10MB == packet_type) //if ethernet header is there
		{
			eptr = (struct ether_header *) data;
			/* Do a couple of checks to see what packet type we have..*/
			if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
			{
				ip = (ip_header*)(data + sizeof(struct ether_header));
				if (check_filter_condition(src_tmp,dest_tmp,and_or,ip))
				{
					compare_with_other(ntohs(ip->identification),file1);
				}
			}
			else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
			{
				//printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
				//		ntohs(eptr->ether_type),
				//		ntohs(eptr->ether_type));
				//	printf("arp packet");

			}
			else  if (ntohs (eptr->ether_type) == ETH_P_IPV6)
			{
				//currenlty not supported
				//printf("Ethernet type hex:%x dec:%d is an IPV6 packet\n",
				//		ntohs(eptr->ether_type),
				//		ntohs(eptr->ether_type));
				//ip6=(ip6_header*)(data + sizeof(struct ether_header));
				//	printf ("\nipv6 packet src ip=%s, des ip=%s\n",inet_ntop(AF_INET6, &ip6->src, str, INET6_ADDRSTRLEN),inet_ntop(AF_INET6, &ip6->dst, str1, INET6_ADDRSTRLEN));

			}

			else {
				//printf("Ethernet type %x not IP\n", ntohs(eptr->ether_type));
			}
		}
		else if (DLT_LINUX_SLL == packet_type) //linux cooked capture
		{
			sll_hdr = (struct sll_header *) data;
			if (ntohs (sll_hdr->sll_protocol) == ETHERTYPE_IP)
			{
				ip = (ip_header*)(data + sizeof(struct sll_header));
				if (check_filter_condition(src_tmp,dest_tmp,and_or,ip))
				compare_with_other(ntohs(ip->identification),file1);
			}
		}
		else if (DLT_RAW == packet_type)  //raw ip
		{
			ip = (ip_header*)(data);
			if (check_filter_condition(src_tmp,dest_tmp,and_or,ip))
			compare_with_other(ntohs(ip->identification),file1);
		}
		else
		{
			//printf ("\nInvalid pcap header type\n");
		}
	}
	printf ("\n");
	printf ("\npacket found count =%d\n",found_count);
	printf ("\npacket drop or not found count =%d\n",not_found_count);
	printf ("\n~~~~comparision done . please check file=%s for found & file=%s for Drop~~~\n\n",FOUND_STORE_FILE,NOT_FOUND_STORE_FILE);
	pcap_close(pcap);
}
