#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 65536

/* 
Global variables for flags and interface
Flag set to 1 needs to be sniffed.
*/
int interface_flag = 0;
char interface[50];
int tcp_flag = 0;
int udp_flag = 0;
int port = -1;
int icmp4_flag = 0;
int icmp6_flag = 0;
int arp_flag = 0;
int ndp_flag = 0;
int igmp_flag = 0;
int mld_flag = 0;
int num_flag = 0;
int num = 1;

/* 
Function to print all interfaces that are available.
At the end it will use pcap_freealldevs() function to free list of devices that allocated pcap_findalldevs().
*/
void print_interface(pcap_if_t *interfaces);

/* 
Function to print ipv6 adress.
Function inspired by: https://stackoverflow.com/questions/3727421/expand-an-ipv6-address-so-i-can-print-it-to-stdout
*/
void print_ipv6(const struct in6_addr *addr);

/* 
Function to print ethernet header.
Prints src MAC, dst MAC and frame length.
*/
void print_eth_hdr(const u_char *packet, int len);

/* 
Function to print data in rows of 16 bytes: offset   hex   ascii.
Function inspired by: https://www.tcpdump.org/other/sniffex.c
*/
void print_hex_ascii_line(const u_char *payload, int len, int offset);

/* 
Function to print timestamp.
Function inspired by: https://www.tcpdump.org/other/sniffex.c
and 
https://www.programcreek.com/cpp/?code=mq1n%2FNoMercy%2FNoMercy-master%2FSource%2FClient%2FNM_Engine%2FINetworkScanner.cpp
*/
void print_packet(const u_char *buffer, int len);

/* 
Function to print timestamp.
*/
void print_time(const u_char *addr, int size);

/* 
Function to print usage.
*/
void usage();

/* 
Callback function for pcap_loop(), which handles recieved packets.
Function checks if packet is ipv4 or ipv6 and what protocol.
Prints timestamp of packet, encoded data of packet, packet and ipv6 adress
*/
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


void print_ipv6(const struct in6_addr *addr)
{
    printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
           (int)addr->s6_addr[0], (int)addr->s6_addr[1],
           (int)addr->s6_addr[2], (int)addr->s6_addr[3],
           (int)addr->s6_addr[4], (int)addr->s6_addr[5],
           (int)addr->s6_addr[6], (int)addr->s6_addr[7],
           (int)addr->s6_addr[8], (int)addr->s6_addr[9],
           (int)addr->s6_addr[10], (int)addr->s6_addr[11],
           (int)addr->s6_addr[12], (int)addr->s6_addr[13],
           (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
}


void print_time(const u_char *addr, int size)
{
    struct timeval tv;
    time_t nowtime;
    struct tm *nowtm;

    gettimeofday(&tv, NULL);
    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);

    char timestr[64];
    strftime(timestr, sizeof(timestr), "%FT%T", nowtm);
    printf("timestamp: %s.%06ld+02:00\n", timestr, tv.tv_usec);
}


void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("0x%04x   ", offset);

    /* hex */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }

    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16)
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
        {
            printf("   ");
        }
    }

    printf("   ");
    /* ascii (if printable) */
    ch = payload;

    for (i = 0; i < len; i++)
    {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    printf("\n");

    return;
}

void print_packet(const u_char *buffer, int len)
{

    int len_rem = len;
    int line_width = 16; /* number of bytes per line */
    int line_len;
    int offset = 0; /* zero-based offset counter */
    const u_char *buff = buffer;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width)
    {
        print_hex_ascii_line(buff, len, offset);
        return;
    }

    /* data spans multiple lines */
    for (;;)
    {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* compute total remaining */
        len_rem -= line_len;
        /* print line */
        print_hex_ascii_line(buff, line_len, offset);
        /* shift pointer to remaining bytes to print */
        buff += line_len;
        /* add offset */
        offset += line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width)
        {
            /* print last line and get out */
            print_hex_ascii_line(buff, len_rem, offset);
            offset += line_width;
            break;
        }
    }
    printf("\n");
    return;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    int size = header->len;
    const struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    u_short ip_len = (ip_header->ihl) * 4;

    const struct ether_header *ethernet_header = (struct ether_header *)packet;

    struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header) + ip_len);
    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_len);
    const struct ip6_hdr *ip6_header;
    const struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_len);
    struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));

    print_time(packet, size);

    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP)
    { // if ETHERTYPE is IPV4

        switch (ip_header->protocol) // Check the Protocol and do accordingly...
        {
        case 1: // ICMPv4 IPV4
            print_eth_hdr(packet, size);
            printf("src IP: %s\n", inet_ntoa(ip->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
            printf("\n");
            print_packet(packet, size);
            break;

        case 2: // IGMP
            print_eth_hdr(packet, size);
            printf("src IP: %s\n", inet_ntoa(ip->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
            printf("\n");
            print_packet(packet, size);
            break;

        case 6: // TCP IPV4
            print_eth_hdr(packet, size);
            printf("src IP: %s\n", inet_ntoa(ip->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
            if (port != -1)
            {
                printf("src port: %d\n", ntohs(tcp_header->th_sport));
                printf("dst port: %d\n", ntohs(tcp_header->th_dport));
            }
            printf("\n");
            print_packet(packet, size);
            break;
        case 17: // UDP IPV4
            print_eth_hdr(packet, size);
            printf("src IP: %s\n", inet_ntoa(ip->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
            if (port != -1)
            {
                printf("src port: %d\n", ntohs(udp_header->uh_dport));
                printf("dst port: %d\n", ntohs(udp_header->uh_dport));
            }
            printf("\n");
            print_packet(packet, size);
            break;

        default:
            break;
        }
    }
    else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6)
    { // if ETHERTYPE is IPV6
        ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ethhdr));
        int protocol = ip6_header->ip6_nxt;

        if (protocol == 6)
        { // TCP IPV6
            print_eth_hdr(packet, size);
            print_ipv6(&ip6_header->ip6_src);
            printf(" > ");
            print_ipv6(&ip6_header->ip6_dst);
            if (port != -1)
            {
                printf("src port: %d\n", ntohs(tcp_header->th_sport));
                printf("dst port: %d\n", ntohs(tcp_header->th_dport));
            }
            printf("\n");
            print_packet(packet, size);
        }
        else if (protocol == 17)
        { // UDP IPV6
            print_eth_hdr(packet, size);
            print_ipv6(&ip6_header->ip6_src);
            printf(" > ");
            print_ipv6(&ip6_header->ip6_dst);
            if (port != -1)
            {
                printf("src port: %d\n", ntohs(udp_header->uh_sport));
                printf("dst port: %d\n", ntohs(udp_header->uh_dport));
            }
            printf("\n");
            print_packet(packet, size);
        }
        else if (protocol == 58)
        { // ICMPv6 IPV6
            print_eth_hdr(packet, size);
            print_ipv6(&ip6_header->ip6_src);
            printf(" > ");
            print_ipv6(&ip6_header->ip6_dst);
            printf("\n");
            print_packet(packet, size);
        }
        else if (protocol == 143)
        { // MLD IPV6
            print_eth_hdr(packet, size);
            print_ipv6(&ip6_header->ip6_src);
            printf(" > ");
            print_ipv6(&ip6_header->ip6_dst);
            printf("\n");
            print_packet(packet, size);
        }
    }
    else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP)
    { // ARP
        char srcIP[16], destIP[16];
        inet_ntop(AF_INET, &(arp->arp_spa), srcIP, sizeof(srcIP));
        inet_ntop(AF_INET, &(arp->arp_tpa), destIP, sizeof(destIP));
        print_eth_hdr(packet, size);
        printf("src IP: %s\n", srcIP);
        printf("dst IP: %s\n", destIP);
        printf("\n");
        print_packet(packet, size);
    }
}

void usage()
{
    printf("Usage: ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] [--ndp] {-n num}\n");
}

void print_eth_hdr(const u_char *packet, int len)
{
    const struct ether_header *ethernet_header = (struct ether_header *)packet;
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header->ether_shost[0], ethernet_header->ether_shost[1], ethernet_header->ether_shost[2], ethernet_header->ether_shost[3], ethernet_header->ether_shost[4], ethernet_header->ether_shost[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet_header->ether_dhost[0], ethernet_header->ether_dhost[1], ethernet_header->ether_dhost[2], ethernet_header->ether_dhost[3], ethernet_header->ether_dhost[4], ethernet_header->ether_dhost[5]);
    printf("frame length: %d bytes\n", len);
}

void print_interface(pcap_if_t *interfaces)
{
    while (interfaces->next != NULL)
    {
        printf("Name: %s   Description: %s \n", interfaces->name, interfaces->description);
        interfaces = interfaces->next;
    }
    pcap_freealldevs(interfaces);
    exit(0);
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[BUFFER_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 net;
    const u_char *packet;
    int opt;
    char port_str[50];
    pcap_if_t *interfaces;

    /* 
     Get a list of capture devices.
    */
    if (pcap_findalldevs(&interfaces, errbuf) == -1)
    {
        fprintf(stderr, "ERROR: No interfaces available. INFO: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    /* 
     Argument wasnt set -> print interfaces.
    */
    if (argc < 2) 
    {
        print_interface(interfaces);
    }

    /* 
     While loop that checks what arguments were given and sets flags.
     Checks if arguments are valid.
    */
    while ((opt = getopt(argc, argv, "i:p:tun:-:")) != -1)
    {
        switch (opt)
        {
        case 'i': // interface
            if(interface_flag == 1){
                fprintf(stderr, "ERROR: Interface already set. INFO: %s\n", errbuf);
                return EXIT_FAILURE;
            }
            interface_flag = 1;
            if (optarg[0] == '-') //check if there is name and not argument after -i
            {
                print_interface(interfaces); // in case of wrong arguments print interface
            }
            strncpy(interface, optarg, 50);
            break;
        case 'p': // port
            port = atoi(optarg);
            sprintf(port_str, "%d", port);
            if (port <= 0 || port >= 65536) //check range of port
            {
                fprintf(stderr, "Invalid port number: %d\n", port);
                exit(EXIT_FAILURE);
            }
            break;
        case 't': //tcp
            tcp_flag = 1;
            break;
        case 'u': //udp
            udp_flag = 1;
            break;
        case 'n': // number of packets
            num_flag = 1;
            num = atoi(optarg);
            break;
        case '-':
            if (strcmp(optarg, "tcp") == 0)
            {
                tcp_flag = 1;
            }
            else if (strcmp(optarg, "udp") == 0)
            {
                udp_flag = 1;
            }
            else if (strcmp(optarg, "icmp4") == 0)
            {
                icmp4_flag = 1;
            }
            else if (strcmp(optarg, "icmp6") == 0)
            {
                icmp6_flag = 1;
            }
            else if (strcmp(optarg, "arp") == 0)
            {
                arp_flag = 1;
            }
            else if (strcmp(optarg, "ndp") == 0)
            {
                ndp_flag = 1;
            }
            else if (strcmp(optarg, "igmp") == 0)
            {
                igmp_flag = 1;
            }
            else if (strcmp(optarg, "mld") == 0)
            {
                mld_flag = 1;
            }
            else if (strcmp(optarg, "interface") == 0)
            {
                if(interface_flag == 1){
                    fprintf(stderr, "ERROR: Interface already set. INFO: %s\n", errbuf);
                    return EXIT_FAILURE;
                }
                interface_flag = 1;
                if (argv[optind] && argv[optind][0] != '-') //check if there is name and not argument after -i
                {
                    strncpy(interface, argv[optind], 50);
                    optind++;
                }
                else // in case of wrong arguments print interface
                {
                    print_interface(interfaces);
                }
            }
            break;
        }
    }

    if (interface_flag == 0) // interface not set so print interfaces
    {
        print_interface(interfaces);
    }

    if (tcp_flag == 1) // if tcp argument is given
    {
        if (port != -1) // concatenate tcp with port
        {    
            strcat(filter_exp, "tcp port ");
            strcat(filter_exp, port_str);
            strcat(filter_exp, " or "); // example: tcp port 23
        }
        else
        {
            strcat(filter_exp, "tcp or "); // concatenate only tcp
        }
    }
    if (udp_flag == 1) // if udp argument is given
    {
        if (port != -1) // concatenate udp with port
        {
            strcat(filter_exp, "udp port ");
            strcat(filter_exp, port_str);
            strcat(filter_exp, " or "); // example: udp port 23
        }
        else
        {
            strcat(filter_exp, "udp or "); // concatenate only udp
        }
    }
    if (icmp4_flag == 1) // if icmp4 argument is given
    {
        strcat(filter_exp, "icmp or "); // concatenate only icmp4
    }
    if (icmp6_flag == 1)
    {
        strcat(filter_exp, "icmp6 or ");
    }
    if (arp_flag == 1)
    {
        strcat(filter_exp, "arp or ");
    }
    if (igmp_flag == 1)
    {
        strcat(filter_exp, "igmp or ");
    }
    if (mld_flag == 1)
    {
        strcat(filter_exp, "mld or ");
    }

    filter_exp[strlen(filter_exp) - 3] = '\0'; // Remove redundant 'or'

    /* Find the properties for the device */
    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interface, errbuf);
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(interface, BUFFER_SIZE, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        exit(1);
    }

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }
    /* process packets from a live capture or savefile */
    pcap_loop(handle, num, process_packet, NULL);

    pcap_close(handle);

    exit(0);
}