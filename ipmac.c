/**
 * @file: ipmac.c
 * @brief: The packet sniffer to capturing just ip and mac address.
 * @author: YoungJoo.Kim <vozlt@vozlt.com>
 * @version:
 * @date: 20060924
 * 
 * shell> gcc -o ipmac ipmac.c -lpcap
 *
 **/

#include <stdio.h>
#include <stdlib.h> /* EXIT_SUCCESS = 0, EXIT_FAILURE = 1 */
#include <string.h>
#include <ctype.h> /* isprint() */
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <net/if_arp.h>
#include <signal.h>
#include <errno.h>

#define CKSUMLEN        (64 - 8)

/* accepted one packet max size */
#define SNAPLEN         65535

/* 0 = only verified packets, 1 = all packets */
#define PROMISC         1

/* wait time(1/1000) for packet reading, if set 0 then wait forever */
#define TO_MS           1000    

/* accepted data max size */
#define DATA_SIZE       8192 

enum _ANSI { GRAY = 30, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, NOT = 00, BOLD = 1, UNBOLD = 0 };

int ansi_flag = 1;

void usage(char *prog);
char *ansi_color (char *str, unsigned int color, unsigned int bold);
void signal_handler(int signo);
unsigned short in_cksum(const u_short *addr, int len, u_short csum);
int send_icmp(char *host);
char *find_macaddr(char *host);
char *inet_ntoa64(struct in_addr ina);
void sniff_callback(u_char *user_arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
void sniff_packet_ipmac(const u_char *pkt_data);
void sniff_packet_verbose(const u_char *pkt_data);

void usage(char *prog)
{
    printf("USAGE   :\n");
    printf("       %s [OPTION]... [EXPRESSION]\n\n", prog);
    printf("OPTIONS :\n");
    printf("       -c [loop counter] (default : 0)\n");
    printf("       -i [interface] (default : eth0)\n");
    printf("       -v verbose print\n");
    printf("       -n no ansi color\n\n");
    printf("       Single Option :\n");
    printf("       -m [HOST] (find mac address)\n");
    printf("EXAMPLE:\n");
    printf("       %s \"ip\"\n",prog);
    printf("       %s -c 5 \"host 10.10.10.10 and port http\"\n",prog);
    printf("       %s -v -c 5 \"host 10.10.10.10 and port http\"\n",prog);
    printf("       %s -m 192.168.0.1\n",prog);

    exit(EXIT_FAILURE);
}

char *ansi_color(char *str, unsigned int color, unsigned int bold)
{
    int len = 0;
    char *ptr = NULL;
    char ac[] = "\033[%d;%dm%s\033[0m";

    if (!ansi_flag) {
        ptr = (char *)calloc(strlen(str) + 1, sizeof(char));
        strncpy(ptr, str, strlen(str));
        return ptr;
    }
    len = strlen(str) + strlen(ac);
    ptr = (char *)calloc(len, sizeof(char));
    bold = (bold|0)&1;

    switch(color) {
        case GRAY:
        case RED:
        case GREEN:
        case YELLOW:
        case BLUE:
        case MAGENTA:
        case CYAN:
        case WHITE:
        case NOT:
            /* %d + %d + %s = 6byte : bold(1) + color(2) + str(1) = 4byte : remain is 2 byte = null + 1 : so = -1 */
            snprintf(ptr, len - 1, ac, bold, color, str);
            break;
        default :
            snprintf(ptr, len - 1, ac, bold, NOT, str);
            break;
    }

    return ptr;
}

void signal_handler(int signo)
{
    switch(signo) {
        case SIGALRM:
            printf("send_icmp [ TIME OUT ]\n");
            exit(EXIT_FAILURE);
        default:
            exit(EXIT_FAILURE);
    }
}

unsigned short in_cksum(const u_short *addr, int len, u_short csum)
{
    int nleft = len;
    const u_short *w = addr;
    u_short answer;
    int sum = csum;

    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) sum += htons(*(u_char *)w << 8);

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

int send_icmp(char *host)
{
    int icmp_socket;
    int ret;
    struct icmp *p, *rp;
    struct sockaddr_in to, from;
    struct ip *ip;
    char buf[DATA_SIZE];
    socklen_t slen;
    int hlen;
    struct hostent *domain;
    char *ipchar;
    unsigned int vozlt_seq = 0xf;

    if ((domain=gethostbyname(host)) == NULL) {
        herror("gethostbyname");
        exit(EXIT_FAILURE);
    }

    ipchar = inet_ntoa64(*((struct in_addr *)domain->h_addr));

    if ((icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(buf, 0x00, DATA_SIZE);

    p = (struct icmp *)buf;
    p->icmp_type=ICMP_ECHO;
    p->icmp_code=0;
    p->icmp_cksum=0;
    p->icmp_seq=vozlt_seq++;
    p->icmp_id=getpid();
    p->icmp_cksum = in_cksum((u_short *)p, CKSUMLEN + 8, 0);
    inet_aton(ipchar, &to.sin_addr);
    to.sin_family = AF_INET;

    ret=sendto(icmp_socket,p,sizeof(*p),MSG_DONTWAIT,(struct sockaddr *)&to, sizeof(to));

    if (ret == -1) {
        perror("sendto");
    }

    signal(SIGALRM, signal_handler);
    alarm(3);

    slen=sizeof(from);
    ret = recvfrom(icmp_socket,buf, DATA_SIZE, 0, (struct sockaddr *)&from, &slen);  

    alarm(0);

    if (ret == -1) {
        printf("%d %d %d\n", ret, errno, EAGAIN);
        perror("recvfrom error");
    }

    ip = (struct ip *)buf;
    hlen = ip->ip_hl*4;
    rp = (struct icmp *)(buf+hlen);

#ifdef DEBUG
    printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    printf("| Reply                                                         |\n");
    printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    printf("| From       : %-49s|\n", inet_ntoa64(from.sin_addr));
    printf("| Type       : %-49d|\n", rp->icmp_type);
    printf("| Code       : %-49d|\n", rp->icmp_code);
    printf("| Seq        : %-49d|\n", rp->icmp_seq);
    printf("| Iden       : %-49d|\n", rp->icmp_id);
    printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
#endif

    return (rp->icmp_type) ? EXIT_FAILURE : EXIT_SUCCESS;
}

char *find_macaddr(char *host)
{
    struct sockaddr_in sin = { 0 };
    struct hostent *domain;
    struct arpreq myarp = { { 0 } }; /* struct sockaddr arp_pa(Protocol address)  */
    static char st_mac[6*sizeof("00")];
    int sock_fd;
    char *ipchar;
    char *macp;

    if ((domain=gethostbyname(host)) == NULL) {  /* get the host info */
        herror("gethostbyname");
        exit(EXIT_FAILURE);
    }

    ipchar = inet_ntoa64(*((struct in_addr *)domain->h_addr));

    if(send_icmp(ipchar) != EXIT_SUCCESS)
        return "ICMP NOT RECEIVED!";

    sin.sin_family = AF_INET;

    inet_aton (ipchar, &sin.sin_addr); 

    memcpy (&myarp.arp_pa, &sin, sizeof(myarp.arp_pa));
    strcpy (myarp.arp_dev, pcap_lookupdev(st_mac));

    if ((sock_fd = socket (AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (ioctl (sock_fd, SIOCGARP, &myarp) == -1) { return "MAC NOT FOUND!"; }

    macp = &myarp.arp_ha.sa_data[0];
    snprintf(st_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",*macp & 0xff, *(macp+1) & 0xff, *(macp+2) & 0xff, *(macp+3) & 0xff, *(macp+4) & 0xff, *(macp+5) & 0xff);

    close(sock_fd);

    return st_mac;
}

char *inet_ntoa64(struct in_addr ina)
{
    static char buf[4*sizeof("123")];
    unsigned char *ucp = (unsigned char *)&ina;

    sprintf(buf, "%d.%d.%d.%d",
            ucp[0] & 0xff,
            ucp[1] & 0xff,
            ucp[2] & 0xff,
            ucp[3] & 0xff);
    return buf;
}

void sniff_callback(u_char *user_arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
    (*user_arg == 0x01) ? sniff_packet_verbose(pkt_data) : sniff_packet_ipmac(pkt_data);
}

void sniff_packet_ipmac(const u_char *pkt_data)
{
    struct ether_header *etherh;
    struct ip *iph;
    struct tcphdr *tcph;
    char data[DATA_SIZE+1];
    char src_mac[18];
    char dst_mac[18];
    char src_ip[16];
    char dst_ip[16];
    char srcs[22];
    char dsts[22];
    char *ansi_srcs = NULL, *ansi_dsts = NULL, *ansi_src_mac = NULL, *ansi_dst_mac = NULL;
    unsigned int src_port;
    unsigned int dst_port;

    memset(src_mac, 0x00, sizeof(src_mac));
    memset(dst_mac, 0x00, sizeof(dst_mac));
    memset(src_ip, 0x00, sizeof(src_ip));
    memset(dst_ip, 0x00, sizeof(dst_ip));
    memset(data, 0x00, sizeof(data));

    etherh = (struct ether_header*)(pkt_data);
    iph = (struct ip*)(pkt_data + sizeof(struct ether_header));
    tcph = (struct tcphdr*)(pkt_data + sizeof(struct ether_header) + sizeof(struct ip));

    /* Source mac address */
    sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
            etherh->ether_shost[0] & 0xff,
            etherh->ether_shost[1] & 0xff,
            etherh->ether_shost[2] & 0xff,
            etherh->ether_shost[3] & 0xff,
            etherh->ether_shost[4] & 0xff,
            etherh->ether_shost[5] & 0xff
    );

    /* Destination mac address */
    sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
            etherh->ether_dhost[0] & 0xff,
            etherh->ether_dhost[1] & 0xff,
            etherh->ether_dhost[2] & 0xff,
            etherh->ether_dhost[3] & 0xff,
            etherh->ether_dhost[4] & 0xff,
            etherh->ether_dhost[5] & 0xff
    );

    sprintf(src_ip,"%s", inet_ntoa64(iph->ip_src));
    sprintf(dst_ip,"%s", inet_ntoa64(iph->ip_dst));
    src_port = ntohs(tcph->source);
    dst_port = ntohs(tcph->dest);

    sprintf(srcs,"%s:%d", src_ip, src_port);
    sprintf(dsts,"%s:%d", dst_ip, dst_port);

    /*--====
     * IPPROTO_TCP == 6
     * iph->ip_len is a all length of TCP/IP header. TCP(20) + IP(20) + data(...)
     * ETHERTYPE_IP == 0x0800
     ====--*/
    if (ntohs(etherh->ether_type) == ETHERTYPE_IP && iph->ip_p == IPPROTO_TCP) {
        ansi_srcs = ansi_color(srcs, YELLOW, UNBOLD);
        ansi_src_mac = ansi_color(src_mac, YELLOW, UNBOLD);
        ansi_dsts = ansi_color(dsts, MAGENTA, UNBOLD);
        ansi_dst_mac = ansi_color(dst_mac, MAGENTA, UNBOLD);
        if (ansi_flag) {
            printf("%-33s%s ~> %-33s%s\n", ansi_srcs, ansi_src_mac, ansi_dsts, ansi_dst_mac);
        } else {
            printf("%-22s%s ~> %-22s%s\n", srcs, src_mac, dsts, dst_mac);
        }
        free(ansi_srcs);
        free(ansi_src_mac);
        free(ansi_dsts);
        free(ansi_dst_mac);
    }
}

void sniff_packet_verbose(const u_char *pkt_data)
{
    struct ether_header *etherh;
    struct ip *iph;
    struct tcphdr *tcph;
    char *payload;
    int i, a, data_len, isprint_c;
    char data[DATA_SIZE+1];
    char fmt[512];

    memset(data, 0x00, sizeof(data));
    etherh = (struct ether_header*)(pkt_data);
    iph = (struct ip*)(pkt_data + sizeof(struct ether_header));
    tcph = (struct tcphdr*)(pkt_data + sizeof(struct ether_header) + sizeof(struct ip));

    /*--==== 
     * /usr/include/netinet/tcp.h: (doff * 4)
     * libpcap:sniffex.c source's (((ip)->ip_vhl) & 0x0f) and doff is equal?
     ====--*/
    payload = (char *)(pkt_data + sizeof(struct ether_header) + sizeof(struct ip) + tcph->doff * 4);

    printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
    printf("| Ethernet Header: 14byte                                       |\n");
    printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");

    /* Source mac address */
    printf("| - Source MAC Address      : ");
    for (i = 0; i < ETH_ALEN; i++) {
        printf("%02x", etherh->ether_shost[i]);
        if (i != (ETH_ALEN -1))
            printf(":");
        if (i == (ETH_ALEN -1))
            printf("%-17c|\n", ' ');
    }

    /* Destination mac address */
    printf("| - Destination MAC Address : ");
    for (i = 0; i < ETH_ALEN; i++) {
        printf("%02x", etherh->ether_dhost[i]);
        if (i != (ETH_ALEN -1))
            printf(":");
        if (i == (ETH_ALEN -1))
            printf("%-17c|\n", ' ');
    }
    printf("| - Ether Type              : 0x%-32x|\n",ntohs(etherh->ether_type));

    /* ETHERTYPE_IP == 0x0800 */
    if (ntohs(etherh->ether_type) == ETHERTYPE_IP) {
        printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
        printf("| IPv4 Header: 20byte + Options(If exists max is 40byte)        |\n");
        printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
        printf("| - Header Length    : %-41d|\n", iph->ip_hl);
        printf("| - Version          : %-41d|\n", iph->ip_v);
        printf("| - Service Type     : %-41d|\n", iph->ip_tos);
        printf("| - Total Length     : %-41d|\n", ntohs(iph->ip_len) );
        printf("| - Ident            : %-41d|\n", ntohs(iph->ip_id));   
        printf("| - Fragment Offset  : %-41d|\n", ntohs(iph->ip_off) );
        printf("| - TTL              : %-41d|\n", iph->ip_ttl);
        printf("| - Protocol         : %-41d|\n", iph->ip_p);  /*  Protocol : /usr/include/netinet/in.h */
        printf("| - Checksum         : %-41d|\n", ntohs(iph->ip_sum) );
        printf("| - Src Address      : %-41s|\n", inet_ntoa64(iph->ip_src));
        printf("| - Dst Address      : %-41s|\n", inet_ntoa64(iph->ip_dst));
    }

    /*--====
     * IPPROTO_TCP == 6
     * iph->ip_len is a all length of TCP/IP header. TCP(20) + IP(20) + data(...)
     ====--*/
    if (iph->ip_p == IPPROTO_TCP) {
        printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
        printf("| TCP Header: 20byte + Options(If exists max is 40byte)         |\n");
        printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
        printf("| - Src Port         : %-41d|\n", ntohs(tcph->source));
        printf("| - Dst Port         : %-41d|\n", ntohs(tcph->dest));
        printf("| - Seq Number       : %-41u|\n", ntohl(tcph->seq));
        printf("| - Ack number       : %-41u|\n", ntohl(tcph->ack_seq));
        printf("| - Data Offset      : %-41d|\n", tcph->doff);  
        printf("| - Flags Urg        : 0x%02x%-37c|\n", tcph->urg, ' ');
        printf("| - Flags Ack        : 0x%02x%-37c|\n", tcph->ack, ' ');
        printf("| - Flags Psh        : 0x%02x%-37c|\n", tcph->psh, ' ');
        printf("| - Flags Rst        : 0x%02x%-37c|\n", tcph->rst, ' ');
        printf("| - Flags Syn        : 0x%02x%-37c|\n", tcph->syn, ' ');
        printf("| - Flags Fin        : 0x%02x%-37c|\n", tcph->fin, ' ');
        printf("| - Window           : %-41d|\n", ntohs(tcph->window));
        printf("| - Checksum         : %-41d|\n", ntohs(tcph->check));
        printf("| - Urgent Pointer   : %-41d|\n", ntohs(tcph->urg_ptr));

        data_len = (ntohs(iph->ip_len)) - 40;
        printf("| - Data Length      : %-41d|\n", data_len);

        data_len = (data_len < DATA_SIZE) ? data_len : DATA_SIZE ;
        strncpy(data, payload, data_len);
        data[data_len] = 0x00;

        printf("|   ");

        isprint_c = 0;
        for(i=0;i < data_len; i++) {
            if (isprint(data[i])) {
                printf("%c", data[i]);
                isprint_c++;
            } else if(data[i] != 0x00) {
                printf(".");
                isprint_c++;
            } else {
                continue;
            }
            if ((i%56) == 55) {
                printf("%-4c|\n|   ", ' ');
            }
        }

        if (data_len) {
            snprintf(fmt, sizeof(fmt), "%%-%dc|\n", 56 + 4 - isprint_c % 56);
            printf(fmt, ' ');
        } else {
            printf("%-60c|\n", ' ');
        }
    }
    printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");

    /* Data hexdump */
    if (data[0] != 0x00) printf("%05d ", 0x0);
    for(i = 0; i < isprint_c; i++) {
        if(data[i] != 0x00){
            printf("%02x ", data[i] & 0xff);
        } else {
            continue;
        }
        if ((i%20) == 19) {
            for(a = 0; i + 1 > i-19+a; a++) {
                if (isprint(data[i-19+a])) {
                    printf("%c", data[i-19+a]);
                } else if(data[i-19+a] != 0x00) {
                    printf(".");
                } else {
                    continue;
                }
            }
            if (i+1 != isprint_c) printf("\n%05d ", i + 1);
        }
    }

    if (data[0] != 0x00 && isprint_c < 20) {
        /* hex's space is 3 */
        snprintf(fmt, sizeof(fmt), "%%-%dc", 56 + 4 - isprint_c % 56 * 3);
        printf(fmt, ' ');
        for(i = 0; i < data_len; i++) {
            if (isprint(data[i])) {
                printf("%c", data[i]);
            } else if(data[i] != 0x00) {
                printf(".");
            } else {
                continue;
            }
        }
    } else if (isprint_c%20) {
        snprintf(fmt, sizeof(fmt), "%%-%dc", 56 + 4 - ((isprint_c%20) % 56 * 3));
        printf(fmt, ' ');
        for(i = (isprint_c - (isprint_c%20)); i < isprint_c; i++) {
            if (isprint(data[i])) {
                printf("%c", data[i]);
            } else if(data[i] != 0x00) {
                printf(".");
            } else {
                continue;
            }
        }
    }

    printf("\n\n");
}

int main(int argc, char **argv)
{
    char *device = NULL, errbuf[PCAP_ERRBUF_SIZE], filter_exp[512];
    unsigned char user_arg = 0x00;
    int loop_counter;
    int opt;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    pcap_t *p;
    struct bpf_program fp;

    if (argc == 1) usage(argv[0]);

    memset(filter_exp, 0x00, sizeof(filter_exp));

    while ( (opt = getopt(argc, argv, "hc:i:vnm:")) != -1 ) {
        switch(opt) {
            case 'c' :
                loop_counter = atoi(optarg);
                break;
            case 'i' :
                device = optarg;
                break;
            case 'v' :
                user_arg = 0x01;
                break;
            case 'n' :
                ansi_flag = 0;
                user_arg = 0x02;
                break;
            case 'm' :
                printf("%s's mac address is %s\n", optarg, ansi_color(find_macaddr(optarg), GREEN, UNBOLD));
                exit(EXIT_SUCCESS);
            case '?' :
                usage(argv[0]);
            default :
                usage(argv[0]);
        }

        if (argc > optind) {
            strncpy(filter_exp, argv[optind], strlen(argv[optind])+1);
        } else {
            usage(argv[0]);
        }
    }

    if (!filter_exp[0]) {
        strncpy(filter_exp, argv[1], strlen(argv[1])+1);
    }

    memset(errbuf, 0x00, sizeof(errbuf));

    /* find a capture device if not specified on command-line */
    device =  (device == NULL) ? pcap_lookupdev(errbuf) : device;
    if (device == NULL) {
        fprintf(stderr, "pcap_lookupdev : %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(device, &netp, &maskp, errbuf) == -1) {
        fprintf(stderr, "pcap_lookupnet : %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /* open capture device */
    p = pcap_open_live(device, SNAPLEN, PROMISC, TO_MS, errbuf);
    if (p == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(p) != DLT_EN10MB) {
        fprintf(stderr, "pcap_datalink(): %s is not an Ethernet\n", device);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(p, &fp, filter_exp, 0, netp) == -1) {
        fprintf(stderr, "pcap_compile(): %s: %s\n", filter_exp, pcap_geterr(p));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(p, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter():  %s: %s\n", filter_exp, pcap_geterr(p));
        exit(EXIT_FAILURE);
    }

    printf("# Interface: %s\n\n", device);
    if (!user_arg) {
        printf("%-43s%s\n", "SOURCE", "DESTINATION");
    }

    /* now we can set our callback function */
    pcap_loop(p, loop_counter, sniff_callback, &user_arg);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(p);

    return(EXIT_SUCCESS);
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
