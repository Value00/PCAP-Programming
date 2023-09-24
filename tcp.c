#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { //IPv4임
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 

    printf("================= 캡쳐한 패킷 정보 출력 ================= \n\n");

    //ethernet header
    printf("[*] Ethernet Header\n");
    printf("    [>] src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]); 
    printf("    [>] dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n\n", eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]); 

    // ip header
    printf("[*] IP Header\n"); 
    printf("    [>] src ip: %s\n", inet_ntoa(ip->iph_sourceip)); 
    //ipv4 출발지 주소 : 출발함
    printf("    [>] dst ip: %s\n\n", inet_ntoa(ip->iph_destip));    
    //ipv4 목적지 주소 : 여기로 전송하려고 함 

    /* determine protocol */
    switch(ip->iph_protocol) {     
        case IPPROTO_TCP:
            printf("[*] Protocol: TCP\n\n");
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

            // TCP 헤더에서 데이터 시작 위치 계산
            int tcp_header_size = TH_OFF(tcp); // TH_OFF 메크로를 이용해 data off 값을 구함
            u_char *tcp_data = (u_char *)(packet + sizeof(struct ethheader) + (ip->iph_ihl << 2) + tcp_header_size);
            int tcp_data_length = ntohs(ip->iph_len) - (ip->iph_ihl << 2) - tcp_header_size;

            printf("[*] TCP Header\n");
            printf("    [>] src port : %u\n", ntohs(tcp->tcp_sport));
            printf("    [>] dst port : %u\n\n", ntohs(tcp->tcp_dport));

            // 데이터 출력 (처음 100바이트만 출력)
            int max_bytes_to_print = 100;
            int bytes_printed = 0;
            printf("[*] data\n");
            printf("    [>]");
            for (int i = 0; i < tcp_data_length && bytes_printed < max_bytes_to_print; i++) {
                printf(" %02x ", tcp_data[i]);
                bytes_printed++;
                if (bytes_printed % 16 == 0) {
                    printf("\n");
                    printf("       ");
                }
            }
            printf("\n\n");
            return;

        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
