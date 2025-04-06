#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // IP 패킷이면
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        // TCP만 처리
        if (ip->iph_protocol == IPPROTO_TCP) {
            int ip_header_len = ip->iph_ihl * 4;

            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
            int tcp_header_len = TH_OFF(tcp) * 4;

            int total_header_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;
            const u_char *payload = packet + total_header_size;

            // Ethernet 출력
            printf("====== Ethernet Header ======\n");
            printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            // IP 출력
            printf("====== IP Header ======\n");
            printf("Src IP : %s\n", inet_ntoa(ip->iph_sourceip));
            printf("Dst IP : %s\n", inet_ntoa(ip->iph_destip));

            // TCP 출력
            printf("====== TCP Header ======\n");
            printf("Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("Dst Port: %d\n", ntohs(tcp->tcp_dport));

            // Payload 출력
            printf("====== Payload (%d bytes) ======\n", payload_len);
            for (int i = 0; i < payload_len; i++) {
                printf("%c", isprint(payload[i]) ? payload[i] : '.');
            }
            printf("\n\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // NIC 이름은 본인 환경에 맞게 설정
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    // 필터 설정 (TCP 패킷만)
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // 패킷 캡처 시작
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
