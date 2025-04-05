//pcap.c

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // IP 패킷
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        // IP header 길이 계산 (단위: 4바이트 -> 바이트로 변환)
        int ip_header_len = ip->iph_ihl * 4;

        // TCP 패킷
        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);

            int tcp_header_len = TH_OFF(tcp) * 4;

            // 메세지 시작 위치
            const u_char *data = (u_char *)tcp + tcp_header_len;
            int data_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

            // 출력
            printf("\n===== Packet Capture =====\n");
            printf("Ethernet Header: src mac: %02x:%02x:%02x:%02x:%02x:%02x | dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
                eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            printf("IP Header: src ip %s | dst ip %s\n", inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));
            printf("TCP Header: src port: %d | dst port: %d\n", ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport));

            if (data_len > 0 && data_len < 1500) {
                printf("Message (%d bytes):\n", data_len);
                for (int i = 0; i < data_len; i++) {
                    if (data[i] >= 32 && data[i] <= 126)
                        printf("%c", data[i]);
                    else
                        printf(".");
                }
                printf("\n");
            }
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // TCP만 출력
    bpf_u_int32 net;

    // pcap 세션 시작 (on NIC with name enp33)
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 2;
    }

    // 필터 설정
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // 패킷 캡처
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}


