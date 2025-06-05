#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
using namespace std;

const string HTTP_REDIRECT_MSG = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";

void usage() // 설명출력
{
    cout << "syntax : tcp-block <interface> <pattern>\n";
    cout << "sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n";
}

// 체크섬 계산 함수
unsigned short checksum(unsigned short *ptr, int nbytes)
{
    long sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
        sum += *(unsigned char *)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void send_rst(const u_char *packet, int packet_len)
{
    const struct ip *ip_hdr = (struct ip *)(packet + 14); // 이더넷해더 이후
    // tcp검증 x
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    const struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr_len); // tcp해더
    int tcp_hdr_len = tcp_hdr->th_off * 4;
    int payload_len = ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;
    uint32_t seq = ntohl(tcp_hdr->th_seq) + payload_len; // 시퀸스 번호 계산

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
        return;

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char buffer[4096] = {};
    struct ip *ip = (struct ip *)buffer;
    struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ip));

    ip->ip_hl = 5;
    ip->ip_v = 4;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ip->ip_id = htons(0);
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_p = IPPROTO_TCP; // tcp프로토콜콜
    ip->ip_sum = 0;
    ip->ip_src = ip_hdr->ip_src;
    ip->ip_dst = ip_hdr->ip_dst;
    ip->ip_sum = checksum((unsigned short *)ip, sizeof(struct ip));

    tcp->th_sport = tcp_hdr->th_sport;
    tcp->th_dport = tcp_hdr->th_dport;
    tcp->th_seq = htonl(seq);
    tcp->th_ack = 0;
    tcp->th_off = 5;
    tcp->th_flags = TH_RST; // reset플래그
    tcp->th_win = htons(0);
    tcp->th_sum = 0;
    tcp->th_urp = 0;

    struct pseudo_header // 수도해더 생성
    {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_len;
    } psh;

    psh.src = ip->ip_src.s_addr;
    psh.dst = ip->ip_dst.s_addr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_len = htons(sizeof(struct tcphdr));

    char pseudo_packet[1024] = {};
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), tcp, sizeof(struct tcphdr));
    tcp->th_sum = checksum((unsigned short *)pseudo_packet, sizeof(psh) + sizeof(struct tcphdr));

    struct sockaddr_in dst; // 전송
    dst.sin_family = AF_INET;
    dst.sin_addr = ip->ip_dst;

    sendto(sock, buffer, sizeof(struct ip) + sizeof(struct tcphdr), 0,
           (struct sockaddr *)&dst, sizeof(dst));

    close(sock);
}

void send_fin(const u_char *packet, int packet_len)
{
    const char *http_redirect = HTTP_REDIRECT_MSG.c_str();
    int http_len = strlen(http_redirect);

    const struct ip *ip_hdr = (struct ip *)(packet + 14); // ip 해더
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    const struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr_len); // tcp해더
    int tcp_hdr_len = tcp_hdr->th_off * 4;
    int payload_len = ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
        return;

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char buffer[4096] = {};
    struct ip *ip = (struct ip *)buffer;
    struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ip));
    char *payload = buffer + sizeof(struct ip) + sizeof(struct tcphdr);
    memcpy(payload, http_redirect, http_len);

    ip->ip_hl = 5;
    ip->ip_v = 4;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + http_len);
    ip->ip_id = htons(0);
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_p = IPPROTO_TCP;
    ip->ip_sum = 0;
    ip->ip_src = ip_hdr->ip_dst;
    ip->ip_dst = ip_hdr->ip_src;
    ip->ip_sum = checksum((unsigned short *)ip, sizeof(struct ip));

    tcp->th_sport = tcp_hdr->th_dport;
    tcp->th_dport = tcp_hdr->th_sport;
    tcp->th_seq = tcp_hdr->th_ack;
    tcp->th_ack = htonl(ntohl(tcp_hdr->th_seq) + payload_len);
    tcp->th_off = 5;
    tcp->th_flags = TH_FIN | TH_ACK;
    tcp->th_win = htons(1024);
    tcp->th_sum = 0;
    tcp->th_urp = 0;

    struct pseudo_header
    {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_len;
    } psh;

    psh.src = ip->ip_src.s_addr;
    psh.dst = ip->ip_dst.s_addr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_len = htons(sizeof(struct tcphdr) + http_len);

    char pseudo_packet[1500] = {};
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), tcp, sizeof(struct tcphdr) + http_len);
    tcp->th_sum = checksum((unsigned short *)pseudo_packet, sizeof(psh) + sizeof(struct tcphdr) + http_len);

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_addr = ip->ip_dst;

    sendto(sock, buffer, sizeof(struct ip) + sizeof(struct tcphdr) + http_len, 0,
           (struct sockaddr *)&dst, sizeof(dst));

    close(sock);
}

bool is_target_packet(const u_char *packet, int packet_len, const string &pattern)
{
    const struct ip *ip_hdr = (struct ip *)(packet + sizeof(ether_header));
    if (ip_hdr->ip_p != IPPROTO_TCP) // ip해더에서 tcp인지 확인한다.
        return false;

    int ip_hdr_len = ip_hdr->ip_hl * 4; // ip해더 길이
    const struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(ether_header) + ip_hdr_len);
    int tcp_hdr_len = tcp_hdr->th_off * 4;

    const u_char *payload = packet + sizeof(ether_header) + ip_hdr_len + tcp_hdr_len; // 페이로드
    int payload_len = ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;

    return std::string((char *)payload, payload_len).find(pattern) != std::string::npos;
}

int main(int argc, char *argv[])
{
    if (argc != 3) // 인자 검사
    {
        usage();
        return 1;
    }

    char *interface = argv[1];
    string pattern = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf); // 핸들생성
    if (handle == nullptr)
    {
        cerr << "pcap_open_live failed: " << errbuf << endl;
        return 1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet); // 패킷 읽기
        if (res == 0)                                     // 타임아웃
            continue;
        if (res == -1 || res == -2) // 에러나 파일끝
            break;

        if (is_target_packet(packet, header->len, pattern))
        {
            cerr << "tcp block " << pattern << " " << errbuf << endl;
            send_rst(packet, header->len);
            send_fin(packet, header->len);
        }
    }

    pcap_close(handle);
    return 0;
}
